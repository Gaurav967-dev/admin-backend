import os
from datetime import datetime, timezone

from dotenv import load_dotenv
load_dotenv()

from typing import Literal
from fastapi import ( FastAPI, Depends, HTTPException, Cookie, Response, Request, status, Query )
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr, Field, field_validator
from sqlalchemy import select, delete, update, func, or_
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError

from .database import Base, engine, get_db
from .models import User, RefreshSession, EmployeeProfile
from .security import ( hash_password, verify_password, create_token, decode_token, hash_jti )
from .profile_schemas import ( ProfilePut, TASK_LABELS, default_tasks )

app = FastAPI(title="Admin Management API")

FRONTEND_ORIGIN = os.getenv(
    "FRONTEND_ORIGIN", "http://localhost:3000"
)
COOKIE_SECURE = (
    os.getenv("COOKIE_SECURE", "false").lower()
    == "true"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[FRONTEND_ORIGIN],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["Content-Type"],
)

Base.metadata.create_all(bind=engine)


class SignupRequest(BaseModel):
    name: str = Field(min_length=2, max_length=100)
    email: EmailStr
    password: str = Field(min_length=12, max_length=128)


class LoginRequest(BaseModel):
    email: EmailStr
    password: str

class UserFields(BaseModel):
    name: str = Field(min_length=2, max_length=100)
    email: EmailStr
    role: Literal["user", "admin"] = "user"
    is_active: bool = True

    @field_validator("name", mode="before")
    @classmethod
    def trim_name(cls, value):
        if isinstance(value, str):
            return value.strip()
        return value

    @field_validator("email", mode="before")
    @classmethod
    def normalize_email(cls, value):
        if isinstance(value, str):
            return value.strip().lower()
        return value

class CreateUserRequest(UserFields):
    password: str = Field(
        min_length=12,
        max_length=128
    )

class UpdateUserRequest(UserFields):
    password: str | None = Field(
        default=None,
        min_length=12,
        max_length=128
    )


def public_user(user: User):
    return {
        "id": user.id,
        "name": user.name,
        "email": user.email,
        "role": user.role
    }


def set_auth_cookies(
    response: Response,
    db: Session,
    user: User
):
    refresh_token, session_id, expiry = create_token(
        user.id,
        "refresh"
    )

    access_token, _, _ = create_token(
        user.id,
        "access",
        session_id=session_id
    )

    id_token, _, _ = create_token(
        user.id,
        "id",
        identity={
            "name": user.name,
            "email": user.email
        }
    )

    db.add(
        RefreshSession(
            user_id=user.id,
            jti_hash=hash_jti(session_id),
            expires_at=expiry,
            revoked=False
        )
    )

    cookies = [
        ("id_token", id_token, 5 * 60, "/verify-token"),
        ("access_token", access_token, 5 * 60, "/"),
        ("refresh_token", refresh_token, 7 * 24 * 60 * 60, "/refresh-token")
    ]

    for name, value, max_age, cookie_path in cookies:
        response.set_cookie(
            key=name,
            value=value,
            httponly=True,
            secure=COOKIE_SECURE,
            samesite="lax",
            max_age=max_age,
            path=cookie_path
        )

    return {
        "id_token": id_token,
        "access_token": access_token,
        "refresh_token": refresh_token,
    }


def current_user(
    access_token: str | None = Cookie(default=None),
    db: Session = Depends(get_db)
):
    if not access_token:
        raise HTTPException(
            status_code=401,
            detail="Not authenticated"
        )

    payload = decode_token(access_token, "access")

    session_id = payload.get("sid")

    if not isinstance(session_id, str):
        raise HTTPException(
            status_code=401,
            detail="Invalid token session"
        )

    try:
        user_id = int(payload["sub"])
    except (TypeError, ValueError):
        raise HTTPException(
            status_code=401,
            detail="Invalid access token subject"
        )

    session = db.scalar(
        select(RefreshSession).where(
            RefreshSession.jti_hash ==
            hash_jti(session_id)
        )
    )

    if (
        session is None
        or session.revoked
        or session.user_id != user_id
        or session.expires_at <= datetime.now(timezone.utc)
    ):
        raise HTTPException(
            status_code=401,
            detail="Session expired or revoked"
        )

    user = db.get(User, user_id)

    if not user or not user.is_active:
        raise HTTPException(
            status_code=401,
            detail="User unavailable"
        )

    return user

def require_admin(
    user: User = Depends(current_user)
):
    if user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Administrator access required"
        )

    return user

def serialize_admin_user(user: User):
    return {
        "id": user.id,
        "name": user.name,
        "email": user.email,
        "role": user.role,
        "is_active": user.is_active
    }

def get_user_summary(db: Session):
    users = db.scalars(select(User).order_by(User.id.asc())).all()

    return {
        "total_users": len(users),
        "active_users": sum(1 for user in users if user.is_active),
        "admins": sum(1 for user in users if user.role == "admin"),
        "users": [
            serialize_admin_user(user)
            for user in users
        ]
    }


# Profile Helpers

def serialize_profile(
    user: User,
    profile: EmployeeProfile | None
):
    # Existing signup users may not have employee profile records yet.
    name_parts = user.name.strip().split(" ", 1)

    first_name = name_parts[0] if name_parts else ""
    last_name = (
        name_parts[1] if len(name_parts) > 1 else ""
    )

    stored_tasks = (
        profile.tasks
        if profile and profile.tasks
        else default_tasks()
    )

    tasks = [
        {
            **task,
            "label": TASK_LABELS[task["key"]],
        }
        for task in stored_tasks
    ]

    enabled_tasks = [task for task in tasks if task["enabled"]]

    progress = (
        round(sum(task["progress"] for task in enabled_tasks) / len(enabled_tasks))
        if enabled_tasks else 0
    )

    if profile and not profile.onboarding_required:
        status = "Not Required"
    elif progress == 100 and enabled_tasks:
        status = "Completed"
    elif progress > 0:
        status = "Onboarding"
    else:
        status = "Not Started"

    return {
        "user_id": user.id,
        "first_name": (profile.first_name if profile else first_name),
        "last_name": (profile.last_name if profile else last_name),
        "email": user.email,
        "role": user.role,
        "phone": profile.phone if profile else None,
        "position": profile.position if profile else None,
        "team": profile.team if profile else None,
        "manager": profile.manager if profile else None,
        "lead": profile.lead if profile else None,
        "onboarding_start": ( profile.onboarding_start.isoformat() if profile and profile.onboarding_start else None),
        "onboarding_required": ( profile.onboarding_required if profile else True),
        "tasks": tasks,
        "onboarding_progress": progress,
        "onboarding_status": status,
        "created_at": ( user.created_at.isoformat() if user.created_at else None),
    }


def save_profile(
    db: Session,
    user: User,
    data: ProfilePut
):
    # Lock the user row only when a phone number is submitted.
    if data.phone is not None:
        db.execute(select(User.id).where(User.id == user.id).with_for_update()).scalar_one()

    # Always load, create the profile.
    profile = db.get(EmployeeProfile, user.id)

    if profile is None:
        profile = EmployeeProfile(
            user_id=user.id,
            first_name=data.first_name,
            last_name=data.last_name,
        )
        db.add(profile)

    # Phone number can only be entered once.
    if data.phone is not None:
        existing_phone = (profile.phone or "").strip()

        if existing_phone and existing_phone != data.phone:
            raise HTTPException(
                status_code=409,
                detail=("Phone number is already set and cannot be changed")
            )

        if not existing_phone:
            profile.phone = data.phone

    # Synchronize employee name and email with existing authentication user.
    user.name = " ".join(
        part
        for part in [data.first_name.strip(), data.last_name.strip()]
        if part
    )

    profile.first_name = data.first_name
    profile.last_name = data.last_name
    profile.position = data.position
    profile.team = data.team
    profile.manager = data.manager
    profile.lead = data.lead

    profile.onboarding_start = data.onboarding_start
    profile.onboarding_required = data.onboarding_required

    # Assign a new JSONB value, allowing SQLAlchemy to detect and persist the change.
    profile.tasks = [task.model_dump() for task in data.tasks]

    try:
        db.commit()
        db.refresh(user)
        db.refresh(profile)
    except IntegrityError:
        db.rollback()

        raise HTTPException(
            status_code=409,
            detail="Email already registered"
        )

    return serialize_profile(user, profile)


def set_identity_cookie(
    response: Response,
    user: User
):
    # Keep informational ID token aligned with an updated name or email.
    token, _, _ = create_token(
        user.id,
        "id",
        identity={
            "name": user.name,
            "email": user.email
        }
    )

    response.set_cookie(
        key="id_token",
        value=token,
        httponly=True,
        secure=COOKIE_SECURE,
        samesite="lax",
        max_age=5 * 60,
        path="/verify-token"
    )


# Reject browser writes from untrusted origins.
@app.middleware("http")
async def check_write_origin(request: Request, call_next):
    if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
        origin = request.headers.get("origin")
        if origin and origin != FRONTEND_ORIGIN:
            return JSONResponse(
                {"detail": "Untrusted origin"},
                status_code=403
            )

    return await call_next(request)

@app.get("/public-stats")
def get_public_stats(db: Session = Depends(get_db)):
    return {
        "total_users": db.scalar(select(func.count()).select_from(User)) or 0,
        "active_users": db.scalar(select(func.count()).select_from(User).where(User.is_active.is_(True))) or 0,
        "admins": db.scalar(select(func.count()).select_from(User).where(User.role == "admin")) or 0,
    }

@app.post("/signup", status_code=201)
def signup(
    data: SignupRequest,
    response: Response,
    db: Session = Depends(get_db)
):
    email = data.email.lower()

    user = User(
        name=data.name.strip(),
        email=email,
        password_hash=hash_password(data.password),
        role="user"
    )

    db.add(user)

    try:
        db.flush()
        tokens = set_auth_cookies(response, db, user)
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(
            status_code=409,
            detail="Email already registered"
        )

    return {
        "message": "Account created successfully",
        "user": public_user(user),
        "tokens": tokens
    }


@app.post("/sign")
def signin(
    data: LoginRequest,
    response: Response,
    db: Session = Depends(get_db)
):
    user = db.scalar(
        select(User).where(
            User.email == data.email.lower()
        )
    )

    if (
        not user
        or not verify_password(
            data.password, user.password_hash
        )
        or not user.is_active
    ):
        raise HTTPException(
            status_code=401,
            detail="Invalid email or password"
        )

    tokens = set_auth_cookies(response, db, user)
    db.commit()

    result = {
        "message": "Login successful",
        "user": public_user(user),
        "tokens": tokens
    }

    return result

@app.get("/verify-token")
def verify_token(
    user: User = Depends(current_user),
    id_token: str | None = Cookie(default=None),
):
    if not id_token:
        raise HTTPException(
            status_code=401,
            detail="ID token missing"
        )

    identity = decode_token(
        id_token,
        "id"
    )

    if identity.get("sub") != str(user.id):
        raise HTTPException(
            status_code=401,
            detail="Token identity mismatch"
        )

    return {
        "valid": True,
        "user": public_user(user)
    }


@app.post("/refresh-token")
def refresh_token(
    response: Response,
    refresh_token: str | None = Cookie(default=None),
    db: Session = Depends(get_db)
):
    if not refresh_token:
        raise HTTPException(
            status_code=401,
            detail="Refresh token missing"
        )

    payload = decode_token(
        refresh_token, "refresh"
    )

    # Lock the session to prevent concurrent reuse.
    session = db.scalar(
        select(RefreshSession)
        .where(
            RefreshSession.jti_hash ==
            hash_jti(payload["jti"])
        )
        .with_for_update()
    )

    if (
        not session
        or session.revoked
        or session.user_id != int(payload["sub"])
        or session.expires_at <= datetime.now(timezone.utc)
    ):
        raise HTTPException(
            status_code=401,
            detail="Refresh session expired or revoked"
        )

    user = db.get(User, session.user_id)

    if not user or not user.is_active:
        raise HTTPException(
            status_code=401,
            detail="User unavailable"
        )

    # Rotation: old refresh token cannot be reused.
    session.revoked = True

    tokens = set_auth_cookies(response, db, user)
    db.commit()

    return {"message": "Token refreshed", "tokens": tokens}


@app.post("/logout")
def logout(
    response: Response,
    user: User = Depends(current_user),
    access_token: str | None = Cookie(default=None),
    db: Session = Depends(get_db)
):
    payload = decode_token(access_token, "access")

    session_id = payload["sid"]

    # Revoke current login session.
    db.execute(
        update(RefreshSession)
        .where(
            RefreshSession.user_id == user.id, RefreshSession.jti_hash == hash_jti(session_id)
        )
        .values(revoked=True)
    )

    db.commit()

    response.delete_cookie("id_token", path="/verify-token")
    response.delete_cookie("access_token", path="/")
    response.delete_cookie("refresh_token", path="/refresh-token")

    return {"message": "Logged out successfully"}


@app.get("/dashboard")
def get_dashboard(
    admin: User = Depends(require_admin),
    db: Session = Depends(get_db)    
):
    return get_user_summary(db)


@app.get("/user")
def get_users(
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=5, ge=1, le=50),
    search: str = Query(default="", max_length=100),
    status_filter: Literal[ "all", "active", "inactive" ] = "all",
    role_filter: Literal[ "all", "admin", "user" ] = "all",
    admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    conditions = []

    if search.strip():
        term = f"%{search.strip()}%"

        conditions.append(
            or_(
                User.name.ilike(term),
                User.email.ilike(term),
            )
        )

    if status_filter == "active":
        conditions.append(User.is_active.is_(True))
    elif status_filter == "inactive":
        conditions.append(User.is_active.is_(False))

    if role_filter != "all":
        conditions.append(User.role == role_filter)

    filtered_total = db.scalar(select(func.count()).select_from(User).where(*conditions)) or 0
    users = db.scalars(select(User).where(*conditions).order_by(User.id.asc()).offset((page - 1) * page_size).limit(page_size)).all()
    total_users = db.scalar(select(func.count()).select_from(User)) or 0
    active_users = db.scalar(select(func.count()).select_from(User).where(User.is_active.is_(True))) or 0
    admins = db.scalar(select(func.count()).select_from(User).where(User.role == "admin")) or 0

    return {
        "users": [
            serialize_admin_user(user)
            for user in users
        ],
        "total_users": total_users,
        "active_users": active_users,
        "admins": admins,
        "page": page,
        "page_size": page_size,
        "filtered_total": filtered_total,
        "total_pages": max(1, (filtered_total + page_size - 1) // page_size),
    }


@app.post("/user", status_code=201)
def create_user(
    data: CreateUserRequest,
    admin: User = Depends(require_admin),
    db: Session = Depends(get_db)
):
    existing_user = db.scalar(
        select(User).where(User.email == data.email)
    )

    if existing_user:
        raise HTTPException(
            status_code=409,
            detail="Email already registered"
        )

    new_user = User(
        name=data.name,
        email=data.email,
        password_hash=hash_password(data.password),
        role=data.role,
        is_active=data.is_active
    )

    db.add(new_user)

    try:
        db.commit()
        db.refresh(new_user)

    except IntegrityError:
        db.rollback()

        raise HTTPException(
            status_code=409,
            detail="Email already registered"
        )

    return {
        "message": "User created successfully",
        "user": serialize_admin_user(new_user)
    }


@app.put("/user")
def update_user(
    data: UpdateUserRequest,
    user_id: int = Query(gt=0),
    admin: User = Depends(require_admin),
    db: Session = Depends(get_db)
):
    user = db.get(User, user_id)

    if not user:
        raise HTTPException(
            status_code=404,
            detail="User not found"
        )

    # Prevent accidentally locking yourself out of the administrator account.
    if user.id == admin.id:
        if data.role != "admin":
            raise HTTPException(
                status_code=400,
                detail="You cannot remove your own admin role"
            )

        if not data.is_active:
            raise HTTPException(
                status_code=400,
                detail="You cannot deactivate your own account"
            )

    user.name = data.name
    user.email = data.email
    user.role = data.role
    user.is_active = data.is_active

    if data.password is not None:
        user.password_hash = hash_password(data.password)

        # Revoke refresh sessions after a password change.
        db.execute(
            update(RefreshSession)
            .where(RefreshSession.user_id == user.id)
            .values(revoked=True)
        )

    # Deactivated accounts must not be able to refresh their old sessions.
    if not data.is_active:
        db.execute(
            update(RefreshSession)
            .where(RefreshSession.user_id == user.id)
            .values(revoked=True)
        )

    try:
        db.commit()
        db.refresh(user)

    except IntegrityError:
        db.rollback()

        raise HTTPException(
            status_code=409,
            detail="Email already registered"
        )

    return {
        "message": "User updated successfully",
        "user": serialize_admin_user(user)
    }


@app.delete("/user")
def delete_user(
    user_id: int = Query(gt=0),
    admin: User = Depends(require_admin),
    db: Session = Depends(get_db)
):
    user = db.get(User, user_id)

    if not user:
        raise HTTPException(
            status_code=404,
            detail="User not found"
        )

    # Prevent an admin from deleting their own account.
    if user.id == admin.id:
        raise HTTPException(
            status_code=400,
            detail="You cannot delete your own account"
        )

    try:
        # Delete associated refresh-token sessions.
        db.execute(
            delete(RefreshSession).where(
                RefreshSession.user_id == user.id
            )
        )

        # Delete the user.
        db.delete(user)

        db.commit()

    except Exception:
        db.rollback()
        raise

    return {
        "message": "User deleted successfully"
    }


@app.get("/profile")
def get_profile(
    user: User = Depends(current_user),
    db: Session = Depends(get_db)
):
    profile = db.get(EmployeeProfile, user.id)

    return serialize_profile(user, profile)


@app.put("/profile")
def update_profile(
    data: ProfilePut,
    response: Response,
    user: User = Depends(current_user),
    db: Session = Depends(get_db)
):
    old_name = user.name
    old_email = user.email
    
    result = save_profile(db, user, data)

    # Regenerate ID token only if identity changes.
    if user.name != old_name or user.email != old_email:
        set_identity_cookie(response, user)

    return {
        "message": "Profile updated successfully",
        "profile": result
    }