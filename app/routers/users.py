from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select, delete, update, func, or_
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from ..database import get_db
from ..dependencies.auth import require_admin
from ..models import User, RefreshSession
from ..schemas.user import ( CreateUserRequest, UpdateUserRequest )
from ..security import hash_password
from ..services.user_service import ( serialize_admin_user, get_user_summary )

router = APIRouter(tags=["User Management"])

@router.get("/dashboard")
def get_dashboard(
    admin: User = Depends(require_admin),
    db: Session = Depends(get_db)    
):
    return get_user_summary(db)


@router.get("/user")
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


@router.post("/user", status_code=201)
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


@router.put("/user")
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


@router.delete("/user")
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