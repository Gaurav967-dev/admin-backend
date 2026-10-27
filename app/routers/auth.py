from datetime import datetime, timezone

from fastapi import ( APIRouter, Cookie, Depends, HTTPException, Response )
from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from ..database import get_db
from ..dependencies.auth import current_user
from ..models import User, RefreshSession
from ..schemas.auth import SignupRequest, LoginRequest
from ..security import ( decode_token, hash_jti, hash_password, verify_password )
from ..services.auth_service import ( public_user, set_auth_cookies )

router = APIRouter(tags=["Authentication"])

@router.post("/signup", status_code=201)
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


@router.post("/sign")
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

@router.get("/verify-token")
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


@router.post("/refresh-token")
def refresh_token(
    response: Response,
    refresh_token: str | None = Cookie(default=None),
    db: Session = Depends(get_db)
):
    # The browser no longer has a refresh cookie.
    if not refresh_token:
        raise HTTPException(
            status_code=419,
            detail="Session expired. Please sign in again."
        )

    # Expired refresh JWT -> 419, Invalid/tampered JWT -> 401.
    payload = decode_token(
        refresh_token,
        "refresh",
        expired_status=419
    )

    try:
        user_id = int(payload["sub"])
    except (TypeError, ValueError) as exc:
        raise HTTPException(
            status_code=401,
            detail="Invalid refresh token subject"
        ) from exc

    # Lock the session to prevent concurrent reuse.
    session = db.scalar(
        select(RefreshSession)
        .where(
            RefreshSession.jti_hash ==
            hash_jti(payload["jti"])
        )
        .with_for_update()
    )

    # Session expired, revoked, or no longer exists.
    if (
        session is None
        or session.revoked
        or session.expires_at <= datetime.now(timezone.utc)
    ):
        raise HTTPException(
            status_code=419,
            detail="Refresh session expired or revoked"
        )

    # A valid token must belong to this session's user.
    if session.user_id != user_id:
        raise HTTPException(
            status_code=401,
            detail="Invalid refresh token session"
        )

    user = db.get(User, session.user_id)

    if not user or not user.is_active:
        raise HTTPException(
            status_code=401,
            detail="User unavailable"
        )

    # Preserve your existing refresh-token rotation.
    session.revoked = True

    tokens = set_auth_cookies(
        response,
        db,
        user
    )

    db.commit()

    return {
        "message": "Token refreshed",
        "tokens": tokens
    }


@router.post("/logout")
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