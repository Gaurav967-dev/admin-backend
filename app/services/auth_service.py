from datetime import datetime, timezone

from fastapi import HTTPException, Response
from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from ..core.config import COOKIE_SECURE
from ..models import User, RefreshSession
from ..schemas.auth import SignupRequest, LoginRequest
from ..security import ( create_token, decode_token, hash_jti, hash_password, verify_password )

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

def register_user(
    db: Session,
    response: Response,
    data: SignupRequest
):
    user = User(
        name=data.name.strip(),
        email=data.email.lower(),
        password_hash=hash_password(data.password),
        role="user"
    )

    db.add(user)

    try:
        db.flush()

        tokens = set_auth_cookies(
            response,
            db,
            user
        )

        db.commit()

    except IntegrityError as exc:
        db.rollback()

        raise HTTPException(
            status_code=409,
            detail="Email already registered"
        ) from exc

    return {
        "message": "Account created successfully",
        "user": public_user(user),
        "tokens": tokens
    }


def sign_in_user(
    db: Session,
    response: Response,
    data: LoginRequest
):
    user = db.scalar(
        select(User).where(
            User.email == data.email.lower()
        )
    )

    if (
        not user
        or not verify_password(
            data.password,
            user.password_hash
        )
        or not user.is_active
    ):
        raise HTTPException(
            status_code=401,
            detail="Invalid email or password"
        )

    tokens = set_auth_cookies(
        response,
        db,
        user
    )

    db.commit()

    return {
        "message": "Login successful",
        "user": public_user(user),
        "tokens": tokens
    }


def verify_identity(
    user: User,
    id_token: str | None
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


def refresh_user_tokens(
    db: Session,
    response: Response,
    refresh_token: str | None
):
    if not refresh_token:
        raise HTTPException(
            status_code=419,
            detail="Session expired. Please sign in again."
        )

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

    session = db.scalar(
        select(RefreshSession)
        .where(
            RefreshSession.jti_hash ==
            hash_jti(payload["jti"])
        )
        .with_for_update()
    )

    if (
        session is None
        or session.revoked
        or session.expires_at <= datetime.now(timezone.utc)
    ):
        raise HTTPException(
            status_code=419,
            detail="Refresh session expired or revoked"
        )

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

    # Rotate refresh session.
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


def sign_out_user(
    db: Session,
    response: Response,
    user: User,
    access_token: str | None
):
    if not access_token:
        raise HTTPException(
            status_code=401,
            detail="Not authenticated"
        )

    payload = decode_token(
        access_token,
        "access"
    )

    session_id = payload["sid"]

    db.execute(
        update(RefreshSession)
        .where(
            RefreshSession.user_id == user.id,
            RefreshSession.jti_hash == hash_jti(session_id)
        )
        .values(revoked=True)
    )

    db.commit()

    response.delete_cookie("id_token", path="/verify-token")
    response.delete_cookie("access_token", path="/")
    response.delete_cookie("refresh_token", path="/refresh-token")

    return {
        "message": "Logged out successfully"
    }