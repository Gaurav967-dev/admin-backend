from fastapi import Response
from sqlalchemy.orm import Session

from ..core.config import COOKIE_SECURE
from ..models import User, RefreshSession
from ..security import create_token, hash_jti

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