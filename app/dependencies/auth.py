from datetime import datetime, timezone

from fastapi import Cookie, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..database import get_db
from ..models import User, RefreshSession
from ..security import decode_token, hash_jti

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
    except (TypeError, ValueError) as exc:
        raise HTTPException(
            status_code=401,
            detail="Invalid access token subject"
        ) from exc

    session = db.scalar(
        select(RefreshSession).where(
            RefreshSession.jti_hash == hash_jti(session_id)
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