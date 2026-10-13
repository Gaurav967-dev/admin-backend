import os
import secrets
import hashlib
from datetime import datetime, timedelta, timezone

import jwt
from jwt import InvalidTokenError
from pwdlib import PasswordHash

from fastapi import HTTPException

SECRET_KEY = os.environ["JWT_SECRET_KEY"]
ALGORITHM = "HS256"

if len(SECRET_KEY) < 32:
    raise HTTPException("JWT secret must be at least 32 characters")

password_hasher = PasswordHash.recommended()

ACCESS_MINUTES = 5
REFRESH_DAYS = 7


def hash_password(password: str) -> str:
    return password_hasher.hash(password)


def verify_password(
    plain_password: str,
    hashed_password: str
) -> bool:
    return password_hasher.verify(
        plain_password, hashed_password
    )


def hash_jti(jti: str) -> str:
    return hashlib.sha256(
        jti.encode("utf-8")
    ).hexdigest()


def create_token(user_id: int, token_type: str, identity: dict | None = None, session_id: str | None = None):
    if token_type not in {"id", "access", "refresh"}:
        raise ValueError("Invalid token type")
    
    now = datetime.now(timezone.utc)

    duration = (
        timedelta(days=REFRESH_DAYS)
        if token_type == "refresh"
        else timedelta(minutes=ACCESS_MINUTES)
    )

    expires_at = now + duration
    jti = secrets.token_urlsafe(32)

    payload = {
        "sub": str(user_id),
        "type": token_type,
        "jti": jti,
        "iat": now,
        "exp": expires_at
    }

    if token_type == "access":
        if not session_id:
            raise ValueError("Session ID is required")

        payload["sid"] = session_id

    if token_type == "id":
        if not identity:
            raise ValueError("ID token requires identity")

        payload["name"] = identity["name"]
        payload["email"] = identity["email"]

    token = jwt.encode(
        payload, SECRET_KEY, algorithm=ALGORITHM
    )

    return token, jti, expires_at

def decode_token(token: str, expected_type: str):
    try:
        payload = jwt.decode(
            token,
            SECRET_KEY,
            algorithms=[ALGORITHM],
            options={
                "require": ["sub", "type", "exp", "jti"]
            }
        )

        if payload["type"] != expected_type:
            raise InvalidTokenError(
                "Incorrect token type"
            )

        return payload

    except InvalidTokenError:
        raise HTTPException(
            status_code=401,
            detail="Invalid or expired token"
        )