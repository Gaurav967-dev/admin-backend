from fastapi import APIRouter, Cookie, Depends, Response
from sqlalchemy.orm import Session

from ..database import get_db
from ..dependencies.auth import current_user
from ..models import User
from ..schemas.auth import SignupRequest, LoginRequest
from ..services.auth_service import ( register_user, sign_in_user, verify_identity, refresh_user_tokens, sign_out_user )

router = APIRouter(tags=["Authentication"])

@router.post("/signup", status_code=201)
def signup(
    data: SignupRequest,
    response: Response,
    db: Session = Depends(get_db)
):
    return register_user(db, response, data)


@router.post("/sign")
def signin(
    data: LoginRequest,
    response: Response,
    db: Session = Depends(get_db)
):
    return sign_in_user(db, response, data)


@router.get("/verify-token")
def verify_token(
    user: User = Depends(current_user),
    id_token: str | None = Cookie(default=None)
):
    return verify_identity(user, id_token)


@router.post("/refresh-token")
def refresh_token(
    response: Response,
    refresh_token: str | None = Cookie(default=None),
    db: Session = Depends(get_db)
):
    return refresh_user_tokens(
        db,
        response,
        refresh_token
    )


@router.post("/logout")
def logout(
    response: Response,
    user: User = Depends(current_user),
    access_token: str | None = Cookie(default=None),
    db: Session = Depends(get_db)
):
    return sign_out_user(
        db,
        response,
        user,
        access_token
    )