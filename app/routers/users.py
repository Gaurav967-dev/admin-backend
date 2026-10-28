from typing import Literal

from fastapi import APIRouter, Depends, Query, HTTPException
from sqlalchemy.orm import Session

from ..database import get_db
from ..dependencies.auth import require_admin
from ..models import User
from ..schemas.user import ( CreateUserRequest, UpdateUserRequest )
from ..services.user_service import ( get_user_summary, list_users, get_user_detail, create_user_record, update_user_record, delete_user_record )

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
    status_filter: Literal[
        "all", "active", "inactive"
    ] = "all",
    role_filter: Literal[
        "all", "admin", "user"
    ] = "all",
    admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    return list_users(
        db=db,
        page=page,
        page_size=page_size,
        search=search,
        status_filter=status_filter,
        role_filter=role_filter,
    )


@router.post("/user", status_code=201)
def create_user(
    data: CreateUserRequest,
    admin: User = Depends(require_admin),
    db: Session = Depends(get_db)
):
    return create_user_record(db, data)


@router.put("/user")
def update_user(
    data: UpdateUserRequest,
    user_id: int = Query(gt=0),
    admin: User = Depends(require_admin),
    db: Session = Depends(get_db)
):
    return update_user_record(
        db,
        user_id,
        data,
        admin
    )


@router.delete("/user")
def delete_user(
    user_id: int = Query(gt=0),
    admin: User = Depends(require_admin),
    db: Session = Depends(get_db)
):
    return delete_user_record(
        db,
        user_id,
        admin
    )


@router.get("user/{user_id}")
def view_user(
    user_id: int,
    admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    if user_id <= 0:
        raise HTTPException(
            status_code=422,
            detail="User ID must be positive"
        )

    return get_user_detail(db, user_id)