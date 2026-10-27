from typing import Literal

from fastapi import HTTPException
from sqlalchemy import select, delete, update, func, or_
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from ..models import User, RefreshSession
from ..schemas.user import CreateUserRequest, UpdateUserRequest
from ..security import hash_password

def serialize_admin_user(user: User):
    return {
        "id": user.id,
        "name": user.name,
        "email": user.email,
        "role": user.role,
        "is_active": user.is_active
    }


def get_user_summary(db: Session):
    users = db.scalars(
        select(User).order_by(User.id.asc())
    ).all()

    return {
        "total_users": len(users),
        "active_users": sum(
            1 for user in users if user.is_active
        ),
        "admins": sum(
            1 for user in users if user.role == "admin"
        ),
        "users": [
            serialize_admin_user(user)
            for user in users
        ]
    }

def list_users(
    db: Session,
    page: int,
    page_size: int,
    search: str,
    status_filter: Literal["all", "active", "inactive"],
    role_filter: Literal["all", "admin", "user"]
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

    filtered_total = db.scalar(
        select(func.count())
        .select_from(User)
        .where(*conditions)
    ) or 0

    users = db.scalars(
        select(User)
        .where(*conditions)
        .order_by(User.id.asc())
        .offset((page - 1) * page_size)
        .limit(page_size)
    ).all()

    total_users = db.scalar(
        select(func.count()).select_from(User)
    ) or 0

    active_users = db.scalar(
        select(func.count())
        .select_from(User)
        .where(User.is_active.is_(True))
    ) or 0

    admins = db.scalar(
        select(func.count())
        .select_from(User)
        .where(User.role == "admin")
    ) or 0

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
        "total_pages": max(
            1,
            (filtered_total + page_size - 1) // page_size
        ),
    }


def create_user_record(
    db: Session,
    data: CreateUserRequest
):
    existing_user = db.scalar(
        select(User).where(
            User.email == data.email
        )
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

    except IntegrityError as exc:
        db.rollback()

        raise HTTPException(
            status_code=409,
            detail="Email already registered"
        ) from exc

    return {
        "message": "User created successfully",
        "user": serialize_admin_user(new_user)
    }


def update_user_record(
    db: Session,
    user_id: int,
    data: UpdateUserRequest,
    admin: User
):
    user = db.get(User, user_id)

    if not user:
        raise HTTPException(
            status_code=404,
            detail="User not found"
        )

    # Prevent administrators from removing
    # their own administrative access.
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
        user.password_hash = hash_password(
            data.password
        )

        # Revoke existing sessions after password changes.
        db.execute(
            update(RefreshSession)
            .where(RefreshSession.user_id == user.id)
            .values(revoked=True)
        )

    # Deactivated users must lose existing sessions.
    if not data.is_active:
        db.execute(
            update(RefreshSession)
            .where(RefreshSession.user_id == user.id)
            .values(revoked=True)
        )

    try:
        db.commit()
        db.refresh(user)

    except IntegrityError as exc:
        db.rollback()

        raise HTTPException(
            status_code=409,
            detail="Email already registered"
        ) from exc

    return {
        "message": "User updated successfully",
        "user": serialize_admin_user(user)
    }


def delete_user_record(
    db: Session,
    user_id: int,
    admin: User
):
    user = db.get(User, user_id)

    if not user:
        raise HTTPException(
            status_code=404,
            detail="User not found"
        )

    if user.id == admin.id:
        raise HTTPException(
            status_code=400,
            detail="You cannot delete your own account"
        )

    try:
        db.execute(
            delete(RefreshSession).where(
                RefreshSession.user_id == user.id
            )
        )

        db.delete(user)
        db.commit()

    except Exception:
        db.rollback()
        raise

    return {
        "message": "User deleted successfully"
    }