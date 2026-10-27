from sqlalchemy import select
from sqlalchemy.orm import Session
from ..models import User

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