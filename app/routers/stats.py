from fastapi import APIRouter, Depends
from sqlalchemy import select, func
from sqlalchemy.orm import Session

from ..database import get_db
from ..models import User

router = APIRouter(tags=["Statistics"])

@router.get("/public-stats")
def get_public_stats(
    db: Session = Depends(get_db)
):
    return {
        "total_users": db.scalar(
            select(func.count()).select_from(User)
        ) or 0,
        "active_users": db.scalar(
            select(func.count())
            .select_from(User)
            .where(User.is_active.is_(True))
        ) or 0,
        "admins": db.scalar(
            select(func.count())
            .select_from(User)
            .where(User.role == "admin")
        ) or 0,
    }