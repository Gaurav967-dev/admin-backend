from fastapi import APIRouter, Depends, Response
from sqlalchemy.orm import Session

from ..database import get_db
from ..dependencies.auth import current_user
from ..models import User, EmployeeProfile
from ..schemas.profile import ProfilePut
from ..services.auth_service import set_identity_cookie
from ..services.profile_service import ( serialize_profile, save_profile )

router = APIRouter(tags=["Profile"])

@router.get("/profile")
def get_profile(
    user: User = Depends(current_user),
    db: Session = Depends(get_db)
):
    profile = db.get(EmployeeProfile, user.id)

    return serialize_profile(user, profile)


@router.put("/profile")
def update_profile(
    data: ProfilePut,
    response: Response,
    user: User = Depends(current_user),
    db: Session = Depends(get_db)
):
    old_name = user.name
    old_email = user.email
    
    result = save_profile(db, user, data)

    # Regenerate ID token only if identity changes.
    if user.name != old_name or user.email != old_email:
        set_identity_cookie(response, user)

    return {
        "message": "Profile updated successfully",
        "profile": result
    }