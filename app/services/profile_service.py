from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from ..models import User, EmployeeProfile
from ..schemas.profile import ( ProfilePut, TASK_LABELS, default_tasks )

def serialize_profile(
    user: User,
    profile: EmployeeProfile | None
):
    # Existing signup users may not have employee profile records yet.
    name_parts = user.name.strip().split(" ", 1)

    first_name = name_parts[0] if name_parts else ""
    last_name = (
        name_parts[1] if len(name_parts) > 1 else ""
    )

    stored_tasks = (
        profile.tasks
        if profile and profile.tasks
        else default_tasks()
    )

    tasks = [
        {
            **task,
            "label": TASK_LABELS[task["key"]],
        }
        for task in stored_tasks
    ]

    enabled_tasks = [task for task in tasks if task["enabled"]]

    progress = (
        round(sum(task["progress"] for task in enabled_tasks) / len(enabled_tasks))
        if enabled_tasks else 0
    )

    if profile and not profile.onboarding_required:
        status = "Not Required"
    elif progress == 100 and enabled_tasks:
        status = "Completed"
    elif progress > 0:
        status = "Onboarding"
    else:
        status = "Not Started"

    return {
        "user_id": user.id,
        "first_name": (profile.first_name if profile else first_name),
        "last_name": (profile.last_name if profile else last_name),
        "email": user.email,
        "role": user.role,
        "phone": profile.phone if profile else None,
        "position": profile.position if profile else None,
        "team": profile.team if profile else None,
        "manager": profile.manager if profile else None,
        "lead": profile.lead if profile else None,
        "onboarding_start": ( profile.onboarding_start.isoformat() if profile and profile.onboarding_start else None),
        "onboarding_required": ( profile.onboarding_required if profile else True),
        "tasks": tasks,
        "onboarding_progress": progress,
        "onboarding_status": status,
        "created_at": ( user.created_at.isoformat() if user.created_at else None),
    }


def save_profile(
    db: Session,
    user: User,
    data: ProfilePut
):
    # Lock the user row only when a phone number is submitted.
    if data.phone is not None:
        db.execute(select(User.id).where(User.id == user.id).with_for_update()).scalar_one()

    # Always load, create the profile.
    profile = db.get(EmployeeProfile, user.id)

    if profile is None:
        profile = EmployeeProfile(
            user_id=user.id,
            first_name=data.first_name,
            last_name=data.last_name,
        )
        db.add(profile)

    # Phone number can only be entered once.
    if data.phone is not None:
        existing_phone = (profile.phone or "").strip()

        if existing_phone and existing_phone != data.phone:
            raise HTTPException(
                status_code=409,
                detail=("Phone number is already set and cannot be changed")
            )

        if not existing_phone:
            profile.phone = data.phone

    # Synchronize employee name and email with existing authentication user.
    user.name = " ".join(
        part
        for part in [data.first_name.strip(), data.last_name.strip()]
        if part
    )

    profile.first_name = data.first_name
    profile.last_name = data.last_name
    profile.position = data.position
    profile.team = data.team
    profile.manager = data.manager
    profile.lead = data.lead

    profile.onboarding_start = data.onboarding_start
    profile.onboarding_required = data.onboarding_required

    # Assign a new JSONB value, allowing SQLAlchemy to detect and persist the change.
    profile.tasks = [task.model_dump() for task in data.tasks]

    try:
        db.commit()
        db.refresh(user)
        db.refresh(profile)
    except IntegrityError:
        db.rollback()

        raise HTTPException(
            status_code=409,
            detail="Email already registered"
        )

    return serialize_profile(user, profile)