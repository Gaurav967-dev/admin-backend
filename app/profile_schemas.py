from datetime import date
from typing import Literal

from pydantic import ( BaseModel, EmailStr, Field, field_validator )

# Onboarding task identifiers.
TaskKey = Literal[ "office_tour", "management_intro", "work_tools", "meet_colleagues", "duties_journal", "requests_handling", "activity_tracking"]

TASK_LABELS = { "office_tour": "Office Tour", "management_intro": "Management Introductory", "work_tools": "Work Tools", "meet_colleagues": "Meet Your Colleagues", "duties_journal": "Duties Journal", "requests_handling": "Requests Handling", "activity_tracking": "Activity Tracking" }

def default_tasks():
    progress = { "office_tour": 100, "work_tools": 20 }

    return [{ "key": key, "enabled": key != "management_intro", "progress": progress.get(key, 0) } for key in TASK_LABELS]

class TaskInput(BaseModel):
    key: TaskKey
    enabled: bool
    progress: int = Field(ge=0, le=100)

class ProfilePut(BaseModel):
    # Required fields for full replacement
    first_name: str = Field(min_length=2, max_length=80)
    last_name: str = Field(max_length=80)
    email: EmailStr
    phone: str | None = Field(max_length=20)
    position: str | None = Field(max_length=100)
    team: str | None = Field(max_length=100)
    manager: str | None = Field(max_length=100)
    lead: str | None = Field(max_length=100)

    onboarding_start: date | None
    onboarding_required: bool

    tasks: list[TaskInput] = Field( min_length=7, max_length=7 )

    @field_validator("first_name", "last_name")
    @classmethod
    def trim_name(cls, value:str):
        return value.strip()

    @field_validator("tasks")
    @classmethod
    def validate_tasks(cls, tasks):
        keys = [task.key for task in tasks]

        if set(keys) != set(TASK_LABELS):
            raise ValueError("Exactly one of each onboarding task is required")

        return tasks