from typing import Literal
from pydantic import BaseModel, EmailStr, Field, field_validator

class UserFields(BaseModel):
    name: str = Field(min_length=2, max_length=100)
    email: EmailStr
    role: Literal["user", "admin"] = "user"
    is_active: bool = True

    @field_validator("name", mode="before")
    @classmethod
    def trim_name(cls, value):
        if isinstance(value, str):
            return value.strip()
        return value

    @field_validator("email", mode="before")
    @classmethod
    def normalize_email(cls, value):
        if isinstance(value, str):
            return value.strip().lower()
        return value


class CreateUserRequest(UserFields):
    password: str = Field(
        min_length=12,
        max_length=128
    )


class UpdateUserRequest(UserFields):
    password: str | None = Field(
        default=None,
        min_length=12,
        max_length=128
    )