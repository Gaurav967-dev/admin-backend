from pydantic import BaseModel, EmailStr, Field, field_validator
from .validators import normalize_name, validate_name, validate_password

class SignupRequest(BaseModel):
    name: str = Field(min_length=2, max_length=100)
    email: EmailStr
    password: str = Field(min_length=12, max_length=128)

    @field_validator("name", mode="before")
    @classmethod
    def trim_name(cls, value):
        return normalize_name(value)

    @field_validator("name")
    @classmethod
    def check_name(cls, value: str):
        return validate_name(value)

    @field_validator("password")
    @classmethod
    def check_password(cls, value: str):
        return validate_password(value)


class LoginRequest(BaseModel):
    email: EmailStr
    password: str