from datetime import datetime, date
from sqlalchemy import String, Boolean, DateTime, Date, ForeignKey, func
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.dialects.postgresql import JSONB
from .database import Base

class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(
        primary_key=True
    )

    name: Mapped[str] = mapped_column(
        String(100)
    )

    email: Mapped[str] = mapped_column(
        String(255), unique=True, index=True
    )

    password_hash: Mapped[str] = mapped_column(
        String(255)
    )

    role: Mapped[str] = mapped_column(
        String(20), default="user"
    )

    is_active: Mapped[bool] = mapped_column(
        Boolean, default=True
    )

    created_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=True
    )

class RefreshSession(Base):
    __tablename__ = "refresh_sessions"

    id: Mapped[int] = mapped_column(
        primary_key=True
    )

    user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id")
    )

    jti_hash: Mapped[str] = mapped_column(
        String(64), unique=True, index=True
    )

    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True)
    )

    revoked: Mapped[bool] = mapped_column(
        Boolean, default=False
    )


class EmployeeProfile(Base):
    __tablename__ = "employee_profiles"

    # One employee profile per registered user
    user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"),
        primary_key=True
    )

    first_name: Mapped[str] = mapped_column(
        String(80), nullable=False
    )

    last_name: Mapped[str] = mapped_column(
        String(80), default="", nullable=False
    )

    phone: Mapped[str | None] = mapped_column(
        String(32), nullable=True
    )

    position: Mapped[str | None] = mapped_column(
        String(100), nullable=True
    )

    team: Mapped[str | None] = mapped_column(
        String(100), nullable=True
    )

    manager: Mapped[str | None] = mapped_column(
        String(100), nullable=True
    )

    lead: Mapped[str | None] = mapped_column(
        String(100), nullable=True
    )

    onboarding_start: Mapped[date | None] = mapped_column(
        Date, nullable=True
    )

    onboarding_required: Mapped[bool] = mapped_column(
        Boolean, default=True, nullable=False
    )

    # PostgreSQL JSONB stores the task configuration.
    tasks: Mapped[list] = mapped_column(
        JSONB, nullable=False, default=list
    )