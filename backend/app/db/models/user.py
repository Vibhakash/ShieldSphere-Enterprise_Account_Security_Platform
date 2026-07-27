import uuid
from datetime import datetime, timezone
from typing import Optional, List

from sqlalchemy import String, Boolean, DateTime, Text, Enum as SAEnum
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.dialects.postgresql import UUID

from app.db.base import Base


class User(Base):
    __tablename__ = "users"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True)
    username: Mapped[str] = mapped_column(String(100), unique=True, nullable=False)
    hashed_password: Mapped[str] = mapped_column(String(255), nullable=False)
    full_name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    role: Mapped[str] = mapped_column(String(50), default="user", nullable=False)

    # 2FA
    totp_secret: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    totp_enabled: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    # Account state
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    is_verified: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    # Password breach tracking
    password_breached: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    password_breach_count: Mapped[int] = mapped_column(default=0, nullable=False)

    # Timestamps
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    last_login_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    # Relationships
    sessions: Mapped[List["UserSession"]] = relationship(  # noqa: F821
        back_populates="user", cascade="all, delete-orphan"
    )
    devices: Mapped[List["Device"]] = relationship(  # noqa: F821
        back_populates="user", cascade="all, delete-orphan"
    )
    login_history: Mapped[List["LoginHistory"]] = relationship(  # noqa: F821
        back_populates="user", cascade="all, delete-orphan"
    )
    threats: Mapped[List["Threat"]] = relationship(  # noqa: F821
        back_populates="user", cascade="all, delete-orphan"
    )
    alerts: Mapped[List["Alert"]] = relationship(  # noqa: F821
        back_populates="user", cascade="all, delete-orphan"
    )
    security_scores: Mapped[List["SecurityScore"]] = relationship(  # noqa: F821
        back_populates="user", cascade="all, delete-orphan"
    )
    behavior_profiles: Mapped[List["BehaviorProfile"]] = relationship(  # noqa: F821
        back_populates="user", cascade="all, delete-orphan"
    )
    audit_logs: Mapped[List["AuditLog"]] = relationship(  # noqa: F821
        back_populates="user", cascade="all, delete-orphan"
    )
    attack_simulations: Mapped[List["AttackSimulation"]] = relationship(  # noqa: F821
        back_populates="user", cascade="all, delete-orphan"
    )
    incident_reports: Mapped[List["IncidentReport"]] = relationship(  # noqa: F821
        back_populates="user", cascade="all, delete-orphan"
    )
    passkeys: Mapped[List["PasskeyCredential"]] = relationship(  # noqa: F821
        back_populates="user", cascade="all, delete-orphan"
    )
    notification_integrations: Mapped[List["NotificationIntegration"]] = relationship(  # noqa: F821
        back_populates="user", cascade="all, delete-orphan"
    )
