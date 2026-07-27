import uuid
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import (
    String,
    Boolean,
    DateTime,
    ForeignKey,
    Text,
    Float,
    Integer,
    JSON,
    Index,
    text,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.dialects.postgresql import UUID

from app.db.base import Base


class IpBlocklist(Base):
    __tablename__ = "ip_blocklist"
    __table_args__ = (
        Index(
            "uq_ip_blocklist_account_ip",
            "user_id",
            "ip_address",
            unique=True,
            postgresql_where=text("user_id IS NOT NULL"),
        ),
        Index(
            "uq_ip_blocklist_global_ip",
            "ip_address",
            unique=True,
            postgresql_where=text("user_id IS NULL"),
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=True, index=True
    )
    ip_address: Mapped[str] = mapped_column(String(45), nullable=False, index=True)
    reason: Mapped[str] = mapped_column(String(255), nullable=False)
    threat_type: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    auto_blocked: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    blocked_by_user_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    blocked_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )
    expires_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)


class SecurityScore(Base):
    __tablename__ = "security_scores"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    score: Mapped[int] = mapped_column(Integer, nullable=False)  # 0-100
    factors: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)  # contributing factor breakdown
    computed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )

    user: Mapped["User"] = relationship(back_populates="security_scores")  # noqa: F821


class BehaviorProfile(Base):
    __tablename__ = "behavior_profiles"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True, unique=True
    )
    # Typical login hours (0-23), stored as JSON list
    typical_hours: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    # Known device IDs
    known_device_ids: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    # Known countries
    known_countries: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    # Known ASNs
    known_asns: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    # Average login frequency per day
    avg_logins_per_day: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    # Baseline built from N samples
    sample_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    last_updated: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )

    user: Mapped["User"] = relationship(back_populates="behavior_profiles")  # noqa: F821
