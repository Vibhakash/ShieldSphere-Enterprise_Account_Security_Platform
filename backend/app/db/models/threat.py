import uuid
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import String, Boolean, DateTime, ForeignKey, Text, Float, JSON
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.dialects.postgresql import UUID

from app.db.base import Base


class Threat(Base):
    __tablename__ = "threats"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    login_event_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), ForeignKey("login_history.id", ondelete="SET NULL"), nullable=True
    )
    simulation_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), ForeignKey("attack_simulations.id", ondelete="SET NULL"), nullable=True
    )

    # Threat classification
    threat_type: Mapped[str] = mapped_column(String(100), nullable=False)
    # brute_force, impossible_travel, unknown_device, unknown_location,
    # credential_breach, sqli_attempt, xss_attempt, port_scan, phishing
    severity: Mapped[str] = mapped_column(String(20), nullable=False)  # low, medium, high, critical
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Source context
    source_ip: Mapped[Optional[str]] = mapped_column(String(45), nullable=True)
    source_country: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    details: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)  # raw contributing signals

    # AI-generated fields
    llm_rca: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # Groq root-cause analysis
    llm_remediation: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    risk_score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)

    # Status
    is_resolved: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    resolved_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    auto_blocked: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    is_simulation: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    detected_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False, index=True
    )

    # Relationships
    user: Mapped["User"] = relationship(back_populates="threats")  # noqa: F821
    login_event: Mapped[Optional["LoginHistory"]] = relationship(back_populates="threats")  # noqa: F821
    alert: Mapped[Optional["Alert"]] = relationship(back_populates="threat", uselist=False)  # noqa: F821


class Alert(Base):
    __tablename__ = "alerts"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    threat_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), ForeignKey("threats.id", ondelete="SET NULL"), nullable=True
    )
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    message: Mapped[str] = mapped_column(Text, nullable=False)
    severity: Mapped[str] = mapped_column(String(20), nullable=False)
    is_read: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )

    # Relationships
    user: Mapped["User"] = relationship(back_populates="alerts")  # noqa: F821
    threat: Mapped[Optional["Threat"]] = relationship(back_populates="alert")
