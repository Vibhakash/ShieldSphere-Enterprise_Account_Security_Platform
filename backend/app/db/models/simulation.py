import uuid
from datetime import datetime, timezone
from typing import Optional, List

from sqlalchemy import String, Boolean, DateTime, ForeignKey, Text, Integer, Float, JSON
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.dialects.postgresql import UUID

from app.db.base import Base


class AttackSimulation(Base):
    __tablename__ = "attack_simulations"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )

    # Simulation config
    sim_type: Mapped[str] = mapped_column(String(100), nullable=False)
    # brute_force, sqli, xss, port_scan, vuln_scan, phishing, packet_capture, social_engineering

    target_url: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    params: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)  # user-supplied parameters

    # Status tracking
    status: Mapped[str] = mapped_column(String(20), default="queued", nullable=False)
    # queued, running, completed, failed, cancelled

    # Docker container IDs
    target_container_id: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    attacker_container_id: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    network_id: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)

    # Results
    summary: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # LLM-generated summary
    threat_ids_triggered: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)  # list of threat UUIDs
    raw_output: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)

    started_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    ended_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )
    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Relationships
    user: Mapped["User"] = relationship(back_populates="attack_simulations")  # noqa: F821
    events: Mapped[List["SimulationEvent"]] = relationship(
        back_populates="simulation", cascade="all, delete-orphan"
    )


class SimulationEvent(Base):
    __tablename__ = "simulation_events"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    simulation_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("attack_simulations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    event_type: Mapped[str] = mapped_column(String(100), nullable=False)
    # login_attempt, sqli_payload, xss_payload, port_hit, packet_captured, alert_triggered
    severity: Mapped[Optional[str]] = mapped_column(String(20), nullable=True)
    source_ip: Mapped[Optional[str]] = mapped_column(String(45), nullable=True)
    target: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    payload: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    response: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    details: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )

    # Relationships
    simulation: Mapped["AttackSimulation"] = relationship(back_populates="events")
