import uuid
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import String, Boolean, DateTime, ForeignKey, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.dialects.postgresql import UUID

from app.db.base import Base


class Device(Base):
    __tablename__ = "devices"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    device_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    fingerprint: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    user_agent: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    browser: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    os: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    device_type: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)  # desktop, mobile, tablet
    is_trusted: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    first_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )
    last_seen: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    last_ip: Mapped[Optional[str]] = mapped_column(String(45), nullable=True)

    # Relationships
    user: Mapped["User"] = relationship(back_populates="devices")  # noqa: F821
