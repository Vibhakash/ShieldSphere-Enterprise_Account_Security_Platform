import uuid
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import String, Boolean, DateTime, ForeignKey, Text, Integer, Float, JSON
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.dialects.postgresql import UUID

from app.db.base import Base


class PasswordBreachCheck(Base):
    __tablename__ = "password_breach_checks"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    sha1_prefix: Mapped[str] = mapped_column(String(10), nullable=False)  # first 5 chars of SHA-1
    breach_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    is_breached: Mapped[bool] = mapped_column(Boolean, nullable=False)
    checked_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )


class UrlScanResult(Base):
    __tablename__ = "url_scan_results"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    url: Mapped[str] = mapped_column(Text, nullable=False)
    virustotal_analysis_id: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    status: Mapped[str] = mapped_column(String(20), default="pending", nullable=False)  # pending, done, error
    malicious_count: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    suspicious_count: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    harmless_count: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    undetected_count: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    verdict: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)  # clean, malicious, suspicious
    raw_results: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    submitted_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)


class IpReputationCheck(Base):
    __tablename__ = "ip_reputation_checks"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    ip_address: Mapped[str] = mapped_column(String(45), nullable=False, index=True)
    overall_verdict: Mapped[str] = mapped_column(String(50), nullable=False)
    virustotal_malicious: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    virustotal_suspicious: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    abuse_confidence_score: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    abuse_total_reports: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    raw_results: Mapped[dict] = mapped_column(JSON, nullable=False)
    checked_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False, index=True
    )


class VulnerabilityScan(Base):
    __tablename__ = "vulnerability_scans"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    target_url: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(String(20), default="running", nullable=False)
    has_https: Mapped[Optional[bool]] = mapped_column(Boolean, nullable=True)
    has_hsts: Mapped[Optional[bool]] = mapped_column(Boolean, nullable=True)
    has_csp: Mapped[Optional[bool]] = mapped_column(Boolean, nullable=True)
    has_x_frame_options: Mapped[Optional[bool]] = mapped_column(Boolean, nullable=True)
    has_x_content_type: Mapped[Optional[bool]] = mapped_column(Boolean, nullable=True)
    has_secure_cookies: Mapped[Optional[bool]] = mapped_column(Boolean, nullable=True)
    risk_score: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)  # 0-100
    findings: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    llm_advice: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    scanned_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )
