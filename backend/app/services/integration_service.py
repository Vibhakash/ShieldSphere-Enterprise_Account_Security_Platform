"""Signed webhook and SMTP alert delivery with persisted delivery history."""
import asyncio
import base64
import hashlib
import hmac
import json
import logging
import smtplib
import ssl
from datetime import datetime, timezone
from email.message import EmailMessage
from typing import Optional
from uuid import UUID

from cryptography.fernet import Fernet
from sqlalchemy import select

from app.core.config import settings
from app.db.models.identity_security import IntegrationDelivery, NotificationIntegration
from app.db.models.threat import Alert, Threat
from app.db.session import AsyncSessionLocal
from app.services.outbound_http import safe_public_post

logger = logging.getLogger(__name__)
SEVERITY = {"low": 1, "medium": 2, "high": 3, "critical": 4}


def _fernet() -> Fernet:
    key = base64.urlsafe_b64encode(hashlib.sha256(settings.JWT_SECRET.encode("utf-8")).digest())
    return Fernet(key)


def encrypt_secret(value: str) -> str:
    return _fernet().encrypt(value.encode("utf-8")).decode("ascii")


def decrypt_secret(value: str) -> str:
    return _fernet().decrypt(value.encode("ascii")).decode("utf-8")


def destination_hint(integration: NotificationIntegration) -> str:
    if integration.integration_type == "email":
        local, _, domain = integration.destination.partition("@")
        return f"{local[:2]}***@{domain}" if domain else "Configured email"
    from urllib.parse import urlsplit
    parsed = urlsplit(integration.destination)
    return parsed.hostname or "Configured webhook"


def _send_email_sync(destination: str, event: dict) -> None:
    if not settings.SMTP_HOST or not settings.SMTP_FROM_EMAIL:
        raise RuntimeError("SMTP_HOST and SMTP_FROM_EMAIL must be configured for email delivery")
    message = EmailMessage()
    message["Subject"] = f"[{event['severity'].upper()}] ShieldSphere: {event['title']}"
    message["From"] = settings.SMTP_FROM_EMAIL
    message["To"] = destination
    message.set_content(
        f"{event['title']}\n\n{event['message']}\n\n"
        f"Severity: {event['severity']}\nEvent: {event['event_type']}\n"
        f"Created: {event['created_at']}\n"
    )
    with smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT, timeout=10) as smtp:
        if settings.SMTP_USE_TLS:
            smtp.starttls(context=ssl.create_default_context())
        if settings.SMTP_USERNAME:
            smtp.login(settings.SMTP_USERNAME, settings.SMTP_PASSWORD)
        smtp.send_message(message)


async def _perform_delivery(integration: NotificationIntegration, event: dict) -> tuple[Optional[int], None]:
    if integration.integration_type == "email":
        await asyncio.to_thread(_send_email_sync, integration.destination, event)
        return None, None
    body = json.dumps(event, separators=(",", ":"), sort_keys=True).encode("utf-8")
    secret = decrypt_secret(integration.signing_secret_encrypted or "")
    signature = hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()
    response = await safe_public_post(
        integration.destination,
        content=body,
        headers={
            "Content-Type": "application/json",
            "User-Agent": "ShieldSphere-Webhook/1.0",
            "X-ShieldSphere-Signature": f"sha256={signature}",
            "X-ShieldSphere-Event": event["event_type"],
        },
    )
    response.raise_for_status()
    return response.status_code, None


async def deliver_to_integration(integration_id: UUID, event: dict, alert_id: Optional[UUID] = None) -> IntegrationDelivery:
    async with AsyncSessionLocal() as db:
        result = await db.execute(select(NotificationIntegration).where(NotificationIntegration.id == integration_id))
        integration = result.scalar_one_or_none()
        if not integration:
            raise ValueError("Integration not found")
        status = "delivered"
        response_code = None
        error_message = None
        try:
            response_code, _ = await _perform_delivery(integration, event)
        except Exception as exc:
            status = "failed"
            error_message = str(exc)[:1000]
            logger.warning("Integration delivery %s failed: %s", integration_id, exc)
        now = datetime.now(timezone.utc)
        integration.last_delivery_at = now
        integration.last_delivery_status = status
        integration.last_error = error_message
        delivery = IntegrationDelivery(
            integration_id=integration.id,
            alert_id=alert_id,
            event_type=event["event_type"],
            status=status,
            response_code=response_code,
            error_message=error_message,
            attempted_at=now,
        )
        db.add(delivery)
        await db.commit()
        await db.refresh(delivery)
        return delivery


async def deliver_alert(alert_id: UUID) -> None:
    """Fan an alert out to every matching active integration."""
    async with AsyncSessionLocal() as db:
        result = await db.execute(
            select(Alert, Threat)
            .outerjoin(Threat, Alert.threat_id == Threat.id)
            .where(Alert.id == alert_id)
        )
        row = result.one_or_none()
        if not row:
            return
        alert, threat = row
        integrations_result = await db.execute(
            select(NotificationIntegration).where(
                NotificationIntegration.user_id == alert.user_id,
                NotificationIntegration.is_active == True,  # noqa
            )
        )
        integrations = integrations_result.scalars().all()
        is_simulation = bool(threat and threat.is_simulation)
        event = {
            "event_type": "security.alert.created",
            "alert_id": str(alert.id),
            "threat_id": str(alert.threat_id) if alert.threat_id else None,
            "title": alert.title,
            "message": alert.message,
            "severity": alert.severity,
            "is_simulation": is_simulation,
            "created_at": alert.created_at.isoformat(),
        }
    jobs = [
        deliver_to_integration(integration.id, event, alert.id)
        for integration in integrations
        if SEVERITY.get(alert.severity, 0) >= SEVERITY.get(integration.minimum_severity, 2)
        and (integration.include_simulations or not is_simulation)
    ]
    if jobs:
        await asyncio.gather(*jobs, return_exceptions=True)
