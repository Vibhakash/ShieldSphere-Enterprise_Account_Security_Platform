"""User-managed real-time notification integrations."""
import secrets
from datetime import datetime, timezone
from uuid import UUID

from email_validator import EmailNotValidError, validate_email
from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.deps import get_client_ip, get_current_user, get_db
from app.db.models.compliance import AuditLog
from app.db.models.identity_security import IntegrationDelivery, NotificationIntegration
from app.db.models.user import User
from app.schemas.common import IntegrationCreate, IntegrationCreated, IntegrationDeliveryOut, IntegrationOut
from app.services.integration_service import deliver_to_integration, destination_hint, encrypt_secret
from app.services.outbound_http import UnsafeOutboundTarget, validate_public_url

router = APIRouter(prefix="/integrations", tags=["Real-time integrations"])


def _out(item: NotificationIntegration, signing_secret: str | None = None):
    values = {
        "id": item.id, "name": item.name, "integration_type": item.integration_type,
        "destination_hint": destination_hint(item), "minimum_severity": item.minimum_severity,
        "include_simulations": item.include_simulations, "is_active": item.is_active,
        "created_at": item.created_at, "last_delivery_at": item.last_delivery_at,
        "last_delivery_status": item.last_delivery_status, "last_error": item.last_error,
    }
    return IntegrationCreated(**values, signing_secret=signing_secret) if signing_secret else IntegrationOut(**values)


@router.get("", response_model=list[IntegrationOut])
async def list_integrations(current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(NotificationIntegration)
        .where(NotificationIntegration.user_id == current_user.id)
        .order_by(NotificationIntegration.created_at.desc())
    )
    return [_out(item) for item in result.scalars().all()]


@router.post("", response_model=IntegrationCreated, status_code=201)
async def create_integration(
    payload: IntegrationCreate,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    destination = payload.destination.strip()
    signing_secret = None
    if payload.integration_type == "webhook":
        try:
            destination = await validate_public_url(destination)
        except UnsafeOutboundTarget as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        signing_secret = secrets.token_urlsafe(32)
    else:
        try:
            destination = validate_email(destination, check_deliverability=False).normalized
        except EmailNotValidError as exc:
            raise HTTPException(status_code=422, detail="A valid destination email is required") from exc
    item = NotificationIntegration(
        user_id=current_user.id,
        name=payload.name,
        integration_type=payload.integration_type,
        destination=destination,
        signing_secret_encrypted=encrypt_secret(signing_secret) if signing_secret else None,
        minimum_severity=payload.minimum_severity,
        include_simulations=payload.include_simulations,
    )
    db.add(item)
    await db.flush()
    db.add(AuditLog(
        user_id=current_user.id, action="integration.created", resource=str(item.id),
        ip_address=get_client_ip(request), status="success",
        details={"type": item.integration_type, "minimum_severity": item.minimum_severity},
    ))
    await db.commit()
    await db.refresh(item)
    return _out(item, signing_secret)


async def _owned(integration_id: UUID, user_id: UUID, db: AsyncSession) -> NotificationIntegration:
    result = await db.execute(
        select(NotificationIntegration).where(
            NotificationIntegration.id == integration_id,
            NotificationIntegration.user_id == user_id,
        )
    )
    item = result.scalar_one_or_none()
    if not item:
        raise HTTPException(status_code=404, detail="Integration not found")
    return item


@router.patch("/{integration_id}/toggle", response_model=IntegrationOut)
async def toggle_integration(
    integration_id: UUID,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    item = await _owned(integration_id, current_user.id, db)
    item.is_active = not item.is_active
    await db.commit()
    await db.refresh(item)
    return _out(item)


@router.post("/{integration_id}/test", response_model=IntegrationDeliveryOut)
async def test_integration(
    integration_id: UUID,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    item = await _owned(integration_id, current_user.id, db)
    event = {
        "event_type": "integration.test",
        "alert_id": None,
        "threat_id": None,
        "title": "ShieldSphere integration test",
        "message": "Your real-time security integration is connected.",
        "severity": "medium",
        "is_simulation": True,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    delivery = await deliver_to_integration(item.id, event)
    if delivery.status == "failed":
        raise HTTPException(status_code=502, detail=delivery.error_message or "Delivery failed")
    return delivery


@router.get("/{integration_id}/deliveries", response_model=list[IntegrationDeliveryOut])
async def list_deliveries(
    integration_id: UUID,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    await _owned(integration_id, current_user.id, db)
    result = await db.execute(
        select(IntegrationDelivery)
        .where(IntegrationDelivery.integration_id == integration_id)
        .order_by(IntegrationDelivery.attempted_at.desc())
        .limit(20)
    )
    return result.scalars().all()


@router.delete("/{integration_id}")
async def delete_integration(
    integration_id: UUID,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    item = await _owned(integration_id, current_user.id, db)
    await db.delete(item)
    await db.commit()
    return {"message": "Integration removed"}
