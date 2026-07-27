"""Threats, alerts, and account IP blocklist API."""
from datetime import datetime, timedelta, timezone
from typing import List, Optional
from uuid import UUID

import redis.asyncio as aioredis
from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, or_

from app.core.config import settings
from app.core.deps import get_db, get_current_user, get_client_ip
from app.db.models.user import User
from app.db.models.threat import Threat, Alert
from app.db.models.security import IpBlocklist
from app.db.models.compliance import AuditLog
from app.schemas.common import (
    ThreatOut,
    AlertOut,
    ThreatListResponse,
    AlertListResponse,
    IpBlockCreate,
    IpBlocklistOut,
)
from app.services.security_score import recalculate_security_score

router = APIRouter(tags=["Threats & Alerts"])
threats_router = APIRouter(prefix="/threats")
alerts_router = APIRouter(prefix="/alerts")
blocklist_router = APIRouter(prefix="/ip-blocklist")

_BLOCK_DURATION_SECONDS = {
    "1h": 60 * 60,
    "24h": 24 * 60 * 60,
    "7d": 7 * 24 * 60 * 60,
    "permanent": None,
}


def _block_key(user_id: Optional[UUID], ip_address: str) -> str:
    """Return the Redis key for an account or platform-wide block."""
    if user_id is None:
        return f"blocked_ip:{ip_address}"
    return f"blocked_ip:{user_id}:{ip_address}"


def _block_out(item: IpBlocklist, current_user: User) -> IpBlocklistOut:
    scope = "global" if item.user_id is None else "account"
    can_unblock = item.user_id == current_user.id or (
        item.user_id is None and current_user.role == "admin"
    )
    return IpBlocklistOut(
        id=item.id,
        user_id=item.user_id,
        ip_address=item.ip_address,
        reason=item.reason,
        threat_type=item.threat_type,
        auto_blocked=item.auto_blocked,
        blocked_at=item.blocked_at,
        expires_at=item.expires_at,
        is_active=item.is_active,
        scope=scope,
        can_unblock=can_unblock,
    )


@threats_router.get("", response_model=ThreatListResponse)
async def list_threats(
    page: int = 1,
    per_page: int = 20,
    severity: Optional[str] = None,
    threat_type: Optional[str] = None,
    is_resolved: Optional[bool] = None,
    include_simulation: bool = False,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    query = select(Threat).where(Threat.user_id == current_user.id)

    if not include_simulation:
        query = query.where(Threat.is_simulation == False)  # noqa
    if severity:
        query = query.where(Threat.severity == severity)
    if threat_type:
        query = query.where(Threat.threat_type == threat_type)
    if is_resolved is not None:
        query = query.where(Threat.is_resolved == is_resolved)

    count_q = select(func.count()).select_from(query.subquery())
    result = await db.execute(count_q)
    total = result.scalar_one()

    result = await db.execute(
        query.order_by(Threat.detected_at.desc())
        .offset((page - 1) * per_page)
        .limit(per_page)
    )
    items = result.scalars().all()

    return ThreatListResponse(total=total, page=page, per_page=per_page, items=items)


@threats_router.get("/{threat_id}", response_model=ThreatOut)
async def get_threat(
    threat_id: UUID,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(Threat).where(Threat.id == threat_id, Threat.user_id == current_user.id)
    )
    threat = result.scalar_one_or_none()
    if not threat:
        raise HTTPException(status_code=404, detail="Threat not found")
    return threat


@threats_router.patch("/{threat_id}/resolve")
async def resolve_threat(
    threat_id: UUID,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(Threat).where(Threat.id == threat_id, Threat.user_id == current_user.id)
    )
    threat = result.scalar_one_or_none()
    if not threat:
        raise HTTPException(status_code=404, detail="Threat not found")
    threat.is_resolved = True
    threat.resolved_at = datetime.now(timezone.utc)
    await db.commit()
    await recalculate_security_score(db, current_user)
    return {"message": "Threat resolved"}


@alerts_router.get("", response_model=AlertListResponse)
async def list_alerts(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(Alert, Threat)
        .outerjoin(Threat, Alert.threat_id == Threat.id)
        .where(Alert.user_id == current_user.id)
        .order_by(Alert.created_at.desc())
        .limit(50)
    )
    rows = result.all()
    alerts = [
        AlertOut.model_validate(alert).model_copy(update={
            "source_ip": threat.source_ip if threat else None,
            "is_simulation": threat.is_simulation if threat else False,
        })
        for alert, threat in rows
    ]
    unread = sum(1 for a in alerts if not a.is_read)
    return AlertListResponse(total=len(alerts), unread_count=unread, items=alerts)


@alerts_router.patch("/read-all")
async def mark_all_read(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(Alert).where(Alert.user_id == current_user.id, Alert.is_read == False)  # noqa
    )
    for alert in result.scalars().all():
        alert.is_read = True
    await db.commit()
    return {"message": "All alerts marked as read"}


@alerts_router.patch("/{alert_id}/read")
async def mark_alert_read(
    alert_id: UUID,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(Alert).where(Alert.id == alert_id, Alert.user_id == current_user.id)
    )
    alert = result.scalar_one_or_none()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    alert.is_read = True
    await db.commit()
    return {"message": "Alert marked as read"}


@blocklist_router.get("", response_model=List[IpBlocklistOut])
async def list_blocked_ips(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    now = datetime.now(timezone.utc)
    result = await db.execute(
        select(IpBlocklist)
        .where(
            IpBlocklist.is_active == True,  # noqa
            or_(IpBlocklist.expires_at.is_(None), IpBlocklist.expires_at > now),
            or_(
                IpBlocklist.user_id == current_user.id,
                IpBlocklist.user_id.is_(None),
            ),
        )
        .order_by(IpBlocklist.blocked_at.desc())
    )
    return [_block_out(item, current_user) for item in result.scalars().all()]


@blocklist_router.post(
    "",
    response_model=IpBlocklistOut,
    status_code=status.HTTP_201_CREATED,
)
async def block_ip(
    payload: IpBlockCreate,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Manually block an IP from authenticating to this account."""
    if payload.ip_address == get_client_ip(request):
        raise HTTPException(
            status_code=400,
            detail="You cannot block the IP address used by your current session",
        )

    now = datetime.now(timezone.utc)
    seconds = _BLOCK_DURATION_SECONDS[payload.duration]
    expires_at = now + timedelta(seconds=seconds) if seconds is not None else None

    global_result = await db.execute(
        select(IpBlocklist).where(
            IpBlocklist.user_id.is_(None),
            IpBlocklist.ip_address == payload.ip_address,
            IpBlocklist.is_active == True,  # noqa
            or_(IpBlocklist.expires_at.is_(None), IpBlocklist.expires_at > now),
        )
    )
    if global_result.scalar_one_or_none():
        raise HTTPException(
            status_code=409,
            detail="This IP address is already blocked platform-wide",
        )

    result = await db.execute(
        select(IpBlocklist).where(
            IpBlocklist.user_id == current_user.id,
            IpBlocklist.ip_address == payload.ip_address,
        )
    )
    entry = result.scalar_one_or_none()
    if (
        entry
        and entry.is_active
        and (entry.expires_at is None or entry.expires_at > now)
    ):
        raise HTTPException(
            status_code=409,
            detail="This IP address is already blocked for your account",
        )

    if entry is None:
        entry = IpBlocklist(
            user_id=current_user.id,
            ip_address=payload.ip_address,
            reason=payload.reason,
            threat_type="manual",
            auto_blocked=False,
            blocked_by_user_id=current_user.id,
            blocked_at=now,
            expires_at=expires_at,
            is_active=True,
        )
        db.add(entry)
    else:
        entry.reason = payload.reason
        entry.threat_type = "manual"
        entry.auto_blocked = False
        entry.blocked_by_user_id = current_user.id
        entry.blocked_at = now
        entry.expires_at = expires_at
        entry.is_active = True

    redis_client = aioredis.from_url(settings.REDIS_URL, decode_responses=True)
    redis_key = _block_key(current_user.id, payload.ip_address)
    redis_written = False
    try:
        await db.flush()
        if seconds is None:
            await redis_client.set(redis_key, "1")
        else:
            await redis_client.set(redis_key, "1", ex=seconds)
        redis_written = True
        db.add(AuditLog(
            user_id=current_user.id,
            action="ip_blocked.manual",
            resource=payload.ip_address,
            ip_address=get_client_ip(request),
            user_agent=request.headers.get("user-agent"),
            status="success",
            details={"reason": payload.reason, "duration": payload.duration},
        ))
        await db.commit()
        await db.refresh(entry)
    except Exception as exc:
        await db.rollback()
        if redis_written:
            try:
                await redis_client.delete(redis_key)
            except Exception:
                pass
        raise HTTPException(
            status_code=503,
            detail="IP blocking is temporarily unavailable; no block was created",
        ) from exc
    finally:
        await redis_client.aclose()

    return _block_out(entry, current_user)


@blocklist_router.delete("/{blocklist_id}")
async def unblock_ip(
    blocklist_id: UUID,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(IpBlocklist).where(IpBlocklist.id == blocklist_id))
    entry = result.scalar_one_or_none()
    if not entry:
        raise HTTPException(status_code=404, detail="Blocked IP not found")
    if entry.user_id != current_user.id and not (
        entry.user_id is None and current_user.role == "admin"
    ):
        raise HTTPException(status_code=403, detail="You cannot remove this IP block")

    redis_client = aioredis.from_url(settings.REDIS_URL, decode_responses=True)
    redis_key = _block_key(entry.user_id, entry.ip_address)
    redis_deleted = False
    try:
        await redis_client.delete(redis_key)
        redis_deleted = True
        entry.is_active = False
        db.add(AuditLog(
            user_id=current_user.id,
            action="ip_blocked.removed",
            resource=entry.ip_address,
            ip_address=get_client_ip(request),
            user_agent=request.headers.get("user-agent"),
            status="success",
            details={"scope": "global" if entry.user_id is None else "account"},
        ))
        await db.commit()
    except Exception as exc:
        await db.rollback()
        if redis_deleted:
            try:
                if entry.expires_at is None:
                    await redis_client.set(redis_key, "1")
                else:
                    ttl = max(
                        1,
                        int(
                            (
                                entry.expires_at - datetime.now(timezone.utc)
                            ).total_seconds()
                        ),
                    )
                    await redis_client.set(redis_key, "1", ex=ttl)
            except Exception:
                pass
        raise HTTPException(
            status_code=503,
            detail="IP unblocking is temporarily unavailable; the block remains active",
        ) from exc
    finally:
        await redis_client.aclose()
    return {"message": f"IP {entry.ip_address} unblocked"}


# Combined router
router.include_router(threats_router)
router.include_router(alerts_router)
router.include_router(blocklist_router)
