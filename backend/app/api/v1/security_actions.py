"""Guided account containment actions."""
from datetime import datetime, timezone
from ipaddress import ip_address

import redis.asyncio as aioredis
from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import select, or_
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.deps import get_client_ip, get_current_user, get_db
from app.core.security import decode_access_token
from app.db.models.compliance import AuditLog
from app.db.models.device import Device
from app.db.models.identity_security import PasskeyCredential
from app.db.models.security import IpBlocklist
from app.db.models.session import UserSession
from app.db.models.threat import Threat
from app.db.models.user import User
from app.schemas.common import ContainmentPreview, ContainmentResult
from app.services.security_score import recalculate_security_score

router = APIRouter(prefix="/security-actions", tags=["Security actions"])


def _session_id(request: Request) -> str | None:
    token = request.cookies.get("access_token") or request.headers.get("Authorization", "").removeprefix("Bearer ")
    payload = decode_access_token(token) if token else None
    return payload.get("session_id") if payload else None


async def _scope(request: Request, user: User, db: AsyncSession):
    current_session_id = _session_id(request)
    session_result = await db.execute(
        select(UserSession).where(UserSession.user_id == user.id, UserSession.is_active == True)  # noqa
    )
    sessions = session_result.scalars().all()
    current_session = next((item for item in sessions if str(item.id) == current_session_id), None)
    devices_result = await db.execute(select(Device).where(Device.user_id == user.id))
    devices = devices_result.scalars().all()
    threats_result = await db.execute(
        select(Threat).where(
            Threat.user_id == user.id,
            Threat.is_resolved == False,  # noqa
            Threat.is_simulation == False,  # noqa
            Threat.severity.in_(["high", "critical"]),
        )
    )
    threats = threats_result.scalars().all()
    current_ip = get_client_ip(request)
    source_ips = {
        threat.source_ip for threat in threats
        if threat.source_ip and threat.source_ip != current_ip and _valid_ip(threat.source_ip)
    }
    return current_session_id, current_session, sessions, devices, threats, source_ips


def _valid_ip(value: str) -> bool:
    try:
        ip_address(value)
        return True
    except ValueError:
        return False


@router.get("/containment-preview", response_model=ContainmentPreview)
async def containment_preview(
    request: Request,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    current_session_id, current_session, sessions, devices, threats, source_ips = await _scope(request, current_user, db)
    current_device_id = current_session.device_id if current_session else None
    return ContainmentPreview(
        other_active_sessions=sum(str(item.id) != current_session_id for item in sessions),
        other_devices=sum(item.device_id != current_device_id for item in devices),
        serious_unresolved_threats=len(threats),
        blockable_source_ips=len(source_ips),
    )


@router.post("/secure-account", response_model=ContainmentResult)
async def secure_account(
    request: Request,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    current_session_id, current_session, sessions, devices, threats, source_ips = await _scope(request, current_user, db)
    now = datetime.now(timezone.utc)
    sessions_revoked = 0
    for item in sessions:
        if str(item.id) != current_session_id:
            item.is_active = False
            item.revoked_at = now
            sessions_revoked += 1

    current_device_id = current_session.device_id if current_session else None
    devices_distrusted = 0
    for item in devices:
        if item.device_id != current_device_id and item.is_trusted:
            item.is_trusted = False
            devices_distrusted += 1

    existing_result = await db.execute(
        select(IpBlocklist).where(
            IpBlocklist.ip_address.in_(source_ips),
            or_(
                IpBlocklist.user_id == current_user.id,
                IpBlocklist.user_id.is_(None),
            ),
        )
    ) if source_ips else None
    existing_rows = existing_result.scalars().all() if existing_result else []
    global_blocks = {
        item.ip_address for item in existing_rows
        if (
            item.user_id is None
            and item.is_active
            and (item.expires_at is None or item.expires_at > now)
        )
    }
    existing = {
        item.ip_address: item for item in existing_rows
        if item.user_id == current_user.id
    }
    ips_blocked = 0
    redis_client = aioredis.from_url(settings.REDIS_URL, decode_responses=True)
    redis_keys_written = []
    try:
        for source_ip in source_ips:
            if source_ip in global_blocks:
                continue
            item = existing.get(source_ip)
            if item:
                if not item.is_active:
                    item.is_active = True
                    item.blocked_at = now
                    ips_blocked += 1
                item.expires_at = None
                item.blocked_by_user_id = current_user.id
                item.reason = "Blocked by Secure my account containment"
            else:
                db.add(IpBlocklist(
                    user_id=current_user.id,
                    ip_address=source_ip,
                    reason="Blocked by Secure my account containment",
                    threat_type="account_containment",
                    auto_blocked=False,
                    blocked_by_user_id=current_user.id,
                ))
                ips_blocked += 1
            redis_key = f"blocked_ip:{current_user.id}:{source_ip}"
            await redis_client.set(
                redis_key, "1"
            )
            redis_keys_written.append(redis_key)
    except Exception as exc:
        await db.rollback()
        for redis_key in redis_keys_written:
            try:
                await redis_client.delete(redis_key)
            except Exception:
                pass
        raise HTTPException(
            status_code=503,
            detail="Account containment is temporarily unavailable; no changes were saved",
        ) from exc
    finally:
        await redis_client.aclose()

    for threat in threats:
        details = dict(threat.details or {})
        details["containment"] = {
            "applied_at": now.isoformat(),
            "source_ip_blocked": bool(threat.source_ip in source_ips),
            "sessions_revoked": sessions_revoked,
        }
        threat.details = details

    db.add(AuditLog(
        user_id=current_user.id,
        action="account.secured",
        resource=str(current_user.id),
        ip_address=get_client_ip(request),
        user_agent=request.headers.get("user-agent"),
        status="success",
        details={
            "sessions_revoked": sessions_revoked,
            "devices_distrusted": devices_distrusted,
            "ips_blocked": ips_blocked,
            "threats_contained": len(threats),
            "current_session_preserved": True,
        },
    ))
    await db.commit()
    await recalculate_security_score(db, current_user)

    passkeys_result = await db.execute(select(PasskeyCredential.id).where(PasskeyCredential.user_id == current_user.id).limit(1))
    recommendations = []
    if current_user.password_breached:
        recommendations.append("Change the breached account password; containment cannot replace it for you.")
    if not current_user.totp_enabled:
        recommendations.append("Enable two-factor authentication in Settings.")
    if passkeys_result.scalar_one_or_none() is None:
        recommendations.append("Register a phishing-resistant passkey in Settings.")
    if not recommendations:
        recommendations.append("Review the contained threats and resolve each one after confirming remediation.")
    return ContainmentResult(
        sessions_revoked=sessions_revoked,
        devices_distrusted=devices_distrusted,
        ips_blocked=ips_blocked,
        threats_contained=len(threats),
        current_session_preserved=True,
        recommendations=recommendations,
        completed_at=now,
    )
