"""
Sessions & Devices API
"""
from datetime import datetime, timezone
from typing import List
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.core.deps import get_db, get_current_user
from app.db.models.user import User
from app.db.models.session import UserSession
from app.db.models.device import Device
from app.schemas.common import SessionOut, DeviceOut
from app.services.geoip_service import lookup_ip
from app.services.security_score import recalculate_security_score

router = APIRouter(tags=["Sessions & Devices"])
sessions_router = APIRouter(prefix="/sessions")
devices_router = APIRouter(prefix="/devices")


def _location_fields(ip: str | None) -> dict:
    if not ip:
        return {
            "country": None,
            "country_code": None,
            "city": None,
            "latitude": None,
            "longitude": None,
        }
    geo = lookup_ip(ip)
    return {
        "country": geo.country,
        "country_code": geo.country_code,
        "city": geo.city,
        "latitude": geo.latitude,
        "longitude": geo.longitude,
    }


def _session_with_location(session: UserSession) -> SessionOut:
    return SessionOut.model_validate(session).model_copy(
        update=_location_fields(session.ip_address)
    )


def _device_with_location(device: Device) -> DeviceOut:
    return DeviceOut.model_validate(device).model_copy(
        update=_location_fields(device.last_ip)
    )


@sessions_router.get("", response_model=List[SessionOut])
async def list_sessions(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(UserSession)
        .where(UserSession.user_id == current_user.id, UserSession.is_active == True)  # noqa
        .order_by(UserSession.last_used_at.desc())
    )
    return [_session_with_location(session) for session in result.scalars().all()]


@sessions_router.delete("/{session_id}")
async def revoke_session(
    session_id: UUID,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(UserSession).where(
            UserSession.id == session_id,
            UserSession.user_id == current_user.id,
        )
    )
    session = result.scalar_one_or_none()
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    session.is_active = False
    session.revoked_at = datetime.now(timezone.utc)
    await db.commit()
    await recalculate_security_score(db, current_user)
    return {"message": "Session revoked"}


@sessions_router.delete("")
async def revoke_all_sessions(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(UserSession).where(
            UserSession.user_id == current_user.id,
            UserSession.is_active == True,  # noqa
        )
    )
    sessions = result.scalars().all()
    for s in sessions:
        s.is_active = False
        s.revoked_at = datetime.now(timezone.utc)
    await db.commit()
    await recalculate_security_score(db, current_user)
    return {"message": f"Revoked {len(sessions)} sessions"}


@devices_router.get("", response_model=List[DeviceOut])
async def list_devices(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(Device)
        .where(Device.user_id == current_user.id)
        .order_by(Device.last_seen.desc())
    )
    return [_device_with_location(device) for device in result.scalars().all()]


@devices_router.patch("/{device_id}/trust")
async def trust_device(
    device_id: UUID,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(Device).where(Device.id == device_id, Device.user_id == current_user.id)
    )
    device = result.scalar_one_or_none()
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
    device.is_trusted = not device.is_trusted
    await db.commit()
    await recalculate_security_score(db, current_user)
    return {"message": f"Device {'trusted' if device.is_trusted else 'untrusted'}", "is_trusted": device.is_trusted}


@devices_router.delete("/{device_id}")
async def remove_device(
    device_id: UUID,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(Device).where(Device.id == device_id, Device.user_id == current_user.id)
    )
    device = result.scalar_one_or_none()
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
    await db.delete(device)
    await db.commit()
    await recalculate_security_score(db, current_user)
    return {"message": "Device removed"}


# Combined router
router.include_router(sessions_router)
router.include_router(devices_router)
