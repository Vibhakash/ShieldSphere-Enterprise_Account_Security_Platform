"""
User Behavior Analytics API
"""
from datetime import datetime, timedelta, timezone
from fastapi import APIRouter, Depends, BackgroundTasks
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.core.deps import get_db, get_current_user
from app.db.models.user import User
from app.db.models.security import BehaviorProfile
from app.db.models.login_history import LoginHistory
from app.db.models.device import Device
from app.db.models.session import UserSession
from app.schemas.common import UBADeviceActivityOut, UBAProfileOut
from app.services.geoip_service import lookup_ip
from app.services.uba_engine import (
    MIN_BASELINE_DEVICES,
    MIN_BASELINE_SAMPLES,
    compute_anomaly_score,
    profile_is_ready,
    rebuild_user_baseline,
)

router = APIRouter(prefix="/uba", tags=["User Behavior Analytics"])


async def _rebuild_baseline_background(user_id):
    """Run a rebuild with its own session after the request session is closed."""
    from app.db.session import AsyncSessionLocal

    async with AsyncSessionLocal() as db:
        await rebuild_user_baseline(db, user_id)


@router.get("/profile", response_model=UBAProfileOut)
async def get_uba_profile(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Return the current behavior baseline for the user."""
    result = await db.execute(
        select(BehaviorProfile).where(BehaviorProfile.user_id == current_user.id)
    )
    profile = result.scalar_one_or_none()
    if not profile_is_ready(profile):
        # Build on demand
        profile = await rebuild_user_baseline(db, current_user.id)
        if not profile:
            from fastapi import HTTPException
            raise HTTPException(
                status_code=404,
                detail=(
                    "A behavior profile needs at least "
                    f"{MIN_BASELINE_SAMPLES} successful sign-ins from "
                    f"{MIN_BASELINE_DEVICES} distinct recognized devices"
                ),
            )
    return profile


@router.get("/baseline-status")
async def get_baseline_status(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Show safe progress toward the two-sample, two-device baseline."""
    result = await db.execute(
        select(LoginHistory).where(
            LoginHistory.user_id == current_user.id,
            LoginHistory.success == True,  # noqa
            LoginHistory.is_simulation == False,  # noqa
        )
    )
    logins = result.scalars().all()
    device_ids = {login.device_id for login in logins if login.device_id}
    return {
        "successful_sign_ins": len(logins),
        "distinct_recognized_devices": len(device_ids),
        "required_successful_sign_ins": MIN_BASELINE_SAMPLES,
        "required_distinct_devices": MIN_BASELINE_DEVICES,
        "ready": len(logins) >= MIN_BASELINE_SAMPLES and len(device_ids) >= MIN_BASELINE_DEVICES,
    }


@router.get("/device-activity", response_model=list[UBADeviceActivityOut])
async def get_device_activity(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Return account device activity for the behavioral analytics view.

    The timeline is assembled from real sign-in history and session lifecycle
    records. Sandbox events are excluded so the user sees account activity only.
    """
    devices_result = await db.execute(
        select(Device)
        .where(Device.user_id == current_user.id)
        .order_by(Device.last_seen.desc())
    )
    devices = devices_result.scalars().all()
    sessions_result = await db.execute(
        select(UserSession)
        .where(UserSession.user_id == current_user.id)
        .order_by(UserSession.created_at.desc())
        .limit(200)
    )
    sessions = sessions_result.scalars().all()
    logins_result = await db.execute(
        select(LoginHistory)
        .where(
            LoginHistory.user_id == current_user.id,
            LoginHistory.is_simulation == False,  # noqa
        )
        .order_by(LoginHistory.timestamp.desc())
        .limit(200)
    )
    logins = logins_result.scalars().all()

    def key(device_id: str | None) -> str:
        return device_id or "unknown-device"

    def location(city: str | None, country: str | None) -> str | None:
        return ", ".join(part for part in (city, country) if part) or None

    records: dict[str, dict] = {}
    for device in devices:
        geo = lookup_ip(device.last_ip) if device.last_ip else None
        records[key(device.device_id)] = {
            "device_id": device.device_id,
            "name": " ".join(part for part in (device.browser, device.os) if part) or "Recognized device",
            "browser": device.browser,
            "os": device.os,
            "device_type": device.device_type,
            "is_trusted": device.is_trusted,
            "is_active": False,
            "last_ip": device.last_ip,
            "location": location(geo.city, geo.country) if geo else None,
            "first_seen": device.first_seen,
            "last_seen": device.last_seen,
            "last_login": None,
            "last_logout": None,
            "last_activity": device.last_seen or device.first_seen,
            "events": [],
        }

    def record_for(device_id: str | None) -> dict:
        item_key = key(device_id)
        if item_key not in records:
            records[item_key] = {
                "device_id": device_id or "Unknown device",
                "name": "Unrecognized device",
                "browser": None, "os": None, "device_type": None,
                "is_trusted": False, "is_active": False, "last_ip": None,
                "location": None, "first_seen": None, "last_seen": None,
                "last_login": None, "last_logout": None, "last_activity": None, "events": [],
            }
        return records[item_key]

    for login in logins:
        item = record_for(login.device_id)
        login_location = location(login.city, login.country)
        item["last_ip"] = item["last_ip"] or login.ip_address
        item["location"] = item["location"] or login_location
        if login.success and (item["last_login"] is None or login.timestamp > item["last_login"]):
            item["last_login"] = login.timestamp
        item["events"].append({
            "event_type": "Successful sign-in" if login.success else "Failed sign-in",
            "timestamp": login.timestamp,
            "ip_address": login.ip_address,
            "location": login_location,
            "details": login.failure_reason if not login.success else None,
        })

    for session in sessions:
        item = record_for(session.device_id)
        item["is_active"] = item["is_active"] or session.is_active
        item["last_ip"] = item["last_ip"] or session.ip_address
        if session.revoked_at:
            if item["last_logout"] is None or session.revoked_at > item["last_logout"]:
                item["last_logout"] = session.revoked_at
            item["events"].append({
                "event_type": "Signed out or revoked",
                "timestamp": session.revoked_at,
                "ip_address": session.ip_address,
                "location": item["location"],
                "details": None,
            })
        elif session.is_active:
            item["events"].append({
                "event_type": "Active session",
                "timestamp": session.last_used_at or session.created_at,
                "ip_address": session.ip_address,
                "location": item["location"],
                "details": f"Started {session.created_at.strftime('%d %b %Y, %H:%M UTC')}",
            })

    activity = []
    for item in records.values():
        item["events"].sort(key=lambda event: event["timestamp"], reverse=True)
        item["events"] = item["events"][:8]
        timestamps = [event["timestamp"] for event in item["events"]]
        if timestamps:
            item["last_activity"] = max([timestamp for timestamp in [item["last_activity"], *timestamps] if timestamp])
        activity.append(UBADeviceActivityOut(**item))
    return sorted(activity, key=lambda item: item.last_activity or item.first_seen or datetime.min.replace(tzinfo=timezone.utc), reverse=True)


@router.post("/rebuild")
async def rebuild_baseline(
    background_tasks: BackgroundTasks,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Trigger a full rebuild of the user's behavior baseline."""
    background_tasks.add_task(_rebuild_baseline_background, current_user.id)
    return {"message": "Baseline rebuild queued"}


@router.get("/anomalies")
async def get_anomaly_history(
    days: int = 30,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Return logins with high anomaly scores."""
    since = datetime.now(timezone.utc) - timedelta(days=days)
    result = await db.execute(
        select(LoginHistory)
        .where(
            LoginHistory.user_id == current_user.id,
            LoginHistory.timestamp >= since,
            LoginHistory.anomaly_score.isnot(None),
            LoginHistory.anomaly_score > 0.3,  # Only notable anomalies
        )
        .order_by(LoginHistory.timestamp.desc())
        .limit(50)
    )
    logins = result.scalars().all()
    return [
        {
            "id": str(l.id),
            "timestamp": l.timestamp.isoformat(),
            "ip": l.ip_address,
            "country": l.country,
            "city": l.city,
            "device_id": l.device_id,
            "anomaly_score": l.anomaly_score,
            "success": l.success,
        }
        for l in logins
    ]
