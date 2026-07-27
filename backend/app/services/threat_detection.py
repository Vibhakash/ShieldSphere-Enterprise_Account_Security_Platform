"""
Threat detection engine.
Runs on every login event (real or simulated) to detect:
- Brute force (Redis sliding window)
- Impossible travel (haversine)
- Unknown device / unknown location
"""
import asyncio
import logging
import math
from datetime import datetime, timedelta, timezone
from typing import Optional, List
from uuid import UUID

import redis.asyncio as aioredis
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, or_

from app.core.config import settings
from app.db.models.login_history import LoginHistory
from app.db.models.threat import Threat, Alert
from app.db.models.security import BehaviorProfile, IpBlocklist
from app.services import llm_service

logger = logging.getLogger(__name__)


def _haversine_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Calculate distance between two geo points in km."""
    R = 6371.0
    phi1, phi2 = math.radians(lat1), math.radians(lat2)
    dphi = math.radians(lat2 - lat1)
    dlambda = math.radians(lon2 - lon1)
    a = math.sin(dphi / 2) ** 2 + math.cos(phi1) * math.cos(phi2) * math.sin(dlambda / 2) ** 2
    return 2 * R * math.asin(math.sqrt(a))


async def _create_threat_and_alert(
    db: AsyncSession,
    user_id: UUID,
    threat_type: str,
    severity: str,
    title: str,
    description: str,
    login_event_id: Optional[UUID],
    simulation_id: Optional[UUID],
    source_ip: Optional[str],
    source_country: Optional[str],
    details: dict,
    is_simulation: bool = False,
) -> Threat:
    """Create a threat record, generate AI RCA, and create an alert."""
    # Generate LLM root-cause analysis asynchronously
    threat_data = {
        "threat_type": threat_type,
        "severity": severity,
        "source_ip": source_ip,
        "country": source_country,
        **details,
    }
    try:
        rca = await llm_service.generate_threat_rca(threat_data)
    except Exception as e:
        logger.error(f"RCA generation failed: {e}")
        rca = None

    threat = Threat(
        user_id=user_id,
        login_event_id=login_event_id,
        simulation_id=simulation_id,
        threat_type=threat_type,
        severity=severity,
        title=title,
        description=description,
        source_ip=source_ip,
        source_country=source_country,
        details=details,
        llm_rca=rca,
        is_simulation=is_simulation,
    )
    db.add(threat)
    await db.flush()  # get the threat.id

    alert = Alert(
        user_id=user_id,
        threat_id=threat.id,
        title=title,
        message=description,
        severity=severity,
    )
    db.add(alert)
    await db.commit()
    await db.refresh(threat)
    from app.services.integration_service import deliver_alert
    asyncio.create_task(deliver_alert(alert.id))
    return threat


async def record_simulation_attack(
    db: AsyncSession,
    *,
    user_id: UUID,
    simulation_id: UUID,
    threat_type: str,
    severity: str,
    title: str,
    description: str,
    source_ip: Optional[str] = None,
    details: Optional[dict] = None,
) -> Threat:
    """Persist one labelled detection and alert for a completed sandbox exercise.

    Simulations deliberately create suspicious behaviour. Keeping these records in
    the normal threat and alert stream lets people verify the defensive workflow,
    while ``is_simulation`` prevents them from being treated as production risk.
    """
    return await _create_threat_and_alert(
        db=db,
        user_id=user_id,
        threat_type=threat_type,
        severity=severity,
        title=title,
        description=description,
        login_event_id=None,
        simulation_id=simulation_id,
        source_ip=source_ip,
        source_country=None,
        details=details or {},
        is_simulation=True,
    )


async def check_brute_force(
    db: AsyncSession,
    redis_client: aioredis.Redis,
    user_id: UUID,
    ip: str,
    login_event_id: UUID,
    simulation_id: Optional[UUID],
    is_simulation: bool,
) -> Optional[Threat]:
    """
    Use Redis sorted set as a sliding window to count failed attempts.
    Key: brute_force:{ip} — members are login_event timestamps.
    """
    key = f"brute_force:{ip}"
    now = datetime.now(timezone.utc).timestamp()
    window_start = now - settings.BRUTE_FORCE_WINDOW_SECONDS

    # Add this timestamp
    await redis_client.zadd(key, {str(now): now})
    # Remove entries outside the window
    await redis_client.zremrangebyscore(key, "-inf", window_start)
    # Set TTL
    await redis_client.expire(key, settings.BRUTE_FORCE_WINDOW_SECONDS * 2)
    # Count attempts in window
    count = await redis_client.zcard(key)

    if count >= settings.BRUTE_FORCE_THRESHOLD:
        logger.warning(f"Brute force detected from {ip}: {count} attempts in window")
        return await _create_threat_and_alert(
            db=db,
            user_id=user_id,
            threat_type="brute_force",
            severity="high",
            title=f"Brute Force Attack Detected from {ip}",
            description=f"{count} failed login attempts from IP {ip} within {settings.BRUTE_FORCE_WINDOW_SECONDS // 60} minutes.",
            login_event_id=login_event_id,
            simulation_id=simulation_id,
            source_ip=ip,
            source_country=None,
            details={"failed_attempts": count, "time_window": f"{settings.BRUTE_FORCE_WINDOW_SECONDS}s", "ip": ip},
            is_simulation=is_simulation,
        )
    return None


async def check_impossible_travel(
    db: AsyncSession,
    user_id: UUID,
    current_login: LoginHistory,
    login_event_id: UUID,
    simulation_id: Optional[UUID],
    is_simulation: bool,
) -> Optional[Threat]:
    """
    Compare current login location with previous login.
    Flag if travel speed exceeds the configured threshold.
    """
    if not current_login.latitude or not current_login.longitude:
        return None

    # Get last successful login for this user (excluding current)
    result = await db.execute(
        select(LoginHistory)
        .where(
            LoginHistory.user_id == user_id,
            LoginHistory.success == True,  # noqa
            LoginHistory.id != login_event_id,
            LoginHistory.latitude.isnot(None),
            LoginHistory.longitude.isnot(None),
        )
        .order_by(LoginHistory.timestamp.desc())
        .limit(1)
    )
    prev_login = result.scalar_one_or_none()
    if not prev_login:
        return None

    distance_km = _haversine_km(
        prev_login.latitude, prev_login.longitude,
        current_login.latitude, current_login.longitude,
    )

    time_diff_hours = (
        current_login.timestamp - prev_login.timestamp
    ).total_seconds() / 3600.0

    if time_diff_hours <= 0:
        return None

    speed_kmh = distance_km / time_diff_hours

    if speed_kmh > settings.IMPOSSIBLE_TRAVEL_MIN_SPEED_KMH and distance_km > 500:
        logger.warning(
            f"Impossible travel for user {user_id}: {distance_km:.0f}km in {time_diff_hours:.1f}h ({speed_kmh:.0f}km/h)"
        )
        prev_loc = f"{prev_login.city or ''}, {prev_login.country or 'unknown'}".strip(", ")
        curr_loc = f"{current_login.city or ''}, {current_login.country or 'unknown'}".strip(", ")
        return await _create_threat_and_alert(
            db=db,
            user_id=user_id,
            threat_type="impossible_travel",
            severity="high",
            title="Impossible Travel Detected",
            description=(
                f"Login from {curr_loc} ({current_login.ip_address}) detected {distance_km:.0f}km "
                f"from previous login at {prev_loc} just {time_diff_hours:.1f} hours ago. "
                f"Computed travel speed: {speed_kmh:.0f}km/h — physically impossible."
            ),
            login_event_id=login_event_id,
            simulation_id=simulation_id,
            source_ip=current_login.ip_address,
            source_country=current_login.country,
            details={
                "distance_km": round(distance_km, 1),
                "time_hours": round(time_diff_hours, 2),
                "speed_kmh": round(speed_kmh, 0),
                "travel_distance_km": round(distance_km, 1),
                "time_since_last_login": f"{time_diff_hours:.1f} hours",
                "from_location": prev_loc,
                "to_location": curr_loc,
                "prev_ip": prev_login.ip_address,
            },
            is_simulation=is_simulation,
        )
    return None


async def check_unknown_device(
    db: AsyncSession,
    user_id: UUID,
    device_id: Optional[str],
    login_event_id: UUID,
    simulation_id: Optional[UUID],
    source_ip: str,
    is_simulation: bool,
) -> Optional[Threat]:
    """Flag if the login device was never seen before for this user."""
    if not device_id:
        return None

    from app.db.models.device import Device
    result = await db.execute(
        select(Device).where(
            Device.user_id == user_id,
            Device.device_id == device_id,
        )
    )
    device = result.scalar_one_or_none()
    if device is None:
        # Completely new device
        return await _create_threat_and_alert(
            db=db,
            user_id=user_id,
            threat_type="unknown_device",
            severity="medium",
            title="New Unrecognized Device Login",
            description=f"A login was detected from a device that has never been seen before for this account. IP: {source_ip}.",
            login_event_id=login_event_id,
            simulation_id=simulation_id,
            source_ip=source_ip,
            source_country=None,
            details={"device_id": device_id, "ip": source_ip, "device_info": "new device"},
            is_simulation=is_simulation,
        )
    return None


async def check_unknown_location(
    db: AsyncSession,
    user_id: UUID,
    country: Optional[str],
    login_event_id: UUID,
    simulation_id: Optional[UUID],
    source_ip: str,
    is_simulation: bool,
) -> Optional[Threat]:
    """Flag if login is from a country not in the user's behavior profile."""
    if not country:
        return None

    result = await db.execute(
        select(BehaviorProfile).where(BehaviorProfile.user_id == user_id)
    )
    profile = result.scalar_one_or_none()
    if not profile or not profile.known_countries:
        return None  # No baseline yet

    known = profile.known_countries.get("countries", [])
    if country not in known and len(known) >= 2:  # Only flag after baseline is built
        return await _create_threat_and_alert(
            db=db,
            user_id=user_id,
            threat_type="unknown_location",
            severity="medium",
            title=f"Login from Unusual Location: {country}",
            description=f"Login detected from {country} ({source_ip}), which is not in this account's historical login locations.",
            login_event_id=login_event_id,
            simulation_id=simulation_id,
            source_ip=source_ip,
            source_country=country,
            details={
                "country": country,
                "ip": source_ip,
                "known_countries": known,
            },
            is_simulation=is_simulation,
        )
    return None


async def run_all_detectors(
    db: AsyncSession,
    redis_client: aioredis.Redis,
    user_id: UUID,
    login_event: LoginHistory,
    success: bool,
    simulation_id: Optional[UUID] = None,
    is_simulation: bool = False,
) -> List[Threat]:
    """Run all threat detectors for a login event. Returns list of threats triggered."""
    threats = []

    if not success:
        # Brute force only triggers on failed logins
        threat = await check_brute_force(
            db=db,
            redis_client=redis_client,
            user_id=user_id,
            ip=login_event.ip_address,
            login_event_id=login_event.id,
            simulation_id=simulation_id,
            is_simulation=is_simulation,
        )
        if threat:
            threats.append(threat)
    else:
        # These only trigger on successful logins
        travel_threat = await check_impossible_travel(
            db=db,
            user_id=user_id,
            current_login=login_event,
            login_event_id=login_event.id,
            simulation_id=simulation_id,
            is_simulation=is_simulation,
        )
        if travel_threat:
            threats.append(travel_threat)

        device_threat = await check_unknown_device(
            db=db,
            user_id=user_id,
            device_id=login_event.device_id,
            login_event_id=login_event.id,
            simulation_id=simulation_id,
            source_ip=login_event.ip_address,
            is_simulation=is_simulation,
        )
        if device_threat:
            threats.append(device_threat)

        location_threat = await check_unknown_location(
            db=db,
            user_id=user_id,
            country=login_event.country,
            login_event_id=login_event.id,
            simulation_id=simulation_id,
            source_ip=login_event.ip_address,
            is_simulation=is_simulation,
        )
        if location_threat:
            threats.append(location_threat)

    # Check if IP should be auto-blocked
    await _check_auto_block(db, redis_client, user_id, login_event.ip_address, threats)

    return threats


async def _check_auto_block(
    db: AsyncSession,
    redis_client: aioredis.Redis,
    user_id: UUID,
    ip: str,
    new_threats: List[Threat],
) -> None:
    """Auto-block an IP for this account after repeated real threats."""
    real_threats = [threat for threat in new_threats if not threat.is_simulation]
    if not real_threats:
        return

    # Simulations and other users' activity must never affect a real account block.
    result = await db.execute(
        select(func.count(Threat.id)).where(
            Threat.user_id == user_id,
            Threat.source_ip == ip,
            Threat.is_resolved == False,  # noqa
            Threat.is_simulation == False,  # noqa
        )
    )
    total = result.scalar_one() or 0

    if total >= settings.AUTO_BLOCK_THREAT_COUNT:
        now = datetime.now(timezone.utc)
        global_result = await db.execute(
            select(IpBlocklist).where(
                IpBlocklist.user_id.is_(None),
                IpBlocklist.ip_address == ip,
                IpBlocklist.is_active == True,  # noqa
                or_(
                    IpBlocklist.expires_at.is_(None),
                    IpBlocklist.expires_at > now,
                ),
            )
        )
        if global_result.scalar_one_or_none():
            return

        existing_result = await db.execute(
            select(IpBlocklist).where(
                IpBlocklist.user_id == user_id,
                IpBlocklist.ip_address == ip,
            )
        )
        block = existing_result.scalar_one_or_none()
        expires_at = now + timedelta(hours=24)
        redis_ttl = 86400
        if block is None:
            block = IpBlocklist(
                user_id=user_id,
                ip_address=ip,
                reason=f"Auto-blocked: {total} threats detected",
                threat_type=real_threats[0].threat_type,
                auto_blocked=True,
                blocked_by_user_id=user_id,
                blocked_at=now,
                expires_at=expires_at,
            )
            db.add(block)
        elif not block.is_active or (
            block.expires_at is not None and block.expires_at <= now
        ):
            block.reason = f"Auto-blocked: {total} threats detected"
            block.threat_type = real_threats[0].threat_type
            block.auto_blocked = True
            block.blocked_by_user_id = user_id
            block.blocked_at = now
            block.expires_at = expires_at
            block.is_active = True
        elif block.expires_at is None:
            redis_ttl = None
        else:
            redis_ttl = max(1, int((block.expires_at - now).total_seconds()))

        for threat in real_threats:
            threat.auto_blocked = True
        redis_key = f"blocked_ip:{user_id}:{ip}"
        if redis_ttl is None:
            await redis_client.set(redis_key, "1")
        else:
            await redis_client.set(redis_key, "1", ex=redis_ttl)
        try:
            await db.commit()
        except Exception:
            await db.rollback()
            await redis_client.delete(redis_key)
            raise
        logger.warning(
            "Auto-blocked IP %s for account %s after %s threats",
            ip,
            user_id,
            total,
        )
