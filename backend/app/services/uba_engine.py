"""
User Behavior Analytics engine.
Builds and updates behavior baselines from real login_history data.
Computes anomaly scores for new logins.
"""
import logging
from collections import Counter
from datetime import datetime, timedelta, timezone
from typing import Optional
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.db.models.login_history import LoginHistory
from app.db.models.security import BehaviorProfile

logger = logging.getLogger(__name__)

# A useful baseline needs both repeated activity and a comparison point.  Two
# logins from the same browser do not tell us whether a future device is new.
MIN_BASELINE_SAMPLES = 2
MIN_BASELINE_DEVICES = 2


def _distinct_device_ids(logins: list[LoginHistory]) -> list[str]:
    """Return the unique, non-empty device identifiers in a login sample."""
    return sorted({login.device_id for login in logins if login.device_id})


def profile_is_ready(profile: Optional[BehaviorProfile]) -> bool:
    """Whether a stored profile meets the current baseline requirements."""
    if profile is None or profile.sample_count < MIN_BASELINE_SAMPLES:
        return False
    devices = (profile.known_device_ids or {}).get("devices", [])
    return len(devices) >= MIN_BASELINE_DEVICES


async def rebuild_user_baseline(db: AsyncSession, user_id: UUID) -> Optional[BehaviorProfile]:
    """
    Rebuild the behavior baseline for a user from their last 90 days of logins.
    """
    since = datetime.now(timezone.utc) - timedelta(days=90)
    result = await db.execute(
        select(LoginHistory)
        .where(
            LoginHistory.user_id == user_id,
            LoginHistory.success == True,  # noqa
            LoginHistory.is_simulation == False,  # noqa
            LoginHistory.timestamp >= since,
        )
        .order_by(LoginHistory.timestamp.desc())
        .limit(500)
    )
    logins = result.scalars().all()

    device_ids = _distinct_device_ids(logins)
    if len(logins) < MIN_BASELINE_SAMPLES or len(device_ids) < MIN_BASELINE_DEVICES:
        logger.debug(
            "Not enough diverse baseline activity for user %s: %s samples, %s devices",
            user_id,
            len(logins),
            len(device_ids),
        )
        return None

    # Compute typical login hours (hour → count)
    hour_counts = Counter(login.timestamp.hour for login in logins)
    total = len(logins)

    # Normalize to percentages
    hour_distribution = {str(h): count / total for h, count in hour_counts.items()}

    # Known device IDs
    # Known countries
    countries = list({login.country for login in logins if login.country})

    # Known ASNs
    asns = list({login.asn for login in logins if login.asn})

    # Average logins per day
    if logins:
        date_counts = Counter(login.timestamp.date() for login in logins)
        avg_per_day = len(logins) / max(len(date_counts), 1)
    else:
        avg_per_day = 0.0

    # Get or create profile
    result = await db.execute(
        select(BehaviorProfile).where(BehaviorProfile.user_id == user_id)
    )
    profile = result.scalar_one_or_none()

    if profile is None:
        profile = BehaviorProfile(user_id=user_id)
        db.add(profile)

    profile.typical_hours = {"distribution": hour_distribution, "peak_hours": [
        int(h) for h, _ in hour_counts.most_common(6)
    ]}
    profile.known_device_ids = {"devices": device_ids}
    profile.known_countries = {"countries": countries}
    profile.known_asns = {"asns": asns}
    profile.avg_logins_per_day = round(avg_per_day, 2)
    profile.sample_count = total
    profile.last_updated = datetime.now(timezone.utc)

    await db.commit()
    await db.refresh(profile)
    logger.info(
        "Rebuilt baseline for user %s: %s samples, %s devices, %s countries",
        user_id,
        total,
        len(device_ids),
        len(countries),
    )
    return profile


def compute_anomaly_score(login: LoginHistory, profile: Optional[BehaviorProfile]) -> float:
    """
    Compute an anomaly score (0.0–1.0) for a login event against the user's baseline.
    Higher = more anomalous.
    """
    if not profile_is_ready(profile):
        return 0.0  # No baseline — can't score

    score = 0.0
    factors = 0

    # Hour-of-day anomaly
    if profile.typical_hours:
        hour = str(login.timestamp.hour)
        dist = profile.typical_hours.get("distribution", {})
        hour_prob = dist.get(hour, 0.0)
        # Low probability hour = high anomaly contribution
        hour_anomaly = max(0.0, 1.0 - (hour_prob * 10))  # scale up low probs
        score += hour_anomaly * 0.25
        factors += 1

    # Country anomaly
    if profile.known_countries and login.country:
        known = profile.known_countries.get("countries", [])
        if login.country not in known:
            score += 0.4
        factors += 1

    # Device anomaly
    if profile.known_device_ids and login.device_id:
        known_devices = profile.known_device_ids.get("devices", [])
        if login.device_id not in known_devices:
            score += 0.35
        factors += 1

    # ASN anomaly
    if profile.known_asns and login.asn:
        known_asns = profile.known_asns.get("asns", [])
        if login.asn not in known_asns:
            score += 0.2
        factors += 1

    return min(score, 1.0)


async def update_baseline_incrementally(
    db: AsyncSession,
    user_id: UUID,
    login: LoginHistory,
) -> None:
    """
    After a successful login, incrementally update the behavior profile.
    Full rebuild is run by the nightly job; this just updates known sets.
    """
    result = await db.execute(
        select(BehaviorProfile).where(BehaviorProfile.user_id == user_id)
    )
    profile = result.scalar_one_or_none()

    if profile is None:
        # Check if we have enough samples now for a first baseline
        result2 = await db.execute(
            select(LoginHistory).where(
                LoginHistory.user_id == user_id,
                LoginHistory.success == True,  # noqa
                LoginHistory.is_simulation == False,  # noqa
            ).limit(MIN_BASELINE_SAMPLES + 1)
        )
        count = len(result2.scalars().all())
        if count >= MIN_BASELINE_SAMPLES:
            await rebuild_user_baseline(db, user_id)
        return

    # Incrementally add to known sets
    changed = False

    if login.country and profile.known_countries:
        countries = profile.known_countries.get("countries", [])
        if login.country not in countries:
            countries.append(login.country)
            profile.known_countries = {"countries": countries}
            changed = True

    if login.device_id and profile.known_device_ids:
        devices = profile.known_device_ids.get("devices", [])
        if login.device_id not in devices:
            devices.append(login.device_id)
            profile.known_device_ids = {"devices": devices}
            changed = True

    if login.asn and profile.known_asns:
        asns = profile.known_asns.get("asns", [])
        if login.asn not in asns:
            asns.append(login.asn)
            profile.known_asns = {"asns": asns}
            changed = True

    if changed:
        profile.sample_count += 1
        profile.last_updated = datetime.now(timezone.utc)
        await db.commit()
