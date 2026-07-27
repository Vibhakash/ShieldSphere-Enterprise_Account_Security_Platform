"""
Dashboard API: real aggregation queries, security score, activity timeline.
"""
from datetime import datetime, timedelta, timezone
from typing import List

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, and_, or_

from app.core.deps import get_db, get_current_user
from app.db.models.user import User
from app.db.models.login_history import LoginHistory
from app.db.models.threat import Threat, Alert
from app.db.models.session import UserSession
from app.db.models.device import Device
from app.db.models.security import IpBlocklist
from app.schemas.common import DashboardStats, SecurityScoreBreakdown, LoginHistoryOut, LoginLocationOut
from app.services.security_score import recalculate_security_score

router = APIRouter(prefix="/dashboard", tags=["Dashboard"])


async def compute_security_score(db: AsyncSession, user: User) -> SecurityScoreBreakdown:
    """Compute real security score from actual DB state."""
    record = await recalculate_security_score(db, user)
    return SecurityScoreBreakdown(
        score=record.score,
        factors=record.factors,
        computed_at=record.computed_at,
    )


@router.get("/stats", response_model=DashboardStats)
async def get_dashboard_stats(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    today = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)

    # Login stats today
    result = await db.execute(
        select(func.count(LoginHistory.id)).where(
            LoginHistory.user_id == current_user.id,
            LoginHistory.timestamp >= today,
            LoginHistory.is_simulation == False,  # noqa
        )
    )
    total_logins_today = result.scalar_one() or 0

    result = await db.execute(
        select(func.count(LoginHistory.id)).where(
            LoginHistory.user_id == current_user.id,
            LoginHistory.timestamp >= today,
            LoginHistory.success == True,  # noqa
            LoginHistory.is_simulation == False,  # noqa
        )
    )
    successful_logins_today = result.scalar_one() or 0
    failed_logins_today = total_logins_today - successful_logins_today

    # Sandbox activity is displayed separately so rehearsals do not change real-account metrics.
    result = await db.execute(
        select(func.count(LoginHistory.id)).where(
            LoginHistory.user_id == current_user.id,
            LoginHistory.timestamp >= today,
            LoginHistory.is_simulation == True,  # noqa
        )
    )
    simulation_login_attempts = result.scalar_one() or 0

    # Active sessions
    result = await db.execute(
        select(func.count(UserSession.id)).where(
            UserSession.user_id == current_user.id,
            UserSession.is_active == True,  # noqa
        )
    )
    active_sessions = result.scalar_one() or 0

    # Unresolved threats
    result = await db.execute(
        select(func.count(Threat.id)).where(
            Threat.user_id == current_user.id,
            Threat.is_resolved == False,  # noqa
            Threat.is_simulation == False,  # noqa
        )
    )
    unresolved_threats = result.scalar_one() or 0

    result = await db.execute(
        select(func.count(Threat.id)).where(
            Threat.user_id == current_user.id,
            Threat.is_resolved == False,  # noqa
            Threat.is_simulation == True,  # noqa
        )
    )
    simulation_threats = result.scalar_one() or 0

    # Unread alerts
    result = await db.execute(
        select(func.count(Alert.id)).where(
            Alert.user_id == current_user.id,
            Alert.is_read == False,  # noqa
        )
    )
    unread_alerts = result.scalar_one() or 0

    result = await db.execute(
        select(func.count(Alert.id))
        .join(Threat, Alert.threat_id == Threat.id)
        .where(
            Alert.user_id == current_user.id,
            Alert.is_read == False,  # noqa
            Threat.is_simulation == True,  # noqa
        )
    )
    simulation_alerts = result.scalar_one() or 0

    # Security score (compute fresh)
    score_breakdown = await compute_security_score(db, current_user)

    # Blocked IPs
    now = datetime.now(timezone.utc)
    result = await db.execute(
        select(func.count(IpBlocklist.id)).where(
            IpBlocklist.is_active == True,  # noqa
            or_(IpBlocklist.expires_at.is_(None), IpBlocklist.expires_at > now),
            or_(
                IpBlocklist.user_id == current_user.id,
                IpBlocklist.user_id.is_(None),
            ),
        )
    )
    blocked_ips = result.scalar_one() or 0

    # Device count
    result = await db.execute(
        select(func.count(Device.id)).where(Device.user_id == current_user.id)
    )
    devices_count = result.scalar_one() or 0

    # Login success rate (last 30 days)
    thirty_ago = datetime.now(timezone.utc) - timedelta(days=30)
    result = await db.execute(
        select(func.count(LoginHistory.id)).where(
            LoginHistory.user_id == current_user.id,
            LoginHistory.timestamp >= thirty_ago,
            LoginHistory.is_simulation == False,  # noqa
        )
    )
    total_30d = result.scalar_one() or 0

    result = await db.execute(
        select(func.count(LoginHistory.id)).where(
            LoginHistory.user_id == current_user.id,
            LoginHistory.timestamp >= thirty_ago,
            LoginHistory.success == True,  # noqa
            LoginHistory.is_simulation == False,  # noqa
        )
    )
    success_30d = result.scalar_one() or 0
    success_rate = round((success_30d / total_30d * 100), 1) if total_30d > 0 else 100.0

    return DashboardStats(
        total_logins_today=total_logins_today,
        successful_logins_today=successful_logins_today,
        failed_logins_today=failed_logins_today,
        active_sessions=active_sessions,
        unresolved_threats=unresolved_threats,
        unread_alerts=unread_alerts,
        security_score=score_breakdown.score,
        blocked_ips=blocked_ips,
        login_success_rate=success_rate,
        devices_count=devices_count,
        last_login=current_user.last_login_at,
        simulation_threats=simulation_threats,
        simulation_alerts=simulation_alerts,
        simulation_login_attempts=simulation_login_attempts,
    )


@router.get("/security-score", response_model=SecurityScoreBreakdown)
async def get_security_score(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    return await compute_security_score(db, current_user)


@router.get("/login-history", response_model=List[LoginHistoryOut])
async def get_login_history(
    page: int = 1,
    per_page: int = 20,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(LoginHistory)
        .where(LoginHistory.user_id == current_user.id)
        .order_by(LoginHistory.timestamp.desc())
        .offset((page - 1) * per_page)
        .limit(per_page)
    )
    return result.scalars().all()


@router.get("/login-locations", response_model=List[LoginLocationOut])
async def get_login_locations(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Return unique login locations for the map, with count per location."""
    thirty_days_ago = datetime.now(timezone.utc) - timedelta(days=90)
    result = await db.execute(
        select(
            LoginHistory.latitude,
            LoginHistory.longitude,
            LoginHistory.country,
            LoginHistory.city,
            func.count(LoginHistory.id).label("count"),
            func.max(LoginHistory.timestamp).label("last_seen"),
        )
        .where(
            LoginHistory.user_id == current_user.id,
            LoginHistory.latitude.isnot(None),
            LoginHistory.longitude.isnot(None),
            LoginHistory.timestamp >= thirty_days_ago,
        )
        .group_by(
            LoginHistory.latitude,
            LoginHistory.longitude,
            LoginHistory.country,
            LoginHistory.city,
        )
        .order_by(func.max(LoginHistory.timestamp).desc())
        .limit(100)
    )
    rows = result.all()
    return [
        LoginLocationOut(
            latitude=row.latitude,
            longitude=row.longitude,
            country=row.country,
            city=row.city,
            count=row.count,
            last_seen=row.last_seen,
        )
        for row in rows
    ]


@router.get("/activity-timeline")
async def get_activity_timeline(
    days: int = 30,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Daily login success/failure counts for timeline chart."""
    since = datetime.now(timezone.utc) - timedelta(days=days)
    result = await db.execute(
        select(
            func.date_trunc("day", LoginHistory.timestamp).label("day"),
            func.count(LoginHistory.id).label("total"),
            func.sum(func.cast(LoginHistory.success, type_=__import__("sqlalchemy").Integer)).label("successes"),
        )
        .where(
            LoginHistory.user_id == current_user.id,
            LoginHistory.timestamp >= since,
            LoginHistory.is_simulation == False,  # noqa
        )
        .group_by("day")
        .order_by("day")
    )
    rows = result.all()
    return [
        {
            "date": row.day.date().isoformat(),
            "total": row.total,
            "successes": int(row.successes or 0),
            "failures": row.total - int(row.successes or 0),
        }
        for row in rows
    ]
