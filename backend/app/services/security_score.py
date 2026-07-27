"""Security-score calculation over current persisted account state."""
from datetime import datetime, timedelta, timezone

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models.device import Device
from app.db.models.security import SecurityScore
from app.db.models.session import UserSession
from app.db.models.threat import Threat
from app.db.models.user import User


async def recalculate_security_score(db: AsyncSession, user: User) -> SecurityScore:
    """Calculate and persist an explainable score using current database state."""
    factors = {
        "base_score": {
            "points": 50,
            "description": "Every account starts with 50 points before protections and risks are applied.",
        }
    }
    score = 50

    if user.totp_enabled:
        points = 25
        score += points
        factors["2fa_enabled"] = {
            "value": True,
            "points": points,
            "description": "Two-factor authentication is enabled.",
        }
    else:
        factors["2fa_enabled"] = {
            "value": False,
            "points": 0,
            "available_points": 25,
            "description": "Enable two-factor authentication to add 25 points.",
        }

    if not user.password_breached:
        points = 15
        score += points
        factors["password_safe"] = {
            "value": True,
            "points": points,
            "description": "The current account password was not found in known breach data when last checked.",
        }
    else:
        penalty = 20
        score -= penalty
        factors["password_breached"] = {
            "value": True,
            "penalty": -penalty,
            "count": user.password_breach_count,
            "description": "The current account password was found in known breach data.",
        }

    thirty_days_ago = datetime.now(timezone.utc) - timedelta(days=30)
    result = await db.execute(
        select(func.count(Threat.id)).where(
            Threat.user_id == user.id,
            Threat.is_resolved == False,  # noqa
            Threat.severity.in_(["high", "critical"]),
            Threat.detected_at >= thirty_days_ago,
            Threat.is_simulation == False,  # noqa
        )
    )
    unresolved_threats = result.scalar_one() or 0
    threat_penalty = min(30, unresolved_threats * 10)
    score -= threat_penalty
    factors["unresolved_threats"] = {
        "count": unresolved_threats,
        "penalty": -threat_penalty,
        "description": "Each unresolved high or critical threat from the last 30 days removes 10 points, up to 30.",
    }

    result = await db.execute(
        select(func.count(Device.id)).where(
            Device.user_id == user.id,
            Device.is_trusted == True,  # noqa
        )
    )
    trusted_devices = result.scalar_one() or 0
    if trusted_devices > 0:
        score += 5
    factors["trusted_devices"] = {
        "count": trusted_devices,
        "points": 5 if trusted_devices else 0,
        "description": "Having at least one trusted device adds 5 points.",
    }

    result = await db.execute(
        select(func.count(UserSession.id)).where(
            UserSession.user_id == user.id,
            UserSession.is_active == True,  # noqa
        )
    )
    active_sessions = result.scalar_one() or 0
    session_penalty = min(15, max(0, active_sessions - 5) * 3)
    score -= session_penalty
    factors["active_sessions"] = {
        "count": active_sessions,
        "penalty": -session_penalty,
        "description": "The first five active sessions have no penalty; each additional session removes 3 points, up to 15.",
    }

    score = max(0, min(100, score))
    factors["final_score"] = score
    record = SecurityScore(user_id=user.id, score=score, factors=factors)
    db.add(record)
    await db.commit()
    await db.refresh(record)
    return record
