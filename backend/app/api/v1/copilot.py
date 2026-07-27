"""
AI Security Copilot API — streaming chat powered by Groq with real user context.
"""
import json
from datetime import datetime, timedelta, timezone
from fastapi import APIRouter, Depends
from fastapi.responses import StreamingResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func

from app.core.deps import get_db, get_current_user
from app.db.models.user import User
from app.db.models.threat import Threat, Alert
from app.db.models.session import UserSession
from app.db.models.device import Device
from app.db.models.login_history import LoginHistory
from app.db.models.security import SecurityScore, IpBlocklist
from app.db.models.assessment import VulnerabilityScan
from app.db.models.simulation import AttackSimulation
from app.schemas.common import CopilotRequest
from app.services.llm_service import copilot_chat

router = APIRouter(prefix="/copilot", tags=["AI Security Copilot"])


async def _build_user_context(db: AsyncSession, user: User) -> dict:
    """Build real context from DB to inject into Groq prompt."""
    seven_days_ago = datetime.now(timezone.utc) - timedelta(days=7)

    # Recent threats
    result = await db.execute(
        select(Threat)
        .where(
            Threat.user_id == user.id,
            Threat.detected_at >= seven_days_ago,
        )
        .order_by(Threat.detected_at.desc())
        .limit(5)
    )
    recent_threats = result.scalars().all()
    threats_summary = ", ".join([f"{'sandbox ' if t.is_simulation else ''}{t.threat_type} ({t.severity})" for t in recent_threats]) or "none"

    # Recent alerts
    result = await db.execute(
        select(Alert)
        .where(Alert.user_id == user.id, Alert.is_read == False)  # noqa
        .order_by(Alert.created_at.desc())
        .limit(3)
    )
    recent_alerts = result.scalars().all()
    alerts_summary = "; ".join([a.title for a in recent_alerts]) or "none"

    # Active sessions
    result = await db.execute(
        select(func.count(UserSession.id)).where(
            UserSession.user_id == user.id,
            UserSession.is_active == True,  # noqa
        )
    )
    active_sessions = result.scalar_one() or 0

    # Device count
    result = await db.execute(
        select(func.count(Device.id)).where(Device.user_id == user.id)
    )
    known_devices = result.scalar_one() or 0

    # Latest security score
    result = await db.execute(
        select(SecurityScore)
        .where(SecurityScore.user_id == user.id)
        .order_by(SecurityScore.computed_at.desc())
        .limit(1)
    )
    score = result.scalar_one_or_none()

    # Recent unique locations
    result = await db.execute(
        select(LoginHistory.country, LoginHistory.city)
        .where(
            LoginHistory.user_id == user.id,
            LoginHistory.success == True,  # noqa
            LoginHistory.timestamp >= seven_days_ago,
            LoginHistory.country.isnot(None),
        )
        .distinct()
        .limit(5)
    )
    locations = [f"{r.city or ''}, {r.country}".strip(", ") for r in result.all()]

    # Recent website vulnerability scans. These keep website questions separate
    # from the account-security score and give the model real scan evidence.
    result = await db.execute(
        select(VulnerabilityScan)
        .where(VulnerabilityScan.user_id == user.id)
        .order_by(VulnerabilityScan.scanned_at.desc())
        .limit(3)
    )
    vulnerability_scans = [
        {
            "target_url": scan.target_url,
            "status": scan.status,
            "risk_score": scan.risk_score,
            "findings": scan.findings or {},
            "scanned_at": scan.scanned_at.isoformat(),
        }
        for scan in result.scalars().all()
    ]

    # Full seven-day account analytics, including clearly separated sandbox data.
    async def count(model, *criteria):
        result = await db.execute(select(func.count(model.id)).where(*criteria))
        return result.scalar_one() or 0

    total_logins = await count(LoginHistory, LoginHistory.user_id == user.id, LoginHistory.timestamp >= seven_days_ago, LoginHistory.is_simulation == False)  # noqa
    failed_logins = await count(LoginHistory, LoginHistory.user_id == user.id, LoginHistory.timestamp >= seven_days_ago, LoginHistory.success == False, LoginHistory.is_simulation == False)  # noqa
    total_threats = await count(Threat, Threat.user_id == user.id, Threat.detected_at >= seven_days_ago, Threat.is_simulation == False)  # noqa
    unresolved_threats = await count(Threat, Threat.user_id == user.id, Threat.is_resolved == False, Threat.is_simulation == False)  # noqa
    unread_alerts = await count(Alert, Alert.user_id == user.id, Alert.is_read == False)  # noqa
    simulations_run = await count(AttackSimulation, AttackSimulation.user_id == user.id, AttackSimulation.created_at >= seven_days_ago)
    simulation_threats = await count(Threat, Threat.user_id == user.id, Threat.detected_at >= seven_days_ago, Threat.is_simulation == True)  # noqa
    blocked_ips = await count(IpBlocklist, IpBlocklist.user_id == user.id, IpBlocklist.is_active == True)  # noqa

    recent_threat_records = [
        {"title": item.title, "type": item.threat_type, "severity": item.severity, "resolved": item.is_resolved, "simulation": item.is_simulation, "detected_at": item.detected_at.isoformat()}
        for item in recent_threats
    ]
    recent_alert_records = [
        {"title": item.title, "severity": item.severity, "read": item.is_read, "created_at": item.created_at.isoformat()}
        for item in recent_alerts
    ]

    return {
        "security_score": score.score if score else "not computed",
        "totp_enabled": user.totp_enabled,
        "active_sessions": active_sessions,
        "unresolved_threats": unresolved_threats,
        "recent_threats_summary": threats_summary,
        "recent_threat_records": recent_threat_records,
        "recent_alerts": alerts_summary,
        "recent_alert_records": recent_alert_records,
        "analytics_7d": {
            "real_login_attempts": total_logins,
            "failed_login_attempts": failed_logins,
            "real_threats": total_threats,
            "unresolved_real_threats": unresolved_threats,
            "unread_alerts": unread_alerts,
            "sandbox_exercises": simulations_run,
            "sandbox_threats": simulation_threats,
            "blocked_ips": blocked_ips,
        },
        "password_breached": user.password_breached,
        "known_devices": known_devices,
        "last_login": user.last_login_at.isoformat() if user.last_login_at else "unknown",
        "recent_locations": ", ".join(locations) or "unknown",
        "vulnerability_scans": vulnerability_scans,
    }


@router.post("/chat")
async def chat(
    payload: CopilotRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Streaming AI copilot chat with real user security context."""
    context = await _build_user_context(db, current_user)
    history = [{"role": m.role, "content": m.content} for m in payload.history]

    async def event_stream():
        async for chunk in copilot_chat(payload.message, context, history):
            # JSON encoding preserves leading spaces, newlines, and Markdown
            # boundaries in model tokens while keeping every SSE event one line.
            yield f"data: {json.dumps(chunk)}\n\n"
        yield "data: [DONE]\n\n"

    return StreamingResponse(event_stream(), media_type="text/event-stream")
