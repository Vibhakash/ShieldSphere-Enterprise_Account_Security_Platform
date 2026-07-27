"""
Attack Simulator API + WebSocket live feed
"""
import asyncio
import json
from datetime import datetime, timezone
from typing import List, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, WebSocket, WebSocketDisconnect
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.core.config import settings
from app.core.deps import get_db, get_current_user
from app.core.security import decode_access_token
from app.db.models.user import User
from app.db.models.session import UserSession
from app.db.models.simulation import AttackSimulation, SimulationEvent
from app.db.models.threat import Alert, Threat
from app.db.models.security import IpBlocklist
from app.db.session import AsyncSessionLocal
from app.schemas.common import (
    SimulationAnswerRequest, SimulationAnswerResult,
    SimulationRequest, SimulationOut, SimulationEventOut,
    ReplayStage, SimulationReplayOut,
)
from app.services.sandbox_manager import run_simulation, get_event_queue

router = APIRouter(prefix="/simulator", tags=["Attack Simulator"])

VALID_SIM_TYPES = [
    "brute_force", "sqli", "xss", "port_scan",
    "vuln_scan", "phishing", "packet_capture", "social_engineering",
]


@router.post("/run", response_model=SimulationOut, status_code=201)
async def start_simulation(
    payload: SimulationRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Start an attack simulation. Returns immediately; use WebSocket for live feed."""
    if payload.sim_type not in VALID_SIM_TYPES:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid sim_type. Must be one of: {VALID_SIM_TYPES}",
        )

    if payload.sim_type == "phishing":
        params = payload.params or {}
        if not isinstance(params.get("urls"), list) or not params["urls"]:
            raise HTTPException(status_code=422, detail="phishing simulations require params.urls")
        if not isinstance(params.get("legitimate_domains"), list) or not params["legitimate_domains"]:
            raise HTTPException(status_code=422, detail="phishing simulations require params.legitimate_domains")
    required_params = {
        "brute_force": ("attacker_ip", "attempts"),
        "sqli": ("target_url", "payloads"), "xss": ("target_url", "payloads"),
        "port_scan": ("target",), "packet_capture": ("duration_seconds",),
    }
    missing = [key for key in required_params.get(payload.sim_type, ()) if key not in (payload.params or {})]
    if missing:
        raise HTTPException(status_code=422, detail=f"{payload.sim_type} requires params: {', '.join(missing)}")

    # Rate limit: max N simulations per hour per user
    from datetime import timedelta
    one_hour_ago = datetime.now(timezone.utc) - timedelta(hours=1)
    result = await db.execute(
        select(AttackSimulation).where(
            AttackSimulation.user_id == current_user.id,
            AttackSimulation.created_at >= one_hour_ago,
        )
    )
    recent = result.scalars().all()
    if len(recent) >= settings.MAX_SIMULATOR_RUNS_PER_HOUR:
        raise HTTPException(
            status_code=429,
            detail=f"Rate limit: max {settings.MAX_SIMULATOR_RUNS_PER_HOUR} simulations per hour",
        )

    sim = AttackSimulation(
        user_id=current_user.id,
        sim_type=payload.sim_type,
        target_url=payload.target_url,
        params=payload.params,
        status="queued",
    )
    db.add(sim)
    await db.commit()
    await db.refresh(sim)

    # Start immediately instead of relying only on the scheduler's next poll.
    # The worker atomically claims queued runs, so this is safe alongside the
    # scheduler and resilient to duplicate requests/restarts.
    from app.workers.auto_block import run_queued_simulation
    asyncio.create_task(run_queued_simulation(sim.id))

    return sim


@router.get("/runs", response_model=List[SimulationOut])
async def list_simulations(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(AttackSimulation)
        .where(AttackSimulation.user_id == current_user.id)
        .order_by(AttackSimulation.created_at.desc())
        .limit(20)
    )
    return result.scalars().all()


@router.delete("/runs")
async def clear_finished_simulations(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Clear completed/failed simulator records and their replay events.

    Active exercises are intentionally retained so an in-progress sandbox run
    cannot lose its evidence or cleanup state. Generated alerts and threats are
    also retained as account-security evidence.
    """
    result = await db.execute(
        select(AttackSimulation).where(
            AttackSimulation.user_id == current_user.id,
            AttackSimulation.status.notin_(["queued", "running"]),
        )
    )
    simulations = result.scalars().all()
    for simulation in simulations:
        await db.delete(simulation)
    await db.commit()
    return {"deleted": len(simulations)}


@router.get("/runs/{sim_id}", response_model=SimulationOut)
async def get_simulation(
    sim_id: UUID,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(AttackSimulation).where(
            AttackSimulation.id == sim_id,
            AttackSimulation.user_id == current_user.id,
        )
    )
    sim = result.scalar_one_or_none()
    if not sim:
        raise HTTPException(status_code=404, detail="Simulation not found")
    return sim


@router.delete("/runs/{sim_id}")
async def delete_simulation(
    sim_id: UUID,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Delete a finished simulation and its replay events.

    Threats and alerts are deliberately retained as account-security evidence;
    their simulation reference is set to null by the database foreign key.
    """
    result = await db.execute(
        select(AttackSimulation).where(
            AttackSimulation.id == sim_id,
            AttackSimulation.user_id == current_user.id,
        )
    )
    simulation = result.scalar_one_or_none()
    if not simulation:
        raise HTTPException(status_code=404, detail="Simulation not found")
    if simulation.status in {"queued", "running"}:
        raise HTTPException(status_code=409, detail="A queued or running simulation cannot be deleted")
    await db.delete(simulation)
    await db.commit()
    return {"message": "Simulation run deleted"}


@router.get("/runs/{sim_id}/events", response_model=List[SimulationEventOut])
async def get_simulation_events(
    sim_id: UUID,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    # Verify ownership
    result = await db.execute(
        select(AttackSimulation).where(
            AttackSimulation.id == sim_id,
            AttackSimulation.user_id == current_user.id,
        )
    )
    if not result.scalar_one_or_none():
        raise HTTPException(status_code=404, detail="Simulation not found")

    result = await db.execute(
        select(SimulationEvent)
        .where(SimulationEvent.simulation_id == sim_id)
        .order_by(SimulationEvent.timestamp.asc())
    )
    return result.scalars().all()


@router.get("/runs/{sim_id}/replay", response_model=SimulationReplayOut)
async def get_simulation_replay(
    sim_id: UUID,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(AttackSimulation).where(
            AttackSimulation.id == sim_id,
            AttackSimulation.user_id == current_user.id,
        )
    )
    simulation = result.scalar_one_or_none()
    if not simulation:
        raise HTTPException(status_code=404, detail="Simulation not found")
    events_result = await db.execute(
        select(SimulationEvent)
        .where(SimulationEvent.simulation_id == sim_id)
        .order_by(SimulationEvent.timestamp.asc())
    )
    events = events_result.scalars().all()
    threats_result = await db.execute(
        select(Threat).where(Threat.simulation_id == sim_id).order_by(Threat.detected_at.asc())
    )
    threats = threats_result.scalars().all()
    threat_ids = [item.id for item in threats]
    alerts_result = await db.execute(select(Alert).where(Alert.threat_id.in_(threat_ids))) if threat_ids else None
    alerts = alerts_result.scalars().all() if alerts_result else []
    source_ips = {item.source_ip for item in threats if item.source_ip}
    blocks_result = await db.execute(
        select(IpBlocklist).where(
            IpBlocklist.ip_address.in_(source_ips),
            IpBlocklist.is_active == True,  # noqa
            IpBlocklist.user_id == current_user.id,
        )
    ) if source_ips else None
    blocks = blocks_result.scalars().all() if blocks_result else []

    phase_map = {
        "network_created": "prepare", "starting_target": "prepare", "target_ready": "prepare",
        "start": "attack", "login_attempt": "attack", "sqli_payload": "attack",
        "xss_payload": "attack", "scanning": "attack", "port_found": "attack",
        "port_scan": "attack", "vuln_scan": "attack", "header_check": "attack",
        "packet_captured": "attack", "packet_capture_complete": "attack",
        "phishing_prompt": "attack", "scenario_generated": "attack",
        "threat_triggered": "detect", "detection_recorded": "detect", "warning": "detect",
        "ai_analysis": "analyze", "result": "analyze",
        "cleanup": "contain", "complete": "verify", "error": "verify",
    }
    title_map = {
        "prepare": "Sandbox prepared", "attack": "Attack activity generated",
        "detect": "Defensive control triggered", "analyze": "Evidence analyzed",
        "contain": "Environment contained", "verify": "Outcome verified",
    }
    timeline = [
        ReplayStage(
            phase=phase_map.get(event.event_type, "observe"),
            title=title_map.get(phase_map.get(event.event_type, "observe"), "Security event observed"),
            description=event.payload or event.event_type.replace("_", " ").title(),
            status="failed" if event.event_type == "error" else "completed",
            severity=event.severity,
            timestamp=event.timestamp,
            evidence={"event_type": event.event_type, **(event.details or {})},
        )
        for event in events
    ]
    for threat in threats:
        timeline.append(ReplayStage(
            phase="detect", title=threat.title, description=threat.description or "Threat detected",
            status="completed", severity=threat.severity, timestamp=threat.detected_at,
            evidence={"threat_id": str(threat.id), "threat_type": threat.threat_type},
        ))
    for block in blocks:
        timeline.append(ReplayStage(
            phase="contain", title="Source IP blocked",
            description=f"{block.ip_address} was added to the active blocklist.",
            status="completed", severity="high", timestamp=block.blocked_at,
            evidence={"ip_address": block.ip_address, "auto_blocked": block.auto_blocked},
        ))
    timeline.sort(key=lambda item: item.timestamp or simulation.created_at)
    start = simulation.started_at or simulation.created_at
    first_detection = threats[0].detected_at if threats else None
    end = simulation.ended_at
    attack_types = {
        "start", "login_attempt", "sqli_payload", "xss_payload", "scanning", "port_found",
        "port_scan", "vuln_scan", "header_check", "packet_captured", "packet_capture_complete",
        "phishing_prompt", "scenario_generated",
    }
    if simulation.status == "failed":
        outcome = "The sandbox run failed before the full defensive workflow completed."
    elif threats:
        outcome = f"ShieldSphere detected {len(threats)} threat(s), generated {len(alerts)} alert(s), and blocked {len(blocks)} source IP(s)."
    elif simulation.status == "completed":
        outcome = "The simulation completed, but no account-threat rule was expected or triggered for this scenario."
    else:
        outcome = "The simulation is still running; the replay will update as evidence arrives."
    return SimulationReplayOut(
        simulation_id=simulation.id,
        sim_type=simulation.sim_type,
        status=simulation.status,
        outcome=outcome,
        attack_events=sum(event.event_type in attack_types for event in events),
        threats_detected=len(threats),
        alerts_generated=len(alerts),
        source_ips_blocked=len(blocks),
        time_to_detect_ms=round((first_detection - start).total_seconds() * 1000) if first_detection else None,
        duration_ms=round((end - start).total_seconds() * 1000) if end else None,
        timeline=timeline,
    )


def _score_social_engineering_answer(raw_output: dict, answers: dict[str, str]) -> tuple[int, int, list[dict]]:
    scenario = raw_output.get("scenario") or {}
    options = scenario.get("options") or []
    choice = answers.get("choice")
    if not choice or not options:
        raise ValueError("Submit the selected social-engineering option as answers.choice")
    selected = next((option for option in options if str(option.get("id", "")).lower() == choice), None)
    if selected is None:
        raise ValueError("The submitted choice is not part of this scenario")
    correct = bool(selected.get("is_correct"))
    return int(correct), 1, [{
        "choice": selected.get("id"),
        "correct": correct,
        "explanation": selected.get("explanation", ""),
    }]


def _score_phishing_answers(raw_output: dict, answers: dict[str, str]) -> tuple[int, int, list[dict]]:
    items = raw_output.get("challenge_items") or []
    if not items:
        raise ValueError("This phishing challenge is not ready for answers")
    feedback = []
    correct = 0
    for item in items:
        challenge_id = item.get("id")
        submitted = answers.get(challenge_id)
        if submitted not in {"phishing", "legitimate"}:
            raise ValueError(f"answers.{challenge_id} must be 'phishing' or 'legitimate'")
        is_correct = submitted == item.get("expected")
        correct += int(is_correct)
        feedback.append({
            "challenge_id": challenge_id,
            "correct": is_correct,
            "expected": item.get("expected"),
            "domain": item.get("domain"),
            "distance": item.get("levenshtein_distance"),
        })
    return correct, len(items), feedback


@router.post("/runs/{sim_id}/answers", response_model=SimulationAnswerResult)
async def submit_simulation_answers(
    sim_id: UUID,
    payload: SimulationAnswerRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Score user choices against challenge data generated and persisted for this run."""
    result = await db.execute(
        select(AttackSimulation).where(
            AttackSimulation.id == sim_id,
            AttackSimulation.user_id == current_user.id,
        )
    )
    simulation = result.scalar_one_or_none()
    if not simulation:
        raise HTTPException(status_code=404, detail="Simulation not found")
    raw_output = simulation.raw_output or {}

    try:
        if simulation.sim_type == "social_engineering":
            correct, total, feedback = _score_social_engineering_answer(raw_output, payload.answers)
        elif simulation.sim_type == "phishing":
            correct, total, feedback = _score_phishing_answers(raw_output, payload.answers)
        else:
            raise HTTPException(status_code=409, detail="This simulation does not accept answer submissions")
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    submitted_at = datetime.now(timezone.utc)
    score = round((correct / total) * 100, 2)
    responses = list(raw_output.get("responses") or [])
    responses.append({
        "answers": payload.answers,
        "score": score,
        "correct": correct,
        "total": total,
        "submitted_at": submitted_at.isoformat(),
    })
    raw_output["responses"] = responses
    simulation.raw_output = raw_output
    await db.commit()

    return SimulationAnswerResult(
        simulation_id=simulation.id,
        sim_type=simulation.sim_type,
        score=score,
        correct=correct,
        total=total,
        feedback=feedback,
        submitted_at=submitted_at,
    )


@router.get("/types")
async def get_simulation_types():
    """Return available simulation types with descriptions."""
    return [
        {"type": "brute_force", "label": "Brute Force Attack", "description": "Simulates rapid failed login attempts to trigger detection"},
        {"type": "sqli", "label": "SQL Injection Demo", "description": "Real SQLi payloads against a vulnerable target"},
        {"type": "xss", "label": "XSS Demonstration", "description": "Real XSS payloads tested for reflection"},
        {"type": "port_scan", "label": "Open Port Discovery", "description": "Real nmap scan with AI hardening advice"},
        {"type": "vuln_scan", "label": "Website Vulnerability Scanner", "description": "Real security header analysis against a URL"},
        {"type": "phishing", "label": "Phishing Detection", "description": "Levenshtein distance-based domain similarity analysis"},
        {"type": "packet_capture", "label": "Network Packet Analyzer", "description": "Traffic analysis with AI explanation"},
        {"type": "social_engineering", "label": "Social Engineering Awareness", "description": "AI-generated unique scenario per session"},
    ]


@router.websocket("/ws/{sim_id}")
async def simulation_websocket(
    websocket: WebSocket,
    sim_id: str,
):
    """WebSocket endpoint for live simulation event feed."""
    await websocket.accept()

    # Browser WebSocket clients cannot reliably set Authorization headers, so
    # accept the HTTP-only access cookie with a query-token fallback.
    token = websocket.cookies.get("access_token") or websocket.query_params.get("token")
    if not token:
        await websocket.close(code=4001, reason="Missing token")
        return

    payload = decode_access_token(token)
    user_id = payload.get("sub") if payload else None
    session_id = payload.get("session_id") if payload else None
    if not payload or not user_id or not session_id or payload.get("2fa_pending"):
        await websocket.close(code=4003, reason="Invalid token")
        return

    try:
        simulation_id = UUID(sim_id)
    except ValueError:
        await websocket.close(code=4004, reason="Simulation not found")
        return

    async with AsyncSessionLocal() as db:
        session_result = await db.execute(
            select(UserSession).where(
                UserSession.id == session_id,
                UserSession.user_id == user_id,
                UserSession.is_active == True,  # noqa
            )
        )
        user_session = session_result.scalar_one_or_none()
        if not user_session or (
            user_session.expires_at is not None
            and user_session.expires_at <= datetime.now(timezone.utc)
        ):
            await websocket.close(code=4003, reason="Session expired or revoked")
            return

        simulation_result = await db.execute(
            select(AttackSimulation).where(
                AttackSimulation.id == simulation_id,
                AttackSimulation.user_id == user_id,
            )
        )
        simulation = simulation_result.scalar_one_or_none()
        if simulation is None:
            await websocket.close(code=4004, reason="Simulation not found")
            return

        if simulation.status in {"completed", "failed", "cancelled"}:
            await websocket.send_text(json.dumps({
                "type": "complete" if simulation.status == "completed" else "error",
                "status": simulation.status,
                "message": simulation.error_message or "Simulation already finished",
            }))
            await websocket.close()
            return

    queue = get_event_queue(str(simulation_id))
    try:
        while True:
            # Wait for next event with timeout
            try:
                event = await asyncio.wait_for(queue.get(), timeout=60.0)
            except asyncio.TimeoutError:
                # Send keepalive ping
                await websocket.send_text(json.dumps({"type": "ping"}))
                continue

            if event is None:
                # Simulation ended
                await websocket.send_text(json.dumps({"type": "complete", "message": "Simulation finished"}))
                break

            await websocket.send_text(json.dumps(event, default=str))

    except WebSocketDisconnect:
        pass
    except Exception as e:
        try:
            await websocket.send_text(json.dumps({"type": "error", "message": str(e)}))
        except Exception:
            pass
