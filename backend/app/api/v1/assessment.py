"""
Security Assessment API: HIBP breach check, VirusTotal URL scan, IP reputation, vuln scanner, password strength.
"""
import asyncio
from datetime import datetime, timezone, timedelta
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.core.deps import get_db, get_current_user
from app.core.security import verify_password, async_verify_password
from app.db.models.user import User
from app.db.models.assessment import (
    PasswordBreachCheck, UrlScanResult, IpReputationCheck, VulnerabilityScan,
)
from app.services.breach_service import check_password_breach
from app.services.reputation_service import (
    submit_url_scan, get_url_scan_result, check_ip_reputation
)
from app.services.outbound_http import safe_public_get, validate_public_url, UnsafeOutboundTarget
from app.schemas.common import (
    BreachCheckRequest, BreachCheckResponse,
    UrlScanRequest, UrlScanOut,
    IpReputationRequest, IpReputationOut,
    VulnScanRequest, VulnScanOut,
    PasswordStrengthRequest, PasswordStrengthResponse,
)

router = APIRouter(prefix="/assessment", tags=["Security Assessment"])


@router.post("/password-strength", response_model=PasswordStrengthResponse)
async def check_password_strength(
    payload: PasswordStrengthRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Real entropy calculation via zxcvbn + HIBP breach check."""
    import zxcvbn as zx

    result = zx.zxcvbn(payload.password)

    # Concurrent HIBP check
    try:
        is_breached, breach_count = await check_password_breach(payload.password)
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc

    labels = ["Very Weak", "Weak", "Fair", "Strong", "Very Strong"]
    score = result["score"]

    # Crack time display
    crack_times = result.get("crack_times_display", {})
    crack_time = crack_times.get("offline_slow_hashing_1e4_per_second", "unknown")

    return PasswordStrengthResponse(
        score=score,
        strength_label=labels[score],
        crack_time_display=crack_time,
        suggestions=result.get("feedback", {}).get("suggestions", []),
        warning=result.get("feedback", {}).get("warning"),
        entropy_bits=round(result.get("guesses_log10", 0) * 3.32, 2),
        is_breached=is_breached,
        breach_count=breach_count,
    )


@router.post("/breach-check", response_model=BreachCheckResponse)
async def breach_check(
    payload: BreachCheckRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Check password against HIBP Pwned Passwords (k-anonymity)."""
    try:
        is_breached, breach_count = await check_password_breach(payload.password)
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc

    import hashlib
    sha1 = hashlib.sha1(payload.password.encode()).hexdigest().upper()
    prefix = sha1[:5]

    # Persist result
    check = PasswordBreachCheck(
        user_id=current_user.id,
        sha1_prefix=prefix,
        breach_count=breach_count,
        is_breached=is_breached,
    )
    db.add(check)

    is_current_password = await async_verify_password(payload.password, current_user.hashed_password)
    if is_current_password:
        current_user.password_breached = is_breached
        current_user.password_breach_count = breach_count

    await db.commit()

    if is_current_password:
        from app.services.security_score import recalculate_security_score
        await recalculate_security_score(db, current_user)

    if is_breached:
        msg = f"⚠️ This password has appeared in {breach_count:,} data breaches. Change it immediately."
    else:
        msg = "✅ Password not found in known data breaches."

    if is_current_password:
        msg += " Your account password status in Settings has been updated with this result."
    else:
        msg += " This was a standalone test; your account password status in Settings was not changed."

    return BreachCheckResponse(
        is_breached=is_breached,
        breach_count=breach_count,
        message=msg,
        is_current_password=is_current_password,
        account_status_updated=is_current_password,
    )


@router.post("/url-scan", response_model=UrlScanOut)
async def scan_url(
    payload: UrlScanRequest,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Submit URL to VirusTotal for scanning."""
    try:
        safe_url = await validate_public_url(payload.url)
    except UnsafeOutboundTarget as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    analysis_id = await submit_url_scan(safe_url)

    scan = UrlScanResult(
        user_id=current_user.id,
        url=safe_url,
        virustotal_analysis_id=analysis_id,
        status="pending" if analysis_id else "error",
    )
    db.add(scan)
    await db.commit()
    await db.refresh(scan)

    if analysis_id:
        background_tasks.add_task(_poll_url_scan, scan_id=scan.id)

    return scan


async def _poll_url_scan(scan_id: UUID, max_attempts: int = 10):
    """Background: poll VirusTotal until result is ready."""
    from app.db.session import AsyncSessionLocal
    async with AsyncSessionLocal() as db:
        result = await db.execute(select(UrlScanResult).where(UrlScanResult.id == scan_id))
        scan = result.scalar_one_or_none()
        if not scan:
            return

        for attempt in range(max_attempts):
            await asyncio.sleep(15)  # VirusTotal typically ready in 15-60s
            data = await get_url_scan_result(scan.virustotal_analysis_id)
            if data and data.get("status") == "completed":
                scan.status = "done"
                scan.malicious_count = data.get("malicious", 0)
                scan.suspicious_count = data.get("suspicious", 0)
                scan.harmless_count = data.get("harmless", 0)
                scan.undetected_count = data.get("undetected", 0)
                scan.verdict = data.get("verdict", "unknown")
                scan.raw_results = data.get("raw", {})
                scan.completed_at = datetime.now(timezone.utc)
                await db.commit()
                return
        # Timeout
        scan.status = "timeout"
        await db.commit()


@router.get("/url-scan/{scan_id}", response_model=UrlScanOut)
async def get_url_scan(
    scan_id: UUID,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(UrlScanResult).where(
            UrlScanResult.id == scan_id,
            UrlScanResult.user_id == current_user.id,
        )
    )
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan


@router.get("/url-scans", response_model=list[UrlScanOut])
async def list_url_scans(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(UrlScanResult)
        .where(UrlScanResult.user_id == current_user.id)
        .order_by(UrlScanResult.submitted_at.desc())
        .limit(20)
    )
    return result.scalars().all()


@router.post("/ip-reputation", response_model=IpReputationOut)
async def ip_reputation(
    payload: IpReputationRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Real-time IP reputation lookup via VirusTotal + AbuseIPDB."""
    result = await check_ip_reputation(payload.ip)
    vt = result.get("virustotal") or {}
    abuse = result.get("abuseipdb") or {}
    check = IpReputationCheck(
        user_id=current_user.id,
        ip_address=payload.ip,
        overall_verdict=result["overall_verdict"],
        virustotal_malicious=vt.get("malicious"),
        virustotal_suspicious=vt.get("suspicious"),
        abuse_confidence_score=abuse.get("abuse_confidence_score"),
        abuse_total_reports=abuse.get("total_reports"),
        raw_results=result,
    )
    db.add(check)
    await db.commit()
    await db.refresh(check)
    return check


@router.get("/ip-reputation", response_model=list[IpReputationOut])
async def list_ip_reputation_checks(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(IpReputationCheck)
        .where(IpReputationCheck.user_id == current_user.id)
        .order_by(IpReputationCheck.checked_at.desc())
        .limit(50)
    )
    return result.scalars().all()


@router.post("/vuln-scan", response_model=VulnScanOut)
async def vuln_scan(
    payload: VulnScanRequest,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Run real vulnerability checks against a URL."""
    try:
        safe_url = await validate_public_url(payload.target_url)
    except UnsafeOutboundTarget as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    scan = VulnerabilityScan(
        user_id=current_user.id,
        target_url=safe_url,
        status="running",
    )
    db.add(scan)
    await db.commit()
    await db.refresh(scan)

    background_tasks.add_task(_run_vuln_scan, scan_id=scan.id, url=safe_url)
    return scan


async def _run_vuln_scan(scan_id: UUID, url: str):
    """Background: execute real security header checks."""
    import httpx
    from app.db.session import AsyncSessionLocal
    from app.services.llm_service import generate_port_scan_advice

    async with AsyncSessionLocal() as db:
        result = await db.execute(select(VulnerabilityScan).where(VulnerabilityScan.id == scan_id))
        scan = result.scalar_one_or_none()
        if not scan:
            return

        try:
            async with httpx.AsyncClient(timeout=15.0, follow_redirects=False) as client:
                resp = await safe_public_get(url, client=client)
                headers = resp.headers

                scan.has_https = url.startswith("https://")
                scan.has_hsts = "strict-transport-security" in headers
                scan.has_csp = "content-security-policy" in headers
                scan.has_x_frame_options = "x-frame-options" in headers
                scan.has_x_content_type = "x-content-type-options" in headers
                scan.has_secure_cookies = "set-cookie" in headers and "secure" in headers.get("set-cookie", "").lower()

                missing = sum([
                    not scan.has_https, not scan.has_hsts, not scan.has_csp,
                    not scan.has_x_frame_options, not scan.has_x_content_type,
                ])
                scan.risk_score = min(100, missing * 20)

                findings = {
                    "https": scan.has_https,
                    "hsts": scan.has_hsts,
                    "csp": scan.has_csp,
                    "x_frame_options": scan.has_x_frame_options,
                    "x_content_type": scan.has_x_content_type,
                    "missing_headers": missing,
                    "server": headers.get("server", "not disclosed"),
                }
                scan.findings = findings

                # AI advice
                advice = await generate_port_scan_advice(
                    [{"header": k, "present": v} for k, v in findings.items()],
                    os_info=f"Web app at {url}"
                )
                scan.llm_advice = advice
                scan.status = "completed"

        except Exception as e:
            scan.status = "error"
            scan.findings = {"error": str(e)}

        await db.commit()


@router.get("/vuln-scans", response_model=list[VulnScanOut])
async def list_vuln_scans(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(VulnerabilityScan)
        .where(VulnerabilityScan.user_id == current_user.id)
        .order_by(VulnerabilityScan.scanned_at.desc())
        .limit(20)
    )
    return result.scalars().all()
