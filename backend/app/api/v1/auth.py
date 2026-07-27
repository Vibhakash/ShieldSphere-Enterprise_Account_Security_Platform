"""
Auth API: register, login, 2FA, refresh, logout, profile
"""
import hashlib
import hmac
import io
import base64
from datetime import datetime, timedelta, timezone
from typing import Optional
from uuid import UUID

import pyotp
import qrcode
from fastapi import APIRouter, Depends, HTTPException, Request, Response, status, BackgroundTasks
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.core.config import settings
from app.core.deps import get_db, get_current_user, get_client_ip
from app.core.rate_limit import limiter
from app.core.security import (
    async_hash_password, async_verify_password,
    create_access_token, create_refresh_token, decode_refresh_token,
    generate_device_id,
)
from app.db.models.user import User
from app.db.models.session import UserSession
from app.db.models.device import Device
from app.db.models.login_history import LoginHistory
from app.db.models.compliance import AuditLog
from app.db.models.security import IpBlocklist
from app.schemas.auth import (
    UserRegister, UserLogin, TokenResponse, TwoFactorVerify,
    TwoFactorSetupResponse, TwoFactorConfirm, RefreshRequest, ChangePassword, UserOut,
)
from app.services.breach_service import check_password_breach
from app.services.geoip_service import lookup_ip
import redis.asyncio as aioredis

router = APIRouter(prefix="/auth", tags=["Authentication"])


def _get_redis() -> aioredis.Redis:
    return aioredis.from_url(settings.REDIS_URL, decode_responses=True)


def _set_auth_cookies(
    response: Response,
    access_token: str,
    refresh_token: str,
) -> None:
    common = {
        "httponly": True,
        "secure": settings.COOKIE_SECURE,
        "samesite": "lax",
        "path": "/",
    }
    response.set_cookie(
        "access_token",
        access_token,
        max_age=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        **common,
    )
    response.set_cookie(
        "refresh_token",
        refresh_token,
        max_age=settings.REFRESH_TOKEN_EXPIRE_DAYS * 86400,
        **common,
    )


def _clear_auth_cookies(response: Response) -> None:
    response.delete_cookie(
        "access_token",
        path="/",
        secure=settings.COOKIE_SECURE,
        httponly=True,
        samesite="lax",
    )
    response.delete_cookie(
        "refresh_token",
        path="/",
        secure=settings.COOKIE_SECURE,
        httponly=True,
        samesite="lax",
    )


async def _log_audit(db: AsyncSession, user_id: Optional[UUID], action: str, request: Request, status: str = "success", details: dict = None):
    log = AuditLog(
        user_id=user_id,
        action=action,
        ip_address=get_client_ip(request),
        user_agent=request.headers.get("user-agent"),
        status=status,
        details=details or {},
    )
    db.add(log)
    await db.commit()


async def _record_login_and_detect(
    db: AsyncSession,
    redis_client: Optional[aioredis.Redis],
    user: User,
    request: Request,
    success: bool,
    failure_reason: Optional[str],
    device_id: Optional[str],
    background_tasks: BackgroundTasks,
) -> LoginHistory:
    """Record the login event, resolve GeoIP, and trigger threat detection."""
    ip = get_client_ip(request)
    ua = request.headers.get("user-agent", "")
    geo = lookup_ip(ip)

    lh = LoginHistory(
        user_id=user.id,
        ip_address=ip,
        user_agent=ua,
        device_id=device_id,
        success=success,
        failure_reason=failure_reason,
        country=geo.country,
        country_code=geo.country_code,
        city=geo.city,
        latitude=geo.latitude,
        longitude=geo.longitude,
        asn=geo.asn,
        isp=geo.isp,
    )
    db.add(lh)
    await db.flush()

    # Trigger threat detection in background
    background_tasks.add_task(
        _run_threat_detection_bg,
        user_id=user.id,
        login_event_id=lh.id,
        success=success,
    )

    return lh


async def _record_unknown_account_attempt(
    db: AsyncSession,
    redis_client: Optional[aioredis.Redis],
    email: str,
    request: Request,
) -> None:
    """Persist an unknown-account failure and enforce an IP sliding window."""
    ip = get_client_ip(request)
    geo = lookup_ip(ip)
    identifier_hash = hmac.new(
        settings.JWT_SECRET.encode("utf-8"),
        email.strip().lower().encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    attempt = LoginHistory(
        user_id=None,
        attempted_identifier_hash=identifier_hash,
        ip_address=ip,
        user_agent=request.headers.get("user-agent", ""),
        success=False,
        failure_reason="unknown_account",
        country=geo.country,
        country_code=geo.country_code,
        city=geo.city,
        latitude=geo.latitude,
        longitude=geo.longitude,
        asn=geo.asn,
        isp=geo.isp,
    )
    db.add(attempt)
    await db.flush()

    try:
        now = datetime.now(timezone.utc).timestamp()
        key = f"credential_stuffing:{ip}"
        window_start = now - settings.BRUTE_FORCE_WINDOW_SECONDS
        pipe = redis_client.pipeline()
        pipe.zremrangebyscore(key, 0, window_start)
        pipe.zadd(key, {str(attempt.id): now})
        pipe.zcard(key)
        pipe.expire(key, settings.BRUTE_FORCE_WINDOW_SECONDS)
        results = await pipe.execute()
        attempt_count = int(results[2])

        if attempt_count >= settings.BRUTE_FORCE_THRESHOLD:
            existing = await db.execute(
                select(IpBlocklist).where(
                    IpBlocklist.user_id.is_(None),
                    IpBlocklist.ip_address == ip,
                )
            )
            block = existing.scalar_one_or_none()
            expires_at = datetime.now(timezone.utc) + timedelta(hours=24)
            if block is None:
                block = IpBlocklist(
                    user_id=None,
                    ip_address=ip,
                    reason=f"Auto-blocked: {attempt_count} unknown-account attempts",
                    threat_type="credential_stuffing",
                    auto_blocked=True,
                    expires_at=expires_at,
                )
                db.add(block)
            else:
                block.reason = f"Auto-blocked: {attempt_count} unknown-account attempts"
                block.threat_type = "credential_stuffing"
                block.auto_blocked = True
                block.blocked_at = datetime.now(timezone.utc)
                block.expires_at = expires_at
                block.is_active = True
            await redis_client.set(f"blocked_ip:{ip}", "1", ex=86400)
    except Exception as redis_err:
        import logging as _logging
        _logging.getLogger(__name__).warning(f"Redis unavailable for credential stuffing tracking: {redis_err}")


async def _run_threat_detection_bg(user_id: UUID, login_event_id: UUID, success: bool):
    """Background task: run threat detection after login."""
    from app.db.session import AsyncSessionLocal
    from app.services.threat_detection import run_all_detectors
    async with AsyncSessionLocal() as db:
        try:
            redis_client = aioredis.from_url(settings.REDIS_URL, decode_responses=True)
            result = await db.execute(
                select(LoginHistory).where(LoginHistory.id == login_event_id)
            )
            login_event = result.scalar_one_or_none()
            if login_event:
                await run_all_detectors(
                    db=db,
                    redis_client=redis_client,
                    user_id=user_id,
                    login_event=login_event,
                    success=success,
                )
            # Update UBA baseline
            from app.services.uba_engine import update_baseline_incrementally
            if success and login_event:
                await update_baseline_incrementally(db, user_id, login_event)
            user_result = await db.execute(select(User).where(User.id == user_id))
            score_user = user_result.scalar_one_or_none()
            if score_user:
                from app.services.security_score import recalculate_security_score
                await recalculate_security_score(db, score_user)
        except Exception as e:
            import logging
            logging.getLogger(__name__).error(f"Threat detection bg error: {e}", exc_info=True)
        finally:
            await db.close()


async def _register_or_update_device(
    db: AsyncSession,
    user_id: UUID,
    device_id: str,
    ua: str,
    ip: str,
) -> Device:
    """Register new device or update last_seen."""
    result = await db.execute(
        select(Device).where(Device.user_id == user_id, Device.device_id == device_id)
    )
    device = result.scalar_one_or_none()

    if device is None:
        # Parse UA for browser/OS info
        browser, os_name, device_type = _parse_ua(ua)
        device = Device(
            user_id=user_id,
            device_id=device_id,
            fingerprint=device_id,
            user_agent=ua,
            browser=browser,
            os=os_name,
            device_type=device_type,
            last_seen=datetime.now(timezone.utc),
            last_ip=ip,
        )
        db.add(device)
    else:
        device.last_seen = datetime.now(timezone.utc)
        device.last_ip = ip

    return device


def _parse_ua(ua: str) -> tuple:
    """Simple UA parsing for browser/OS/device_type."""
    ua_lower = ua.lower()
    if "mobile" in ua_lower or "android" in ua_lower:
        device_type = "mobile"
    elif "tablet" in ua_lower or "ipad" in ua_lower:
        device_type = "tablet"
    else:
        device_type = "desktop"

    if "chrome" in ua_lower:
        browser = "Chrome"
    elif "firefox" in ua_lower:
        browser = "Firefox"
    elif "safari" in ua_lower:
        browser = "Safari"
    elif "edge" in ua_lower:
        browser = "Edge"
    else:
        browser = "Unknown"

    if "windows" in ua_lower:
        os_name = "Windows"
    elif "mac" in ua_lower:
        os_name = "macOS"
    elif "linux" in ua_lower:
        os_name = "Linux"
    elif "android" in ua_lower:
        os_name = "Android"
    elif "ios" in ua_lower or "iphone" in ua_lower:
        os_name = "iOS"
    else:
        os_name = "Unknown"

    return browser, os_name, device_type


@router.post("/register", response_model=UserOut, status_code=status.HTTP_201_CREATED)
@limiter.limit("5/minute")
async def register(
    payload: UserRegister,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    # Check email uniqueness
    result = await db.execute(select(User).where(User.email == payload.email))
    if result.scalar_one_or_none():
        raise HTTPException(status_code=400, detail="Email already registered")

    result = await db.execute(select(User).where(User.username == payload.username))
    if result.scalar_one_or_none():
        raise HTTPException(status_code=400, detail="Username already taken")

    # Check password breach
    try:
        is_breached, breach_count = await check_password_breach(payload.password)
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc

    hashed_pw = await async_hash_password(payload.password)
    user = User(
        email=payload.email,
        username=payload.username,
        hashed_password=hashed_pw,
        full_name=payload.full_name,
        password_breached=is_breached,
        password_breach_count=breach_count,
    )
    db.add(user)
    await db.commit()
    await db.refresh(user)

    await _log_audit(db, user.id, "user.register", request, details={"email": payload.email})
    return user


@router.post("/login", response_model=TokenResponse)
@limiter.limit("10/minute")
async def login(
    payload: UserLogin,
    request: Request,
    response: Response,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
):
    redis_client = None
    try:
        redis_client = _get_redis()
    except Exception as redis_err:
        import logging as _logging
        _logging.getLogger(__name__).error(
            "Redis client initialization failed during login: %s", redis_err
        )
        raise HTTPException(
            status_code=503,
            detail="Authentication is temporarily unavailable",
        ) from redis_err

    # Redis is required here: allowing login while the block store is
    # unavailable would silently bypass active account protections.
    ip = get_client_ip(request)
    if redis_client is not None:
        try:
            is_blocked = await redis_client.get(f"blocked_ip:{ip}")
            if is_blocked:
                raise HTTPException(status_code=403, detail="Your IP address has been blocked due to suspicious activity")
        except HTTPException:
            raise
        except Exception as redis_err:
            import logging as _logging
            _logging.getLogger(__name__).error(
                "Redis unavailable for IP block check: %s", redis_err
            )
            raise HTTPException(
                status_code=503,
                detail="Authentication is temporarily unavailable",
            ) from redis_err

    result = await db.execute(select(User).where(User.email == payload.email))
    user = result.scalar_one_or_none()

    password_valid = bool(
        user and await async_verify_password(payload.password, user.hashed_password)
    )
    if not password_valid:
        # Record failed login
        if user:
            fake_user_obj = user
            await _record_login_and_detect(
                db, redis_client, fake_user_obj, request, False, "invalid_password",
                None, background_tasks
            )
        else:
            await _record_unknown_account_attempt(db, redis_client, payload.email, request)
        await db.commit()
        raise HTTPException(status_code=401, detail="Invalid email or password")

    # Account-specific blocks are evaluated only after credentials are valid so
    # this check cannot be used to discover whether an email address exists.
    if redis_client is not None:
        try:
            is_account_blocked = await redis_client.get(
                f"blocked_ip:{user.id}:{ip}"
            )
            if is_account_blocked:
                raise HTTPException(
                    status_code=403,
                    detail="This IP address is blocked from authenticating to your account",
                )
        except HTTPException:
            raise
        except Exception as redis_err:
            import logging as _logging
            _logging.getLogger(__name__).error(
                "Redis unavailable for account IP block check: %s", redis_err
            )
            raise HTTPException(
                status_code=503,
                detail="Authentication is temporarily unavailable",
            ) from redis_err

    if not user.is_active:
        raise HTTPException(status_code=403, detail="Account is inactive")

    # Generate device ID
    fingerprint = payload.device_fingerprint or ""
    ua = payload.user_agent or request.headers.get("user-agent", "")
    device_id = generate_device_id(fingerprint, ua, ip)

    # Register/update device
    device = await _register_or_update_device(db, user.id, device_id, ua, ip)

    # If 2FA enabled, issue temp token and require 2FA
    if user.totp_enabled:
        temp_token = create_access_token(
            {"sub": str(user.id), "2fa_pending": True},
            expires_delta=timedelta(minutes=5),
        )
        return TokenResponse(
            access_token=temp_token,
            refresh_token="",
            requires_2fa=True,
            user_id=str(user.id),
        )

    # Issue full tokens
    session = UserSession(
        user_id=user.id,
        device_id=device_id,
        ip_address=ip,
        user_agent=ua,
        expires_at=datetime.now(timezone.utc) + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS),
        last_used_at=datetime.now(timezone.utc),
    )
    db.add(session)
    await db.flush()

    access_token = create_access_token({"sub": str(user.id), "session_id": str(session.id)})
    refresh_token = create_refresh_token({"sub": str(user.id), "session_id": str(session.id)})

    # Hash refresh token for storage
    session.refresh_token_hash = hashlib.sha256(refresh_token.encode()).hexdigest()

    # Update user last login
    user.last_login_at = datetime.now(timezone.utc)

    # Record login event
    await _record_login_and_detect(db, redis_client, user, request, True, None, device_id, background_tasks)

    await db.commit()

    await _log_audit(db, user.id, "user.login", request)

    _set_auth_cookies(response, access_token, refresh_token)

    return TokenResponse(access_token=access_token, refresh_token=refresh_token)


@router.post("/login/2fa", response_model=TokenResponse)
@limiter.limit("10/minute")
async def verify_2fa(
    payload: TwoFactorVerify,
    request: Request,
    response: Response,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
):
    from app.core.security import decode_access_token
    token_data = decode_access_token(payload.temp_token)
    if not token_data or not token_data.get("2fa_pending"):
        raise HTTPException(status_code=401, detail="Invalid or expired 2FA token")

    user_id = token_data.get("sub")
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    totp = pyotp.TOTP(user.totp_secret)
    if not totp.verify(payload.code, valid_window=1):
        raise HTTPException(status_code=401, detail="Invalid 2FA code")

    ip = get_client_ip(request)
    ua = request.headers.get("user-agent", "")
    device_id = generate_device_id("", ua, ip)

    session = UserSession(
        user_id=user.id,
        device_id=device_id,
        ip_address=ip,
        user_agent=ua,
        expires_at=datetime.now(timezone.utc) + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS),
        last_used_at=datetime.now(timezone.utc),
    )
    db.add(session)
    await db.flush()

    access_token = create_access_token({"sub": str(user.id), "session_id": str(session.id)})
    refresh_token = create_refresh_token({"sub": str(user.id), "session_id": str(session.id)})
    session.refresh_token_hash = hashlib.sha256(refresh_token.encode()).hexdigest()
    user.last_login_at = datetime.now(timezone.utc)

    redis_client = None
    try:
        redis_client = _get_redis()
    except Exception:
        pass
    await _record_login_and_detect(db, redis_client, user, request, True, None, device_id, background_tasks)
    await db.commit()

    _set_auth_cookies(response, access_token, refresh_token)

    return TokenResponse(access_token=access_token, refresh_token=refresh_token)


@router.post("/refresh", response_model=TokenResponse)
@limiter.limit("30/minute")
async def refresh_token(
    payload: RefreshRequest,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_db),
):
    supplied_refresh_token = payload.refresh_token or request.cookies.get("refresh_token")
    if not supplied_refresh_token:
        raise HTTPException(status_code=401, detail="Refresh token is required")

    token_data = decode_refresh_token(supplied_refresh_token)
    if not token_data:
        raise HTTPException(status_code=401, detail="Invalid refresh token")

    session_id = token_data.get("session_id")
    user_id = token_data.get("sub")

    result = await db.execute(
        select(UserSession).where(
            UserSession.id == session_id,
            UserSession.user_id == user_id,
            UserSession.is_active == True,  # noqa
        )
    )
    session = result.scalar_one_or_none()
    if not session or (
        session.expires_at is not None
        and session.expires_at <= datetime.now(timezone.utc)
    ):
        raise HTTPException(status_code=401, detail="Session expired or revoked")

    # Verify refresh token hash
    provided_hash = hashlib.sha256(supplied_refresh_token.encode()).hexdigest()
    if session.refresh_token_hash != provided_hash:
        raise HTTPException(status_code=401, detail="Refresh token mismatch")

    user_result = await db.execute(
        select(User).where(User.id == user_id, User.is_active == True)  # noqa
    )
    if user_result.scalar_one_or_none() is None:
        raise HTTPException(status_code=401, detail="User is inactive or no longer exists")

    new_access_token = create_access_token({"sub": user_id, "session_id": session_id})
    new_refresh_token = create_refresh_token({"sub": user_id, "session_id": session_id})

    session.refresh_token_hash = hashlib.sha256(new_refresh_token.encode()).hexdigest()
    session.last_used_at = datetime.now(timezone.utc)
    await db.commit()

    _set_auth_cookies(response, new_access_token, new_refresh_token)

    return TokenResponse(access_token=new_access_token, refresh_token=new_refresh_token)


@router.post("/change-password")
@limiter.limit("5/minute")
async def change_password(
    payload: ChangePassword,
    request: Request,
    response: Response,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Change the password and revoke every existing session for the account."""
    if not await async_verify_password(payload.current_password, current_user.hashed_password):
        await _log_audit(
            db,
            current_user.id,
            "user.password_change",
            request,
            status="failure",
            details={"reason": "invalid_current_password"},
        )
        raise HTTPException(status_code=400, detail="Current password is incorrect")

    if await async_verify_password(payload.new_password, current_user.hashed_password):
        raise HTTPException(status_code=400, detail="New password must differ from the current password")

    try:
        is_breached, breach_count = await check_password_breach(payload.new_password)
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc

    current_user.hashed_password = await async_hash_password(payload.new_password)
    current_user.password_breached = is_breached
    current_user.password_breach_count = breach_count

    sessions_result = await db.execute(
        select(UserSession).where(
            UserSession.user_id == current_user.id,
            UserSession.is_active == True,  # noqa
        )
    )
    now = datetime.now(timezone.utc)
    sessions = sessions_result.scalars().all()
    for user_session in sessions:
        user_session.is_active = False
        user_session.revoked_at = now

    db.add(AuditLog(
        user_id=current_user.id,
        action="user.password_change",
        ip_address=get_client_ip(request),
        user_agent=request.headers.get("user-agent"),
        status="success",
        details={"revoked_sessions": len(sessions), "password_breached": is_breached},
    ))
    await db.commit()

    _clear_auth_cookies(response)
    from app.services.security_score import recalculate_security_score
    await recalculate_security_score(db, current_user)
    return {
        "message": "Password changed successfully. Sign in again on all devices.",
        "revoked_sessions": len(sessions),
        "password_breached": is_breached,
        "password_breach_count": breach_count,
    }


@router.post("/logout")
async def logout(
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    # Find and revoke current session
    token = request.cookies.get("access_token") or request.headers.get("Authorization", "").replace("Bearer ", "")
    if token:
        from app.core.security import decode_access_token
        payload = decode_access_token(token)
        if payload:
            session_id = payload.get("session_id")
            result = await db.execute(select(UserSession).where(UserSession.id == session_id))
            session = result.scalar_one_or_none()
            if session:
                session.is_active = False
                session.revoked_at = datetime.now(timezone.utc)
                await db.commit()

    _clear_auth_cookies(response)
    await _log_audit(db, current_user.id, "user.logout", request)
    return {"message": "Logged out successfully"}


@router.get("/me", response_model=UserOut)
async def get_me(current_user: User = Depends(get_current_user)):
    return current_user


@router.post("/2fa/setup", response_model=TwoFactorSetupResponse)
async def setup_2fa(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    if current_user.totp_enabled:
        raise HTTPException(status_code=400, detail="2FA is already enabled")

    secret = pyotp.random_base32()
    totp = pyotp.TOTP(secret)
    qr_uri = totp.provisioning_uri(name=current_user.email, issuer_name="ShieldSphere")

    # Generate QR code as base64 PNG
    qr = qrcode.make(qr_uri)
    buf = io.BytesIO()
    qr.save(buf, format="PNG")
    qr_data_url = "data:image/png;base64," + base64.b64encode(buf.getvalue()).decode()

    # Store secret temporarily (not activated yet)
    current_user.totp_secret = secret
    await db.commit()

    return TwoFactorSetupResponse(secret=secret, qr_uri=qr_uri, qr_data_url=qr_data_url)


@router.post("/2fa/confirm")
async def confirm_2fa(
    payload: TwoFactorConfirm,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    if not current_user.totp_secret:
        raise HTTPException(status_code=400, detail="2FA not set up — call /2fa/setup first")
    if current_user.totp_enabled:
        raise HTTPException(status_code=400, detail="2FA is already active")

    totp = pyotp.TOTP(current_user.totp_secret)
    if not totp.verify(payload.code, valid_window=1):
        raise HTTPException(status_code=400, detail="Invalid TOTP code")

    current_user.totp_enabled = True
    await db.commit()
    await _log_audit(db, current_user.id, "2fa.enabled", request)
    from app.services.security_score import recalculate_security_score
    await recalculate_security_score(db, current_user)
    return {"message": "2FA enabled successfully"}


@router.post("/2fa/disable")
async def disable_2fa(
    payload: TwoFactorConfirm,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    if not current_user.totp_enabled:
        raise HTTPException(status_code=400, detail="2FA is not enabled")

    totp = pyotp.TOTP(current_user.totp_secret)
    if not totp.verify(payload.code, valid_window=1):
        raise HTTPException(status_code=400, detail="Invalid TOTP code")

    current_user.totp_enabled = False
    current_user.totp_secret = None
    await db.commit()
    await _log_audit(db, current_user.id, "2fa.disabled", request)
    from app.services.security_score import recalculate_security_score
    await recalculate_security_score(db, current_user)
    return {"message": "2FA disabled"}
