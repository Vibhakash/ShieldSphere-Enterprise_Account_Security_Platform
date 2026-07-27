"""WebAuthn passkey registration, management, and passwordless login."""
import base64
import hashlib
import json
import logging
from datetime import datetime, timedelta, timezone
from uuid import UUID, uuid4

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Request, Response
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from webauthn import (
    base64url_to_bytes,
    generate_authentication_options,
    generate_registration_options,
    options_to_json,
    verify_authentication_response,
    verify_registration_response,
)
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    PublicKeyCredentialDescriptor,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)

from app.api.v1.auth import (
    _log_audit,
    _record_login_and_detect,
    _register_or_update_device,
    _set_auth_cookies,
)
from app.core.config import settings
from app.core.deps import get_client_ip, get_current_user, get_db
from app.core.rate_limit import limiter
from app.core.security import create_access_token, create_refresh_token, generate_device_id
from app.db.models.identity_security import PasskeyCredential
from app.db.models.session import UserSession
from app.db.models.user import User
from app.schemas.auth import PasskeyLoginVerify, PasskeyRegistrationVerify, TokenResponse
from app.schemas.common import PasskeyOut
import redis.asyncio as aioredis

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/auth/passkeys", tags=["Passkeys"])


def _redis() -> aioredis.Redis:
    return aioredis.from_url(settings.REDIS_URL, decode_responses=True)


def _b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


async def _store_ceremony(kind: str, payload: dict) -> str:
    ceremony_id = str(uuid4())
    client = _redis()
    try:
        await client.set(
            f"webauthn:{kind}:{ceremony_id}",
            json.dumps(payload),
            ex=settings.WEBAUTHN_CHALLENGE_TTL_SECONDS,
        )
    except Exception as exc:
        raise HTTPException(status_code=503, detail="Passkey challenge storage is unavailable") from exc
    finally:
        await client.aclose()
    return ceremony_id


async def _consume_ceremony(kind: str, ceremony_id: str) -> dict:
    try:
        UUID(ceremony_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="Invalid passkey ceremony") from exc
    client = _redis()
    key = f"webauthn:{kind}:{ceremony_id}"
    try:
        raw = await client.getdel(key)
    except Exception as exc:
        raise HTTPException(status_code=503, detail="Passkey challenge storage is unavailable") from exc
    finally:
        await client.aclose()
    if not raw:
        raise HTTPException(status_code=400, detail="Passkey request expired or was already used")
    return json.loads(raw)


@router.get("", response_model=list[PasskeyOut])
async def list_passkeys(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(PasskeyCredential)
        .where(PasskeyCredential.user_id == current_user.id)
        .order_by(PasskeyCredential.created_at.desc())
    )
    return result.scalars().all()


@router.post("/register/options")
async def registration_options(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(PasskeyCredential).where(PasskeyCredential.user_id == current_user.id))
    existing = result.scalars().all()
    options = generate_registration_options(
        rp_id=settings.WEBAUTHN_RP_ID,
        rp_name=settings.WEBAUTHN_RP_NAME,
        user_id=current_user.id.bytes,
        user_name=current_user.email,
        user_display_name=current_user.full_name or current_user.username,
        exclude_credentials=[
            PublicKeyCredentialDescriptor(id=base64url_to_bytes(item.credential_id)) for item in existing
        ],
        authenticator_selection=AuthenticatorSelectionCriteria(
            resident_key=ResidentKeyRequirement.REQUIRED,
            user_verification=UserVerificationRequirement.REQUIRED,
        ),
    )
    ceremony_id = await _store_ceremony(
        "registration",
        {"challenge": _b64url(options.challenge), "user_id": str(current_user.id)},
    )
    return {"ceremony_id": ceremony_id, "options": json.loads(options_to_json(options))}


@router.post("/register/verify", response_model=PasskeyOut, status_code=201)
async def registration_verify(
    payload: PasskeyRegistrationVerify,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    ceremony = await _consume_ceremony("registration", payload.ceremony_id)
    if ceremony.get("user_id") != str(current_user.id):
        raise HTTPException(status_code=403, detail="Passkey request belongs to another account")
    try:
        verified = verify_registration_response(
            credential=payload.credential,
            expected_challenge=base64url_to_bytes(ceremony["challenge"]),
            expected_rp_id=settings.WEBAUTHN_RP_ID,
            expected_origin=settings.WEBAUTHN_ORIGIN,
            require_user_verification=True,
        )
    except Exception as exc:
        logger.info("Passkey registration verification failed: %s", exc)
        raise HTTPException(status_code=400, detail="The authenticator response could not be verified") from exc

    credential_id = _b64url(verified.credential_id)
    duplicate = await db.execute(select(PasskeyCredential).where(PasskeyCredential.credential_id == credential_id))
    if duplicate.scalar_one_or_none():
        raise HTTPException(status_code=409, detail="This passkey is already registered")
    response_data = payload.credential.get("response") or {}
    item = PasskeyCredential(
        user_id=current_user.id,
        credential_id=credential_id,
        public_key=verified.credential_public_key,
        sign_count=verified.sign_count,
        transports=response_data.get("transports") or [],
        device_type=getattr(verified.credential_device_type, "value", str(verified.credential_device_type)),
        backed_up=verified.credential_backed_up,
        name=payload.name,
    )
    db.add(item)
    await db.commit()
    await db.refresh(item)
    await _log_audit(db, current_user.id, "passkey.registered", request, details={"passkey_id": str(item.id), "name": item.name})
    return item


@router.delete("/{passkey_id}")
async def delete_passkey(
    passkey_id: UUID,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(PasskeyCredential).where(PasskeyCredential.id == passkey_id, PasskeyCredential.user_id == current_user.id)
    )
    item = result.scalar_one_or_none()
    if not item:
        raise HTTPException(status_code=404, detail="Passkey not found")
    name = item.name
    await db.delete(item)
    await db.commit()
    await _log_audit(db, current_user.id, "passkey.removed", request, details={"passkey_id": str(passkey_id), "name": name})
    return {"message": "Passkey removed"}


@router.post("/login/options")
@limiter.limit("20/minute")
async def authentication_options(request: Request):
    options = generate_authentication_options(
        rp_id=settings.WEBAUTHN_RP_ID,
        allow_credentials=[],
        user_verification=UserVerificationRequirement.REQUIRED,
    )
    ceremony_id = await _store_ceremony("authentication", {"challenge": _b64url(options.challenge)})
    return {"ceremony_id": ceremony_id, "options": json.loads(options_to_json(options))}


@router.post("/login/verify", response_model=TokenResponse)
@limiter.limit("10/minute")
async def authentication_verify(
    payload: PasskeyLoginVerify,
    request: Request,
    response: Response,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
):
    ceremony = await _consume_ceremony("authentication", payload.ceremony_id)
    credential_id = str(payload.credential.get("id") or "")
    result = await db.execute(
        select(PasskeyCredential, User)
        .join(User, User.id == PasskeyCredential.user_id)
        .where(PasskeyCredential.credential_id == credential_id, User.is_active == True)  # noqa
    )
    row = result.one_or_none()
    if not row:
        raise HTTPException(status_code=401, detail="Passkey is not recognized")
    passkey, user = row
    try:
        verified = verify_authentication_response(
            credential=payload.credential,
            expected_challenge=base64url_to_bytes(ceremony["challenge"]),
            expected_rp_id=settings.WEBAUTHN_RP_ID,
            expected_origin=settings.WEBAUTHN_ORIGIN,
            credential_public_key=passkey.public_key,
            credential_current_sign_count=passkey.sign_count,
            require_user_verification=True,
        )
    except Exception as exc:
        logger.info("Passkey authentication verification failed: %s", exc)
        raise HTTPException(status_code=401, detail="Passkey verification failed") from exc

    ip = get_client_ip(request)
    ua = request.headers.get("user-agent", "")
    device_id = generate_device_id(payload.device_fingerprint or "", ua, ip)
    await _register_or_update_device(db, user.id, device_id, ua, ip)
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
    access_token = create_access_token({"sub": str(user.id), "session_id": str(session.id), "amr": ["passkey"]})
    refresh_token = create_refresh_token({"sub": str(user.id), "session_id": str(session.id)})
    session.refresh_token_hash = hashlib.sha256(refresh_token.encode()).hexdigest()
    passkey.sign_count = verified.new_sign_count
    passkey.last_used_at = datetime.now(timezone.utc)
    passkey.backed_up = verified.credential_backed_up
    user.last_login_at = datetime.now(timezone.utc)
    redis_client = _redis()
    try:
        await _record_login_and_detect(db, redis_client, user, request, True, None, device_id, background_tasks)
        await db.commit()
    finally:
        await redis_client.aclose()
    await _log_audit(db, user.id, "user.login.passkey", request, details={"passkey_id": str(passkey.id)})
    _set_auth_cookies(response, access_token, refresh_token)
    return TokenResponse(access_token=access_token, refresh_token=refresh_token)
