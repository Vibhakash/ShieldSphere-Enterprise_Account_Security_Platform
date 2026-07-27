from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any
import hashlib

import jwt
from jwt.exceptions import InvalidTokenError
import bcrypt as _bcrypt

from app.core.config import settings


import asyncio

def hash_password(password: str) -> str:
    """Hash password using bcrypt directly (avoids passlib 72-byte detection bug)."""
    pwd_bytes = password.encode("utf-8")
    salt = _bcrypt.gensalt(rounds=10)  # rounds=10 is ~100ms, still very secure
    return _bcrypt.hashpw(pwd_bytes, salt).decode("utf-8")


async def async_hash_password(password: str) -> str:
    """Async-safe bcrypt hash — runs in thread pool to avoid blocking the event loop."""
    return await asyncio.to_thread(hash_password, password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify password against bcrypt hash (sync — use async_verify_password in async contexts)."""
    try:
        return _bcrypt.checkpw(
            plain_password.encode("utf-8"),
            hashed_password.encode("utf-8")
        )
    except Exception:
        return False


async def async_verify_password(plain_password: str, hashed_password: str) -> bool:
    """Async-safe bcrypt verify — runs in thread pool to avoid blocking the event loop."""
    return await asyncio.to_thread(verify_password, plain_password, hashed_password)


def create_access_token(data: Dict[str, Any], expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (
        expires_delta or timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    to_encode.update({"exp": expire, "type": "access"})
    return jwt.encode(to_encode, settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM)


def create_refresh_token(data: Dict[str, Any]) -> str:
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
    to_encode.update({"exp": expire, "type": "refresh"})
    return jwt.encode(to_encode, settings.JWT_REFRESH_SECRET, algorithm=settings.JWT_ALGORITHM)


def decode_access_token(token: str) -> Optional[Dict[str, Any]]:
    try:
        payload = jwt.decode(token, settings.JWT_SECRET, algorithms=[settings.JWT_ALGORITHM])
        if payload.get("type") != "access":
            return None
        return payload
    except InvalidTokenError:
        return None


def decode_refresh_token(token: str) -> Optional[Dict[str, Any]]:
    try:
        payload = jwt.decode(token, settings.JWT_REFRESH_SECRET, algorithms=[settings.JWT_ALGORITHM])
        if payload.get("type") != "refresh":
            return None
        return payload
    except InvalidTokenError:
        return None


def generate_device_id(fingerprint: str, user_agent: str, ip: str) -> str:
    """Generate a stable device ID from fingerprint components."""
    raw = f"{fingerprint}:{user_agent}:{ip}"
    return hashlib.sha256(raw.encode()).hexdigest()[:32]
