from datetime import datetime, timezone
from ipaddress import ip_address, ip_network
from typing import AsyncGenerator, Optional
from fastapi import Depends, HTTPException, Request, status, Cookie
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import AsyncSessionLocal
from app.core.security import decode_access_token
from app.db.models.user import User
from app.db.models.session import UserSession
from sqlalchemy import select


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    async with AsyncSessionLocal() as session:
        try:
            yield session
        finally:
            await session.close()


async def get_current_user(
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> User:
    """Extract and validate JWT from Authorization header or cookie."""
    token: Optional[str] = None

    # Try Authorization header first
    auth_header = request.headers.get("Authorization")
    if auth_header and auth_header.startswith("Bearer "):
        token = auth_header[7:]

    # Fall back to cookie
    if not token:
        token = request.cookies.get("access_token")

    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )

    payload = decode_access_token(token)
    if not payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
        )

    user_id = payload.get("sub")
    session_id = payload.get("session_id")

    if not user_id or not session_id or payload.get("2fa_pending"):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token payload")

    # Verify session still active in DB
    result = await db.execute(
        select(UserSession).where(
            UserSession.id == session_id,
            UserSession.user_id == user_id,
            UserSession.is_active == True,  # noqa
        )
    )
    session_obj = result.scalar_one_or_none()
    if not session_obj or (
        session_obj.expires_at is not None
        and session_obj.expires_at <= datetime.now(timezone.utc)
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session has expired or been revoked",
        )

    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()

    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")
    if not user.is_active:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Account is inactive")

    return user


async def get_current_superuser(current_user: User = Depends(get_current_user)) -> User:
    if current_user.role != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin access required")
    return current_user


def get_client_ip(request: Request) -> str:
    """Return the forwarded client IP only when the direct peer is trusted."""
    from app.core.config import settings

    peer = request.client.host if request.client else "0.0.0.0"
    forwarded = request.headers.get("X-Forwarded-For")
    try:
        peer_ip = ip_address(peer)
        trusted_peer = any(
            peer_ip in ip_network(network, strict=False)
            for network in settings.trusted_proxy_networks_list
        )
    except ValueError:
        trusted_peer = False

    if forwarded and trusted_peer:
        candidate = forwarded.split(",")[0].strip()
        try:
            return str(ip_address(candidate))
        except ValueError:
            pass
    return peer
