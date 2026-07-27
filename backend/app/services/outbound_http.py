"""Safe outbound HTTP helpers for user-supplied public targets."""
import asyncio
import socket
from ipaddress import ip_address
from typing import Optional
from urllib.parse import urljoin, urlsplit

import httpx


class UnsafeOutboundTarget(ValueError):
    """Raised when a URL could reach local, private, or otherwise unsafe infrastructure."""


def _is_public_ip(value: str) -> bool:
    address = ip_address(value.split("%", 1)[0])
    return address.is_global


async def validate_public_url(url: str) -> str:
    """Validate scheme, authority, and every currently resolved address."""
    try:
        parsed = urlsplit(url.strip())
        port = parsed.port
    except ValueError as exc:
        raise UnsafeOutboundTarget("URL has an invalid host or port") from exc

    if parsed.scheme.lower() not in {"http", "https"}:
        raise UnsafeOutboundTarget("Only HTTP and HTTPS URLs are allowed")
    if not parsed.hostname:
        raise UnsafeOutboundTarget("URL must include a hostname")
    if parsed.username is not None or parsed.password is not None:
        raise UnsafeOutboundTarget("Credentials in URLs are not allowed")

    hostname = parsed.hostname.rstrip(".").lower()
    if hostname == "localhost" or hostname.endswith(".localhost"):
        raise UnsafeOutboundTarget("Localhost targets are not allowed")

    try:
        addresses = {_is_public_ip(hostname)}
    except ValueError:
        loop = asyncio.get_running_loop()
        try:
            records = await loop.getaddrinfo(
                hostname,
                port or (443 if parsed.scheme.lower() == "https" else 80),
                type=socket.SOCK_STREAM,
            )
        except OSError as exc:
            raise UnsafeOutboundTarget("Hostname could not be resolved") from exc
        resolved = {record[4][0] for record in records}
        if not resolved:
            raise UnsafeOutboundTarget("Hostname did not resolve to an address")
        addresses = {_is_public_ip(value) for value in resolved}

    if addresses != {True}:
        raise UnsafeOutboundTarget("Private, loopback, reserved, and link-local targets are not allowed")
    return parsed.geturl()


async def safe_public_get(
    url: str,
    *,
    client: Optional[httpx.AsyncClient] = None,
    max_redirects: int = 5,
) -> httpx.Response:
    """GET a public URL while validating every redirect destination."""
    owns_client = client is None
    if client is None:
        client = httpx.AsyncClient(timeout=15.0, follow_redirects=False)

    current_url = await validate_public_url(url)
    try:
        for _ in range(max_redirects + 1):
            response = await client.get(current_url, follow_redirects=False)
            if response.status_code not in {301, 302, 303, 307, 308}:
                return response
            location = response.headers.get("location")
            if not location:
                return response
            current_url = await validate_public_url(urljoin(current_url, location))
        raise UnsafeOutboundTarget(f"Too many redirects; maximum is {max_redirects}")
    finally:
        if owns_client:
            await client.aclose()


async def safe_public_post(
    url: str,
    *,
    content: bytes,
    headers: Optional[dict[str, str]] = None,
    client: Optional[httpx.AsyncClient] = None,
) -> httpx.Response:
    """POST bytes to a validated public URL without following redirects."""
    owns_client = client is None
    if client is None:
        client = httpx.AsyncClient(timeout=10.0, follow_redirects=False)
    target = await validate_public_url(url)
    try:
        return await client.post(target, content=content, headers=headers, follow_redirects=False)
    finally:
        if owns_client:
            await client.aclose()
