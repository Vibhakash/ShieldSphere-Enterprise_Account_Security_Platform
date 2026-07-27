"""
Password breach service using HaveIBeenPwned Pwned Passwords k-anonymity API.
Only the first 5 characters of the SHA-1 hash are sent to the API.
No API key required.
"""
import hashlib
import logging
from typing import Tuple

import httpx

logger = logging.getLogger(__name__)

HIBP_API = "https://api.pwnedpasswords.com/range/"


async def check_password_breach(password: str) -> Tuple[bool, int]:
    """
    Check if a password has appeared in known data breaches.
    Returns (is_breached, breach_count).
    Uses k-anonymity: only the first 5 chars of SHA-1 are sent to the API.
    """
    sha1_hash = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix = sha1_hash[:5]
    suffix = sha1_hash[5:]

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.get(
                f"{HIBP_API}{prefix}",
                headers={"Add-Padding": "true"},
            )
            response.raise_for_status()

        lines = response.text.splitlines()
        for line in lines:
            if ":" not in line:
                continue
            hash_suffix, count = line.split(":", 1)
            if hash_suffix.upper() == suffix:
                return True, int(count)

        return False, 0

    except httpx.TimeoutException as exc:
        logger.error("HIBP API timeout")
        raise RuntimeError("Password breach service timed out; no result was recorded") from exc
    except Exception as e:
        logger.error(f"HIBP API error: {e}")
        raise RuntimeError("Password breach service is unavailable; no result was recorded") from e
