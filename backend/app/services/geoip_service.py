"""
GeoIP service using MaxMind GeoLite2.
Returns city, country, lat/lng for a given IP address.
"""
import os
import logging
import json
import base64
from functools import lru_cache
from typing import Optional
from dataclasses import dataclass
from urllib.error import URLError
from urllib.parse import quote
from urllib.request import Request, urlopen

from app.core.config import settings

logger = logging.getLogger(__name__)

_reader = None


def _get_reader():
    global _reader
    if _reader is not None:
        return _reader
    db_path = settings.GEOLITE2_DB_PATH
    if not os.path.exists(db_path):
        logger.warning(f"GeoLite2 database not found at {db_path}. GeoIP lookups will be skipped.")
        return None
    try:
        import geoip2.database
        _reader = geoip2.database.Reader(db_path)
        logger.info(f"GeoLite2 database loaded from {db_path}")
        return _reader
    except Exception as e:
        logger.error(f"Failed to load GeoLite2 database: {e}")
        return None


@dataclass
class GeoIPResult:
    country: Optional[str] = None
    country_code: Optional[str] = None
    city: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    asn: Optional[str] = None
    isp: Optional[str] = None


def lookup_ip(ip: str) -> GeoIPResult:
    """Resolve an IP address to geographic data."""
    # Skip private/loopback IPs
    if _is_private_ip(ip):
        return GeoIPResult(country="Local", country_code="LO", city="Localhost")

    reader = _get_reader()
    if reader is None:
        return _lookup_maxmind_geolite_webservice(ip)

    try:
        response = reader.city(ip)
        return GeoIPResult(
            country=response.country.name,
            country_code=response.country.iso_code,
            city=response.city.name,
            latitude=response.location.latitude,
            longitude=response.location.longitude,
        )
    except Exception as e:
        logger.debug(f"GeoIP lookup failed for {ip}: {e}")
        return _lookup_maxmind_geolite_webservice(ip)


@lru_cache(maxsize=2048)
def _lookup_maxmind_geolite_webservice(ip: str) -> GeoIPResult:
    """Use MaxMind's GeoLite City endpoint when an MMDB file is unavailable.

    The lookup is opt-in: deployments must configure both MaxMind credentials.
    Results are cached because several sessions can share the same public IP.
    """
    account_id = settings.MAXMIND_ACCOUNT_ID.strip()
    license_key = settings.MAXMIND_LICENSE_KEY.strip()
    if not account_id or not license_key:
        return GeoIPResult()

    credentials = base64.b64encode(f"{account_id}:{license_key}".encode()).decode()
    request = Request(
        f"https://geolite.info/geoip/v2.1/city/{quote(ip, safe='')}",
        headers={"Authorization": f"Basic {credentials}", "Accept": "application/json"},
    )
    try:
        with urlopen(request, timeout=3) as response:  # noqa: S310 - fixed HTTPS provider URL
            data = json.loads(response.read().decode("utf-8"))
        country = data.get("country") or {}
        city = data.get("city") or {}
        location = data.get("location") or {}
        return GeoIPResult(
            country=(country.get("names") or {}).get("en"),
            country_code=country.get("iso_code"),
            city=(city.get("names") or {}).get("en"),
            latitude=location.get("latitude"),
            longitude=location.get("longitude"),
        )
    except (URLError, TimeoutError, ValueError, OSError) as exc:
        logger.warning("MaxMind GeoLite lookup failed for %s: %s", ip, exc)
        return GeoIPResult()


def _is_private_ip(ip: str) -> bool:
    """Check if IP is private/loopback."""
    private_prefixes = (
        "127.", "10.", "192.168.", "::1", "localhost",
        "172.16.", "172.17.", "172.18.", "172.19.", "172.20.",
        "172.21.", "172.22.", "172.23.", "172.24.", "172.25.",
        "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.",
    )
    return any(ip.startswith(prefix) for prefix in private_prefixes)
