"""
IP and URL reputation service using VirusTotal and AbuseIPDB APIs.
Both are real API calls with the provided keys.
"""
import base64
import logging
import asyncio
from typing import Optional, Dict, Any
from datetime import datetime, timezone

import httpx

from app.core.config import settings

logger = logging.getLogger(__name__)

VT_BASE = "https://www.virustotal.com/api/v3"
ABUSEIPDB_BASE = "https://api.abuseipdb.com/api/v2"


def _vt_headers() -> Dict[str, str]:
    return {"x-apikey": settings.require_api_key("virustotal")}


def _abuseipdb_headers() -> Dict[str, str]:
    return {"Key": settings.require_api_key("abuseipdb"), "Accept": "application/json"}


async def submit_url_scan(url: str) -> Optional[str]:
    """
    Submit a URL to VirusTotal for scanning.
    Returns the analysis ID to poll with get_url_scan_result().
    """
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.post(
                f"{VT_BASE}/urls",
                headers=_vt_headers(),
                data={"url": url},
            )
            if response.status_code == 200:
                data = response.json()
                return data["data"]["id"]
            else:
                logger.error(f"VirusTotal URL submit error {response.status_code}: {response.text}")
                return None
    except Exception as e:
        logger.error(f"VirusTotal URL submit failed: {e}")
        return None


async def get_url_scan_result(analysis_id: str) -> Optional[Dict[str, Any]]:
    """
    Poll VirusTotal for URL scan results.
    Returns dict with stats or None if still queued/error.
    """
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.get(
                f"{VT_BASE}/analyses/{analysis_id}",
                headers=_vt_headers(),
            )
            if response.status_code != 200:
                return None
            data = response.json()
            attrs = data.get("data", {}).get("attributes", {})
            status = attrs.get("status", "queued")
            if status != "completed":
                return {"status": status}

            stats = attrs.get("stats", {})
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            harmless = stats.get("harmless", 0)
            undetected = stats.get("undetected", 0)

            if malicious > 0:
                verdict = "malicious"
            elif suspicious > 0:
                verdict = "suspicious"
            else:
                verdict = "clean"

            return {
                "status": "completed",
                "malicious": malicious,
                "suspicious": suspicious,
                "harmless": harmless,
                "undetected": undetected,
                "verdict": verdict,
                "raw": attrs,
            }
    except Exception as e:
        logger.error(f"VirusTotal get result failed: {e}")
        return None


async def check_ip_virustotal(ip: str) -> Optional[Dict[str, Any]]:
    """Look up IP reputation on VirusTotal."""
    try:
        async with httpx.AsyncClient(timeout=20.0) as client:
            response = await client.get(
                f"{VT_BASE}/ip_addresses/{ip}",
                headers=_vt_headers(),
            )
            if response.status_code != 200:
                logger.warning(f"VT IP lookup {ip}: HTTP {response.status_code}")
                return None
            data = response.json()
            attrs = data.get("data", {}).get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            return {
                "source": "virustotal",
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
                "country": attrs.get("country"),
                "asn": attrs.get("asn"),
                "as_owner": attrs.get("as_owner"),
                "reputation": attrs.get("reputation", 0),
                "verdict": "malicious" if stats.get("malicious", 0) > 0 else "clean",
            }
    except Exception as e:
        logger.error(f"VirusTotal IP lookup failed for {ip}: {e}")
        return None


async def check_ip_abuseipdb(ip: str) -> Optional[Dict[str, Any]]:
    """Look up IP reputation on AbuseIPDB."""
    try:
        async with httpx.AsyncClient(timeout=20.0) as client:
            response = await client.get(
                f"{ABUSEIPDB_BASE}/check",
                headers=_abuseipdb_headers(),
                params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": True},
            )
            if response.status_code != 200:
                logger.warning(f"AbuseIPDB lookup {ip}: HTTP {response.status_code}")
                return None
            data = response.json().get("data", {})
            return {
                "source": "abuseipdb",
                "abuse_confidence_score": data.get("abuseConfidenceScore", 0),
                "country_code": data.get("countryCode"),
                "isp": data.get("isp"),
                "domain": data.get("domain"),
                "total_reports": data.get("totalReports", 0),
                "last_reported": data.get("lastReportedAt"),
                "is_tor": data.get("isTor", False),
                "verdict": "malicious" if data.get("abuseConfidenceScore", 0) > 50 else "clean",
            }
    except Exception as e:
        logger.error(f"AbuseIPDB lookup failed for {ip}: {e}")
        return None


async def check_ip_reputation(ip: str) -> Dict[str, Any]:
    """Combined IP reputation check from both VirusTotal and AbuseIPDB."""
    vt_result, abuse_result = await asyncio.gather(
        check_ip_virustotal(ip),
        check_ip_abuseipdb(ip),
        return_exceptions=True,
    )

    result = {
        "ip": ip,
        "virustotal": vt_result if not isinstance(vt_result, Exception) else None,
        "abuseipdb": abuse_result if not isinstance(abuse_result, Exception) else None,
        "overall_verdict": "unknown",
        "checked_at": datetime.now(timezone.utc).isoformat(),
    }

    # Determine overall verdict
    is_malicious = False
    if result["virustotal"] and result["virustotal"].get("verdict") == "malicious":
        is_malicious = True
    if result["abuseipdb"] and result["abuseipdb"].get("abuse_confidence_score", 0) > 50:
        is_malicious = True

    available = result["virustotal"] is not None or result["abuseipdb"] is not None
    result["overall_verdict"] = "malicious" if is_malicious else ("clean" if available else "unknown")
    return result
