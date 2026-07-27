import uuid
import hashlib
import hmac
import json

import httpx
import pytest
from pydantic import ValidationError
from starlette.requests import Request

from app.api.v1.security_actions import _valid_ip
from app.api.v1.threats import _block_key
from app.core.config import settings
from app.core.deps import get_client_ip
from app.db.models.identity_security import NotificationIntegration
from app.schemas.common import IntegrationCreate, IpBlockCreate
from app.services import integration_service
from app.services.integration_service import decrypt_secret, destination_hint, encrypt_secret


def test_integration_signing_secret_round_trip():
    secret = "a-test-secret-that-is-not-stored-in-plain-text"
    encrypted = encrypt_secret(secret)
    assert encrypted != secret
    assert decrypt_secret(encrypted) == secret


def test_webhook_destination_hint_does_not_expose_path_or_query():
    integration = NotificationIntegration(
        id=uuid.uuid4(),
        user_id=uuid.uuid4(),
        name="SOC",
        integration_type="webhook",
        destination="https://alerts.example.com/private/path?token=secret",
        minimum_severity="high",
    )
    assert destination_hint(integration) == "alerts.example.com"


@pytest.mark.asyncio
async def test_webhook_delivery_is_json_and_hmac_signed(monkeypatch):
    secret = "webhook-signing-secret"
    integration = NotificationIntegration(
        id=uuid.uuid4(),
        user_id=uuid.uuid4(),
        name="SOC",
        integration_type="webhook",
        destination="https://alerts.example.com/hook",
        signing_secret_encrypted=encrypt_secret(secret),
        minimum_severity="medium",
    )
    event = {
        "event_type": "integration.test",
        "title": "Test",
        "message": "Delivery test",
        "severity": "medium",
        "created_at": "2026-07-22T12:00:00Z",
    }
    captured = {}

    async def fake_post(url, *, content, headers):
        captured.update(url=url, content=content, headers=headers)
        request = httpx.Request("POST", url)
        return httpx.Response(204, request=request)

    monkeypatch.setattr(integration_service, "safe_public_post", fake_post)
    status_code, _ = await integration_service._perform_delivery(integration, event)

    expected_body = json.dumps(event, separators=(",", ":"), sort_keys=True).encode("utf-8")
    expected_signature = hmac.new(secret.encode(), expected_body, hashlib.sha256).hexdigest()
    assert status_code == 204
    assert captured["content"] == expected_body
    assert captured["headers"]["X-ShieldSphere-Signature"] == f"sha256={expected_signature}"
    assert captured["headers"]["X-ShieldSphere-Event"] == "integration.test"


@pytest.mark.parametrize("value", ["debug", "urgent", ""])
def test_integration_rejects_unknown_severity(value):
    with pytest.raises(ValidationError):
        IntegrationCreate(
            name="Test",
            integration_type="webhook",
            destination="https://example.com/hook",
            minimum_severity=value,
        )


def test_containment_only_accepts_real_ip_literals():
    assert _valid_ip("203.0.113.10")
    assert _valid_ip("2001:db8::1")
    assert not _valid_ip("not-an-ip")


def test_manual_ip_block_normalizes_address_and_accepts_supported_duration():
    payload = IpBlockCreate(
        ip_address=" 2001:0db8:0:0::1 ",
        reason="Repeated failed sign-ins",
        duration="7d",
    )
    assert payload.ip_address == "2001:db8::1"
    assert payload.duration == "7d"


@pytest.mark.parametrize("duration", ["10m", "30d", "forever", ""])
def test_manual_ip_block_rejects_unsupported_duration(duration):
    with pytest.raises(ValidationError):
        IpBlockCreate(
            ip_address="203.0.113.10",
            reason="Repeated failed sign-ins",
            duration=duration,
        )


def test_ip_block_redis_keys_separate_accounts_from_global_blocks():
    user_id = uuid.uuid4()
    ip = "203.0.113.10"
    assert _block_key(None, ip) == f"blocked_ip:{ip}"
    assert _block_key(user_id, ip) == f"blocked_ip:{user_id}:{ip}"


def _request_from(peer: str, forwarded: str) -> Request:
    return Request({
        "type": "http",
        "method": "GET",
        "path": "/",
        "headers": [(b"x-forwarded-for", forwarded.encode())],
        "client": (peer, 12345),
    })


def test_client_ip_accepts_forwarding_from_trusted_proxy(monkeypatch):
    monkeypatch.setattr(settings, "TRUSTED_PROXY_NETWORKS", "10.0.0.0/8")
    assert get_client_ip(_request_from("10.1.2.3", "203.0.113.20")) == "203.0.113.20"


def test_client_ip_ignores_forwarding_from_untrusted_peer(monkeypatch):
    monkeypatch.setattr(settings, "TRUSTED_PROXY_NETWORKS", "10.0.0.0/8")
    assert get_client_ip(_request_from("198.51.100.7", "203.0.113.20")) == "198.51.100.7"
