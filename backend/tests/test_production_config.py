import os

import pytest
from fastapi import Response
from pydantic import ValidationError

os.environ.setdefault("DATABASE_URL", "postgresql+psycopg://test:test@localhost/test")
os.environ.setdefault("JWT_SECRET", "test-access-secret-with-sufficient-length")
os.environ.setdefault("JWT_REFRESH_SECRET", "test-refresh-secret-with-sufficient-length")

from app.api.v1.auth import _set_auth_cookies  # noqa: E402
from app.core.config import Settings, settings  # noqa: E402
from app.schemas.auth import RefreshRequest  # noqa: E402


def _production_settings(**overrides):
    values = {
        "DATABASE_URL": "postgresql+psycopg://app:password@postgres/app",
        "REDIS_URL": "redis://:password@redis:6379/0",
        "JWT_SECRET": "a" * 40,
        "JWT_REFRESH_SECRET": "b" * 40,
        "APP_ENV": "production",
        "CORS_ORIGINS": "https://security.example.com",
        "ALLOWED_HOSTS": "security.example.com,backend,localhost,127.0.0.1",
        "TRUSTED_PROXY_NETWORKS": "172.30.0.0/24",
        "WEBAUTHN_RP_ID": "security.example.com",
        "WEBAUTHN_ORIGIN": "https://security.example.com",
        "COOKIE_SECURE": True,
    }
    values.update(overrides)
    return Settings(_env_file=None, **values)


def test_valid_production_settings_are_accepted():
    production = _production_settings()
    assert production.APP_ENV == "production"
    assert production.COOKIE_SECURE is True


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("JWT_SECRET", "replace-me"),
        ("JWT_REFRESH_SECRET", "replace-me"),
        ("CORS_ORIGINS", "*"),
        ("CORS_ORIGINS", "http://security.example.com"),
        ("WEBAUTHN_ORIGIN", "https://different.example.com"),
        ("COOKIE_SECURE", False),
        ("ALLOWED_HOSTS", "*"),
    ],
)
def test_unsafe_production_settings_are_rejected(field, value):
    with pytest.raises(ValidationError):
        _production_settings(**{field: value})


def test_refresh_request_allows_http_only_cookie_flow():
    assert RefreshRequest().refresh_token is None


def test_authentication_cookies_are_secure_in_production_mode(monkeypatch):
    monkeypatch.setattr(settings, "COOKIE_SECURE", True)
    response = Response()
    _set_auth_cookies(response, "access", "refresh")
    cookies = response.headers.getlist("set-cookie")
    assert len(cookies) == 2
    assert all("HttpOnly" in cookie for cookie in cookies)
    assert all("Secure" in cookie for cookie in cookies)
    assert all("SameSite=lax" in cookie for cookie in cookies)
