from pathlib import Path
from ipaddress import ip_network
from urllib.parse import urlparse

from pydantic import field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict
from typing import List

BACKEND_DIR = Path(__file__).resolve().parents[2]


class Settings(BaseSettings):
    # Database
    DATABASE_URL: str

    @field_validator("DATABASE_URL", mode="before")
    @classmethod
    def normalize_async_postgres_url(cls, value: str) -> str:
        """Accept standard Postgres/Neon URLs with the async psycopg driver."""
        url = str(value or "").strip().strip('"').strip("'")
        if url.startswith("postgresql+psycopg://"):
            return url
        if url.startswith("postgresql://"):
            return "postgresql+psycopg://" + url.removeprefix("postgresql://")
        if url.startswith("postgres://"):
            return "postgresql+psycopg://" + url.removeprefix("postgres://")
        return url

    # Redis
    REDIS_URL: str = "redis://localhost:6379/0"

    # JWT
    JWT_SECRET: str
    JWT_REFRESH_SECRET: str
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7

    # WebAuthn / passkeys. RP ID must match the hostname used in the browser.
    WEBAUTHN_RP_ID: str = "127.0.0.1"
    WEBAUTHN_RP_NAME: str = "ShieldSphere"
    WEBAUTHN_ORIGIN: str = "http://127.0.0.1:3000"
    WEBAUTHN_CHALLENGE_TTL_SECONDS: int = 300

    # Optional email notification transport. Webhook integrations work without it.
    SMTP_HOST: str = ""
    SMTP_PORT: int = 587
    SMTP_USERNAME: str = ""
    SMTP_PASSWORD: str = ""
    SMTP_FROM_EMAIL: str = ""
    SMTP_USE_TLS: bool = True

    # External APIs
    GROQ_API_KEY: str = ""
    VIRUSTOTAL_API_KEY: str = ""
    ABUSEIPDB_API_KEY: str = ""

    # GeoIP
    GEOLITE2_DB_PATH: str = str(BACKEND_DIR / "data" / "GeoLite2-City.mmdb")

    @field_validator("GEOLITE2_DB_PATH", mode="after")
    @classmethod
    def resolve_geoip_path(cls, value: str) -> str:
        """Resolve relative .env paths from the backend directory, not process cwd."""
        path = Path(value).expanduser()
        if not path.is_absolute():
            path = BACKEND_DIR / path
        return str(path.resolve())

    # Sandbox
    SANDBOX_NETWORK_INTERNET_EGRESS: bool = False

    # App
    APP_ENV: str = "development"
    CORS_ORIGINS: str = "http://localhost:3000"
    ALLOWED_HOSTS: str = "localhost,127.0.0.1"
    API_DOCS_ENABLED: bool = True
    COOKIE_SECURE: bool = False
    # Only these direct peers may supply X-Forwarded-For. Configure the
    # reverse proxy's address/network in production.
    TRUSTED_PROXY_NETWORKS: str = "127.0.0.1/32,::1/128"

    @property
    def cors_origins_list(self) -> List[str]:
        return [origin.strip() for origin in self.CORS_ORIGINS.split(",")]

    @property
    def cors_allow_all_origins(self) -> bool:
        """Whether CORS should reflect every requesting origin.

        ``allow_origins=["*"]`` cannot be used with credentialed requests:
        browsers reject that combination.  The middleware uses this flag to
        reflect the caller's Origin header instead, so cookie-based login still
        works when an administrator deliberately chooses open CORS.
        """
        return self.cors_origins_list == ["*"]

    @property
    def allowed_hosts_list(self) -> List[str]:
        return [host.strip() for host in self.ALLOWED_HOSTS.split(",") if host.strip()]

    @property
    def trusted_proxy_networks_list(self) -> List[str]:
        return [
            network.strip()
            for network in self.TRUSTED_PROXY_NETWORKS.split(",")
            if network.strip()
        ]

    @model_validator(mode="after")
    def validate_production_security(self):
        if self.APP_ENV.lower() != "production":
            return self

        errors = []
        if len(self.JWT_SECRET) < 32 or "replace-" in self.JWT_SECRET.lower():
            errors.append("JWT_SECRET must be a non-placeholder value of at least 32 characters")
        if len(self.JWT_REFRESH_SECRET) < 32 or "replace-" in self.JWT_REFRESH_SECRET.lower():
            errors.append(
                "JWT_REFRESH_SECRET must be a non-placeholder value of at least 32 characters"
            )
        if self.JWT_SECRET == self.JWT_REFRESH_SECRET:
            errors.append("JWT_SECRET and JWT_REFRESH_SECRET must be different")
        if not self.COOKIE_SECURE:
            errors.append("COOKIE_SECURE must be true")

        origins = self.cors_origins_list
        if not origins or any(
            urlparse(origin).scheme != "https"
            or urlparse(origin).hostname in {"localhost", "127.0.0.1"}
            for origin in origins
        ) and not self.cors_allow_all_origins:
            errors.append("CORS_ORIGINS must contain only explicit public HTTPS origins")
        if not self.allowed_hosts_list or "*" in self.allowed_hosts_list:
            errors.append("ALLOWED_HOSTS must contain explicit hostnames and cannot use '*'")

        webauthn_origin = urlparse(self.WEBAUTHN_ORIGIN)
        if (
            webauthn_origin.scheme != "https"
            or not webauthn_origin.hostname
            or webauthn_origin.hostname != self.WEBAUTHN_RP_ID
        ):
            errors.append(
                "WEBAUTHN_ORIGIN must be HTTPS and its hostname must match WEBAUTHN_RP_ID"
            )

        try:
            if not self.trusted_proxy_networks_list:
                errors.append("TRUSTED_PROXY_NETWORKS must contain the reverse proxy network")
            for network in self.trusted_proxy_networks_list:
                ip_network(network, strict=False)
        except ValueError:
            errors.append("TRUSTED_PROXY_NETWORKS contains an invalid IP network")

        smtp_values = [
            self.SMTP_HOST,
            self.SMTP_USERNAME,
            self.SMTP_PASSWORD,
            self.SMTP_FROM_EMAIL,
        ]
        if any(smtp_values) and not all(smtp_values):
            errors.append(
                "SMTP_HOST, SMTP_USERNAME, SMTP_PASSWORD, and SMTP_FROM_EMAIL "
                "must all be configured when email delivery is enabled"
            )

        if errors:
            raise ValueError("; ".join(errors))
        return self

    # Threat detection thresholds
    BRUTE_FORCE_THRESHOLD: int = 5          # failed attempts
    BRUTE_FORCE_WINDOW_SECONDS: int = 300   # 5 minutes
    IMPOSSIBLE_TRAVEL_MIN_SPEED_KMH: float = 900.0  # faster than commercial flight
    AUTO_BLOCK_THREAT_COUNT: int = 3        # threats before auto-block
    MAX_SIMULATOR_RUNS_PER_HOUR: int = 5

    # Security score weights
    SCORE_2FA_ENABLED: int = 25
    SCORE_NO_BREACH: int = 25
    SCORE_RECENT_THREATS_PENALTY: int = -10  # per unresolved threat (max -30)
    SCORE_TRUSTED_DEVICE: int = 10
    SCORE_STALE_SESSION_PENALTY: int = -5

    model_config = SettingsConfigDict(
        env_file=BACKEND_DIR / ".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    def require_api_key(self, service: str) -> str:
        keys = {
            "groq": self.GROQ_API_KEY,
            "virustotal": self.VIRUSTOTAL_API_KEY,
            "abuseipdb": self.ABUSEIPDB_API_KEY,
        }
        value = keys[service].strip()
        if not value:
            raise RuntimeError(f"{service.upper()} API key is not configured")
        return value


settings = Settings()
