from datetime import datetime
from typing import Optional, List, Dict, Any, Literal
from uuid import UUID
from ipaddress import ip_address
from pydantic import BaseModel, field_validator


class ThreatOut(BaseModel):
    id: UUID
    user_id: UUID
    threat_type: str
    severity: str
    title: str
    description: Optional[str]
    source_ip: Optional[str]
    source_country: Optional[str]
    details: Optional[Dict[str, Any]]
    llm_rca: Optional[str]
    llm_remediation: Optional[str]
    risk_score: Optional[float]
    is_resolved: bool
    resolved_at: Optional[datetime]
    auto_blocked: bool
    is_simulation: bool
    detected_at: datetime

    model_config = {"from_attributes": True}


class AlertOut(BaseModel):
    id: UUID
    user_id: UUID
    threat_id: Optional[UUID]
    title: str
    message: str
    severity: str
    source_ip: Optional[str] = None
    is_simulation: bool = False
    is_read: bool
    created_at: datetime

    model_config = {"from_attributes": True}


class ThreatListResponse(BaseModel):
    total: int
    page: int
    per_page: int
    items: List[ThreatOut]


class AlertListResponse(BaseModel):
    total: int
    unread_count: int
    items: List[AlertOut]


class DashboardStats(BaseModel):
    total_logins_today: int
    successful_logins_today: int
    failed_logins_today: int
    active_sessions: int
    unresolved_threats: int
    unread_alerts: int
    security_score: int
    blocked_ips: int
    login_success_rate: float  # 0-100
    devices_count: int
    last_login: Optional[datetime]
    simulation_threats: int = 0
    simulation_alerts: int = 0
    simulation_login_attempts: int = 0


class SecurityScoreBreakdown(BaseModel):
    score: int
    factors: Dict[str, Any]
    computed_at: datetime


class LoginHistoryOut(BaseModel):
    id: UUID
    ip_address: str
    country: Optional[str]
    country_code: Optional[str]
    city: Optional[str]
    latitude: Optional[float]
    longitude: Optional[float]
    device_id: Optional[str]
    user_agent: Optional[str]
    success: bool
    failure_reason: Optional[str]
    anomaly_score: Optional[float]
    is_simulation: bool
    timestamp: datetime

    model_config = {"from_attributes": True}


class LoginLocationOut(BaseModel):
    latitude: float
    longitude: float
    country: Optional[str]
    city: Optional[str]
    count: int
    last_seen: datetime


class SessionOut(BaseModel):
    id: UUID
    device_id: Optional[str]
    ip_address: Optional[str]
    user_agent: Optional[str]
    is_active: bool
    last_used_at: Optional[datetime]
    expires_at: Optional[datetime]
    created_at: datetime
    country: Optional[str] = None
    country_code: Optional[str] = None
    city: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None

    model_config = {"from_attributes": True}


class DeviceOut(BaseModel):
    id: UUID
    device_id: str
    browser: Optional[str]
    os: Optional[str]
    device_type: Optional[str]
    is_trusted: bool
    first_seen: datetime
    last_seen: Optional[datetime]
    last_ip: Optional[str]
    country: Optional[str] = None
    country_code: Optional[str] = None
    city: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None

    model_config = {"from_attributes": True}


class BreachCheckRequest(BaseModel):
    password: str


class BreachCheckResponse(BaseModel):
    is_breached: bool
    breach_count: int
    message: str
    is_current_password: bool
    account_status_updated: bool


class UrlScanRequest(BaseModel):
    url: str


class UrlScanOut(BaseModel):
    id: UUID
    url: str
    status: str
    malicious_count: Optional[int]
    suspicious_count: Optional[int]
    harmless_count: Optional[int]
    verdict: Optional[str]
    submitted_at: datetime
    completed_at: Optional[datetime]

    model_config = {"from_attributes": True}


class IpReputationRequest(BaseModel):
    ip: str

    @field_validator("ip")
    @classmethod
    def valid_ip_address(cls, value: str) -> str:
        try:
            return str(ip_address(value.strip()))
        except ValueError as exc:
            raise ValueError("A valid IPv4 or IPv6 address is required") from exc


class IpReputationOut(BaseModel):
    id: UUID
    ip_address: str
    overall_verdict: str
    virustotal_malicious: Optional[int]
    virustotal_suspicious: Optional[int]
    abuse_confidence_score: Optional[int]
    abuse_total_reports: Optional[int]
    raw_results: Dict[str, Any]
    checked_at: datetime

    model_config = {"from_attributes": True}


class IpBlocklistOut(BaseModel):
    id: UUID
    user_id: Optional[UUID]
    ip_address: str
    reason: str
    threat_type: Optional[str]
    auto_blocked: bool
    blocked_at: datetime
    expires_at: Optional[datetime]
    is_active: bool
    scope: Literal["account", "global"]
    can_unblock: bool

    model_config = {"from_attributes": True}


class IpBlockCreate(BaseModel):
    ip_address: str
    reason: str
    duration: Literal["1h", "24h", "7d", "permanent"]

    @field_validator("ip_address")
    @classmethod
    def normalize_ip(cls, value: str) -> str:
        try:
            return str(ip_address(value.strip()))
        except ValueError as exc:
            raise ValueError("Enter a valid IPv4 or IPv6 address") from exc

    @field_validator("reason")
    @classmethod
    def validate_reason(cls, value: str) -> str:
        normalized = value.strip()
        if not 3 <= len(normalized) <= 255:
            raise ValueError("Reason must be between 3 and 255 characters")
        return normalized


class VulnScanRequest(BaseModel):
    target_url: str


class VulnScanOut(BaseModel):
    id: UUID
    target_url: str
    status: str
    has_https: Optional[bool]
    has_hsts: Optional[bool]
    has_csp: Optional[bool]
    risk_score: Optional[int]
    findings: Optional[Dict[str, Any]]
    llm_advice: Optional[str]
    scanned_at: datetime

    model_config = {"from_attributes": True}


class SimulationRequest(BaseModel):
    sim_type: str
    target_url: Optional[str] = None
    params: Optional[Dict[str, Any]] = None


class SimulationOut(BaseModel):
    id: UUID
    sim_type: str
    target_url: Optional[str]
    status: str
    summary: Optional[str]
    started_at: Optional[datetime]
    ended_at: Optional[datetime]
    created_at: datetime
    error_message: Optional[str]

    model_config = {"from_attributes": True}


class SimulationEventOut(BaseModel):
    id: UUID
    event_type: str
    severity: Optional[str]
    source_ip: Optional[str]
    payload: Optional[str]
    details: Optional[Dict[str, Any]]
    timestamp: datetime

    model_config = {"from_attributes": True}


class SimulationAnswerRequest(BaseModel):
    answers: Dict[str, str]

    @field_validator("answers")
    @classmethod
    def answers_are_present_and_bounded(cls, value: Dict[str, str]) -> Dict[str, str]:
        if not value or len(value) > 20:
            raise ValueError("Submit between 1 and 20 answers")
        normalized = {}
        for key, answer in value.items():
            if not isinstance(key, str) or not isinstance(answer, str):
                raise ValueError("Answer keys and values must be strings")
            normalized[key.strip()] = answer.strip().lower()
        return normalized


class SimulationAnswerResult(BaseModel):
    simulation_id: UUID
    sim_type: str
    score: float
    correct: int
    total: int
    feedback: List[Dict[str, Any]]
    submitted_at: datetime


class CopilotMessage(BaseModel):
    role: str
    content: str


class CopilotRequest(BaseModel):
    message: str
    history: List[CopilotMessage] = []


class AuditLogOut(BaseModel):
    id: UUID
    action: str
    resource: Optional[str]
    ip_address: Optional[str]
    status: str
    timestamp: datetime
    details: Optional[Dict[str, Any]]

    model_config = {"from_attributes": True}


class UBAProfileOut(BaseModel):
    user_id: UUID
    typical_hours: Optional[Dict]
    known_device_ids: Optional[Dict]
    known_countries: Optional[Dict]
    known_asns: Optional[Dict]
    avg_logins_per_day: Optional[float]
    sample_count: int
    last_updated: datetime

    model_config = {"from_attributes": True}


class UBADeviceEventOut(BaseModel):
    event_type: str
    timestamp: datetime
    ip_address: Optional[str] = None
    location: Optional[str] = None
    details: Optional[str] = None


class UBADeviceActivityOut(BaseModel):
    device_id: str
    name: str
    browser: Optional[str] = None
    os: Optional[str] = None
    device_type: Optional[str] = None
    is_trusted: bool = False
    is_active: bool = False
    last_ip: Optional[str] = None
    location: Optional[str] = None
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    last_login: Optional[datetime] = None
    last_logout: Optional[datetime] = None
    last_activity: Optional[datetime] = None
    events: List[UBADeviceEventOut] = []


class IncidentReportOut(BaseModel):
    id: UUID
    title: str
    period_start: Optional[datetime]
    period_end: Optional[datetime]
    threat_count: Optional[int]
    executive_summary: Optional[str]
    recommendations: Optional[str]
    generated_at: datetime

    model_config = {"from_attributes": True}


class PasswordStrengthRequest(BaseModel):
    password: str


class PasswordStrengthResponse(BaseModel):
    score: int  # 0-4 (zxcvbn)
    strength_label: str  # Very Weak, Weak, Fair, Strong, Very Strong
    crack_time_display: str
    suggestions: List[str]
    warning: Optional[str]
    entropy_bits: float
    is_breached: bool
    breach_count: int


class PasskeyOut(BaseModel):
    id: UUID
    name: str
    device_type: Optional[str]
    backed_up: bool
    transports: Optional[List[str]]
    created_at: datetime
    last_used_at: Optional[datetime]

    model_config = {"from_attributes": True}


class IntegrationCreate(BaseModel):
    name: str
    integration_type: str
    destination: str
    minimum_severity: str = "medium"
    include_simulations: bool = True

    @field_validator("name")
    @classmethod
    def valid_integration_name(cls, value: str) -> str:
        value = value.strip()
        if not 1 <= len(value) <= 100:
            raise ValueError("Integration name must be between 1 and 100 characters")
        return value

    @field_validator("integration_type")
    @classmethod
    def valid_integration_type(cls, value: str) -> str:
        value = value.strip().lower()
        if value not in {"webhook", "email"}:
            raise ValueError("Integration type must be webhook or email")
        return value

    @field_validator("minimum_severity")
    @classmethod
    def valid_minimum_severity(cls, value: str) -> str:
        value = value.strip().lower()
        if value not in {"low", "medium", "high", "critical"}:
            raise ValueError("Minimum severity must be low, medium, high, or critical")
        return value


class IntegrationOut(BaseModel):
    id: UUID
    name: str
    integration_type: str
    destination_hint: str
    minimum_severity: str
    include_simulations: bool
    is_active: bool
    created_at: datetime
    last_delivery_at: Optional[datetime]
    last_delivery_status: Optional[str]
    last_error: Optional[str]


class IntegrationCreated(IntegrationOut):
    signing_secret: Optional[str] = None


class IntegrationDeliveryOut(BaseModel):
    id: UUID
    integration_id: UUID
    alert_id: Optional[UUID]
    event_type: str
    status: str
    response_code: Optional[int]
    error_message: Optional[str]
    attempted_at: datetime

    model_config = {"from_attributes": True}


class ContainmentPreview(BaseModel):
    other_active_sessions: int
    other_devices: int
    serious_unresolved_threats: int
    blockable_source_ips: int
    current_session_preserved: bool = True


class ContainmentResult(BaseModel):
    sessions_revoked: int
    devices_distrusted: int
    ips_blocked: int
    threats_contained: int
    current_session_preserved: bool
    recommendations: List[str]
    completed_at: datetime


class ReplayStage(BaseModel):
    phase: str
    title: str
    description: str
    status: str
    severity: Optional[str] = None
    timestamp: Optional[datetime] = None
    evidence: Dict[str, Any] = {}


class SimulationReplayOut(BaseModel):
    simulation_id: UUID
    sim_type: str
    status: str
    outcome: str
    attack_events: int
    threats_detected: int
    alerts_generated: int
    source_ips_blocked: int
    time_to_detect_ms: Optional[int]
    duration_ms: Optional[int]
    timeline: List[ReplayStage]
