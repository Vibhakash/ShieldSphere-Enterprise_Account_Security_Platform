export type UserOut = {
  id: string;
  email: string;
  username: string;
  full_name: string | null;
  role: string;
  totp_enabled: boolean;
  is_active: boolean;
  password_breached: boolean;
  password_breach_count: number;
  created_at: string;
  last_login_at: string | null;
};

export type TokenResponse = {
  access_token: string;
  refresh_token: string;
  token_type: "bearer";
  requires_2fa: boolean;
  user_id: string | null;
};

export type DashboardStats = {
  total_logins_today: number;
  successful_logins_today: number;
  failed_logins_today: number;
  active_sessions: number;
  unresolved_threats: number;
  unread_alerts: number;
  security_score: number;
  blocked_ips: number;
  login_success_rate: number;
  devices_count: number;
  last_login: string | null;
  simulation_threats: number;
  simulation_alerts: number;
  simulation_login_attempts: number;
};

export type SecurityScore = {
  score: number;
  factors: Record<string, unknown>;
  computed_at: string;
};

export type LoginHistoryOut = {
  id: string;
  ip_address: string;
  country: string | null;
  country_code: string | null;
  city: string | null;
  latitude: number | null;
  longitude: number | null;
  device_id: string | null;
  user_agent: string | null;
  success: boolean;
  failure_reason: string | null;
  anomaly_score: number | null;
  is_simulation: boolean;
  timestamp: string;
};

export type LoginLocationOut = {
  latitude: number;
  longitude: number;
  country: string | null;
  city: string | null;
  count: number;
  last_seen: string;
};

export type ActivityDay = { date: string; total: number; successes: number; failures: number };

export type SessionOut = {
  id: string;
  device_id: string | null;
  ip_address: string | null;
  user_agent: string | null;
  is_active: boolean;
  last_used_at: string | null;
  expires_at: string | null;
  created_at: string;
  country: string | null;
  country_code: string | null;
  city: string | null;
  latitude: number | null;
  longitude: number | null;
};

export type DeviceOut = {
  id: string;
  device_id: string;
  browser: string | null;
  os: string | null;
  device_type: string | null;
  is_trusted: boolean;
  first_seen: string;
  last_seen: string | null;
  last_ip: string | null;
  country: string | null;
  country_code: string | null;
  city: string | null;
  latitude: number | null;
  longitude: number | null;
};

export type ThreatOut = {
  id: string;
  user_id: string;
  threat_type: string;
  severity: string;
  title: string;
  description: string | null;
  source_ip: string | null;
  source_country: string | null;
  details: Record<string, unknown> | null;
  llm_rca: string | null;
  llm_remediation: string | null;
  risk_score: number | null;
  is_resolved: boolean;
  resolved_at: string | null;
  auto_blocked: boolean;
  is_simulation: boolean;
  detected_at: string;
};

export type AlertOut = {
  id: string;
  user_id: string;
  threat_id: string | null;
  title: string;
  message: string;
  severity: string;
  source_ip: string | null;
  is_simulation: boolean;
  is_read: boolean;
  created_at: string;
};

export type IpBlocklistOut = {
  id: string;
  user_id: string | null;
  ip_address: string;
  reason: string;
  threat_type: string | null;
  auto_blocked: boolean;
  blocked_at: string;
  expires_at: string | null;
  is_active: boolean;
  scope: "account" | "global";
  can_unblock: boolean;
};

export type PasswordStrengthResponse = {
  score: 0 | 1 | 2 | 3 | 4;
  strength_label: string;
  crack_time_display: string;
  suggestions: string[];
  warning: string | null;
  entropy_bits: number;
  is_breached: boolean;
  breach_count: number;
};

export type BreachCheckResponse = {
  is_breached: boolean;
  breach_count: number;
  message: string;
  is_current_password: boolean;
  account_status_updated: boolean;
};

export type UrlScanOut = {
  id: string;
  url: string;
  status: string;
  malicious_count: number | null;
  suspicious_count: number | null;
  harmless_count: number | null;
  verdict: string | null;
  submitted_at: string;
  completed_at: string | null;
};

export type IpReputationOut = {
  id: string;
  ip_address: string;
  overall_verdict: string;
  virustotal_malicious: number | null;
  virustotal_suspicious: number | null;
  abuse_confidence_score: number | null;
  abuse_total_reports: number | null;
  raw_results: Record<string, unknown>;
  checked_at: string;
};

export type VulnScanOut = {
  id: string;
  target_url: string;
  status: string;
  has_https: boolean | null;
  has_hsts: boolean | null;
  has_csp: boolean | null;
  risk_score: number | null;
  findings: Record<string, unknown> | null;
  llm_advice: string | null;
  scanned_at: string;
};

export type UBAProfileOut = {
  user_id: string;
  typical_hours: Record<string, unknown> | null;
  known_device_ids: Record<string, unknown> | null;
  known_countries: Record<string, unknown> | null;
  known_asns: Record<string, unknown> | null;
  avg_logins_per_day: number | null;
  sample_count: number;
  last_updated: string;
};

export type UBAAnomaly = {
  id: string;
  timestamp: string;
  ip: string;
  country: string | null;
  city: string | null;
  device_id: string | null;
  anomaly_score: number;
  success: boolean;
};

export type UBADeviceEvent = {
  event_type: string;
  timestamp: string;
  ip_address: string | null;
  location: string | null;
  details: string | null;
};

export type UBADeviceActivity = {
  device_id: string;
  name: string;
  browser: string | null;
  os: string | null;
  device_type: string | null;
  is_trusted: boolean;
  is_active: boolean;
  last_ip: string | null;
  location: string | null;
  first_seen: string | null;
  last_seen: string | null;
  last_login: string | null;
  last_logout: string | null;
  last_activity: string | null;
  events: UBADeviceEvent[];
};

export type SimType =
  | "brute_force"
  | "sqli"
  | "xss"
  | "port_scan"
  | "vuln_scan"
  | "phishing"
  | "packet_capture"
  | "social_engineering";

export type SimulationOut = {
  id: string;
  sim_type: string;
  target_url: string | null;
  status: string;
  summary: string | null;
  started_at: string | null;
  ended_at: string | null;
  created_at: string;
  error_message: string | null;
};

export type SimulationEventOut = {
  id: string;
  event_type: string;
  severity: string | null;
  source_ip: string | null;
  payload: string | null;
  details: Record<string, unknown> | null;
  timestamp: string;
};

export type SimulationAnswerResult = {
  simulation_id: string;
  sim_type: string;
  score: number;
  correct: number;
  total: number;
  feedback: Array<Record<string, unknown>>;
  submitted_at: string;
};

export type AuditLogOut = {
  id: string;
  action: string;
  resource: string | null;
  ip_address: string | null;
  status: string;
  timestamp: string;
  details: Record<string, unknown> | null;
};

export type IncidentReportOut = {
  id: string;
  title: string;
  period_start: string | null;
  period_end: string | null;
  threat_count: number | null;
  executive_summary: string | null;
  recommendations: string | null;
  generated_at: string;
};

export type PasskeyOut = {
  id: string;
  name: string;
  device_type: string | null;
  backed_up: boolean;
  transports: string[] | null;
  created_at: string;
  last_used_at: string | null;
};

export type IntegrationOut = {
  id: string;
  name: string;
  integration_type: "webhook" | "email";
  destination_hint: string;
  minimum_severity: "low" | "medium" | "high" | "critical";
  include_simulations: boolean;
  is_active: boolean;
  created_at: string;
  last_delivery_at: string | null;
  last_delivery_status: string | null;
  last_error: string | null;
  signing_secret?: string | null;
};

export type IntegrationDeliveryOut = {
  id: string;
  integration_id: string;
  alert_id: string | null;
  event_type: string;
  status: string;
  response_code: number | null;
  error_message: string | null;
  attempted_at: string;
};

export type ContainmentPreview = {
  other_active_sessions: number;
  other_devices: number;
  serious_unresolved_threats: number;
  blockable_source_ips: number;
  current_session_preserved: boolean;
};

export type ContainmentResult = {
  sessions_revoked: number;
  devices_distrusted: number;
  ips_blocked: number;
  threats_contained: number;
  current_session_preserved: boolean;
  recommendations: string[];
  completed_at: string;
};

export type ReplayStage = {
  phase: "prepare" | "attack" | "detect" | "analyze" | "contain" | "verify" | "observe";
  title: string;
  description: string;
  status: string;
  severity: string | null;
  timestamp: string | null;
  evidence: Record<string, unknown>;
};

export type SimulationReplayOut = {
  simulation_id: string;
  sim_type: string;
  status: string;
  outcome: string;
  attack_events: number;
  threats_detected: number;
  alerts_generated: number;
  source_ips_blocked: number;
  time_to_detect_ms: number | null;
  duration_ms: number | null;
  timeline: ReplayStage[];
};
