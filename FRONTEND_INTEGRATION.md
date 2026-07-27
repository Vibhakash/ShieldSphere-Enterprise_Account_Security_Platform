# ShieldSphere Frontend Integration Specification

## Purpose

ShieldSphere is an enterprise account-security platform. It lets an authenticated user manage account access, inspect login activity and risk, respond to threats, run security assessments, use AI-powered security assistance, execute isolated attack simulations, and export security/compliance data.

This document specifies product functionality and backend integration contracts only.

## Backend at a glance

- API framework: FastAPI
- Base API prefix: `/api/v1`
- Local API origin: `http://127.0.0.1:8000`
- Interactive contract: `http://127.0.0.1:8000/docs`
- Health endpoint: `GET http://127.0.0.1:8000/health`
- Data format: JSON unless an endpoint is explicitly an event stream or a download
- IDs: UUID strings
- Timestamps: ISO-8601 timestamps in UTC
- All backend state is persisted in PostgreSQL. Redis supports detection windows and temporary blocks. Docker is required for attack simulations.

## Frontend environment and transport

Use environment variables rather than hard-coding origins:

```dotenv
VITE_API_ORIGIN=http://127.0.0.1:8000
VITE_API_BASE_URL=http://127.0.0.1:8000/api/v1
VITE_SIMULATOR_WS_URL=ws://127.0.0.1:8000/api/v1/simulator/ws
```

For another frontend origin, add that exact origin to `CORS_ORIGINS` in `backend/.env`, then restart the backend. Do not expose or copy any backend secrets into frontend environment variables.

### Shared request behavior

- Send `Content-Type: application/json` for JSON requests.
- Protected HTTP endpoints accept `Authorization: Bearer <access_token>`.
- The backend also sets HTTP-only `access_token` and `refresh_token` cookies after a successful login/refresh. For same-site local development, requests may use `credentials: "include"`.
- Token values are also returned in login and refresh JSON. If the frontend is served from a separate site and cannot use cookies, use the bearer-token path. Never put tokens in URLs except for the simulator WebSocket fallback described below.
- On `401`, attempt one token refresh if a valid refresh token is available. If refresh fails, clear authenticated client state and require login.
- FastAPI errors normally have the shape `{ "detail": "message" }`. Validation failures (`422`) may contain a list in `detail`.
- Treat `429` as rate limiting and surface the backend message without repeatedly retrying.

### Public endpoints

| Method | Path | Purpose |
|---|---|---|
| GET | `/` | Service metadata and documentation path |
| GET | `/health` | API/database health result: `status`, `service`, `version`, `database` |
| POST | `/api/v1/auth/register` | Create an account |
| POST | `/api/v1/auth/login` | Password login; may start 2FA |
| POST | `/api/v1/auth/login/2fa` | Complete a 2FA login |
| POST | `/api/v1/auth/refresh` | Rotate tokens |

Every other `/api/v1/*` HTTP endpoint requires an authenticated, active session.

## Authentication and account lifecycle

### Account data contracts

`UserOut` is returned by registration and `GET /auth/me`:

```ts
type UserOut = {
  id: string;
  email: string;
  username: string;
  full_name: string | null;
  role: string;                 // normally "user"; "admin" is supported by the backend
  totp_enabled: boolean;
  is_active: boolean;
  password_breached: boolean;
  password_breach_count: number;
  created_at: string;
  last_login_at: string | null;
};

type TokenResponse = {
  access_token: string;
  refresh_token: string;
  token_type: "bearer";
  requires_2fa: boolean;
  user_id: string | null;
};
```

### Authentication API

| Method and path | Request body / query | Successful result | Functional behavior |
|---|---|---|---|
| `POST /auth/register` | `{ email, username, password, full_name? }` | `201 UserOut` | Username: 3–30 alphanumeric/underscore characters. Password: minimum 8 characters. The backend checks the password against HIBP and records its breach status. Rate limit: 5/minute. |
| `POST /auth/login` | `{ email, password, device_fingerprint?, user_agent? }` | `TokenResponse` | On normal login, stores session/device/login history, triggers threat detection, and sets cookies. If `requires_2fa: true`, do not treat the temporary `access_token` as an authenticated session. Instead present TOTP verification. Rate limit: 10/minute. |
| `POST /auth/login/2fa` | `{ code, temp_token }` | `TokenResponse` | Complete the TOTP login. Use the temporary token received from `/login`. Rate limit: 10/minute. |
| `POST /auth/refresh` | `{ refresh_token }` | rotated `TokenResponse` | Replaces both tokens and updates the active session. Rate limit: 30/minute. |
| `POST /auth/logout` | no body | `{ message }` | Revokes the current session and removes auth cookies. |
| `GET /auth/me` | no body | `UserOut` | Restore the authenticated user when the application starts. |
| `POST /auth/change-password` | `{ current_password, new_password }` | `{ message, revoked_sessions, password_breached, password_breach_count }` | The new password must be at least 8 characters and differ from the current one. All active sessions are revoked, including the current one; clear client auth state and require a new login. Rate limit: 5/minute. |
| `POST /auth/2fa/setup` | no body | `{ secret, qr_uri, qr_data_url }` | Starts TOTP setup. Use `qr_data_url` or `secret` to enroll the authenticator. It does not enable 2FA until confirmation. |
| `POST /auth/2fa/confirm` | `{ code }` | `{ message }` | Verifies the current TOTP code and enables 2FA. |
| `POST /auth/2fa/disable` | `{ code }` | `{ message }` | Verifies the current TOTP code and disables 2FA. |

### Required authentication flow

1. Register or log in with email/password.
2. If login returns `requires_2fa: false`, retain the returned token pair using the frontend’s secure token strategy and fetch `/auth/me`.
3. If login returns `requires_2fa: true`, keep only the temporary token long enough to call `/auth/login/2fa` with the user’s TOTP code. Do not call protected APIs with it.
4. After `/auth/login/2fa`, establish the authenticated session exactly as for a normal login.
5. On app initialization, use `/auth/me`. If it returns `401`, use `/auth/refresh` once when a refresh token is available; otherwise return to unauthenticated state.
6. After logout, password change, session revocation, or an unrecoverable `401`, clear all frontend credential state.

## Functional modules and API contract

### Dashboard and security score

The dashboard uses real persisted logins, sessions, threats, devices, blocks, and current account security settings. `GET /dashboard/stats` and `GET /dashboard/security-score` calculate and persist a fresh security score, so refresh them after actions that alter sessions, devices, passwords, or 2FA.

| Method and path | Query | Response |
|---|---|---|
| `GET /dashboard/stats` | none | `{ total_logins_today, successful_logins_today, failed_logins_today, active_sessions, unresolved_threats, unread_alerts, security_score, blocked_ips, login_success_rate, devices_count, last_login }` |
| `GET /dashboard/security-score` | none | `{ score, factors, computed_at }` |
| `GET /dashboard/login-history` | `page=1`, `per_page=20` | `LoginHistoryOut[]` |
| `GET /dashboard/login-locations` | none | `LoginLocationOut[]` |
| `GET /dashboard/activity-timeline` | `days=30` | `{ date, total, successes, failures }[]` |

```ts
type LoginHistoryOut = {
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

type LoginLocationOut = {
  latitude: number;
  longitude: number;
  country: string | null;
  city: string | null;
  count: number;
  last_seen: string;
};
```

`factors` is an extensible JSON object. Render it generically rather than assuming a fixed set of keys. Current keys include `2fa_enabled`, `password_safe` or `password_breached`, `unresolved_threats`, `trusted_devices`, `active_sessions`, and `final_score`.

### Sessions and recognized devices

| Method and path | Request | Response | Required behavior |
|---|---|---|---|
| `GET /sessions` | none | `SessionOut[]` | List active sessions for the current user only. |
| `DELETE /sessions/{session_id}` | path UUID | `{ message }` | Revoke that user-owned session. Refresh session and score data afterward. |
| `DELETE /sessions` | none | `{ message }` | Revoke all active sessions. The current request succeeds, but its session becomes invalid afterward. Clear auth state. |
| `GET /devices` | none | `DeviceOut[]` | List known devices for the current user. |
| `PATCH /devices/{device_id}/trust` | path UUID | `{ message, is_trusted }` | Toggles the trust state; refresh device and score data. |
| `DELETE /devices/{device_id}` | path UUID | `{ message }` | Removes a user-owned device; refresh device and score data. |

```ts
type SessionOut = {
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

type DeviceOut = {
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
```

### Threats, alerts, and IP blocks

The backend owns all detection decisions. The frontend can filter, inspect, resolve, acknowledge, and unblock; it does not create threats or alerts.

| Method and path | Query / request | Response |
|---|---|---|
| `GET /threats` | `page=1`, `per_page=20`, `severity?`, `threat_type?`, `is_resolved?`, `include_simulation=false` | `{ total, page, per_page, items: ThreatOut[] }` |
| `GET /threats/{threat_id}` | path UUID | `ThreatOut` |
| `PATCH /threats/{threat_id}/resolve` | path UUID | `{ message }` |
| `GET /alerts` | none | `{ total, unread_count, items: AlertOut[] }` |
| `PATCH /alerts/read-all` | no body | `{ message }` |
| `PATCH /alerts/{alert_id}/read` | path UUID | `{ message }` |
| `GET /ip-blocklist` | none | `IpBlocklistOut[]` |
| `DELETE /ip-blocklist/{blocklist_id}` | path UUID | `{ message }` |

```ts
type ThreatOut = {
  id: string;
  user_id: string;
  threat_type: string;
  severity: "low" | "medium" | "high" | "critical" | string;
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

type AlertOut = {
  id: string;
  user_id: string;
  threat_id: string | null;
  title: string;
  message: string;
  severity: string;
  is_read: boolean;
  created_at: string;
};

type IpBlocklistOut = {
  id: string;
  ip_address: string;
  reason: string;
  threat_type: string | null;
  auto_blocked: boolean;
  blocked_at: string;
  expires_at: string | null;
  is_active: boolean;
};
```

After resolving a threat, refresh both the threats query and dashboard score/statistics. After marking alerts read, refresh alerts and dashboard statistics. `include_simulation` defaults to `false`; enable it only when the user asks to see simulator-created threats.

### Security assessment tools

All assessment calls are authenticated. URL-based tools reject private, loopback, link-local, embedded-credential, and non-HTTP(S) targets. Do not retry a `422` URL validation error with altered network targets.

| Method and path | Request | Response / follow-up |
|---|---|---|
| `POST /assessment/password-strength` | `{ password }` | `PasswordStrengthResponse`; evaluates zxcvbn strength and HIBP breach status without persisting a general-purpose password value. |
| `POST /assessment/breach-check` | `{ password }` | `{ is_breached, breach_count, message, is_current_password, account_status_updated }`; persists a privacy-preserving SHA-1 prefix result. It updates the account status in both directions only when the tested password matches the current account password; standalone tests never alter Settings. |
| `POST /assessment/url-scan` | `{ url }` | `UrlScanOut` with initial `status` normally `pending`. Poll the single-result endpoint until `done`, `error`, or `timeout`. |
| `GET /assessment/url-scan/{scan_id}` | path UUID | `UrlScanOut` for a user-owned scan. |
| `GET /assessment/url-scans` | none | Latest 20 `UrlScanOut` records. |
| `POST /assessment/ip-reputation` | `{ ip }` | `IpReputationOut`; IP must be a literal IPv4 or IPv6 address, not a hostname. |
| `GET /assessment/ip-reputation` | none | Latest 50 `IpReputationOut` records. |
| `POST /assessment/vuln-scan` | `{ target_url }` | `VulnScanOut` with initial `status: "running"`. Poll `GET /assessment/vuln-scans` until the record is `completed` or `error`. |
| `GET /assessment/vuln-scans` | none | Latest 20 `VulnScanOut` records. |

```ts
type PasswordStrengthResponse = {
  score: 0 | 1 | 2 | 3 | 4;
  strength_label: "Very Weak" | "Weak" | "Fair" | "Strong" | "Very Strong";
  crack_time_display: string;
  suggestions: string[];
  warning: string | null;
  entropy_bits: number;
  is_breached: boolean;
  breach_count: number;
};

type UrlScanOut = {
  id: string;
  url: string;
  status: "pending" | "done" | "error" | "timeout" | string;
  malicious_count: number | null;
  suspicious_count: number | null;
  harmless_count: number | null;
  verdict: string | null;
  submitted_at: string;
  completed_at: string | null;
};

type IpReputationOut = {
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

type VulnScanOut = {
  id: string;
  target_url: string;
  status: "running" | "completed" | "error" | string;
  has_https: boolean | null;
  has_hsts: boolean | null;
  has_csp: boolean | null;
  risk_score: number | null;
  findings: Record<string, unknown> | null;
  llm_advice: string | null;
  scanned_at: string;
};
```

For URL scans, poll approximately every 5–15 seconds; the backend polls VirusTotal in the background. For vulnerability scans, poll the list endpoint at a similar interval and find the returned scan ID. Stop polling on a terminal status or when the user leaves the relevant feature.

### AI security copilot

`POST /api/v1/copilot/chat` returns a Server-Sent Events (SSE) stream, not JSON.

Request:

```json
{
  "message": "Explain my recent unresolved threats",
  "history": [
    { "role": "user", "content": "Previous message" },
    { "role": "assistant", "content": "Previous reply" }
  ]
}
```

Each chunk arrives as an SSE `data:` value. The stream ends with `data: [DONE]`. Preserve the conversation history on the client and send it in the next request. The backend automatically grounds the response in the authenticated user’s current threats, alerts, security score, sessions, devices, login history, and account state.

Use an SSE-capable POST implementation that can send the bearer token, or use the authenticated cookie path in a same-site deployment. Handle a missing/invalid Groq configuration as a request failure rather than displaying fabricated AI output.

### User behavior analytics (UBA)

| Method and path | Query / request | Response / behavior |
|---|---|---|
| `GET /uba/profile` | none | `UBAProfileOut`. If no profile exists, backend attempts a build. Returns `404` until at least 10 login samples exist. |
| `POST /uba/rebuild` | no body | `{ message: "Baseline rebuild queued" }`. The rebuild runs in the background. Refresh the profile later. |
| `GET /uba/anomalies` | `days=30` | Up to 50 noteworthy login anomalies. |

```ts
type UBAProfileOut = {
  user_id: string;
  typical_hours: Record<string, unknown> | null;
  known_device_ids: Record<string, unknown> | null;
  known_countries: Record<string, unknown> | null;
  known_asns: Record<string, unknown> | null;
  avg_logins_per_day: number | null;
  sample_count: number;
  last_updated: string;
};

type UBAAnomaly = {
  id: string;
  timestamp: string;
  ip: string;
  country: string | null;
  city: string | null;
  device_id: string | null;
  anomaly_score: number;
  success: boolean;
};
```

### Attack simulator

The simulator executes only in an isolated Docker network. It must never be represented as a generic public-target attack tool. Creation queues a persisted run; the backend worker claims it, executes it, persists events, and removes containers/network after completion.

#### Simulator API

| Method and path | Request / query | Response |
|---|---|---|
| `GET /simulator/types` | none | Available simulation type metadata. Use this as the authoritative type list. |
| `POST /simulator/run` | `SimulationRequest` | `201 SimulationOut` with initial `status: "queued"`. |
| `GET /simulator/runs` | none | Latest 20 `SimulationOut` records for the current user. |
| `GET /simulator/runs/{sim_id}` | path UUID | One user-owned `SimulationOut`. |
| `GET /simulator/runs/{sim_id}/events` | path UUID | Chronological `SimulationEventOut[]`; use after reconnect or after completion. |
| `POST /simulator/runs/{sim_id}/answers` | `{ answers: Record<string, string> }` | `SimulationAnswerResult`; only for completed phishing and social-engineering challenges. |
| `WS /simulator/ws/{sim_id}` | authentication described below | Live event feed while a simulation runs. |

```ts
type SimulationRequest = {
  sim_type:
    | "brute_force"
    | "sqli"
    | "xss"
    | "port_scan"
    | "vuln_scan"
    | "phishing"
    | "packet_capture"
    | "social_engineering";
  target_url?: string | null;
  params?: Record<string, unknown> | null;
};

type SimulationOut = {
  id: string;
  sim_type: string;
  target_url: string | null;
  status: "queued" | "running" | "completed" | "failed" | "cancelled" | string;
  summary: string | null;
  started_at: string | null;
  ended_at: string | null;
  created_at: string;
  error_message: string | null;
};

type SimulationEventOut = {
  id: string;
  event_type: string;
  severity: string | null;
  source_ip: string | null;
  payload: string | null;
  details: Record<string, unknown> | null;
  timestamp: string;
};
```

#### Simulation input requirements

The backend rate-limits each user to 5 simulation runs per hour. Validate these requirements before submission and also display the backend’s validation error if returned.

| `sim_type` | Required `params` | Optional data | Backend behavior |
|---|---|---|---|
| `brute_force` | `attacker_ip` (valid IP), `attempts` (positive integer) | `username` | Sends real failed logins to the isolated target and triggers the same brute-force detection pipeline used by normal login history. |
| `sqli` | `target_url`, `payloads` (non-empty string array) | none | Runs the payloads against the disposable sandbox target’s deliberately vulnerable login endpoint. |
| `xss` | `target_url`, `payloads` (non-empty string array) | none | Runs the payloads against the disposable sandbox target’s deliberately vulnerable search endpoint. |
| `port_scan` | `target` | `ports` | Runs nmap inside the isolated simulator environment and records open ports/services. |
| `vuln_scan` | none | `target_url` | Inspects the sandbox target’s headers from the isolated attacker environment. |
| `packet_capture` | `duration_seconds` (1–60) | none | Captures traffic generated within the isolated sandbox and emits packet records. |
| `phishing` | `urls` (non-empty array of URL strings or `{ url, description? }`), `legitimate_domains` (non-empty string array) | none | Performs domain-similarity analysis and a safe public reachability check, then creates answerable classification items. |
| `social_engineering` | none | `user_role` (defaults to `employee`) | Requests a unique AI-generated scenario and produces answerable options. |

The `sqli`, `xss`, and `port_scan` parameters are required by the current API contract, but their probes execute against the backend-created isolated sandbox target, not a public target supplied by the user.

#### Simulator runtime flow

1. Call `POST /simulator/run` and retain the returned simulation UUID.
2. Immediately open `ws://.../api/v1/simulator/ws/{simulationId}`. Browser WebSocket clients cannot normally add an Authorization header. The backend accepts the authenticated access cookie or `?token=<access_token>` query fallback. Prefer cookie authentication where available; use the query fallback only over secure transport and avoid logging the URL.
3. Also poll `GET /simulator/runs/{simulationId}` every 1–2 seconds while the status is `queued` or `running`. This covers WebSocket reconnects and makes terminal errors visible.
4. For each live event, append or update simulation state from:

```ts
type SimulationWsEvent = {
  type: string;       // e.g. start, target_ready, login_attempt, packet_captured, complete, error
  payload?: string;
  severity?: string;
  timestamp?: string;
  details?: Record<string, unknown>;
};
```

5. The socket may send `{ "type": "ping" }` after inactivity; keep it open. It sends a `complete` event at the end. If it fails or reconnects, call `GET /simulator/runs/{id}/events` to recover the full persisted ordered event history.
6. Stop polling when status is `completed`, `failed`, or `cancelled`. Surface `error_message` for failed runs.

#### Answerable simulator flows

For phishing, collect `phishing_prompt` events. `details` contains `challenge_id`, `url`, `domain`, and `reachable`. Do not infer or invent the answer; submit one lower-case answer for every prompt:

```json
{
  "answers": {
    "url_1": "phishing",
    "url_2": "legitimate"
  }
}
```

For social engineering, collect the `scenario_generated` event. Its `details` contains the generated scenario and selectable option IDs. Submit the selected ID as:

```json
{ "answers": { "choice": "<option-id>" } }
```

The answer endpoint returns:

```ts
type SimulationAnswerResult = {
  simulation_id: string;
  sim_type: "phishing" | "social_engineering" | string;
  score: number;       // percentage, 0–100
  correct: number;
  total: number;
  feedback: Array<Record<string, unknown>>;
  submitted_at: string;
};
```

An answers object must contain 1–20 string entries. It is valid to submit multiple attempts; the backend records each response with the simulation.

### Compliance and reports

| Method and path | Query | Response / behavior |
|---|---|---|
| `GET /compliance/audit-logs` | `page=1`, `per_page=50` | `AuditLogOut[]` for the current user. |
| `GET /compliance/gdpr-export` | none | JSON download with `Content-Disposition: attachment; filename=shieldsphere_gdpr_export.json`. Use a blob/download flow, not ordinary JSON state handling. |
| `POST /reports/generate` | `days=30` query parameter | `IncidentReportOut`. Builds a persisted AI executive report from real data in the selected period. |
| `GET /reports` | none | Latest 20 `IncidentReportOut` records. |

```ts
type AuditLogOut = {
  id: string;
  action: string;
  resource: string | null;
  ip_address: string | null;
  status: string;
  timestamp: string;
  details: Record<string, unknown> | null;
};

type IncidentReportOut = {
  id: string;
  title: string;
  period_start: string | null;
  period_end: string | null;
  threat_count: number | null;
  executive_summary: string | null;
  recommendations: string | null;
  generated_at: string;
};
```

The GDPR export includes profile, login history, threats, and audit logs for the authenticated user. It is user data; do not cache or send it to unrelated client-side services.

### Security workflow additions

#### Passkeys

- `GET /api/v1/auth/passkeys` lists the authenticated user's registered passkeys.
- `POST /api/v1/auth/passkeys/register/options` begins registration and returns `{ ceremony_id, options }`.
- `POST /api/v1/auth/passkeys/register/verify` accepts `{ ceremony_id, name, credential }`.
- `POST /api/v1/auth/passkeys/login/options` begins passwordless authentication without an existing session.
- `POST /api/v1/auth/passkeys/login/verify` accepts the browser credential and returns the normal token response.
- `DELETE /api/v1/auth/passkeys/{id}` removes a passkey owned by the current user.

WebAuthn challenges are one-time, expire after five minutes, and are stored server-side in Redis. The configured RP ID and origin must match the hostname and origin used by the frontend.

#### Account containment

- `GET /api/v1/security-actions/containment-preview` shows the exact containment scope.
- `POST /api/v1/security-actions/secure-account` preserves the current session, revokes other sessions, distrusts other devices, blocks source IPs from unresolved high/critical real threats, records an audit entry, and returns follow-up recommendations.

Containment does not silently change the user's password or mark threats resolved.

#### Real-time integrations

- `GET/POST /api/v1/integrations` lists or creates webhook/email channels.
- `PATCH /api/v1/integrations/{id}/toggle` pauses or resumes a channel.
- `POST /api/v1/integrations/{id}/test` sends a persisted test delivery.
- `GET /api/v1/integrations/{id}/deliveries` returns recent delivery history.
- `DELETE /api/v1/integrations/{id}` removes a channel.

Webhook creation returns the HMAC signing secret once. Webhook payloads use `X-ShieldSphere-Signature` and `X-ShieldSphere-Event` headers. Email delivery requires the backend SMTP settings documented in `README.md`.

#### Replay and Excel export

- `GET /api/v1/simulator/runs/{id}/replay` returns readable timeline stages, outcome, event counts, alerts, blocked sources, time-to-detect, and duration.
- `GET /api/v1/compliance/gdpr-export` returns an XLSX workbook. Use the response `Content-Disposition` filename and the Office Open XML content type.

## Required frontend feature coverage

Implement functional access to every module below.

1. Account registration, password login, TOTP login completion, token refresh, logout, account lookup, password change, and TOTP enable/disable.
2. Current security statistics, score factors, login history, login locations, and daily activity data.
3. Active-session management and recognized-device management.
4. Threat filtering/detail/resolve, alert listing/read/read-all, and active IP block listing/unblocking.
5. Password strength, breach check, asynchronous URL reputation scan/history, IP reputation check/history, and asynchronous web vulnerability scan/history.
6. Streaming AI security copilot conversation with persisted client-side conversation context for the current browser session.
7. Behavior-profile lookup, on-demand rebuild, and anomaly-history lookup.
8. All eight simulator types, live WebSocket events, persisted-event recovery, terminal-state handling, and phishing/social-engineering answer submission.
9. Audit-log retrieval, GDPR JSON export, report generation, and report history.

## Error and empty-state behavior

- `400`: input or state conflict, such as duplicate registration data, invalid password change, or 2FA already enabled/disabled.
- `401`: missing, expired, revoked, malformed, or temporary 2FA token used as an access token. Attempt a single refresh when applicable; otherwise clear authentication.
- `403`: inactive account or blocked source IP.
- `404`: user-owned resource not found, UBA profile cannot yet be built, or invalid simulator ownership.
- `409`: answers submitted to a simulation type that does not accept answers.
- `422`: request validation or unsafe URL rejected. Preserve the field-level backend message.
- `429`: auth/simulator rate limit reached. Do not auto-loop retries.
- `500`/`503`: service/dependency failure. External integrations may require configured Groq, VirusTotal, AbuseIPDB, HIBP connectivity, Docker, Nmap, or packet-capture permissions.

For list endpoints, an empty array or zero totals is a valid state. UBA specifically uses `404` when fewer than 10 login samples exist; this is not an application outage.

## Backend operational dependencies relevant to the frontend

- PostgreSQL and Redis must be running for normal authenticated functionality.
- Docker Desktop must be running before starting any simulator run.
- Simulator packet capture additionally depends on host packet-capture support and permissions.
- URL and IP reputation checks require the backend’s VirusTotal/AbuseIPDB configuration. AI features require the backend’s Groq configuration.
- HIBP password checks are performed server-side using k-anonymity; the frontend must send the password only to this configured backend over HTTPS in production.
- `SANDBOX_NETWORK_INTERNET_EGRESS=false` keeps simulator attack containers isolated. Do not add a frontend feature that attempts to bypass sandbox restrictions.

## Integration acceptance checklist

- [ ] The configured API origin and WebSocket origin are environment-driven.
- [ ] Protected requests attach authentication consistently and handle `401`/refresh once.
- [ ] Every documented endpoint is reachable from its corresponding frontend capability.
- [ ] URL/vulnerability scans and simulator runs use polling or streaming until a terminal status.
- [ ] Simulator events survive page/socket reconnect through `GET /simulator/runs/{id}/events`.
- [ ] Phishing and social-engineering submissions use only server-issued challenge IDs and option IDs.
- [ ] GDPR export is downloaded as a JSON file from the authenticated request.
- [ ] No API keys, database URLs, JWT secrets, or simulator Docker controls are exposed in frontend code.

## Strict frontend implementation rules

The frontend builder must follow these rules without exception:

1. Build only functionality that is backed by an endpoint or WebSocket contract documented in this file. Do not create login methods, user roles, admin settings, notification channels, integrations, actions, reports, scans, simulator capabilities, or account controls unless the corresponding backend contract exists.
2. Do not use demo records, fake metrics, static activity feeds, fabricated AI responses, hard-coded scan results, placeholder charts, or seeded user/security data. Every displayed security value must come from a successful backend response.
3. Do not create a clickable control unless it performs its documented backend action successfully. If an action has no backend endpoint, omit the control entirely.
4. Do not leave disabled controls that suggest an unavailable feature will work later. If a backend dependency is unavailable, show the backend error or an honest unavailable state instead.
5. For a successful request that returns no records, show an honest empty state, for example: `No threats recorded yet.`, `No active sessions found.`, `No scan history is available.`, `No reports have been generated yet.`, or `No anomaly data is available yet.` Do not substitute sample data.
6. For UBA profile `404`, explain that at least 10 login samples are required before a behavior profile can be built. Do not show an invented profile.
7. For asynchronous scans and simulations, show their real `queued`, `running`, `pending`, `completed`, `done`, `error`, `timeout`, or `failed` state from the API. Do not report completion until the backend returns a terminal successful status.
8. For the AI copilot, render only streamed server output. If the request fails or the AI service is unavailable, show an error state; do not generate a client-side substitute response.
9. For phishing and social-engineering simulations, use only the challenge IDs, option IDs, events, and feedback returned by the backend. Never pre-fill answers or compute substitute scores on the client.
10. Preserve backend authorization boundaries. Do not expose controls for admin-only behavior, cross-user data, direct database access, API-key management, Docker management, or unsupported integrations.
11. Handle `401`, `403`, `404`, `409`, `422`, `429`, `500`, and `503` using the real backend response. Never convert an error into a successful-looking result.
12. Before treating the frontend implementation as complete, verify every rendered action against the documented API contract and remove any control with no working backend implementation.
