# ShieldSphere Features, Behavior, and Technology

## Product purpose

ShieldSphere is an enterprise account-security platform. It protects user accounts by recording access activity, detecting suspicious behavior, calculating an explainable security score, providing assessment tools, generating AI-assisted security guidance, and running authorized simulations inside an isolated Docker sandbox.

All application data is persisted in PostgreSQL. The platform does not create seeded product records, fabricated security findings, or canned AI results.

## Feature inventory

| Feature | How it works | Primary technology |
|---|---|---|
| Account registration | Validates email, username, and password requirements; checks the submitted password against HIBP; stores a bcrypt hash and breach-status metadata. | FastAPI, Pydantic, Passlib/bcrypt, HIBP k-anonymity, PostgreSQL/SQLAlchemy |
| Password login | Validates credentials, checks active IP blocks, records login history, derives a device identity, creates a server-tracked session, and starts detection in the background. | JWT, bcrypt, Redis, PostgreSQL, FastAPI background tasks |
| Token refresh and logout | Refresh tokens are verified against the active session’s stored hash and rotated on every refresh. Logout revokes the current database session. | python-jose, SHA-256 refresh-token hashes, PostgreSQL |
| Two-factor authentication | Generates a TOTP secret and QR enrollment value, confirms a live TOTP code before enabling it, and requires a temporary 2FA token during login for protected accounts. | PyOTP, QRCode/Pillow, JWT |
| Password change | Verifies the old password, checks the new password against HIBP, updates security metadata, revokes all active sessions, and requires a new login. | Passlib/bcrypt, HIBP, PostgreSQL |
| Session management | Lists active sessions only for the authenticated user. A user can revoke one session or all sessions. Expired sessions are deactivated by a scheduled job. | FastAPI, SQLAlchemy async ORM, APScheduler |
| Device management | Stores device identifiers and parsed browser/OS/device data from successful logins. Users can list, trust/untrust, or remove their own devices. | FastAPI, SQLAlchemy, device fingerprint derivation |
| Login history and locations | Records successful and failed login attempts with IP, device, outcome, location, anomaly score, and simulation flag. Aggregates known coordinates into login locations. | PostgreSQL, GeoIP2, MaxMind GeoLite2 City |
| Dashboard statistics | Calculates current counts for logins, active sessions, unresolved threats, unread alerts, devices, blocks, and success rate from persisted records. | FastAPI, SQLAlchemy aggregation queries |
| Explainable security score | Recalculates a 0–100 score from 2FA state, password breach status, unresolved threats, trusted devices, and session count. Persists both the score and factor breakdown. | PostgreSQL, SQLAlchemy, security-score service |
| Brute-force detection | Maintains a Redis sorted-set sliding window of failed attempts, creates threats/alerts when a threshold is reached, and can auto-block the IP. Unknown-account attempts are stored using a hash of the attempted identifier. | Redis, PostgreSQL, APScheduler, threat-detection service |
| Additional threat detection | Evaluates credential breach risk, impossible travel, unfamiliar devices, unfamiliar locations, and behavioral anomalies from actual login data. | GeoIP2, PostgreSQL, UBA engine, Groq RCA |
| Threat response | Lists, filters, inspects, and resolves the authenticated user’s threats; exposes AI root-cause analysis, remediation text, and weighted risk context when available. | FastAPI, PostgreSQL, Groq |
| Alerts and IP blocklist | Stores user alerts, tracks read state, supports bulk acknowledgement, lists active IP blocks, and permits unblocking by block record ID. | FastAPI, PostgreSQL, Redis |
| Password strength check | Evaluates a password with zxcvbn and HIBP, returning score, entropy estimate, crack-time estimate, suggestions, warning, and breach count. | zxcvbn, HIBP k-anonymity |
| Password breach check | Sends only the first five characters of the password SHA-1 hash to HIBP, persists the privacy-preserving result, and updates account breach status when needed. | hashlib, HTTPX, HIBP Pwned Passwords |
| URL reputation scan | Validates that the URL is publicly routable, submits it to VirusTotal, persists the pending scan, and polls VirusTotal in the background until it completes, errors, or times out. | VirusTotal API, HTTPX, FastAPI background tasks, PostgreSQL |
| IP reputation check | Accepts only literal IPv4/IPv6 addresses, looks them up through VirusTotal and AbuseIPDB, combines their result, and persists the full provider result. | VirusTotal API, AbuseIPDB API, HTTPX, PostgreSQL |
| Web vulnerability scan | Validates a public URL, performs real HTTP header checks, calculates a risk score from missing protections, persists findings, and requests Groq hardening advice. | HTTPX, SSRF-safe outbound HTTP service, Groq, PostgreSQL |
| Outbound-request protection | Rejects private, loopback, link-local, non-HTTP(S), credential-embedded, and unsafe redirect targets before URL-based backend probes run. | Python IP/URL validation, DNS/IP safety checks, HTTPX |
| AI security copilot | Streams an SSE response from Groq that is grounded in the authenticated user’s recent threats, alerts, score, sessions, devices, and login context. | Groq SDK, FastAPI StreamingResponse/SSE, PostgreSQL |
| AI threat analysis | When threats are created, the backend can generate root-cause narrative, attack-path hypotheses, and remediation recommendations using real incident signals. | Groq SDK, threat-detection service |
| User behavior analytics | Builds a baseline from historical login hours, devices, countries, ASNs, and login frequency. New activity receives an anomaly score; baselines can be rebuilt on demand and nightly. | PostgreSQL, SQLAlchemy, APScheduler, UBA engine |
| Executive incident reports | Aggregates real account activity over a requested period, asks Groq for an executive summary, persists the report, and makes report history available. | PostgreSQL, Groq SDK, FastAPI |
| Audit trail and GDPR export | Returns paginated audit records and generates a JSON export of the user profile, login history, threats, and audit log data at request time. | PostgreSQL, FastAPI JSONResponse |
| SQL injection simulation | Runs supplied payloads against the disposable sandbox target’s deliberately vulnerable login endpoint and persists live events/results. | Docker, Flask/SQLite target, Python requests, PostgreSQL |
| XSS simulation | Sends supplied payloads to the sandbox target, checks whether each payload is reflected unescaped, and persists event results. | Docker, Flask target, Python requests, PostgreSQL |
| Brute-force simulation | Sends real failed logins from the isolated attacker container and feeds those failures into the same brute-force detection path used by production login events. | Docker, Redis, PostgreSQL, FastAPI, Python requests |
| Port-discovery simulation | Executes an nmap service scan from the isolated attacker container against the isolated target and records returned port/service information. | Docker, python-nmap/Nmap, PostgreSQL |
| Sandbox vulnerability scan | Inspects the sandbox target’s live HTTP response headers from the attacker environment and records the result. | Docker, Python requests, PostgreSQL |
| Packet-capture simulation | Captures traffic generated inside the isolated sandbox, persists packet events, and can request an AI explanation of captured traffic. | Docker, Scapy, Groq, PostgreSQL |
| Phishing-awareness simulation | Uses caller-supplied URLs and legitimate domains, calculates real Levenshtein domain distance, performs safe reachability checks, persists challenge items, and scores submitted classifications server-side. | Python URL parsing, Levenshtein implementation, HTTPX, PostgreSQL |
| Social-engineering simulation | Uses Groq to generate a scenario for a supplied role, persists the scenario/options, and scores the selected option server-side. | Groq SDK, PostgreSQL |
| Simulation event streaming | Persists every simulation event and streams events over a user-owned WebSocket. Clients can recover an event history through the REST endpoint after reconnecting. | FastAPI WebSockets, asyncio queues, PostgreSQL |
| Simulator isolation and cleanup | Creates a unique internal Docker bridge network and disposable target/attacker containers per run, then removes containers and network when the run ends. Docker absence fails the run rather than falling back to host probing. | Docker SDK, Docker Desktop/CLI, isolated bridge networking |
| Rate limiting and security boundaries | Applies request limits to sensitive authentication routes and per-user simulator creation, validates session ownership for every protected resource, and rejects temporary 2FA tokens on protected routes. | SlowAPI, JWT validation, PostgreSQL, Redis |
| Health and verification | Exposes a database-aware health endpoint and includes scripts for migrations, tests, compilation, Alembic validation, Docker image builds, and opt-in PostgreSQL/Redis integration tests. | FastAPI, Alembic, unittest, Docker, PowerShell |

## API and user-facing capabilities

The backend API is versioned under `/api/v1` and provides these feature groups:

- `/auth`: registration, login, TOTP verification, refresh, logout, account lookup, password change, and 2FA setup/confirmation/disable.
- `/dashboard`: current statistics, explainable security score, login history, locations, and daily activity timeline.
- `/sessions` and `/devices`: session revocation and device trust/removal.
- `/threats`, `/alerts`, and `/ip-blocklist`: threat response, alert acknowledgement, and IP block management.
- `/assessment`: password strength, breach checks, URL reputation scans, IP reputation checks, and vulnerability scans.
- `/copilot`: streaming AI security chat.
- `/uba`: behavior profile, baseline rebuild, and anomaly history.
- `/simulator`: eight isolated simulator types, run history, persisted events, WebSocket feed, and challenge answers.
- `/compliance` and `/reports`: audit logs, GDPR export, incident report generation, and report history.

See [FRONTEND_INTEGRATION.md](FRONTEND_INTEGRATION.md) for the complete request/response contract, authentication flow, polling rules, simulator WebSocket behavior, and frontend implementation constraints.

## Technology stack

### API, validation, and application runtime

- Python 3.12 with FastAPI and Uvicorn.
- Pydantic v2 and pydantic-settings for request validation and environment configuration.
- Structured logging with structlog.
- SlowAPI for endpoint rate limits.
- FastAPI/Starlette WebSockets for simulator event feeds and `StreamingResponse` for AI SSE output.

### Data and background processing

- PostgreSQL is the system of record.
- SQLAlchemy 2 async ORM with psycopg 3 provides database access.
- Alembic manages schema migrations and validates model/migration alignment.
- Redis with redis-py/hiredis provides brute-force sliding windows and active IP-block lookup.
- APScheduler runs queued simulations, behavior-baseline rebuilds, expired-block cleanup, stale-session cleanup, and restart recovery.

### Authentication and account security

- python-jose creates and validates access, refresh, and temporary 2FA JWTs.
- Passlib/bcrypt securely hashes account passwords.
- PyOTP provides TOTP verification.
- qrcode and Pillow produce the 2FA enrollment QR image.

### Security intelligence and external services

- GeoIP2 and a local MaxMind GeoLite2 City database resolve IP location data.
- HTTPX and aiohttp make bounded outbound requests to HIBP, VirusTotal, AbuseIPDB, and approved public targets.
- HIBP Pwned Passwords uses SHA-1 prefix k-anonymity; plaintext passwords are not sent to HIBP.
- Groq provides security copilot streaming, threat analysis, report summaries, scenario generation, packet explanations, and hardening advice.
- zxcvbn calculates password-strength estimates.

### Isolated attack simulator

- Docker SDK controls disposable simulator networks and containers.
- Docker Desktop/CLI builds and runs the target and attacker images.
- The target is a deliberately vulnerable Flask application backed by a container-local SQLite database; it never shares the ShieldSphere production database.
- The attacker uses Python requests, Scapy, and python-nmap/Nmap to perform real probes only inside the Docker sandbox.
- The sandbox network is internal by default, preventing simulation containers from reaching the public internet.

### Quality and verification tooling

- Python `unittest` covers security boundaries, scoring, outbound URL safety, simulator utilities, and opt-in real PostgreSQL/Redis integration behavior.
- `backend/scripts/verify.ps1` runs unit tests, compilation, Alembic validation, and optionally PostgreSQL/Redis integration coverage with `-Integration`.
- Docker target/attacker images and isolated simulation smoke paths are verified locally.

## Runtime requirements

| Requirement | Why it is needed |
|---|---|
| PostgreSQL | Stores users, sessions, devices, logins, threats, alerts, scans, reports, simulations, and audit records. |
| Redis | Supports detection windows and active IP block checks. |
| Docker Desktop and Docker CLI | Required for all simulator runs and sandbox isolation. |
| Nmap | Required for open-port discovery simulations. |
| Npcap/WinPcap-compatible packet capture permissions | Required for live Scapy packet capture where applicable. |
| GeoLite2 City database | Enables geographic login-location enrichment. |
| Groq API key | Required for copilot, AI analyses, reports, generated scenarios, and AI advice. |
| VirusTotal API key | Required for URL scanning and VirusTotal IP reputation data. |
| AbuseIPDB API key | Required for supplemental IP reputation data. |

## Verification status

- PostgreSQL migrations are at Alembic head and schema validation reports no ungenerated migration operations.
- The backend test suite, source compilation, and Alembic validation pass.
- Opt-in PostgreSQL/Redis integration tests create uniquely named records and Redis keys, assert real persistence/window behavior, and clean up after themselves.
- Docker target and attacker images build successfully, and local isolated smoke checks have exercised packet capture, brute-force attempts, and vulnerability-header scanning.
- No product demo records or placeholder backend responses are required for normal operation.

