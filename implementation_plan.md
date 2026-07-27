# ShieldSphere – Enterprise Account Security Platform
## Implementation Plan (for Antigravity)

> **Assumption flagged:** "brock api" is interpreted as **Groq API** (fast, free-tier LLM inference — llama-3.x / mixtral models via the `groq` Python SDK). If you meant AWS Bedrock or another provider, swap `services/llm_service.py` accordingly — everything else in this plan is provider-agnostic.

---

## 1. What This Project Is

ShieldSphere is a full-stack **enterprise account security platform** that combines real authentication security (2FA, session/device management, threat detection) with an **AI security intelligence layer** (Groq-powered copilot, root-cause analysis, behavior analytics) and an **AI Attack Simulator** — a sandboxed environment where real (but contained) attacks are executed against a dummy target so ShieldSphere's actual detection engine reacts to genuine signals, not scripted demo output.

This is a rebuild of a prior version of the project that used Railway-hosted PostgreSQL (trial expired). This version uses a **locally installed, native PostgreSQL instance** instead of any managed/cloud Postgres service.

**Core principle for the whole build: no hardcoded/mocked data anywhere in the product.** Every dashboard number, alert, score, and AI explanation must be derived from real computation over real data — including the "attack" data generated inside the sandbox.

---

## 2. Tech Stack

| Layer | Technology |
|---|---|
| Backend | **FastAPI** (Python 3.11+), Pydantic v2 |
| Database | **PostgreSQL** — native local install (not Railway, not a managed cloud service) |
| ORM/Migrations | SQLAlchemy 2.0 + Alembic |
| Frontend | **Next.js 14** (App Router), TypeScript, Tailwind CSS, shadcn/ui |
| Auth | JWT (python-jose) + HTTP-only cookies, `pyotp` for TOTP 2FA |
| Cache / Rate-limit / Pub-Sub | Redis |
| Background jobs | APScheduler (or Celery + Redis if job volume grows) |
| Realtime | WebSockets (FastAPI native) for live dashboard + simulator feed |
| LLM | **Groq API** (`groq` SDK) — Copilot, RCA, incident summaries, simulator explanations |
| Device fingerprint | FingerprintJS (frontend) |
| GeoIP | MaxMind GeoLite2 (downloaded local `.mmdb` file, via `geoip2` library) |
| Password breach check | HaveIBeenPwned **Pwned Passwords** k-Anonymity API (free, no key needed) |
| URL/IP reputation | VirusTotal API (free tier) + AbuseIPDB (free tier, optional secondary source) |
| Maps | react-leaflet (OpenStreetMap tiles — no API key needed) |
| Charts | Recharts |
| Sandbox / Attack Simulator | Docker + docker-compose (isolated bridge network), `python-nmap`, `scapy`/`pyshark`, `playwright`, `requests` |
| Containerization (whole app, optional) | Docker Compose for local dev consistency (Postgres itself still native-installed per your requirement, or containerized locally as an alternative — see §5) |

---

## 3. High-Level Architecture

```
                          ┌─────────────────────────┐
                          │   Next.js Frontend       │
                          │  (dashboard, auth, sim)  │
                          └───────────┬──────────────┘
                                      │ REST + WebSocket
                          ┌───────────▼──────────────┐
                          │      FastAPI Backend      │
                          │  ┌─────────────────────┐  │
                          │  │ Auth & Session Mgmt  │  │
                          │  │ Threat Detection Eng │  │
                          │  │ UBA Engine           │  │
                          │  │ LLM Service (Groq)   │  │
                          │  │ External API Clients │  │
                          │  │ Sandbox Manager       │  │
                          │  └─────────────────────┘  │
                          └─────┬──────────┬──────────┘
                                │          │
                     ┌──────────▼──┐   ┌───▼─────────┐
                     │ PostgreSQL   │   │   Redis      │
                     │ (native, local)│   │ (cache/pubsub)│
                     └──────────────┘   └──────────────┘
                                │
                     ┌──────────▼──────────────────┐
                     │  Sandbox Docker Network       │
                     │  (isolated, no internet egress)│
                     │  ┌───────────┐ ┌────────────┐ │
                     │  │target-app │ │attacker-sim│ │
                     │  │(vulnerable│ │(real attack│ │
                     │  │dummy app) │ │ scripts)   │ │
                     │  └───────────┘ └────────────┘ │
                     └────────────────────────────────┘
```

The sandbox network is **only spun up on-demand** when a user starts a simulation, and torn down after. Events from `target-app` flow into the *same* threat-detection code path used for real production logins — that's what makes the simulator's output genuine instead of scripted.

---

## 4. Local PostgreSQL Setup (No Railway)

1. Download and install PostgreSQL natively for your OS from postgresql.org (not a container, not a hosted service), or via your OS package manager.
2. Create a dedicated DB and user:
   ```sql
   CREATE DATABASE shieldsphere;
   CREATE USER shieldsphere_admin WITH PASSWORD '<strong-local-password>';
   GRANT ALL PRIVILEGES ON DATABASE shieldsphere TO shieldsphere_admin;
   ```
3. Backend `.env`:
   ```
   DATABASE_URL=postgresql+psycopg://shieldsphere_admin:<password>@localhost:5432/shieldsphere
   ```
4. Alembic manages all schema migrations — no manual DDL beyond initial DB/user creation.
5. **Note for Antigravity:** do not introduce Railway, Supabase, Neon, or any other managed Postgres provider anywhere in config, docs, or deployment scripts. This must remain a locally-hosted PostgreSQL instance.

---

## 5. Database Schema (Core Tables)

| Table | Purpose |
|---|---|
| `users` | account, hashed password, TOTP secret, role |
| `sessions` | active JWT sessions, device_id, expiry |
| `devices` | fingerprint, user agent, trusted flag, first_seen |
| `login_history` | every login attempt, success/fail, IP, geo, device, timestamp |
| `login_locations` | resolved lat/lng per login, for the interactive map |
| `threats` | detected threat events (type, severity, source login_history row, resolved flag) |
| `alerts` | user-facing alerts generated from threats |
| `ip_blocklist` | auto-blocked IPs, reason, expiry |
| `security_scores` | computed per-user security score + contributing factors |
| `behavior_profiles` | UBA baseline: typical login hours, devices, locations per user |
| `password_breach_checks` | HIBP check results (hash-suffix, breach count, timestamp) |
| `url_scan_results` | VirusTotal/phishing scan outputs |
| `vulnerability_scans` | website vulnerability scanner results |
| `attack_simulations` | one row per simulator run: type, status, started/ended, sandbox container ids |
| `simulation_events` | raw events captured during a simulation (real HTTP requests, packets, scan hits) |
| `audit_logs` | GDPR/compliance audit trail |
| `incident_reports` | AI-generated executive summaries tied to threats/simulations |

All AI-facing tables (`threats`, `simulation_events`, `behavior_profiles`) are the actual inputs to Groq prompts — the LLM never receives pre-written incident text, only real rows.

---

## 6. Backend Structure (FastAPI)

```
backend/
  app/
    core/            # config, security utils, JWT, deps
    db/
      models/        # SQLAlchemy models (one file per domain)
      migrations/    # Alembic
      session.py
    api/v1/
      auth.py
      sessions.py
      devices.py
      dashboard.py
      threats.py
      assessment.py      # breach checker, URL scanner, IP reputation
      copilot.py         # AI Security Copilot chat endpoint
      uba.py
      simulator.py       # Attack Simulator endpoints + WebSocket feed
      compliance.py
      reports.py
    services/
      threat_detection.py   # brute force, impossible travel, unknown device/location
      uba_engine.py          # behavior baselining + anomaly scoring
      llm_service.py         # Groq client wrapper, prompt templates
      geoip_service.py
      breach_service.py      # HIBP k-anonymity
      reputation_service.py  # VirusTotal / AbuseIPDB
      sandbox_manager.py     # spins up/tears down docker sandbox, streams events
    workers/
      auto_block.py          # background: auto-IP-block on threshold
      profile_builder.py     # background: rebuild behavior baselines
    sandbox/
      docker-compose.sim.yml
      target_app/             # deliberately vulnerable mini Flask app (SQLi/XSS endpoints, weak login)
      attacker_scripts/       # brute_force.py, sqli_probe.py, xss_probe.py, port_scan.py, phishing_clone.py
  alembic.ini
  requirements.txt
```

---

## 7. Frontend Structure (Next.js)

```
frontend/
  app/
    (auth)/login, register, verify-2fa
    dashboard/                 # security dashboard & analytics
    sessions-devices/
    threats/                   # threat feed, alerts
    assessment/                 # breach checker, URL scanner, IP checker UI
    copilot/                    # chat UI for AI Security Copilot
    simulator/                  # Attack Simulator hub + live run view
      password-strength/
      phishing-quiz/
      social-engineering/
      website-scanner/
      sqli-demo/
      xss-demo/
      packet-analyzer/
      port-discovery/
    compliance/
  components/
    charts/, maps/, security-score/, live-feed/
  lib/
    api.ts
    websocket.ts
    types.ts
```

---

## 8. Feature Implementation Breakdown

### 8.1 Authentication & Identity Security
- Email/password auth, bcrypt/argon2 hashing.
- JWT access + refresh tokens, stored in HTTP-only cookies.
- TOTP 2FA via `pyotp`, QR provisioning for Google Authenticator/Authy.
- Device fingerprinting (FingerprintJS on frontend → hash stored in `devices`).
- Session list + "log out this device" / "log out everywhere."
- Login history and geographic map (real GeoIP resolution per login, plotted via react-leaflet).

### 8.2 Security Dashboard & Analytics
- Aggregation queries (not cached fake numbers) over `login_history`, `threats`, `sessions` for: success/failure rates, active sessions, device usage breakdown, recent activity timeline.
- Security Score: computed server-side from real factors (2FA enabled, breached password, stale devices, recent unresolved threats) — recalculated on every relevant event, not a static number.

### 8.3 Intelligent Threat Detection
Runs as a service triggered on every login event (real or simulated):
- **Brute force:** sliding-window count of failed attempts per IP/user in Redis.
- **Impossible travel:** haversine distance between last two login geo-points vs. elapsed time.
- **Unknown device / unknown location:** compare against `behavior_profiles` baseline.
- Threshold breach → row in `threats` → `alerts` → optional auto entry in `ip_blocklist`.

### 8.4 Security Assessment Tools
- **Password Breach Checker:** HIBP Pwned Passwords k-anonymity (SHA-1 prefix lookup, only 5 hash chars sent — real API call, real result).
- **URL Phishing Scanner:** VirusTotal URL scan, real submission + polling for results.
- **IP Reputation Checker:** VirusTotal/AbuseIPDB real lookup.
- All results persisted, not recomputed with placeholder text.

### 8.5 AI Security Intelligence (Groq-powered)
- **AI Security Copilot:** chat endpoint that pulls the user's real recent threats/alerts/scores from Postgres, injects into a Groq prompt, returns plain-language explanation + recommendations. No canned responses.
- **User Behavior Analytics (UBA):** background job builds/updates each user's baseline (typical login hour range, common devices, common ASNs/locations) from real `login_history`; anomaly score computed per new login via statistical distance from baseline.
- **LLM Root Cause Analysis:** whenever a `threats` row is created, backend assembles the actual contributing signals (IP, device novelty, breach status, time-of-day deviation, prior alerts) and sends them to Groq to generate a root-cause narrative + attack-path hypothesis + remediation steps — grounded in that specific incident's real data.

### 8.6 AI Threat Response
- Incident summary + severity classification generated by Groq from the real `threats`/`simulation_events` rows for that incident.
- Explainable risk score: expose the actual weighted factors (not just a number) alongside the AI narrative.

### 8.7 AI Attack Simulator — Sandbox Architecture

This is the module you specifically want built around **real sandboxed execution, zero hardcoded/demo data.**

**Design:**
- `sandbox_manager.py` spins up an isolated docker-compose stack per simulation run: an internal-only bridge network (`--internal`, no internet egress), containing:
  - `target-app`: a small intentionally-vulnerable Flask/Node app with a real login form, a real SQLi-vulnerable query endpoint, and a real reflected/stored XSS endpoint, plus a couple of deliberately open/misconfigured ports for the port-scanner module.
  - `attacker-sim`: a container that runs real Python scripts (`requests`, `Playwright`) that actually execute the attack pattern against `target-app` — e.g. genuinely firing 20 failed logins in 10 seconds for the brute-force demo, genuinely sending SQLi payloads, genuinely injecting an XSS payload and checking if it reflects unescaped.
- `target-app`'s auth events are pushed (via a lightweight internal webhook) into the **same** `threat_detection.py` pipeline used for production logins, tagged with `is_simulation=true` and linked to an `attack_simulations` row. This is what guarantees the detection results are computed live, not scripted.
- Each of the 8 sub-modules maps to a real mechanism, not a mocked UI state:

| Sub-module | How it stays "real, not hardcoded" |
|---|---|
| 1. Password Strength Demonstration | Actual entropy calculation (zxcvbn or custom) + real crack-time estimate math on whatever password the user types |
| 2. Phishing Website Detection Challenge | Dynamically renders a real cloned page + a real legitimate page each round (templated, randomized), then runs actual domain-similarity (Levenshtein) and header checks the user's answer is scored against |
| 3. Social Engineering Awareness | Scenario text generated per-session by Groq (varied each run) rather than a fixed script bank; scoring based on user's actual choices |
| 4. Website Vulnerability Scanner | Runs real checks (HTTPS presence, security headers via `requests`, cookie flags, CSP) against a URL the user provides (or the sandbox target) — real HTTP responses inspected |
| 5. SQL Injection Demonstration | Real payload sent to `target-app`'s vulnerable endpoint vs. its parameterized-query sibling endpoint; the actual differing responses are shown |
| 6. XSS Demonstration | Real payload injected into `target-app`; actual DOM/response inspected for unescaped reflection |
| 7. Network Packet Analyzer | `scapy`/`pyshark` captures real packets generated during that simulation run on the sandbox network interface; Groq explains the actual captured packets |
| 8. Open Port Discovery | Real `nmap` scan against `target-app`'s container IP; real open ports/services returned, matched against a CVE reference table, Groq generates the hardening advice from those real findings |

- After each run: `sandbox_manager.py` tears the stack down, and `attack_simulations`/`simulation_events` retain the full real record for the AI Copilot and reports to reference later.
- Frontend gets a **live feed** over WebSocket during the run (real-time packet/log lines as they're generated), not a pre-recorded animation.

### 8.8 Compliance & Reporting
- GDPR report, audit logs, login audit history, user data export — all generated from real DB queries at request time.
- AI-generated executive summary via Groq, built from the real aggregated period data.

### 8.9 Automatic Response
- Auto IP blocking when `threats` severity/frequency crosses threshold (background worker, real Redis-backed rule evaluation).
- AI-generated recovery suggestions tied to the specific real incident.

---

## 9. External APIs & Keys Needed

| Service | Purpose | Key required? |
|---|---|---|
| Groq | LLM Copilot, RCA, simulator narration | Yes (free tier) |
| HaveIBeenPwned Pwned Passwords | Breach check | No (k-anonymity endpoint is keyless) |
| VirusTotal | URL/IP reputation | Yes (free tier, ~4 req/min) |
| AbuseIPDB (optional secondary) | IP reputation | Yes (free tier) |
| MaxMind GeoLite2 | GeoIP resolution | Free account, download `.mmdb` file locally |

---

## 10. Environment Variables (backend `.env`)

```
DATABASE_URL=postgresql+psycopg://shieldsphere_admin:<password>@localhost:5432/shieldsphere
REDIS_URL=redis://localhost:6379/0
JWT_SECRET=
JWT_REFRESH_SECRET=
GROQ_API_KEY=
VIRUSTOTAL_API_KEY=
ABUSEIPDB_API_KEY=
GEOLITE2_DB_PATH=./data/GeoLite2-City.mmdb
SANDBOX_NETWORK_INTERNET_EGRESS=false
```

---

## 11. Development Phases

- [ ] **Phase 0 — Foundations:** local Postgres install, Alembic init, base FastAPI + Next.js scaffolds, JWT auth, TOTP 2FA.
- [ ] **Phase 1 — Sessions & Devices:** device fingerprinting, session list, login history, login map.
- [ ] **Phase 2 — Threat Detection Engine:** brute force / impossible travel / unknown device-location detectors, alerts, auto-blocking.
- [ ] **Phase 3 — Dashboard & Analytics:** real aggregation endpoints + charts, security score engine.
- [ ] **Phase 4 — Assessment Tools:** HIBP, VirusTotal, IP reputation integrations.
- [ ] **Phase 5 — AI Layer:** Groq service wrapper, Copilot chat, LLM RCA on threat creation, UBA baseline + anomaly scoring.
- [ ] **Phase 6 — Attack Simulator Sandbox:** docker-compose sandbox stack, `target-app`, attacker scripts, sandbox_manager, WebSocket live feed, all 8 sub-modules wired to real detection pipeline.
- [ ] **Phase 7 — Compliance & Reporting:** audit logs, GDPR export, AI executive summaries.
- [ ] **Phase 8 — Polish:** security hardening review, rate limiting, error handling, deployment scripts (local/self-hosted, no Railway).

---

## 12. Security & Isolation Notes for the Sandbox

- Sandbox docker network must be `internal: true` (no route to the internet) so simulated attacks can never reach anything outside the sandbox.
- `target-app` is a separate, disposable container — never shares the production database or codebase.
- Simulation containers are ephemeral: created per run, destroyed after, so no simulation data lingers as an attack surface.
- Rate-limit simulator runs per user to prevent resource exhaustion on the host machine.

---

## 13. Deployment (No Railway)

Since PostgreSQL is a native local install per your requirement, deployment options for the rest of the stack:
- **Local-only / self-hosted for now:** run FastAPI (uvicorn), Next.js, Redis, and the sandbox stack all on your machine or a VM you control.
- If you later want a public deployment, options that keep Postgres separate/native include a VPS (e.g., a basic Linux box) where you install Postgres natively yourself rather than using any managed database add-on — flag this explicitly to Antigravity so it doesn't default back to a managed Postgres provider.

---

## 14. Requirements From the Project Owner

The owner must provide these machine-level services, accounts, keys, and permissions before every backend feature can be tested end to end. Never commit real secrets to Git or include them in screenshots or logs.

### Required software

1. Python 3.11+ and the existing `backend/venv` environment.
2. PostgreSQL installed locally and running as a Windows service.
3. Redis running locally or at the configured `REDIS_URL`.
4. Docker Desktop with Docker Compose v2 and the Docker CLI.
5. Nmap available on `PATH` for local port scans.
6. Npcap with WinPcap-compatible mode for Scapy packet capture on Windows.

### Required accounts and files

| Requirement | Purpose | Owner-provided value |
|---|---|---|
| Groq account | Copilot, RCA, reports, explanations, scenarios | `GROQ_API_KEY` |
| VirusTotal account | URL scans and IP reputation | `VIRUSTOTAL_API_KEY` |
| AbuseIPDB account | Secondary IP reputation | `ABUSEIPDB_API_KEY` |
| MaxMind account | GeoIP lookup | Current `GeoLite2-City.mmdb` |
| PostgreSQL account | Application persistence | Database, username, and strong password in `DATABASE_URL` |

HIBP Pwned Passwords does not require an API key.

### Required `backend/.env` values

```dotenv
DATABASE_URL=postgresql+psycopg://shieldsphere_admin:<url-encoded-password>@localhost:5432/shieldsphere
REDIS_URL=redis://localhost:6379/0
JWT_SECRET=<long-random-secret>
JWT_REFRESH_SECRET=<different-long-random-secret>
JWT_ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=30
REFRESH_TOKEN_EXPIRE_DAYS=7
GROQ_API_KEY=<groq-key>
VIRUSTOTAL_API_KEY=<virustotal-key>
ABUSEIPDB_API_KEY=<abuseipdb-key>
GEOLITE2_DB_PATH=./data/GeoLite2-City.mmdb
SANDBOX_NETWORK_INTERNET_EGRESS=false
APP_ENV=development
CORS_ORIGINS=http://localhost:3000
```

Generate two independent JWT secrets:

```powershell
python -c "import secrets; print(secrets.token_urlsafe(64))"
python -c "import secrets; print(secrets.token_urlsafe(64))"
```

Use the first output for `JWT_SECRET` and the second for `JWT_REFRESH_SECRET`.

## 15. Owner Setup Steps (Windows PowerShell)

Run these commands from the project root unless the step says otherwise.

### Step 1 — Create PostgreSQL database and user

Open `psql` as the PostgreSQL administrator and run:

```sql
CREATE USER shieldsphere_admin WITH PASSWORD '<strong-unique-password>';
CREATE DATABASE shieldsphere OWNER shieldsphere_admin;
GRANT ALL PRIVILEGES ON DATABASE shieldsphere TO shieldsphere_admin;
```

URL-encode special characters in the password before putting it in `DATABASE_URL`. Verify PostgreSQL:

```powershell
Get-Service *postgres*
```

### Step 2 — Start and verify Redis

Start the owner's Redis installation and run:

```powershell
redis-cli ping
```

The expected response is `PONG`. If Redis is remote, update `REDIS_URL`; do not switch application technology.

### Step 3 — Install and verify Docker Desktop

Install and start Docker Desktop, wait until its engine is ready, then run:

```powershell
docker version
docker compose version
docker compose -f backend/sandbox/docker-compose.sim.yml build
```

Do not change the sandbox network setting `internal: true`.

### Step 4 — Install Nmap and Npcap

Install Nmap and Npcap. Enable WinPcap API-compatible mode during Npcap setup. Open a new elevated PowerShell terminal and verify:

```powershell
nmap --version
backend\venv\Scripts\python.exe -c "from scapy.all import get_if_list; print('\n'.join(get_if_list()))"
```

Run live packet capture with administrator permission and only on interfaces the owner is authorized to inspect.

### Step 5 — Add the GeoLite2 database

Download the current GeoLite2 City database from the owner's MaxMind account and place the extracted file at:

```text
backend/data/GeoLite2-City.mmdb
```

Confirm `GEOLITE2_DB_PATH` points to it.

### Step 6 — Configure secrets and API keys

Add the Groq, VirusTotal, AbuseIPDB, database, Redis, and JWT values to `backend/.env`. Do not put real values in Markdown files, source files, API requests, or Git commits.

### Step 7 — Install backend dependencies

```powershell
backend\venv\Scripts\python.exe -m pip install -r backend\requirements.txt
```

### Step 8 — Apply and verify migrations

```powershell
Set-Location backend
venv\Scripts\alembic.exe upgrade head
venv\Scripts\alembic.exe current
venv\Scripts\alembic.exe check
Set-Location ..
```

The current revision must be migration head and the check must report no new upgrade operations.

### Step 9 — Start and verify the backend

```powershell
Set-Location backend
venv\Scripts\python.exe -m uvicorn main:app --reload --host 127.0.0.1 --port 8000
```

Keep that terminal running. In another terminal run:

```powershell
Invoke-RestMethod http://127.0.0.1:8000/health
```

The response should contain `status: ok` and `database: ok`. Local API documentation is available at `http://127.0.0.1:8000/docs`.

### Step 10 — Final checklist

- PostgreSQL is running and Alembic is at head.
- Redis returns `PONG`.
- Docker Desktop is running and both sandbox images build.
- Nmap is available on `PATH`.
- Npcap is installed; packet capture has administrator permission.
- `backend/data/GeoLite2-City.mmdb` exists.
- Required API keys and independent JWT secrets are configured but not committed.
- `/health` reports both API and database healthy.
