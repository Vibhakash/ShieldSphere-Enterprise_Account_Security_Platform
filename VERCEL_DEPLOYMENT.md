# ShieldSphere: GitHub and Vercel Deployment

This guide deploys the React/Vite frontend on Vercel and the complete
ShieldSphere backend on a Docker-capable Linux server.

## 1. Supported production architecture

| Component | Production location |
|---|---|
| React/Vite frontend | Vercel |
| FastAPI API and migrations | Docker-capable Linux server |
| PostgreSQL | Production Compose stack or managed PostgreSQL |
| Redis | Production Compose stack or managed Redis |
| HTTPS/API reverse proxy | Caddy in the production Compose stack |
| Docker attack simulator | Dedicated Docker-capable backend host only |
| Background security jobs | Long-running backend process |

Vercel supports FastAPI through Python Functions, but deploying this complete
backend as a Vercel Function would disable or weaken important functionality:

- The attack simulator creates isolated Docker containers and needs a Docker
  daemon.
- The embedded APScheduler jobs need a long-running process. Vercel Functions
  scale down and should use Vercel Cron or a separate worker instead.
- Realtime connections are limited by a function invocation's lifetime and must
  keep durable state outside the process.
- The function filesystem is read-only except for temporary `/tmp` storage.

Official references:

- [Vite on Vercel](https://vercel.com/docs/frameworks/frontend/vite)
- [FastAPI on Vercel](https://vercel.com/docs/frameworks/backend/fastapi)
- [Vercel Function limits](https://vercel.com/docs/functions/limitations)
- [Vercel Python runtime](https://vercel.com/docs/functions/runtimes/python)
- [Vercel runtime filesystem](https://vercel.com/docs/functions/runtimes)

For every ShieldSphere feature to work, use Vercel for the frontend and the
existing Docker deployment for the backend.

## 2. Domain plan

Use two subdomains under the same parent domain:

```text
security.example.com      -> Vercel frontend
api.security.example.com  -> backend server
```

Related custom domains are important for secure cookie authentication and
passkeys. A `*.vercel.app` frontend combined with an unrelated backend domain
can make browser cookie rules and WebAuthn configuration unreliable.

Do not use wildcard CORS. ShieldSphere intentionally requires the exact frontend
HTTPS origin.

## 3. Local release verification

From the repository root:

```powershell
cd backend
.\venv\Scripts\python.exe -m pip install -r requirements.txt
.\venv\Scripts\python.exe -m pytest -q
.\venv\Scripts\python.exe -m pip check
.\venv\Scripts\python.exe -m pip_audit -r requirements.txt
cd ..\frontend
npm ci
npm audit
npm run lint
npm run build
cd ..
```

If the host certificate store prevents `pip-audit` from contacting its advisory
service, run the audit in a disposable container without disabling TLS:

```powershell
docker run --rm -v "${PWD}\backend\requirements.txt:/requirements.txt:ro" python:3.12-slim sh -c "python -m pip install --quiet pip-audit==2.10.1 && python -m pip_audit -r /requirements.txt --progress-spinner off"
```

## 4. Prepare Git safely

Never commit:

```text
backend/.env
backend/.env.production
frontend/.env
frontend/.env.local
frontend/.vercel/
backend/data/GeoLite2-City.mmdb
*.pem, *.key, *.p12, *.pfx
database dumps and local logs
```

They are covered by the repository `.gitignore`. Verify before staging:

```powershell
git status --ignored
git check-ignore -v backend/.env frontend/.env backend/data/GeoLite2-City.mmdb
```

The three paths should be reported as ignored. Do not use `git add -f`.

Run a credential-oriented source scan:

```powershell
git grep -n -I -E "BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY|ghp_[A-Za-z0-9]+|sk-[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16}"
```

No result is expected. Placeholder values in `.env.example` are expected and
must not be real credentials.

### Brand-new, empty GitHub repository

```powershell
git init
git add .
git status
git commit -m "Prepare ShieldSphere for production deployment"
git branch -M main
git remote add origin https://github.com/YOUR-ACCOUNT/YOUR-REPOSITORY.git
git push -u origin main
```

Review `git status` before the commit.

### Existing GitHub or Lovable repository

Do not initialize a replacement repository and do not force-push. Clone the
existing repository into a fresh folder, copy these working-tree changes into
that clone, review the diff, commit normally, and push:

```powershell
git clone https://github.com/YOUR-ACCOUNT/YOUR-REPOSITORY.git ShieldSphere-clean
cd ShieldSphere-clean
# Copy changed project files here, excluding ignored secret/runtime files.
git status
git add .
git commit -m "Prepare ShieldSphere for production deployment"
git push
```

Enable GitHub secret scanning and push protection in the repository security
settings when available.

## 5. Deploy the backend

### Server prerequisites

- Linux server with Docker Engine and Docker Compose
- DNS `A`/`AAAA` record for `api.security.example.com`
- TCP ports 80 and 443 open; UDP 443 is optional for HTTP/3
- `backend/data/GeoLite2-City.mmdb` placed on the server
- Enough memory and disk space for PostgreSQL, Redis and simulation images

Copy and configure the single backend environment example:

```powershell
Copy-Item backend\.env.example backend\.env.production
```

Set at least:

```dotenv
APP_DOMAIN=api.security.example.com
FRONTEND_ORIGIN=https://security.example.com
ACME_EMAIL=your-real-email@example.net

POSTGRES_USER=shieldsphere
POSTGRES_PASSWORD=<24-or-more-random-alphanumeric-characters>
POSTGRES_DB=shieldsphere
REDIS_PASSWORD=<24-or-more-random-alphanumeric-characters>

JWT_SECRET=<at-least-32-random-characters>
JWT_REFRESH_SECRET=<different-at-least-32-random-characters>

WEBAUTHN_RP_ID=security.example.com
```

`FRONTEND_ORIGIN` must be the exact Vercel custom-domain origin and
`WEBAUTHN_RP_ID` must be its hostname.

Add the Groq, VirusTotal and AbuseIPDB API keys required by their corresponding
features. To enable email integration, set all of `SMTP_HOST`, `SMTP_USERNAME`,
`SMTP_PASSWORD`, and `SMTP_FROM_EMAIL`. Leave all four empty to disable email.
SMTP credentials belong only on the backend server, not in Vercel.

Validate:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\deploy-production.ps1 -ValidateOnly
```

Start the normal backend stack:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\deploy-production.ps1
```

For the attack simulator, use a dedicated backend host and explicitly enable
the Docker-socket override:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\deploy-production.ps1 -EnableSimulator
```

Docker socket access is effectively host-root access. Do not enable this on a
shared server.

Check the backend:

```powershell
docker compose --env-file backend/.env.production -f compose.production.yml ps
docker compose --env-file backend/.env.production -f compose.production.yml logs --tail 100
```

Open:

```text
https://api.security.example.com/health
```

The response must show `"status": "ok"`, `"database": "ok"` and `"redis": "ok"`.
Alembic migrations run automatically before the API starts.

## 6. Create the Vercel frontend project

1. Sign in to Vercel.
2. Select **Add New -> Project**.
3. Import the GitHub repository.
4. Set **Root Directory** to `frontend`.
5. Confirm **Framework Preset** is `Vite`.
6. Use **Install Command** `npm ci`.
7. Use **Build Command** `npm run build`.
8. Use **Output Directory** `dist`.
9. Do not add backend secrets to this project.

Add these Vercel environment variables for Production:

```dotenv
VITE_API_ORIGIN=https://api.security.example.com
VITE_API_BASE_URL=https://api.security.example.com/api/v1
VITE_SIMULATOR_WS_URL=wss://api.security.example.com/api/v1/simulator/ws
```

These values are embedded at build time. Redeploy after changing one.

Deploy the project. `frontend/vercel.json` supplies SPA deep-link routing and
baseline browser security headers.

## 7. Attach the frontend custom domain

1. Open the Vercel project.
2. Go to **Settings -> Domains**.
3. Add `security.example.com`.
4. Create the DNS record Vercel requests.
5. Wait until Vercel marks the domain valid and HTTPS is active.

If the final domain differs from the value originally configured:

1. Change `FRONTEND_ORIGIN` and `WEBAUTHN_RP_ID` in
   `backend/.env.production`.
2. Restart the backend deployment.
3. Update the Vercel `VITE_*` variables if the API hostname changed.
4. Redeploy the Vercel project.

Passkeys created on a development hostname do not transfer to the production
hostname; users register a new passkey in production.

## 8. Preview deployment policy

Each Vercel preview receives a changing `*.vercel.app` hostname. Do not add a
wildcard origin to backend CORS just to support previews.

Use one of these safer approaches:

- Test non-authenticated UI rendering in ordinary preview deployments.
- Create a fixed staging domain, staging backend, database and Redis instance.
- Configure the staging backend with that one exact staging frontend origin.

Never connect pull-request previews to the production database.

## 9. Production verification

After both deployments are available, test:

1. Registration, login, logout and refresh after a page reload
2. Two-factor authentication
3. Passkey registration and passkey login
4. Dashboard score and readable factor explanations
5. Password breach assessment and settings consistency
6. Threat, failed-login and alert IP blocking
7. Active-session and recognized-device maps
8. URL/IP/website assessments
9. AI Copilot streaming
10. Excel GDPR export
11. SMTP test delivery and signed webhook delivery
12. Simulator event stream and attack-to-defense replay
13. Secure My Account containment flow

In browser developer tools confirm:

- API requests go only to the expected HTTPS API hostname.
- Authentication cookies are `Secure` and `HttpOnly`.
- No access or refresh token is stored in `localStorage`.
- No mixed-content, CORS or WebSocket errors appear.

## 10. Updates and rollback

Every pushed commit creates a Vercel deployment. Promote only a tested
deployment to Production. Vercel can roll the frontend domain back to an earlier
deployment.

Before backend upgrades:

- Back up PostgreSQL and verify restoration.
- Pull the reviewed commit.
- Run the deployment preflight.
- Rebuild and start the stack.
- Check health and migration logs before accepting traffic.

Rollback application code only after checking whether a newer database migration
is backward compatible.
