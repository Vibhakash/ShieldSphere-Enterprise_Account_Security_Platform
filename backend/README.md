# ShieldSphere backend

The backend uses local PostgreSQL, Redis, and Docker Desktop. It does not require a managed database service.

## Run locally

1. Populate `backend/.env` with the local PostgreSQL connection string, Redis URL, JWT secrets, and any external-service API keys.
2. Ensure PostgreSQL and Redis are running.
3. Start Docker Desktop before using the attack simulator.
4. Run the backend from the repository root:

   ```powershell
   powershell -ExecutionPolicy Bypass -File .\backend\scripts\start.ps1
   ```

The startup script applies Alembic migrations before starting Uvicorn at `http://127.0.0.1:8000`.

## Verify

Run all unit checks, schema validation, and sandbox image builds:

```powershell
powershell -ExecutionPolicy Bypass -File .\backend\scripts\verify.ps1
```

To omit Docker image builds:

```powershell
powershell -ExecutionPolicy Bypass -File .\backend\scripts\verify.ps1 -SkipDockerBuild
```

To also run local PostgreSQL and Redis integration tests (the tests create and clean up uniquely named records):

```powershell
powershell -ExecutionPolicy Bypass -File .\backend\scripts\verify.ps1 -Integration
```

## Simulator isolation

Every attack simulation requires Docker. The backend creates a unique internal bridge network, starts a disposable target and attacker container, records live events, and removes the containers and network afterward. When Docker is unavailable, a simulation fails rather than probing the backend host.
