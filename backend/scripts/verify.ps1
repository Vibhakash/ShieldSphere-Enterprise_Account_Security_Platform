[CmdletBinding()]
param(
    [switch]$SkipDockerBuild,
    [switch]$Integration
)

$backendRoot = Split-Path -Parent $PSScriptRoot
$pythonPath = Join-Path $backendRoot "venv\Scripts\python.exe"

if (-not (Test-Path -LiteralPath $pythonPath)) {
    throw "Backend virtual environment was not found at $pythonPath."
}

Set-Location -LiteralPath $backendRoot

& $pythonPath -m unittest discover -s tests -v
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

if ($Integration) {
    # Run real-service tests in a fresh Python process. Unit-test modules set
    # placeholder settings, while this suite must load backend/.env instead.
    $env:RUN_BACKEND_INTEGRATION_TESTS = "1"
    & $pythonPath -m unittest discover -s tests -p "test_integration_postgres_redis.py" -v
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
}

& $pythonPath -m compileall -q app tests sandbox
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

& $pythonPath -m alembic check
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

if (-not $SkipDockerBuild) {
    docker build --tag shieldsphere-target:latest sandbox/target_app
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    docker build --tag shieldsphere-attacker:latest sandbox/attacker_scripts
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
}

Write-Output "ShieldSphere backend verification passed."
