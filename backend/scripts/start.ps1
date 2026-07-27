[CmdletBinding()]
param(
    [string]$HostAddress = "127.0.0.1",
    [int]$Port = 8000,
    [switch]$SkipMigrations
)

$backendRoot = Split-Path -Parent $PSScriptRoot
$pythonPath = Join-Path $backendRoot "venv\Scripts\python.exe"

if (-not (Test-Path -LiteralPath $pythonPath)) {
    throw "Backend virtual environment was not found at $pythonPath. Create it and install requirements first."
}

Set-Location -LiteralPath $backendRoot

if (-not $SkipMigrations) {
    & $pythonPath -m alembic upgrade head
    if ($LASTEXITCODE -ne 0) {
        exit $LASTEXITCODE
    }
}

$env:SHIELDSPHERE_HOST_ADDRESS = $HostAddress
$env:SHIELDSPHERE_PORT = [string]$Port
& $pythonPath main.py
exit $LASTEXITCODE
