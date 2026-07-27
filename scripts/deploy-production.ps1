[CmdletBinding()]
param(
    [string]$EnvironmentFile = "backend/.env.production",
    [switch]$EnableSimulator,
    [switch]$ValidateOnly
)

$projectRoot = Split-Path -Parent $PSScriptRoot
$environmentPath = if ([System.IO.Path]::IsPathRooted($EnvironmentFile)) {
    $EnvironmentFile
} else {
    Join-Path $projectRoot $EnvironmentFile
}
$productionCompose = Join-Path $projectRoot "compose.production.yml"
$simulatorCompose = Join-Path $projectRoot "compose.simulator.yml"
$geoIpDatabase = Join-Path $projectRoot "backend\data\GeoLite2-City.mmdb"

if (-not (Test-Path -LiteralPath $environmentPath)) {
    throw "Missing $environmentPath. Copy backend/.env.example to backend/.env.production and replace every placeholder."
}
if (-not (Test-Path -LiteralPath $geoIpDatabase)) {
    throw "Missing GeoLite2-City.mmdb at $geoIpDatabase."
}

$environmentValues = @{}
foreach ($line in Get-Content -LiteralPath $environmentPath) {
    $trimmed = $line.Trim()
    if (-not $trimmed -or $trimmed.StartsWith("#") -or -not $trimmed.Contains("=")) {
        continue
    }
    $parts = $trimmed.Split("=", 2)
    $name = $parts[0].Trim()
    $value = $parts[1].Trim()
    if (
        $value.Length -ge 2 -and
        (($value.StartsWith('"') -and $value.EndsWith('"')) -or
         ($value.StartsWith("'") -and $value.EndsWith("'")))
    ) {
        $value = $value.Substring(1, $value.Length - 2)
    }
    $environmentValues[$name] = $value
}

$validationErrors = [System.Collections.Generic.List[string]]::new()
$requiredNames = @(
    "APP_DOMAIN",
    "FRONTEND_ORIGIN",
    "WEBAUTHN_RP_ID",
    "ACME_EMAIL",
    "POSTGRES_USER",
    "POSTGRES_PASSWORD",
    "POSTGRES_DB",
    "REDIS_PASSWORD",
    "JWT_SECRET",
    "JWT_REFRESH_SECRET"
)
foreach ($name in $requiredNames) {
    if (-not $environmentValues.ContainsKey($name) -or
        [string]::IsNullOrWhiteSpace($environmentValues[$name])) {
        $validationErrors.Add("$name is required.")
    }
}

$domain = $environmentValues["APP_DOMAIN"]
if ($domain -and (
    $domain -notmatch '^(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$' -or
    $domain -match '(^|\.)example\.(com|org|net)$' -or
    $domain -in @("localhost", "127.0.0.1")
)) {
    $validationErrors.Add("APP_DOMAIN must be the real public hostname, without a scheme or path.")
}

$frontendOrigin = $environmentValues["FRONTEND_ORIGIN"]
if ($frontendOrigin) {
    try {
        $frontendUri = [System.Uri]::new($frontendOrigin)
        if (
            $frontendUri.Scheme -ne "https" -or
            -not $frontendUri.Host -or
            $frontendUri.AbsolutePath -ne "/" -or
            $frontendUri.Query -or
            $frontendUri.Fragment -or
            $frontendUri.Host -match '(^|\.)example\.(com|org|net)$' -or
            $frontendUri.Host -in @("localhost", "127.0.0.1")
        ) {
            throw "Invalid frontend origin"
        }
        if ($environmentValues["WEBAUTHN_RP_ID"] -ne $frontendUri.Host) {
            $validationErrors.Add("WEBAUTHN_RP_ID must equal the FRONTEND_ORIGIN hostname.")
        }
    } catch {
        $validationErrors.Add("FRONTEND_ORIGIN must be the real public HTTPS origin without a path.")
    }
}

$acmeEmail = $environmentValues["ACME_EMAIL"]
if ($acmeEmail) {
    try {
        $parsedEmail = [System.Net.Mail.MailAddress]::new($acmeEmail)
        if ($parsedEmail.Address -ne $acmeEmail -or $acmeEmail -match '@example\.(com|org|net)$') {
            throw "Invalid deployment email"
        }
    } catch {
        $validationErrors.Add("ACME_EMAIL must be a real valid email address.")
    }
}

foreach ($name in @("POSTGRES_USER", "POSTGRES_DB")) {
    $value = $environmentValues[$name]
    if ($value -and $value -notmatch '^[A-Za-z0-9_]+$') {
        $validationErrors.Add("$name may contain only letters, numbers, and underscores.")
    }
}
foreach ($name in @("POSTGRES_PASSWORD", "REDIS_PASSWORD")) {
    $value = $environmentValues[$name]
    if ($value -and (
        $value.Length -lt 24 -or
        $value -notmatch '^[A-Za-z0-9_-]+$' -or
        $value -match '(?i)(replace|change.?me|example|your-)'
    )) {
        $validationErrors.Add("$name must be at least 24 characters using letters, numbers, underscores, or hyphens.")
    }
}

$jwtSecret = $environmentValues["JWT_SECRET"]
$refreshSecret = $environmentValues["JWT_REFRESH_SECRET"]
foreach ($name in @("JWT_SECRET", "JWT_REFRESH_SECRET")) {
    $value = $environmentValues[$name]
    if ($value -and (
        $value.Length -lt 32 -or
        $value -match '(?i)(replace|change.?me|example|secret-with|your-|<|>)'
    )) {
        $validationErrors.Add("$name must be a unique random value of at least 32 characters.")
    }
}
if ($jwtSecret -and $refreshSecret -and $jwtSecret -ceq $refreshSecret) {
    $validationErrors.Add("JWT_SECRET and JWT_REFRESH_SECRET must be different.")
}

$smtpFields = @("SMTP_HOST", "SMTP_USERNAME", "SMTP_PASSWORD", "SMTP_FROM_EMAIL")
$configuredSmtpFields = @($smtpFields | Where-Object {
    $environmentValues.ContainsKey($_) -and
    -not [string]::IsNullOrWhiteSpace($environmentValues[$_])
})
if ($configuredSmtpFields.Count -gt 0 -and $configuredSmtpFields.Count -ne $smtpFields.Count) {
    $validationErrors.Add("SMTP is partially configured; set all SMTP host, username, password, and from-email fields or leave all four empty.")
}
if ($environmentValues["SMTP_FROM_EMAIL"]) {
    try {
        [void][System.Net.Mail.MailAddress]::new($environmentValues["SMTP_FROM_EMAIL"])
    } catch {
        $validationErrors.Add("SMTP_FROM_EMAIL is not a valid email address.")
    }
}
if ($environmentValues["SMTP_PORT"]) {
    $smtpPort = 0
    if (-not [int]::TryParse($environmentValues["SMTP_PORT"], [ref]$smtpPort) -or
        $smtpPort -lt 1 -or $smtpPort -gt 65535) {
        $validationErrors.Add("SMTP_PORT must be between 1 and 65535.")
    }
}
if ($environmentValues["SMTP_USE_TLS"] -and
    $environmentValues["SMTP_USE_TLS"] -notin @("true", "false")) {
    $validationErrors.Add("SMTP_USE_TLS must be true or false.")
}

if ($validationErrors.Count -gt 0) {
    throw "Production environment validation failed:`n- $($validationErrors -join "`n- ")"
}

$composeArguments = @(
    "compose",
    "--env-file", $environmentPath,
    "-f", $productionCompose
)
if ($EnableSimulator) {
    $composeArguments += @("-f", $simulatorCompose)
}

Set-Location -LiteralPath $projectRoot

& docker @composeArguments config --quiet
if ($LASTEXITCODE -ne 0) {
    exit $LASTEXITCODE
}

if ($ValidateOnly) {
    Write-Output "Production Compose configuration is valid."
    exit 0
}

if ($EnableSimulator) {
    & docker @composeArguments --profile sandbox-images build sandbox-target sandbox-attacker
    if ($LASTEXITCODE -ne 0) {
        exit $LASTEXITCODE
    }
}

& docker @composeArguments up --detach --build --remove-orphans
exit $LASTEXITCODE
