[CmdletBinding()]
param(
    [switch]$SkipInstall,
    [switch]$NoBrowser
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$ProjectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
Set-Location $ProjectRoot

$VenvPython = Join-Path $ProjectRoot ".venv\Scripts\python.exe"
if (-not (Test-Path -LiteralPath $VenvPython)) {
    Write-Host "Creating Python virtual environment..."
    if (Get-Command py -ErrorAction SilentlyContinue) {
        & py -3.12 -m venv .venv
    }
    elseif (Get-Command python -ErrorAction SilentlyContinue) {
        & python -m venv .venv
    }
    else {
        throw "Python 3.12 is required. Install it from https://www.python.org/downloads/"
    }
}

if (-not $SkipInstall) {
    & $VenvPython -c "import fastapi, streamlit, sqlalchemy" 2>$null
    if ($LASTEXITCODE -ne 0) {
        Write-Host "Installing application dependencies..."
        & $VenvPython -m pip install --upgrade pip
        & $VenvPython -m pip install -e .
    }
}

$EnvFile = Join-Path $ProjectRoot ".env"
if (-not (Test-Path -LiteralPath $EnvFile)) {
    Copy-Item -LiteralPath (Join-Path $ProjectRoot ".env.example") -Destination $EnvFile
    $Secret = & $VenvPython -c "import secrets; print(secrets.token_urlsafe(48))"
    $Content = Get-Content -Raw -LiteralPath $EnvFile
    $Content = $Content -replace "SECRET_KEY=replace-with-a-long-random-secret", "SECRET_KEY=$Secret"
    Set-Content -LiteralPath $EnvFile -Value $Content -Encoding utf8
    Write-Host "Created .env with a random application secret."
}

$ExistingContent = Get-Content -Raw -LiteralPath $EnvFile
if ($ExistingContent -match '(?m)^SECRET_KEY=replace-with-a-long-random-secret\s*$') {
    $Secret = & $VenvPython -c "import secrets; print(secrets.token_urlsafe(48))"
    $ExistingContent = $ExistingContent -replace "SECRET_KEY=replace-with-a-long-random-secret", "SECRET_KEY=$Secret"
    Set-Content -LiteralPath $EnvFile -Value $ExistingContent -Encoding utf8
    Write-Host "Replaced placeholder application secret."
}

function Get-AppSetting {
    param([string]$Name, [string]$Default)
    $ProcessValue = [Environment]::GetEnvironmentVariable($Name)
    if ($ProcessValue) { return $ProcessValue }
    $Match = Select-String -LiteralPath $EnvFile -Pattern "^$([regex]::Escape($Name))=(.*)$" | Select-Object -First 1
    if ($Match) { return $Match.Matches[0].Groups[1].Value.Trim() }
    return $Default
}

function Test-RunningPid {
    param([string]$PidFile)
    if (-not (Test-Path -LiteralPath $PidFile)) { return $false }
    $SavedPid = Get-Content -LiteralPath $PidFile -ErrorAction SilentlyContinue
    if (-not $SavedPid) { return $false }
    return $null -ne (Get-Process -Id ([int]$SavedPid) -ErrorAction SilentlyContinue)
}

$ApiPort = Get-AppSetting "GARUDA_API_PORT" "8000"
$DashboardPort = Get-AppSetting "GARUDA_DASHBOARD_PORT" "8501"
$ApiUrl = "http://127.0.0.1:$ApiPort"
$DashboardUrl = "http://127.0.0.1:$DashboardPort"
$LogDir = Join-Path $ProjectRoot "logs"
New-Item -ItemType Directory -Path $LogDir -Force | Out-Null

Write-Host "Applying database migrations..."
& $VenvPython -m alembic upgrade head

$ApiPidFile = Join-Path $LogDir "api.pid"
$DashboardPidFile = Join-Path $LogDir "dashboard.pid"

if (-not (Test-RunningPid $ApiPidFile)) {
    $ApiProcess = Start-Process -FilePath $VenvPython `
        -ArgumentList @("-m", "uvicorn", "app.main:app", "--host", "127.0.0.1", "--port", $ApiPort) `
        -WorkingDirectory $ProjectRoot -WindowStyle Hidden -PassThru `
        -RedirectStandardOutput (Join-Path $LogDir "api.log") `
        -RedirectStandardError (Join-Path $LogDir "api-error.log")
    Set-Content -LiteralPath $ApiPidFile -Value $ApiProcess.Id
}
else {
    Write-Host "API is already running."
}

if (-not (Test-RunningPid $DashboardPidFile)) {
    $DashboardProcess = Start-Process -FilePath $VenvPython `
        -ArgumentList @("-m", "streamlit", "run", "dashboard/streamlit_app.py", "--server.address", "127.0.0.1", "--server.port", $DashboardPort, "--server.headless", "true") `
        -WorkingDirectory $ProjectRoot -WindowStyle Hidden -PassThru `
        -RedirectStandardOutput (Join-Path $LogDir "dashboard.log") `
        -RedirectStandardError (Join-Path $LogDir "dashboard-error.log")
    Set-Content -LiteralPath $DashboardPidFile -Value $DashboardProcess.Id
}
else {
    Write-Host "Dashboard is already running."
}

for ($Attempt = 1; $Attempt -le 30; $Attempt++) {
    try {
        $Health = Invoke-RestMethod -Uri "$ApiUrl/api/health" -TimeoutSec 2
        if ($Health.ok) { break }
    }
    catch {
        Start-Sleep -Seconds 1
    }
}

Write-Host "Garuda is running:"
Write-Host "  Dashboard: $DashboardUrl"
Write-Host "  API docs:  $ApiUrl/docs"
Write-Host "  Logs:      $LogDir"
Write-Host "To stop it: Stop-Process -Id (Get-Content logs\api.pid),(Get-Content logs\dashboard.pid)"

if (-not $NoBrowser) {
    Start-Process $DashboardUrl
}
