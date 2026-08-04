@echo off
setlocal

cd /d "%~dp0"
title Garuda Docker Launcher

where docker >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Docker Desktop is not installed or docker.exe is not on PATH.
    echo Install Docker Desktop, start it, and run this file again.
    pause
    exit /b 1
)

docker compose version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Docker Compose v2 is not available.
    pause
    exit /b 1
)

docker info >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Docker Desktop is not running.
    echo Start Docker Desktop and run this file again.
    pause
    exit /b 1
)

if /I "%GARUDA_LAUNCHER_CHECK%"=="1" exit /b 0

if not exist ".env" (
    echo Creating secure environment configuration...
    powershell -NoProfile -ExecutionPolicy Bypass -Command ^
        "$secret=[Convert]::ToHexString([Security.Cryptography.RandomNumberGenerator]::GetBytes(32)).ToLower(); $content=Get-Content -Raw -LiteralPath '.env.example'; $content=$content.Replace('SECRET_KEY=replace-with-a-long-random-secret','SECRET_KEY='+$secret); Set-Content -LiteralPath '.env' -Value $content -Encoding utf8"
    if errorlevel 1 (
        echo [ERROR] Could not create .env.
        pause
        exit /b 1
    )
)

echo Building and starting Garuda...
docker compose up -d --build
if errorlevel 1 (
    echo [ERROR] Garuda could not be started. Review the Docker output above.
    pause
    exit /b 1
)

set "DASHBOARD_PORT=8501"
for /f "tokens=1,* delims==" %%A in (.env) do if /I "%%A"=="GARUDA_DASHBOARD_PORT" set "DASHBOARD_PORT=%%B"

timeout /t 5 /nobreak >nul
docker compose ps
echo.
echo Garuda is starting at http://localhost:%DASHBOARD_PORT%
echo To stop it later, run: docker compose down

if /I not "%GARUDA_NO_BROWSER%"=="1" start "" "http://localhost:%DASHBOARD_PORT%"

endlocal
