#!/usr/bin/env bash
set -Eeuo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$PROJECT_ROOT"

if ! command -v docker >/dev/null 2>&1; then
  echo "[ERROR] Docker is not installed or is not on PATH." >&2
  exit 1
fi

if ! docker compose version >/dev/null 2>&1; then
  echo "[ERROR] Docker Compose v2 is not available." >&2
  exit 1
fi

if ! docker info >/dev/null 2>&1; then
  echo "[ERROR] The Docker daemon is not running or your user cannot access it." >&2
  exit 1
fi

if [[ "${GARUDA_LAUNCHER_CHECK:-0}" == "1" ]]; then
  exit 0
fi

if [[ ! -f .env ]]; then
  echo "Creating secure environment configuration..."
  if command -v openssl >/dev/null 2>&1; then
    APP_SECRET="$(openssl rand -hex 32)"
  else
    APP_SECRET="$(od -An -N32 -tx1 /dev/urandom | tr -d ' \n')"
  fi
  TEMP_ENV=".env.tmp.$$"
  trap 'rm -f "$TEMP_ENV"' EXIT
  awk -v secret="$APP_SECRET" '
    /^SECRET_KEY=/ { print "SECRET_KEY=" secret; next }
    { print }
  ' .env.example > "$TEMP_ENV"
  mv "$TEMP_ENV" .env
  trap - EXIT
  chmod 600 .env
fi

echo "Building and starting Garuda..."
docker compose up -d --build

DASHBOARD_PORT="$(sed -n 's/^GARUDA_DASHBOARD_PORT=//p' .env | tail -n 1)"
DASHBOARD_PORT="${DASHBOARD_PORT:-8501}"
DASHBOARD_URL="http://localhost:${DASHBOARD_PORT}"

sleep 5
docker compose ps
echo
echo "Garuda is starting at ${DASHBOARD_URL}"
echo "To stop it later, run: docker compose down"

if [[ "${GARUDA_NO_BROWSER:-0}" != "1" ]]; then
  if command -v xdg-open >/dev/null 2>&1; then
    xdg-open "$DASHBOARD_URL" >/dev/null 2>&1 &
  elif command -v open >/dev/null 2>&1; then
    open "$DASHBOARD_URL"
  fi
fi
