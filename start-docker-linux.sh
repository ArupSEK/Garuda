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

ENV_CREATED=0
if [[ ! -f .env ]]; then
  cp .env.example .env
  ENV_CREATED=1
fi

SECRET_COUNT="$(grep -c '^[[:space:]]*SECRET_KEY[[:space:]]*=' .env || true)"
CURRENT_SECRET="$(sed -n 's/^[[:space:]]*SECRET_KEY[[:space:]]*=[[:space:]]*//p' .env | tail -n 1 | tr -d '\r')"
if [[ "$SECRET_COUNT" != "1" || "$CURRENT_SECRET" == "replace-with-a-long-random-secret" || ${#CURRENT_SECRET} -lt 32 ]]; then
  if command -v openssl >/dev/null 2>&1; then
    APP_SECRET="$(openssl rand -hex 32)"
  else
    APP_SECRET="$(od -An -N32 -tx1 /dev/urandom | tr -d ' \n')"
  fi
  TEMP_ENV=".env.tmp.$$"
  trap 'rm -f "$TEMP_ENV"' EXIT
  awk -v secret="$APP_SECRET" '
    /^[[:space:]]*SECRET_KEY[[:space:]]*=/ { next }
    { print }
    END { print "SECRET_KEY=" secret }
  ' .env > "$TEMP_ENV"
  mv "$TEMP_ENV" .env
  trap - EXIT
  if [[ "$ENV_CREATED" == "1" ]]; then
    echo "Created .env with a secure application secret."
  else
    echo "Repaired the missing or invalid SECRET_KEY in .env."
  fi
fi
chmod 600 .env

echo "Building and starting Garuda..."
docker compose --env-file .env up -d --build

DASHBOARD_PORT="$(sed -n 's/^GARUDA_DASHBOARD_PORT=//p' .env | tail -n 1)"
DASHBOARD_PORT="${DASHBOARD_PORT:-8501}"
DASHBOARD_URL="http://localhost:${DASHBOARD_PORT}"

sleep 5
docker compose --env-file .env ps
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
