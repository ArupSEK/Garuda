#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_ROOT"

PYTHON_BIN="${PYTHON_BIN:-python3}"
VENV_PYTHON="$PROJECT_ROOT/.venv/bin/python"

if [[ ! -x "$VENV_PYTHON" ]]; then
  echo "Creating Python virtual environment..."
  "$PYTHON_BIN" -m venv .venv
fi

if ! "$VENV_PYTHON" -c 'import fastapi, streamlit, sqlalchemy' >/dev/null 2>&1; then
  echo "Installing application dependencies..."
  "$VENV_PYTHON" -m pip install --upgrade pip
  "$VENV_PYTHON" -m pip install -e .
fi

if [[ ! -f .env ]]; then
  cp .env.example .env
  APP_SECRET="$($VENV_PYTHON -c 'import secrets; print(secrets.token_urlsafe(48))')"
  "$VENV_PYTHON" -c 'from pathlib import Path; import sys; p=Path(".env"); p.write_text(p.read_text().replace("SECRET_KEY=replace-with-a-long-random-secret", "SECRET_KEY=" + sys.argv[1]))' "$APP_SECRET"
  echo "Created .env with a random application secret."
fi

if grep -q '^SECRET_KEY=replace-with-a-long-random-secret$' .env; then
  APP_SECRET="$($VENV_PYTHON -c 'import secrets; print(secrets.token_urlsafe(48))')"
  "$VENV_PYTHON" -c 'from pathlib import Path; import sys; p=Path(".env"); p.write_text(p.read_text().replace("SECRET_KEY=replace-with-a-long-random-secret", "SECRET_KEY=" + sys.argv[1]))' "$APP_SECRET"
  echo "Replaced placeholder application secret."
fi

read_setting() {
  local name="$1" default="$2" current
  current="${!name:-}"
  if [[ -n "$current" ]]; then
    printf '%s' "$current"
    return
  fi
  current="$(sed -n "s/^${name}=//p" .env | head -n 1)"
  printf '%s' "${current:-$default}"
}

API_PORT="$(read_setting GARUDA_API_PORT 8000)"
DASHBOARD_PORT="$(read_setting GARUDA_DASHBOARD_PORT 8501)"
API_URL="http://127.0.0.1:${API_PORT}"
DASHBOARD_URL="http://127.0.0.1:${DASHBOARD_PORT}"
mkdir -p logs data evidence reports

echo "Applying database migrations..."
"$VENV_PYTHON" -m alembic upgrade head

is_running() {
  local pid_file="$1"
  [[ -f "$pid_file" ]] && kill -0 "$(cat "$pid_file")" 2>/dev/null
}

if ! is_running logs/api.pid; then
  nohup "$VENV_PYTHON" -m uvicorn app.main:app --host 127.0.0.1 --port "$API_PORT" \
    >logs/api.log 2>logs/api-error.log &
  echo $! > logs/api.pid
else
  echo "API is already running."
fi

if ! is_running logs/dashboard.pid; then
  nohup "$VENV_PYTHON" -m streamlit run dashboard/streamlit_app.py \
    --server.address 127.0.0.1 --server.port "$DASHBOARD_PORT" --server.headless true \
    >logs/dashboard.log 2>logs/dashboard-error.log &
  echo $! > logs/dashboard.pid
else
  echo "Dashboard is already running."
fi

for _ in $(seq 1 30); do
  if "$VENV_PYTHON" -c "import urllib.request; urllib.request.urlopen('${API_URL}/api/health', timeout=2)" >/dev/null 2>&1; then
    break
  fi
  sleep 1
done

echo "Garuda is running:"
echo "  Dashboard: ${DASHBOARD_URL}"
echo "  API docs:  ${API_URL}/docs"
echo "  Logs:      ${PROJECT_ROOT}/logs"
echo 'To stop it: kill "$(cat logs/api.pid)" "$(cat logs/dashboard.pid)"'

if [[ "${NO_BROWSER:-0}" != "1" ]]; then
  if command -v xdg-open >/dev/null 2>&1; then
    xdg-open "$DASHBOARD_URL" >/dev/null 2>&1 &
  elif command -v open >/dev/null 2>&1; then
    open "$DASHBOARD_URL"
  fi
fi
