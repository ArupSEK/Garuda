# Installation

## Kali Linux / Ubuntu / WSL2

```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip nmap git
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -e '.[dev]'
cp .env.example .env
./scripts/check_dependencies.sh
./scripts/initialize_database.sh
```

Install Naabu, ProjectDiscovery httpx, Nuclei, dnsx, testssl.sh, ssh-audit, and GoWitness only from their official signed releases. Pin and record versions for each engagement. Do not substitute the Python package named `httpx` for the ProjectDiscovery binary; both are used for different purposes.

Start the API and dashboard:

```bash
source .venv/bin/activate
uvicorn app.main:app --host 127.0.0.1 --port 8000
streamlit run dashboard/streamlit_app.py --server.address 127.0.0.1 --server.port 8501
```

For WSL, run these commands inside Ubuntu/Kali WSL. Browse to the printed localhost URLs from Windows.

## Docker Desktop / Docker Compose

This is the recommended end-user installation. Docker bundles Nmap, Naabu, ProjectDiscovery httpx/Nuclei, a pinned Nuclei template snapshot, dnsx, testssl.sh, ssh-audit, GoWitness, and Chromium. No scanner installation or template update is required on the host.

```bash
cp .env.example .env
# Replace SECRET_KEY in .env with: python -c "import secrets; print(secrets.token_urlsafe(48))"
docker compose build
docker compose up -d
docker compose ps
curl http://127.0.0.1:8000/api/health
```

Or use the one-click launcher: `start-docker-windows.bat` on Windows, or `./start-docker-linux.sh` on Linux, Kali, Ubuntu, and WSL. The first build downloads and verifies the pinned scanner assets and can take several minutes. Later starts reuse the built images.

If either host port is occupied, set `GARUDA_API_PORT` or `GARUDA_DASHBOARD_PORT` in `.env`.

Stop with `docker compose down`. Data remains in the mounted `data`, `evidence`, `reports`, and `logs` directories.

## Optional PDF support

```bash
pip install -e '.[pdf]'
```

WeasyPrint may require platform libraries documented by its maintainers. All other report formats work without it.
