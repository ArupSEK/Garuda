# Installation

## Kali Linux / Ubuntu / WSL2

```bash
chmod +x scripts/install_tools.sh
./scripts/install_tools.sh
cp .env.example .env
python -c 'from pathlib import Path; import secrets; p=Path(".env"); p.write_text(p.read_text().replace("replace-with-a-long-random-secret", secrets.token_urlsafe(48)))'
sed -i 's#^NUCLEI_TEMPLATES_PATH=.*#NUCLEI_TEMPLATES_PATH=/opt/garuda/nuclei-templates#' .env
./scripts/check_dependencies.sh
./scripts/initialize_database.sh
```

The installer downloads pinned official scanner releases, verifies published checksums where supplied, installs the immutable Nuclei template and testssl.sh snapshots, creates the Python environment, and prints dependency status. Do not substitute the Python package named `httpx` for the ProjectDiscovery binary; both are used for different purposes.

Start both services with one command:

```bash
./scripts/start_linux.sh
```

For a manual development start, run these in two terminals:

```bash
source .venv/bin/activate
uvicorn app.main:app --host 127.0.0.1 --port 8000
```

```bash
source .venv/bin/activate
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

Or use the one-click launcher: `start-docker-windows.bat` on Windows, or `./start-docker-linux.sh` on Linux, Kali, Ubuntu, and WSL. The launcher creates `.env` and repairs missing, blank, placeholder, weak, or duplicate application secrets automatically. The first build downloads and verifies the pinned scanner assets and can take several minutes. Later starts reuse the built images.

Windows Command Prompt users should use `copy .env.example .env` instead of `cp`. PowerShell users should use `Copy-Item .env.example .env`. The one-click Windows launcher performs this securely and avoids either manual command.

If either host port is occupied, set `GARUDA_API_PORT` or `GARUDA_DASHBOARD_PORT` in `.env`.

Stop with `docker compose down`. Data remains in the mounted `data`, `evidence`, `reports`, and `logs` directories.

## Windows

Docker Desktop or WSL2 is recommended for real scanner execution. Double-click:

```bat
start-docker-windows.bat
```

For application-only native development in PowerShell:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\start_windows.ps1
```

## Verification and URLs

```bash
./scripts/check_dependencies.sh
python -m pytest
python -m ruff check .
docker compose ps
curl http://127.0.0.1:8000/api/health
```

- Dashboard: `http://127.0.0.1:8501`
- API: `http://127.0.0.1:8000`
- OpenAPI documentation: `http://127.0.0.1:8000/docs`

## Optional PDF support

```bash
pip install -e '.[pdf]'
```

WeasyPrint may require platform libraries documented by its maintainers. All other report formats work without it.
