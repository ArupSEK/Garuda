# Garuda

Garuda is a modular Python security assessment platform for authorized external reconnaissance, web inspection, service fingerprinting, and safe vulnerability-template validation.

This release upgrades the original port-scanner MVP into an orchestrator with scan profiles, normalized evidence, optional Nmap and Nuclei integrations, a safer localhost API, and a modern web interface.

## What it can do

- Validate and pin public DNS targets before network access.
- Scan up to 256 selected TCP ports concurrently.
- Identify externally reachable services.
- Inspect HTTP/HTTPS using the already validated IP address to reduce DNS-rebinding risk.
- Check selected HTTP hardening headers and technology disclosures.
- Collect TLS protocol, cipher, and certificate summaries.
- Use Nmap for optional service/version fingerprinting.
- Use Nuclei for optional rate-limited safe-template checks.
- Normalize findings into severity, confidence, evidence, recommendation, references, and fingerprints.
- Export the complete assessment report as JSON.

## Safety boundary

Garuda requires explicit authorization and currently permits public internet targets only. The included profiles do not enable exploitation, brute force, denial-of-service, destructive testing, persistence, credential attacks, or intrusive red-team actions.

Nuclei execution is opt-in and excludes templates tagged as DoS, fuzzing, brute force, default-login, headless, and code execution. Review your installed template collection before using it against a client environment.

## Requirements

- Python 3.10 or later
- Optional: Nmap in `PATH`
- Optional: Nuclei in `PATH`

Garuda's built-in modules use only the Python standard library.

## Run

```powershell
python server.py
```

Open the displayed address, normally:

```text
http://127.0.0.1:8087
```

To enable the optional Nuclei adapter:

```powershell
$env:GARUDA_ENABLE_NUCLEI="1"
python server.py
```

On Linux or macOS:

```bash
GARUDA_ENABLE_NUCLEI=1 python server.py
```

## Profiles

- `external-safe`: built-in TCP reachability and pinned HTTP/TLS inspection.
- `web-safe`: built-in modules plus optional safe Nuclei template checks.
- `red-team-readonly`: built-in modules, optional Nmap service detection, and optional safe Nuclei checks. This version remains read-only and does not exploit targets.

## Test

```powershell
python -m unittest discover -s tests -v
```

## Project structure

```text
garuda/
├── models.py
├── orchestrator.py
├── process.py
├── scope.py
└── modules/
    ├── base.py
    ├── tcp_connect.py
    ├── http_probe.py
    ├── nmap_adapter.py
    └── nuclei_adapter.py
```

## Next development milestones

1. Persistent scan jobs and SQLite/PostgreSQL storage.
2. Authenticated web/API sessions and OpenAPI/Postman import.
3. Crawling, endpoint inventory, and role-based authorization comparison.
4. CVE, EPSS, and KEV enrichment.
5. Signed custom-module repository and template review workflow.
6. Distributed scanning agents and attack-path correlation.
