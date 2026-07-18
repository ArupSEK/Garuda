# Garuda

Garuda is a Python-based penetration testing toolkit for authorized reconnaissance and security assessment workflows.

This first MVP includes a local web application and a bounded external-IP scanner. It performs public-target validation, TCP connect checks, HTTP response inspection, TLS certificate summaries, JSON reporting, and finding triage. Destructive tests, exploit payloads, stealth behavior, and private-network scans are not enabled.

## Run

```powershell
python server.py
```

Open the printed local URL, usually:

```text
http://127.0.0.1:8087
```

If port `8087` is busy, the server selects the next available local port.

## Test

```powershell
python -m unittest discover -s tests
```

## Current Safety Controls

- Explicit authorization is required for every scan request.
- Targets must resolve only to public internet IP addresses.
- Port lists are capped at 25 ports per scan.
- Socket timeouts are capped at 5 seconds.
- The module only performs low-impact reconnaissance.
