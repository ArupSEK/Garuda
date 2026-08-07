# Master Prompt Implementation Status

Assessment date: 2026-08-05

This file maps the Master Development Prompt to the implemented Version 1 repository. “Implemented” means executable code and automated coverage exist. “Partial” identifies a deliberate safety boundary or an integration that still needs a trusted data source or deeper engine.

## Version 1 implementation

| Area | Status | Implementation |
|---|---|---|
| Authorized engagement workflow | Implemented | Owner, authorization reference, dates, approved public IPv4/CIDR scope, exclusions, contact, scan window, acknowledgement, creator, edit, and close workflow |
| Scope controls | Implemented | Public IPv4 validation, private/special-use rejection, `/24` default ceiling, expansion limit, deduplication, engagement membership, and exclusions |
| Process safety | Implemented | Fixed argument arrays, no `shell=True`, bounded rates/concurrency/timeouts, optional-tool isolation, cancellation, child termination, RBAC, redaction, and audit records |
| Scan profiles | Implemented | Server-enforced Quick, Standard, Full, and bounded Custom profiles; browser/API callers cannot supply arbitrary tool arguments |
| Nmap | Implemented | TCP confirmation, selected UDP scanning, service/version/CPE/OS evidence, reviewed NSE allowlist, XML parsing, and raw evidence |
| Naabu | Implemented | Top 100, top 1,000, full, or explicit custom discovery; only Nmap-confirmed results enter final inventory; confirmation counts are recorded |
| ProjectDiscovery httpx | Implemented | Status, title, redirect, server, technology, content metadata, favicon/response hashes, response time, CPE, TLS, JARM, CNAME, ASN, and CDN/WAF indication |
| Nuclei | Implemented | Pinned signed templates, approved directories/tags/severities, JSONL parsing, rate/concurrency limits, and explicit intrusive-tag exclusions |
| TLS and STARTTLS | Implemented | testssl.sh direct TLS and controlled FTP/SMTP/POP3/IMAP/LDAP/NNTP/MySQL/PostgreSQL/XMPP/Sieve STARTTLS routing with JSON findings |
| SSH | Implemented | ssh-audit only after Nmap confirms SSH; rate test disabled; weak KEX/key/cipher/MAC parsing |
| DNS | Implemented | dnsx A/AAAA/PTR/CNAME/NS/MX/TXT/SOA/SRV/CAA, wildcard, and safe AXFR verification plus Nmap recursion evidence |
| Screenshots | Implemented | GoWitness/Chromium collection, authenticated delivery, asset linkage, and heuristic login/admin/dashboard/default-page classification |
| Protocol checks | Implemented with safe limits | FTP, Telnet, SMTP checklist, DNS, explicit opt-in SNMP default-community probe, SMB, RDP, NTP, HTTP methods/headers, databases, Docker API, Kubernetes API, Redis, MongoDB, and Elasticsearch exposure checks |
| Finding pipeline | Implemented | Unified schema, redaction, CVE/CWE/CPE/CVSS 3.1/4.0 fields, stable CVE-aware fingerprint, confidence rationale, deduplication, evidence sources, and lifecycle fields |
| CISA KEV | Implemented | Official JSON catalog, bounded refresh, local cache, failure-safe fallback, required-action enrichment, and coverage status |
| Risk scoring | Implemented | Configurable weighted CVSS, exposure, KEV, exploit, confidence, criticality, authentication, EOL, patch, and business-impact signals |
| Persistence | Implemented | SQLite, PostgreSQL-compatible SQLAlchemy models, Alembic baseline, scan/asset/service/finding/evidence/audit history |
| Comparison | Implemented | New/still-open/resolved/reopened findings, severity/confidence/evidence changes, ports, management exposure, services, versions, encryption/CPE, TLS certificate evidence, and severity charts |
| Analyst workflow | Implemented | Status, validation/remediation notes, false-positive justification, owner, target date, accepted-risk expiry, evidence view, and audit-backed history |
| Reports | Implemented | Executive/technical HTML and PDF, findings/assets/services CSV, complete or selected JSON/JSONL, and HTML/PDF/CSV/JSON comparison reports |
| Dashboard | Implemented | Login, command center, engagements, new scan, live progress/stop, assets/detail/history/screenshots, vulnerability workbench, comparison, reports, and settings posture |
| Deployment | Implemented | Non-root Docker image, Compose health gating, Windows/Linux one-click Docker launchers, native Windows/Linux launchers, pinned scanner bundle, and PDF system libraries |
| Testing and CI | Implemented | Fixture/mock-only unit tests, Ruff, compilation/OpenAPI checks, Compose validation, and GitHub Actions; tests never scan external systems |
| Version 2 interfaces | Implemented | Non-operational ZGrab2 and Greenbone/OpenVAS adapters explicitly fail closed until reviewed |

## Deliberate limits and remaining work

| Area | Status | Reason / recommended next step |
|---|---|---|
| Vendor advisory, fixed version, product EOL, patch availability, and exploit maturity feeds | Partial | Nuclei metadata and official CISA KEV are used now. Add authenticated/cached vendor, NVD, OSV, and lifecycle providers without converting uncertain banner matches into confirmed CVEs. |
| SMTP relay/user enumeration, SMB guest login, database login, and RDP NLA negotiation | Manual or not tested | Version 1 does not authenticate, transmit test mail, enumerate accounts, or create sessions. The checklist reports this explicitly instead of claiming a pass. |
| Permitted scan window | Recorded, not scheduler-enforced | Add a structured timezone-aware schedule model and queue gate before supporting scheduled execution. Authorization start and expiry dates are enforced now. |
| Automated evidence/data purge | Not enabled | `RETENTION_DAYS` is visible as deployment policy, but Version 1 does not delete customer evidence automatically. Use a reviewed backup-and-retention runbook before enabling destructive cleanup. |
| Dedicated immutable finding-status table | Partial | Status changes and previous/current values are retained in the audit log. Add a normalized status-history table if regulatory reporting requires it. |
| Deep engine selection | Version 2 | Add Standard/Deep/Combined selection only after Greenbone resource isolation, feed management, and safe scan configuration are reviewed. |
| Celery/Redis distributed workers | Version 2 | Current worker is bounded and cancellable in-process. Add signed jobs and queue-level tenancy before horizontal scaling. |
| PostgreSQL production Compose profile | Version 2 | Models are compatible; the default appliance intentionally uses local SQLite. Add backup, encryption, HA, and migration runbooks before production PostgreSQL. |
| IPv6 | Not in Version 1 | The requested external mode accepts public IPv4 only. |

The application does not implement exploitation, brute force, credential attacks, denial of service, unrestricted fuzzing, evasion, payloads, persistence, or destructive testing.
