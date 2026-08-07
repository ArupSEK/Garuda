"""Controlled background scan orchestration and persistence."""

import asyncio
import logging
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select

from app.config import get_settings
from app.core.constants import ScanStatus
from app.core.exceptions import (
    CommandExecutionError,
    ScanCancelled,
    ScannerError,
    ToolUnavailableError,
)
from app.database import SessionLocal
from app.models import Asset, AuditLog, Evidence, Finding, Scan, Service
from app.scanners.base import ScanContext
from app.scanners.dnsx_scanner import DnsxScanner
from app.scanners.gowitness_scanner import GoWitnessScanner
from app.scanners.httpx_scanner import HttpxScanner
from app.scanners.naabu_scanner import NaabuScanner
from app.scanners.nmap_scanner import NmapScanner
from app.scanners.nuclei_scanner import NucleiScanner
from app.scanners.ssh_audit_scanner import SshAuditScanner
from app.scanners.testssl_scanner import TestsslScanner
from app.services.deduplicator import deduplicate
from app.services.finding_normalizer import normalize_finding
from app.services.intelligence_service import CisaKevProvider
from app.services.protocol_check_service import evaluate_protocol_checks
from app.services.risk_engine import calculate_risk
from app.utils.command_runner import command_runner
from app.utils.redaction import redact

logger = logging.getLogger(__name__)


class ScanOrchestrator:
    def __init__(self) -> None:
        self.settings = get_settings()
        self.tasks: dict[str, asyncio.Task] = {}
        self.semaphore = asyncio.Semaphore(self.settings.scan_concurrency)
        self.intelligence = CisaKevProvider(
            url=self.settings.cisa_kev_url,
            cache_path=self.settings.cisa_kev_cache_path,
            refresh_hours=self.settings.intelligence_refresh_hours,
            timeout=self.settings.intelligence_timeout,
        )

    def start(self, scan_public_id: str) -> None:
        task = asyncio.create_task(self._run_bounded(scan_public_id), name=f"scan-{scan_public_id}")
        self.tasks[scan_public_id] = task
        task.add_done_callback(lambda _: self.tasks.pop(scan_public_id, None))

    async def _run_bounded(self, scan_public_id: str) -> None:
        async with self.semaphore:
            await self.run(scan_public_id)

    async def cancel(self, scan_public_id: str) -> bool:
        killed = await command_runner.cancel(scan_public_id)
        task = self.tasks.get(scan_public_id)
        if task and not task.done():
            task.cancel()
            killed = True
        if killed:
            with SessionLocal() as db:
                scan = db.scalar(select(Scan).where(Scan.public_id == scan_public_id))
                if scan:
                    scan.status = ScanStatus.CANCELLED
                    scan.current_stage = "cancelled"
                    scan.end_time = datetime.now(UTC)
                    db.commit()
        return killed

    async def run(self, scan_public_id: str) -> None:
        with SessionLocal() as db:
            scan = db.scalar(select(Scan).where(Scan.public_id == scan_public_id))
            if not scan:
                return
            scan.status = ScanStatus.RUNNING
            scan.start_time = datetime.now(UTC)
            scan.current_stage = "nmap confirmation"
            scan.progress = 5
            initial_options = dict(scan.options or {})
            initial_options["target_progress"] = {
                "completed": [],
                "pending": list(scan.targets),
            }
            scan.options = initial_options
            if self.settings.scanner_versions:
                scan.scanner_versions = {
                    name.strip(): version.strip()
                    for item in self.settings.scanner_versions.split(",")
                    if "=" in item
                    for name, version in [item.split("=", 1)]
                }
            db.commit()
            context = ScanContext(
                scan.public_id,
                scan.targets,
                self.settings.evidence_dir / scan.public_id,
                scan.profile,
                {
                    **scan.options,
                    "nuclei_templates_path": str(self.settings.nuclei_templates_path),
                },
            )
            context.work_dir.mkdir(parents=True, exist_ok=True)
            self._initialize_coverage(scan.public_id)
        try:
            await self._record_scanner_versions(scan_public_id)
            naabu = NaabuScanner(self.settings.naabu_path)
            naabu_results: list[dict[str, Any]] = []
            if naabu.available:
                self._progress(scan_public_id, 10, "naabu discovery (pending nmap confirmation)")
                naabu_results = await self._run_optional(scan_public_id, naabu, context)
            else:
                self._set_coverage(scan_public_id, naabu.name, "unavailable")

            nmap = NmapScanner(self.settings.nmap_path)
            self._set_coverage(scan_public_id, nmap.name, "running")
            nmap_data = await nmap.scan(context)
            self._persist_nmap(scan_public_id, nmap_data)
            self._record_naabu_confirmation(scan_public_id, naabu_results, nmap_data)
            self._set_target_progress(scan_public_id, context.targets, [])
            service_count = sum(len(asset.get("services", [])) for asset in nmap_data.get("assets", []))
            self._set_coverage(
                scan_public_id,
                nmap.name,
                "completed",
                evidence_count=service_count,
            )
            hostname_mapping = context.options.get("hostnames") or {}
            submitted_hostnames = (
                list(hostname_mapping.values()) if isinstance(hostname_mapping, dict) else []
            )
            confirmed = self._confirmed_endpoints(nmap_data)
            confirmed["hostnames"] = list(
                dict.fromkeys([*submitted_hostnames, *confirmed.get("hostnames", [])])
            )
            context.options.update(confirmed)
            raw_findings: list[dict[str, Any]] = []
            if context.profile != "quick":
                protocol_findings, protocol_checklist = evaluate_protocol_checks(nmap_data)
                raw_findings.extend(protocol_findings)
                self._merge_checklist(scan_public_id, protocol_checklist)

            self._progress(scan_public_id, 45, "http probing")
            httpx = HttpxScanner(self.settings.httpx_path)
            if not context.options.get("http_urls"):
                self._set_coverage(scan_public_id, httpx.name, "not_applicable")
            elif httpx.available:
                http_observations = await self._run_optional(scan_public_id, httpx, context)
                self._persist_httpx(scan_public_id, http_observations)
            else:
                self._set_coverage(scan_public_id, httpx.name, "unavailable")

            self._progress(scan_public_id, 55, "DNS evidence")
            dnsx = DnsxScanner(self.settings.dnsx_path)
            if dnsx.available:
                await self._run_optional(scan_public_id, dnsx, context)
            else:
                self._set_coverage(scan_public_id, dnsx.name, "unavailable")

            self._progress(scan_public_id, 65, "safe vulnerability validation")
            if context.profile != "quick":
                nuclei = NucleiScanner(self.settings.nuclei_path)
                if not context.options.get("nuclei_targets"):
                    self._set_coverage(scan_public_id, nuclei.name, "not_applicable")
                elif nuclei.available:
                    raw_findings.extend(await self._run_optional(scan_public_id, nuclei, context))
                else:
                    self._set_coverage(scan_public_id, nuclei.name, "unavailable")

                if context.options.get("enable_tls", True):
                    testssl = TestsslScanner(self.settings.testssl_path)
                    if not context.options.get("tls_endpoints"):
                        self._set_coverage(scan_public_id, testssl.name, "not_applicable")
                    elif testssl.available:
                        raw_findings.extend(await self._run_optional(scan_public_id, testssl, context))
                    else:
                        self._set_coverage(scan_public_id, testssl.name, "unavailable")
                else:
                    self._set_coverage(scan_public_id, "testssl.sh", "disabled")

                if context.options.get("enable_ssh", True):
                    ssh_audit = SshAuditScanner(self.settings.ssh_audit_path)
                    if not context.options.get("ssh_endpoints"):
                        self._set_coverage(scan_public_id, ssh_audit.name, "not_applicable")
                    elif ssh_audit.available:
                        raw_findings.extend(await self._run_optional(scan_public_id, ssh_audit, context))
                    else:
                        self._set_coverage(scan_public_id, ssh_audit.name, "unavailable")
                else:
                    self._set_coverage(scan_public_id, "ssh-audit", "disabled")
            else:
                for scanner_name in ("nuclei", "testssl.sh", "ssh-audit"):
                    self._set_coverage(scan_public_id, scanner_name, "skipped_by_profile")

            self._progress(scan_public_id, 85, "visual evidence")
            gowitness = GoWitnessScanner(self.settings.gowitness_path)
            if not context.options.get("enable_screenshots", False):
                self._set_coverage(scan_public_id, gowitness.name, "disabled")
            elif not context.options.get("http_urls"):
                self._set_coverage(scan_public_id, gowitness.name, "not_applicable")
            elif gowitness.available:
                await self._run_optional(scan_public_id, gowitness, context)
            else:
                self._set_coverage(scan_public_id, gowitness.name, "unavailable")

            self._progress(scan_public_id, 92, "CISA KEV correlation")
            if raw_findings:
                self._set_coverage(scan_public_id, "cisa-kev", "running")
                raw_findings, enrichment = await self.intelligence.enrich_many(raw_findings)
                self._set_coverage(
                    scan_public_id,
                    "cisa-kev",
                    "completed" if enrichment.available else "unavailable",
                    detail=enrichment.detail,
                    evidence_count=enrichment.matched if enrichment.available else None,
                )
            else:
                self._set_coverage(scan_public_id, "cisa-kev", "not_applicable")

            self._progress(scan_public_id, 96, "normalizing findings")
            self._persist_findings(scan_public_id, raw_findings)
            self._finish(scan_public_id, ScanStatus.COMPLETED, None)
        except (asyncio.CancelledError, ScanCancelled):
            self._finish(scan_public_id, ScanStatus.CANCELLED, None)
        except ToolUnavailableError as exc:
            self._fail_running_coverage(scan_public_id, str(exc))
            self._finish(scan_public_id, ScanStatus.FAILED, str(exc))
        except ScannerError as exc:
            logger.warning("scan_failed id=%s error=%s", scan_public_id, exc)
            self._fail_running_coverage(scan_public_id, str(exc))
            self._finish(scan_public_id, ScanStatus.FAILED, str(exc))
        except Exception as exc:
            logger.exception("unexpected_scan_failure id=%s", scan_public_id)
            self._fail_running_coverage(scan_public_id, str(exc))
            self._finish(
                scan_public_id, ScanStatus.FAILED, f"Unexpected scan failure: {exc.__class__.__name__}"
            )

    async def _run_optional(self, scan_id: str, scanner: Any, context: ScanContext) -> list[Any]:
        """Keep a recoverable optional probe failure from discarding Nmap results."""
        self._set_coverage(scan_id, scanner.name, "running")
        try:
            result = await scanner.scan(context)
            self._set_coverage(
                scan_id,
                scanner.name,
                "completed",
                evidence_count=len(result) if isinstance(result, list) else None,
            )
            return result
        except (CommandExecutionError, ToolUnavailableError, OSError, ValueError) as exc:
            logger.warning(
                "optional_scanner_failed id=%s scanner=%s error=%s",
                scan_id,
                scanner.name,
                exc,
            )
            self._set_coverage(scan_id, scanner.name, "failed", detail=str(exc))
            return []

    async def _record_scanner_versions(self, scan_id: str) -> None:
        """Record configured or safely queried tool versions for the audit trail."""
        configured = {
            name.strip(): version.strip()
            for item in self.settings.scanner_versions.split(",")
            if "=" in item
            for name, version in [item.split("=", 1)]
        }
        version_commands = {
            "nmap": [self.settings.nmap_path, "--version"],
            "naabu": [self.settings.naabu_path, "-version"],
            "httpx": [self.settings.httpx_path, "-version"],
            "nuclei": [self.settings.nuclei_path, "-version"],
            "testssl.sh": [self.settings.testssl_path, "--version"],
            "ssh-audit": [self.settings.ssh_audit_path, "--version"],
            "dnsx": [self.settings.dnsx_path, "-version"],
            "gowitness": [self.settings.gowitness_path, "version"],
        }
        for name, args in version_commands.items():
            if name in configured or not command_runner.dependency_available(args[0]):
                continue
            try:
                result = await command_runner.run(
                    scan_id,
                    args,
                    timeout=15,
                )
            except (CommandExecutionError, ToolUnavailableError, OSError):
                configured[name] = "installed; version query unavailable"
                continue
            output = result.stdout.strip() or result.stderr.strip()
            configured[name] = next(
                (line.strip()[:200] for line in output.splitlines() if line.strip()),
                "installed; version not reported",
            )
        with SessionLocal() as db:
            scan = db.scalar(select(Scan).where(Scan.public_id == scan_id))
            if scan:
                scan.scanner_versions = configured
                db.commit()

    @staticmethod
    def _initialize_coverage(scan_id: str) -> None:
        for scanner_name in (
            "naabu",
            "nmap",
            "httpx",
            "dnsx",
            "nuclei",
            "testssl.sh",
            "ssh-audit",
            "gowitness",
            "cisa-kev",
        ):
            ScanOrchestrator._set_coverage(scan_id, scanner_name, "pending")

    @staticmethod
    def _set_coverage(
        scan_id: str,
        scanner_name: str,
        status: str,
        *,
        detail: str | None = None,
        evidence_count: int | None = None,
    ) -> None:
        with SessionLocal() as db:
            scan = db.scalar(select(Scan).where(Scan.public_id == scan_id))
            if not scan:
                return
            options = dict(scan.options or {})
            coverage = dict(options.get("coverage") or {})
            entry: dict[str, Any] = {
                "status": status,
                "updated_at": datetime.now(UTC).isoformat(),
            }
            if detail:
                entry["detail"] = detail[:500]
            if evidence_count is not None:
                entry["evidence_count"] = evidence_count
            coverage[scanner_name] = entry
            options["coverage"] = coverage
            checklist = dict(options.get("checklist") or {})
            checklist_status = {
                "failed": "SCAN ERROR",
                "unavailable": "NOT TESTED",
                "not_applicable": "NOT APPLICABLE",
                "disabled": "NOT TESTED",
                "skipped_by_profile": "NOT TESTED",
                "pending": "INCONCLUSIVE",
                "running": "INCONCLUSIVE",
            }.get(status, "INFORMATIONAL")
            if status == "completed" and scanner_name in {"testssl.sh", "ssh-audit"}:
                checklist_status = "FAIL" if (evidence_count or 0) > 0 else "PASS"
            checklist[scanner_name] = {
                "status": checklist_status,
                "coverage_status": status,
                "detail": detail or "",
                "updated_at": entry["updated_at"],
            }
            options["checklist"] = checklist
            scan.options = options
            db.commit()

    @staticmethod
    def _merge_checklist(scan_id: str, entries: dict[str, dict[str, str]]) -> None:
        """Merge protocol-specific checklist results into the scan record."""
        with SessionLocal() as db:
            scan = db.scalar(select(Scan).where(Scan.public_id == scan_id))
            if not scan:
                return
            options = dict(scan.options or {})
            checklist = dict(options.get("checklist") or {})
            timestamp = datetime.now(UTC).isoformat()
            checklist.update(
                {
                    key: {**value, "coverage_status": "completed", "updated_at": timestamp}
                    for key, value in entries.items()
                }
            )
            options["checklist"] = checklist
            scan.options = options
            db.commit()

    @staticmethod
    def _fail_running_coverage(scan_id: str, detail: str) -> None:
        with SessionLocal() as db:
            scan = db.scalar(select(Scan).where(Scan.public_id == scan_id))
            if not scan:
                return
            options = dict(scan.options or {})
            coverage = dict(options.get("coverage") or {})
            for scanner_name, entry in coverage.items():
                if entry.get("status") == "running":
                    coverage[scanner_name] = {
                        "status": "failed",
                        "detail": detail[:500],
                        "updated_at": datetime.now(UTC).isoformat(),
                    }
            options["coverage"] = coverage
            checklist = dict(options.get("checklist") or {})
            for scanner_name, entry in coverage.items():
                if entry.get("status") == "failed":
                    checklist[scanner_name] = {
                        "status": "SCAN ERROR",
                        "coverage_status": "failed",
                        "detail": detail[:500],
                        "updated_at": datetime.now(UTC).isoformat(),
                    }
            options["checklist"] = checklist
            scan.options = options
            db.commit()

    @staticmethod
    def _confirmed_endpoints(nmap_data: dict[str, Any]) -> dict[str, list[Any]]:
        """Derive follow-up targets exclusively from Nmap-confirmed open services."""
        http_urls: list[str] = []
        ssh_endpoints: list[dict[str, Any]] = []
        tls_endpoints: list[dict[str, Any]] = []
        service_targets: list[str] = []
        hostnames: list[str] = []
        for asset in nmap_data.get("assets", []):
            ip = asset["ip"]
            if asset.get("hostname"):
                hostnames.append(asset["hostname"])
            for service in asset.get("services", []):
                protocol = str(service.get("protocol", "")).lower()
                port = int(service["port"])
                endpoint = {"ip": ip, "port": port, "protocol": protocol}
                service_targets.append(f"{ip}:{port}")
                if protocol in {"http", "http-proxy"}:
                    http_urls.append(f"http://{ip}:{port}")
                if protocol in {"https", "ssl", "tls", "https-alt"} or port in {
                    443,
                    465,
                    636,
                    853,
                    993,
                    995,
                    8443,
                }:
                    if protocol.startswith("http"):
                        http_urls.append(f"https://{ip}:{port}")
                    tls_endpoints.append(endpoint)
                else:
                    starttls_protocols = {
                        "ftp": "ftp",
                        "smtp": "smtp",
                        "submission": "smtp",
                        "pop3": "pop3",
                        "imap": "imap",
                        "ldap": "ldap",
                        "nntp": "nntp",
                        "postgresql": "postgres",
                        "mysql": "mysql",
                        "xmpp-client": "xmpp",
                        "xmpp-server": "xmpp-server",
                        "sieve": "sieve",
                    }
                    starttls_ports = {
                        21: "ftp",
                        25: "smtp",
                        110: "pop3",
                        119: "nntp",
                        143: "imap",
                        389: "ldap",
                        587: "smtp",
                        3306: "mysql",
                        4190: "sieve",
                        5222: "xmpp",
                        5269: "xmpp-server",
                        5432: "postgres",
                    }
                    starttls = starttls_protocols.get(protocol) or starttls_ports.get(port)
                    if starttls:
                        tls_endpoints.append({**endpoint, "starttls": starttls})
                if protocol == "ssh" or port == 22:
                    ssh_endpoints.append(endpoint)
        return {
            "http_urls": http_urls,
            "ssh_endpoints": ssh_endpoints,
            "tls_endpoints": tls_endpoints,
            "nuclei_targets": list(dict.fromkeys([*http_urls, *service_targets])),
            "hostnames": list(dict.fromkeys(hostnames)),
        }

    def _progress(self, scan_id: str, progress: int, stage: str) -> None:
        with SessionLocal() as db:
            scan = db.scalar(select(Scan).where(Scan.public_id == scan_id))
            if scan:
                scan.progress, scan.current_stage = progress, stage
                db.commit()

    @staticmethod
    def _set_target_progress(scan_id: str, completed: list[str], pending: list[str]) -> None:
        with SessionLocal() as db:
            scan = db.scalar(select(Scan).where(Scan.public_id == scan_id))
            if scan:
                options = dict(scan.options or {})
                options["target_progress"] = {
                    "completed": list(completed),
                    "pending": list(pending),
                }
                scan.options = options
                db.commit()

    @staticmethod
    def _record_naabu_confirmation(
        scan_id: str,
        naabu_results: list[dict[str, Any]],
        nmap_data: dict[str, Any],
    ) -> None:
        """Record that only Nmap-confirmed Naabu discoveries enter the final inventory."""
        discovered = {
            (str(item.get("ip")), int(item["port"]))
            for item in naabu_results
            if item.get("ip") and item.get("port")
        }
        confirmed = {
            (str(asset["ip"]), int(service["port"]))
            for asset in nmap_data.get("assets", [])
            for service in asset.get("services", [])
            if str(service.get("transport", "tcp")).lower() == "tcp"
        }
        unconfirmed = sorted(discovered - confirmed)
        with SessionLocal() as db:
            scan = db.scalar(select(Scan).where(Scan.public_id == scan_id))
            if not scan:
                return
            options = dict(scan.options or {})
            options["naabu_confirmation"] = {
                "discovered": len(discovered),
                "confirmed_by_nmap": len(discovered & confirmed),
                "discarded_unconfirmed": len(unconfirmed),
                "unconfirmed_sample": [f"{ip}:{port}" for ip, port in unconfirmed[:25]],
            }
            scan.options = options
            db.commit()

    def _persist_nmap(self, scan_id: str, data: dict[str, Any]) -> None:
        with SessionLocal() as db:
            scan = db.scalar(select(Scan).where(Scan.public_id == scan_id))
            if not scan:
                return
            for item in data.get("assets", []):
                asset = Asset(
                    scan_id=scan.id,
                    ip=item["ip"],
                    hostname=item.get("hostname"),
                    reachability=item.get("reachability", "unknown"),
                    operating_system=item.get("os"),
                )
                db.add(asset)
                db.flush()
                for svc in item.get("services", []):
                    db.add(
                        Service(
                            asset_id=asset.id,
                            port=svc["port"],
                            transport=svc["transport"],
                            protocol=svc["protocol"],
                            product=svc.get("product"),
                            version=svc.get("version"),
                            cpe=svc.get("cpe", []),
                            banner=redact(svc.get("banner")),
                            encryption=svc["protocol"] in {"https", "ssl", "tls"},
                            confidence=svc.get("confidence", "potential"),
                            source_scanner="nmap",
                            raw_evidence_location=str(self.settings.evidence_dir / scan_id / "nmap.xml"),
                        )
                    )
            db.commit()

    def _persist_httpx(self, scan_id: str, observations: list[dict[str, Any]]) -> None:
        if not observations:
            return
        with SessionLocal() as db:
            scan = db.scalar(select(Scan).where(Scan.public_id == scan_id))
            if not scan:
                return
            for observation in observations:
                ip = str(observation.get("ip") or "")
                port = observation.get("port")
                if not ip or not port:
                    continue
                asset = db.scalar(select(Asset).where(Asset.scan_id == scan.id, Asset.ip == ip))
                if not asset:
                    continue
                service = db.scalar(
                    select(Service).where(Service.asset_id == asset.id, Service.port == int(port))
                )
                if not service:
                    continue
                technologies = observation.get("technologies") or []
                if not service.product:
                    service.product = (
                        str(observation.get("server") or "")
                        or ", ".join(str(value) for value in technologies)
                        or None
                    )
                service.cpe = sorted(set(service.cpe or []) | set(observation.get("cpe") or []))
                service.banner = redact(
                    f"HTTP {observation.get('status_code')}; title={observation.get('title') or ''}; "
                    f"redirect={observation.get('location') or ''}; cdn={observation.get('cdn_name') or ''}"
                )[:1000]
                service.encryption = bool(observation.get("tls")) or str(
                    observation.get("url", "")
                ).startswith("https://")
                service.raw_evidence_location = str(
                    self.settings.evidence_dir / scan_id / "httpx.jsonl"
                )
                if observation.get("asn"):
                    asset.asn = str(observation["asn"])[:64]
            db.commit()

    def _persist_findings(self, scan_id: str, raw: list[dict[str, Any]]) -> None:
        with SessionLocal() as db:
            scan = db.scalar(select(Scan).where(Scan.public_id == scan_id))
            if not scan:
                return
            engagement_id = scan.engagement.public_id
            normalized = deduplicate(
                [normalize_finding(item, scan_id=scan_id, engagement_id=engagement_id) for item in raw]
            )
            for item in normalized:
                risk_score, item["priority"] = calculate_risk(item)
                for risk_context_field in (
                    "authentication_required",
                    "product_eol",
                    "patch_available",
                    "business_impact",
                ):
                    item.pop(risk_context_field, None)
                item.pop("scan_id", None)
                item.pop("engagement_id", None)
                previous = db.scalar(
                    select(Finding)
                    .where(
                        Finding.engagement_public_id == engagement_id,
                        Finding.finding_id == item["finding_id"],
                    )
                    .order_by(Finding.last_seen.desc())
                )
                if previous:
                    item["first_seen"] = previous.first_seen
                    item["status"] = (
                        "reopened"
                        if previous.status in {"resolved", "mitigated", "false positive", "not applicable"}
                        else "still open"
                    )
                finding = Finding(scan_id=scan.id, engagement_public_id=engagement_id, **item)
                db.add(finding)
                db.flush()
                evidence_scanners = item.get("source_references") or [item["scanner"]]
                for evidence_scanner in evidence_scanners:
                    evidence_file = self._evidence_file(
                        scan_id,
                        item,
                        scanner=str(evidence_scanner),
                    )
                    db.add(
                        Evidence(
                            finding_db_id=finding.id,
                            scanner=str(evidence_scanner),
                            evidence_type="scanner-output",
                            file_location=str(evidence_file) if evidence_file else None,
                            redacted_content=(
                                item.get("evidence", "")
                                if evidence_scanner == item["scanner"]
                                else "Corroborating scanner evidence is retained in the linked raw output."
                            ),
                        )
                    )
                asset = db.scalar(
                    select(Asset).where(Asset.scan_id == scan.id, Asset.ip == item["asset_ip"])
                )
                if asset:
                    asset.risk_score = max(asset.risk_score, risk_score)
            db.commit()

    def _evidence_file(
        self,
        scan_id: str,
        finding: dict[str, Any],
        *,
        scanner: str | None = None,
    ):
        base = self.settings.evidence_dir / scan_id
        scanner = scanner or finding.get("scanner")
        if scanner == "nuclei":
            return base / "nuclei.jsonl"
        if scanner == "testssl.sh":
            return base / f"testssl-{finding.get('asset_ip')}-{finding.get('port')}.json"
        if scanner == "ssh-audit":
            return base / f"ssh-audit-{finding.get('asset_ip')}-{finding.get('port')}.json"
        if scanner == "nmap":
            return base / "nmap.xml"
        return None

    def _finish(self, scan_id: str, status: str, error: str | None) -> None:
        with SessionLocal() as db:
            scan = db.scalar(select(Scan).where(Scan.public_id == scan_id))
            if scan:
                scan.status = status
                scan.progress = 100 if status == ScanStatus.COMPLETED else scan.progress
                scan.current_stage = str(status)
                scan.error_message = error
                scan.end_time = datetime.now(UTC)
                db.add(
                    AuditLog(
                        user_id=scan.started_by,
                        action="scan.finish",
                        target=scan.public_id,
                        result=str(status),
                        details={"error": error} if error else {},
                    )
                )
                db.commit()


scan_orchestrator = ScanOrchestrator()
