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
from app.models import Asset, AuditLog, Finding, Scan, Service
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
from app.services.risk_engine import calculate_risk
from app.utils.command_runner import command_runner

logger = logging.getLogger(__name__)


class ScanOrchestrator:
    def __init__(self) -> None:
        self.settings = get_settings()
        self.tasks: dict[str, asyncio.Task] = {}

    def start(self, scan_public_id: str) -> None:
        task = asyncio.create_task(self.run(scan_public_id), name=f"scan-{scan_public_id}")
        self.tasks[scan_public_id] = task
        task.add_done_callback(lambda _: self.tasks.pop(scan_public_id, None))

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
            naabu = NaabuScanner(self.settings.naabu_path)
            if naabu.available:
                self._progress(scan_public_id, 10, "naabu discovery (pending nmap confirmation)")
                await self._run_optional(scan_public_id, naabu, context)
            else:
                self._set_coverage(scan_public_id, naabu.name, "unavailable")

            nmap = NmapScanner(self.settings.nmap_path)
            self._set_coverage(scan_public_id, nmap.name, "running")
            nmap_data = await nmap.scan(context)
            self._persist_nmap(scan_public_id, nmap_data)
            service_count = sum(len(asset.get("services", [])) for asset in nmap_data.get("assets", []))
            self._set_coverage(
                scan_public_id,
                nmap.name,
                "completed",
                evidence_count=service_count,
            )
            context.options.update(self._confirmed_endpoints(nmap_data))
            raw_findings: list[dict[str, Any]] = []

            self._progress(scan_public_id, 45, "http probing")
            httpx = HttpxScanner(self.settings.httpx_path)
            if not context.options.get("http_urls"):
                self._set_coverage(scan_public_id, httpx.name, "not_applicable")
            elif httpx.available:
                await self._run_optional(scan_public_id, httpx, context)
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

            self._progress(scan_public_id, 95, "normalizing findings")
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
                endpoint = {"ip": ip, "port": port}
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
                            banner=svc.get("banner"),
                            encryption=svc["protocol"] in {"https", "ssl", "tls"},
                            confidence=svc.get("confidence", "potential"),
                            source_scanner="nmap",
                            raw_evidence_location=str(self.settings.evidence_dir / scan_id / "nmap.xml"),
                        )
                    )
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
                _, item["priority"] = calculate_risk(item)
                item.pop("scan_id", None)
                item.pop("engagement_id", None)
                db.add(Finding(scan_id=scan.id, engagement_public_id=engagement_id, **item))
            db.commit()

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
