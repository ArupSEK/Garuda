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
            db.commit()
            context = ScanContext(
                scan.public_id,
                scan.targets,
                self.settings.evidence_dir / scan.public_id,
                scan.profile,
                scan.options,
            )
            context.work_dir.mkdir(parents=True, exist_ok=True)
        try:
            naabu = NaabuScanner(self.settings.naabu_path)
            if naabu.available:
                self._progress(scan_public_id, 10, "naabu discovery (pending nmap confirmation)")
                await naabu.scan(context)
            nmap = NmapScanner(self.settings.nmap_path)
            nmap_data = await nmap.scan(context)
            self._persist_nmap(scan_public_id, nmap_data)
            context.options.update(self._confirmed_endpoints(nmap_data))
            raw_findings: list[dict[str, Any]] = []
            self._progress(scan_public_id, 45, "http probing")
            httpx = HttpxScanner(self.settings.httpx_path)
            if httpx.available:
                await self._run_optional(scan_public_id, httpx, context)
            self._progress(scan_public_id, 65, "safe vulnerability checks")
            if context.profile != "quick":
                nuclei = NucleiScanner(self.settings.nuclei_path)
                if nuclei.available:
                    raw_findings.extend(await self._run_optional(scan_public_id, nuclei, context))
                if context.options.get("enable_tls", True):
                    testssl = TestsslScanner(self.settings.testssl_path)
                    if testssl.available:
                        raw_findings.extend(await self._run_optional(scan_public_id, testssl, context))
                if context.options.get("enable_ssh", True):
                    ssh_audit = SshAuditScanner(self.settings.ssh_audit_path)
                    if ssh_audit.available:
                        raw_findings.extend(await self._run_optional(scan_public_id, ssh_audit, context))
            self._persist_findings(scan_public_id, raw_findings)
            self._finish(scan_public_id, ScanStatus.COMPLETED, None)
        except (asyncio.CancelledError, ScanCancelled):
            self._finish(scan_public_id, ScanStatus.CANCELLED, None)
        except ToolUnavailableError as exc:
            self._finish(scan_public_id, ScanStatus.FAILED, str(exc))
        except ScannerError as exc:
            logger.warning("scan_failed id=%s error=%s", scan_public_id, exc)
            self._finish(scan_public_id, ScanStatus.FAILED, str(exc))
        except Exception as exc:
            logger.exception("unexpected_scan_failure id=%s", scan_public_id)
            self._finish(
                scan_public_id, ScanStatus.FAILED, f"Unexpected scan failure: {exc.__class__.__name__}"
            )

    @staticmethod
    async def _run_optional(scan_id: str, scanner: Any, context: ScanContext) -> list[dict]:
        """Keep a recoverable optional probe failure from discarding Nmap results."""
        try:
            return await scanner.scan(context)
        except (CommandExecutionError, ToolUnavailableError) as exc:
            logger.warning(
                "optional_scanner_failed id=%s scanner=%s error=%s",
                scan_id,
                scanner.name,
                exc,
            )
            return []

    @staticmethod
    def _confirmed_endpoints(nmap_data: dict[str, Any]) -> dict[str, list[Any]]:
        """Derive follow-up targets exclusively from Nmap-confirmed open services."""
        http_urls: list[str] = []
        ssh_endpoints: list[dict[str, Any]] = []
        tls_endpoints: list[dict[str, Any]] = []
        for asset in nmap_data.get("assets", []):
            ip = asset["ip"]
            for service in asset.get("services", []):
                protocol = str(service.get("protocol", "")).lower()
                port = int(service["port"])
                endpoint = {"ip": ip, "port": port}
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
