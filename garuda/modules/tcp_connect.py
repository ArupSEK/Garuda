from __future__ import annotations

import concurrent.futures
import socket
import time
from typing import Any

from garuda.models import Evidence, Finding, ModuleResult, ScanContext
from garuda.modules.base import ScanModule

SERVICE_MAP = {
    21: "ftp", 22: "ssh", 25: "smtp", 53: "dns", 80: "http", 110: "pop3",
    143: "imap", 443: "https", 445: "smb", 587: "smtp-submission", 993: "imaps",
    995: "pop3s", 1433: "mssql", 1521: "oracle", 3306: "mysql", 3389: "rdp",
    5432: "postgresql", 5900: "vnc", 6379: "redis", 8080: "http", 8443: "https",
    9200: "elasticsearch",
}
SENSITIVE = {"smb", "rdp", "vnc", "redis", "elasticsearch", "mysql", "postgresql", "mssql", "oracle"}


class TcpConnectModule(ScanModule):
    name = "tcp-connect"
    description = "Concurrent TCP reachability and external service exposure checks."

    def run(self, context: ScanContext) -> ModuleResult:
        started = time.perf_counter()
        work = [(address, port) for address in context.target.addresses for port in context.request.ports]
        results: list[dict[str, Any]] = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=min(32, len(work) or 1)) as executor:
            futures = [executor.submit(self._connect, address, port, 2.5) for address, port in work]
            for future in concurrent.futures.as_completed(futures):
                results.append(future.result())

        open_ports = sorted((item for item in results if item["state"] == "open"), key=lambda item: (item["port"], item["address"]))
        context.shared["open_ports"] = open_ports
        findings: list[Finding] = []
        for item in open_ports:
            service = item["service"]
            findings.append(Finding(
                module=self.name,
                title=f"Externally reachable {service} service on TCP/{item['port']}",
                severity="medium" if service in SENSITIVE else "info",
                confidence="confirmed",
                asset=context.target.host,
                category="network-exposure",
                evidence=Evidence(summary=f"{item['address']}:{item['port']} accepted a TCP connection.", details=item),
                recommendation=self._recommendation(service),
                fingerprint=f"{context.target.host}:{item['port']}:{service}",
            ))

        return ModuleResult(
            module=self.name,
            status="completed",
            duration_ms=round((time.perf_counter() - started) * 1000, 2),
            findings=findings,
            artifacts={"open_ports": open_ports, "probes": len(results)},
        )

    @staticmethod
    def _connect(address: str, port: int, timeout: float) -> dict[str, Any]:
        started = time.perf_counter()
        try:
            with socket.create_connection((address, port), timeout=timeout):
                state, error = "open", None
        except (TimeoutError, OSError) as exc:
            state, error = "closed_or_filtered", exc.__class__.__name__
        return {
            "address": address,
            "port": port,
            "state": state,
            "service": SERVICE_MAP.get(port, "unknown"),
            "latency_ms": round((time.perf_counter() - started) * 1000, 2),
            "error": error,
        }

    @staticmethod
    def _recommendation(service: str) -> str:
        if service in {"smb", "rdp", "vnc"}:
            return "Restrict administrative services to VPN or allowlisted management networks."
        if service in {"redis", "elasticsearch", "mysql", "postgresql", "mssql", "oracle"}:
            return "Do not expose data services directly to the internet; use private networking and strong authentication."
        return "Confirm the service is intended to be public, patched, monitored, and protected by access controls."
