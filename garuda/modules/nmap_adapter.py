from __future__ import annotations

import time
import xml.etree.ElementTree as ET

from garuda.models import Evidence, Finding, ModuleResult, ScanContext
from garuda.modules.base import ScanModule
from garuda.process import executable_available, run_command


class NmapAdapter(ScanModule):
    name = "nmap-service-detection"
    description = "Optional Nmap TCP service and version fingerprinting using non-exploit probes."

    def capability(self) -> dict[str, object]:
        return {**super().capability(), "available": executable_available("nmap"), "required_binary": "nmap"}

    def run(self, context: ScanContext) -> ModuleResult:
        started = time.perf_counter()
        if not executable_available("nmap"):
            return ModuleResult(self.name, "skipped", 0.0, message="Nmap is not installed or not in PATH.")

        address = context.target.addresses[0]
        ports = ",".join(str(port) for port in context.request.ports)
        command = [
            "nmap", "-sT", "-sV", "--version-light", "-Pn", "--reason",
            "--max-retries", "2", "--host-timeout", "180s", "-p", ports, "-oX", "-", address,
        ]
        try:
            completed = run_command(command, timeout=200)
        except Exception as exc:
            return ModuleResult(self.name, "failed", round((time.perf_counter() - started) * 1000, 2), message=str(exc))
        if completed.returncode not in {0, 1} or not completed.stdout.strip():
            return ModuleResult(
                self.name, "failed", round((time.perf_counter() - started) * 1000, 2),
                message=(completed.stderr.strip() or "Nmap returned no XML output.")[:500],
            )

        services, findings = self._parse(completed.stdout, context.target.host)
        return ModuleResult(
            module=self.name,
            status="completed",
            duration_ms=round((time.perf_counter() - started) * 1000, 2),
            findings=findings,
            artifacts={"services": services, "command": command[:-1] + ["<validated-address>"]},
        )

    @staticmethod
    def _parse(xml_text: str, asset: str) -> tuple[list[dict[str, object]], list[Finding]]:
        root = ET.fromstring(xml_text)
        services: list[dict[str, object]] = []
        findings: list[Finding] = []
        for port_node in root.findall(".//port"):
            state_node = port_node.find("state")
            if state_node is None or state_node.attrib.get("state") != "open":
                continue
            service_node = port_node.find("service")
            data = {
                "port": int(port_node.attrib.get("portid", "0")),
                "protocol": port_node.attrib.get("protocol", "tcp"),
                "name": service_node.attrib.get("name", "unknown") if service_node is not None else "unknown",
                "product": service_node.attrib.get("product") if service_node is not None else None,
                "version": service_node.attrib.get("version") if service_node is not None else None,
                "extrainfo": service_node.attrib.get("extrainfo") if service_node is not None else None,
                "tunnel": service_node.attrib.get("tunnel") if service_node is not None else None,
            }
            services.append(data)
            if data["product"] or data["version"]:
                findings.append(Finding(
                    module="nmap-service-detection",
                    title=f"Service fingerprint identified on TCP/{data['port']}",
                    severity="info",
                    confidence="probable",
                    asset=asset,
                    category="service-fingerprint",
                    evidence=Evidence(summary="Nmap identified a probable service product/version.", details=data),
                    recommendation="Validate the identified version and correlate it with vendor advisories and applicable CVEs.",
                    fingerprint=f"{asset}:{data['port']}:fingerprint:{data['product']}:{data['version']}",
                ))
        return services, findings
