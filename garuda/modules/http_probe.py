from __future__ import annotations

import socket
import ssl
import time
from typing import Any

from garuda.models import Evidence, Finding, ModuleResult, ScanContext
from garuda.modules.base import ScanModule

HTTP_PORTS = {80: False, 443: True, 8080: False, 8443: True}
EXPECTED_HEADERS = {
    "content-security-policy": "Define a restrictive Content-Security-Policy.",
    "x-content-type-options": "Set X-Content-Type-Options: nosniff.",
    "referrer-policy": "Set a suitable Referrer-Policy.",
    "permissions-policy": "Set a restrictive Permissions-Policy.",
}


class HttpProbeModule(ScanModule):
    name = "http-probe"
    description = "Pinned-IP HTTP/TLS inspection, header analysis, and lightweight technology evidence."

    def run(self, context: ScanContext) -> ModuleResult:
        started = time.perf_counter()
        open_ports = context.shared.get("open_ports", [])
        candidates = [item for item in open_ports if item["port"] in HTTP_PORTS]
        artifacts: list[dict[str, Any]] = []
        findings: list[Finding] = []

        for item in candidates:
            use_tls = HTTP_PORTS[item["port"]]
            result = self._request(
                host=context.target.host,
                address=item["address"],
                port=item["port"],
                path=context.target.path,
                use_tls=use_tls,
                timeout=5.0,
            )
            if not result:
                continue
            artifacts.append(result)
            findings.extend(self._findings(context, result, use_tls))

        context.shared["http_services"] = artifacts
        return ModuleResult(
            module=self.name,
            status="completed",
            duration_ms=round((time.perf_counter() - started) * 1000, 2),
            findings=findings,
            artifacts={"services": artifacts},
        )

    def _request(self, *, host: str, address: str, port: int, path: str, use_tls: bool, timeout: float) -> dict[str, Any] | None:
        request_path = path if path.startswith("/") else f"/{path}"
        for method in ("HEAD", "GET"):
            try:
                with socket.create_connection((address, port), timeout=timeout) as raw:
                    stream: socket.socket | ssl.SSLSocket = raw
                    tls: dict[str, Any] | None = None
                    if use_tls:
                        ssl_context = ssl.create_default_context()
                        stream = ssl_context.wrap_socket(raw, server_hostname=host)
                        certificate = stream.getpeercert()
                        tls = {
                            "version": stream.version(),
                            "cipher": stream.cipher()[0] if stream.cipher() else None,
                            "certificate": {
                                "subject": self._name_tuple(certificate.get("subject", ())),
                                "issuer": self._name_tuple(certificate.get("issuer", ())),
                                "not_after": certificate.get("notAfter"),
                            },
                        }
                    payload = (
                        f"{method} {request_path} HTTP/1.1\r\n"
                        f"Host: {host}\r\n"
                        "User-Agent: Garuda-Authorized-Scanner/1.0\r\n"
                        "Accept: */*\r\n"
                        "Connection: close\r\n\r\n"
                    ).encode("ascii", "strict")
                    stream.sendall(payload)
                    response = self._read_limited(stream, 65536)
                parsed = self._parse_response(response)
                if method == "HEAD" and parsed.get("status") in {405, 501}:
                    continue
                parsed.update({"address": address, "port": port, "method": method, "tls": tls})
                return parsed
            except (OSError, TimeoutError, ssl.SSLError, UnicodeError):
                return None
        return None

    @staticmethod
    def _read_limited(stream: socket.socket | ssl.SSLSocket, limit: int) -> bytes:
        chunks: list[bytes] = []
        total = 0
        while total < limit:
            chunk = stream.recv(min(8192, limit - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
        return b"".join(chunks)

    @staticmethod
    def _parse_response(response: bytes) -> dict[str, Any]:
        header_blob, _, body = response.partition(b"\r\n\r\n")
        lines = header_blob.decode("iso-8859-1", "replace").split("\r\n")
        status = None
        reason = ""
        if lines:
            parts = lines[0].split(" ", 2)
            if len(parts) >= 2 and parts[1].isdigit():
                status = int(parts[1])
                reason = parts[2] if len(parts) == 3 else ""
        headers: dict[str, str] = {}
        for line in lines[1:]:
            if ":" in line:
                key, value = line.split(":", 1)
                headers[key.strip().lower()] = value.strip()
        return {
            "status": status,
            "reason": reason,
            "headers": headers,
            "body_sample": body[:2048].decode("utf-8", "replace"),
        }

    def _findings(self, context: ScanContext, result: dict[str, Any], use_tls: bool) -> list[Finding]:
        headers = result["headers"]
        findings: list[Finding] = []
        missing = [name for name in EXPECTED_HEADERS if name not in headers]
        if use_tls and "strict-transport-security" not in headers:
            missing.append("strict-transport-security")
        if "x-frame-options" not in headers and "frame-ancestors" not in headers.get("content-security-policy", "").lower():
            missing.append("frame-protection")

        if missing:
            findings.append(Finding(
                module=self.name,
                title=f"Missing recommended HTTP security controls on TCP/{result['port']}",
                severity="low",
                confidence="confirmed",
                asset=context.target.host,
                category="web-hardening",
                evidence=Evidence(
                    summary=f"Missing controls: {', '.join(sorted(missing))}",
                    details={"url": context.target.display_url, "status": result["status"], "missing": missing},
                ),
                recommendation="Configure the missing response-header protections where compatible with the application.",
                fingerprint=f"{context.target.host}:{result['port']}:headers:{','.join(sorted(missing))}",
            ))

        disclosures = {key: headers[key] for key in ("server", "x-powered-by") if key in headers}
        if disclosures:
            findings.append(Finding(
                module=self.name,
                title=f"Technology information disclosed on TCP/{result['port']}",
                severity="info",
                confidence="confirmed",
                asset=context.target.host,
                category="information-disclosure",
                evidence=Evidence(summary="Response headers disclose implementation details.", details=disclosures),
                recommendation="Reduce unnecessary product and version disclosure in externally visible headers.",
                fingerprint=f"{context.target.host}:{result['port']}:technology-disclosure",
            ))
        return findings

    @staticmethod
    def _name_tuple(items: tuple) -> dict[str, str]:
        parsed: dict[str, str] = {}
        for group in items:
            for key, value in group:
                parsed[key] = value
        return parsed
