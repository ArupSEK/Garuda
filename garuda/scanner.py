from __future__ import annotations

import concurrent.futures
import ipaddress
import socket
import ssl
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from http.client import HTTPConnection, HTTPSConnection
from typing import Iterable
from urllib.parse import urlsplit


DEFAULT_PORTS = [21, 22, 25, 53, 80, 110, 143, 443, 445, 587, 993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 9200]
MAX_PORTS_PER_SCAN = 25
MAX_WORKERS = 16
DEFAULT_TIMEOUT = 2.5


class ScopeError(ValueError):
    """Raised when a scan target is outside the allowed public scope."""


@dataclass(frozen=True)
class Target:
    original: str
    host: str
    addresses: tuple[str, ...]


def normalize_target(raw_target: str) -> str:
    target = raw_target.strip()
    if not target:
        raise ScopeError("Target is required.")

    if "://" in target:
        parsed = urlsplit(target)
        host = parsed.hostname
    else:
        parsed = urlsplit(f"//{target.split('/', 1)[0]}")
        host = parsed.hostname or target.split("/", 1)[0]

    if not host:
        raise ScopeError("Target host could not be parsed.")

    return host.strip("[]").rstrip(".")


def is_public_address(address: str) -> bool:
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return False
    return ip.is_global


def resolve_public_target(raw_target: str) -> Target:
    host = normalize_target(raw_target)
    addresses: set[str] = set()

    try:
        direct_ip = ipaddress.ip_address(host)
    except ValueError:
        direct_ip = None

    if direct_ip is not None:
        addresses.add(str(direct_ip))
    else:
        try:
            records = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
        except socket.gaierror as exc:
            raise ScopeError(f"Target could not be resolved: {exc}") from exc

        for record in records:
            sockaddr = record[4]
            if sockaddr:
                addresses.add(sockaddr[0])

    if not addresses:
        raise ScopeError("Target did not resolve to an IP address.")

    blocked = sorted(address for address in addresses if not is_public_address(address))
    if blocked:
        raise ScopeError(f"Target resolves to non-public address(es): {', '.join(blocked)}")

    return Target(original=raw_target.strip(), host=host, addresses=tuple(sorted(addresses)))


def parse_ports(raw_ports: str | Iterable[int] | None) -> list[int]:
    if raw_ports is None or raw_ports == "":
        return DEFAULT_PORTS.copy()

    ports: set[int] = set()
    if isinstance(raw_ports, str):
        chunks = [part.strip() for part in raw_ports.split(",") if part.strip()]
        for chunk in chunks:
            try:
                if "-" in chunk:
                    start_text, end_text = chunk.split("-", 1)
                    start = int(start_text)
                    end = int(end_text)
                    if start > end:
                        start, end = end, start
                    ports.update(range(start, end + 1))
                else:
                    ports.add(int(chunk))
            except ValueError as exc:
                raise ScopeError(f"Invalid port expression: {chunk}") from exc
    else:
        try:
            ports.update(int(port) for port in raw_ports)
        except ValueError as exc:
            raise ScopeError("Port values must be integers.") from exc

    invalid = [port for port in ports if port < 1 or port > 65535]
    if invalid:
        raise ScopeError(f"Invalid port(s): {', '.join(str(port) for port in sorted(invalid))}")

    if len(ports) > MAX_PORTS_PER_SCAN:
        raise ScopeError(f"Port list is limited to {MAX_PORTS_PER_SCAN} ports per scan.")

    return sorted(ports)


def scan_target(raw_target: str, raw_ports: str | Iterable[int] | None = None, timeout: float = DEFAULT_TIMEOUT) -> dict:
    target = resolve_public_target(raw_target)
    ports = parse_ports(raw_ports)
    timeout = max(0.5, min(float(timeout), 5.0))
    started = time.perf_counter()

    with concurrent.futures.ThreadPoolExecutor(max_workers=min(MAX_WORKERS, len(ports) or 1)) as executor:
        futures = [executor.submit(_scan_port, target, port, timeout) for port in ports]
        port_results = [future.result() for future in concurrent.futures.as_completed(futures)]

    port_results.sort(key=lambda item: item["port"])
    open_ports = [item for item in port_results if item["state"] == "open"]

    return {
        "target": target.original,
        "host": target.host,
        "addresses": target.addresses,
        "started_at": datetime.now(timezone.utc).isoformat(),
        "duration_ms": round((time.perf_counter() - started) * 1000, 2),
        "authorization_required": True,
        "policy": {
            "scope": "public-internet-addresses-only",
            "max_ports": MAX_PORTS_PER_SCAN,
            "timeout_seconds": timeout,
            "destructive_tests": False,
        },
        "summary": {
            "ports_scanned": len(port_results),
            "open_ports": len(open_ports),
            "http_services": sum(1 for item in open_ports if item.get("http")),
            "tls_services": sum(1 for item in open_ports if item.get("tls")),
        },
        "ports": port_results,
        "findings": build_findings(open_ports),
    }


def _scan_port(target: Target, port: int, timeout: float) -> dict:
    address_results = [_connect(address, port, timeout) for address in target.addresses]
    best = next((result for result in address_results if result["state"] == "open"), address_results[0])
    result = {
        "port": port,
        "state": best["state"],
        "address": best["address"],
        "latency_ms": best.get("latency_ms"),
        "error": best.get("error"),
    }

    if result["state"] != "open":
        return result

    service = infer_service(port)
    result["service"] = service

    if service in {"http", "https"}:
        http_result = inspect_http(target.host, best["address"], port, service == "https", timeout)
        if http_result:
            result["http"] = http_result
            if http_result.get("tls"):
                result["tls"] = http_result["tls"]

    return result


def _connect(address: str, port: int, timeout: float) -> dict:
    started = time.perf_counter()
    try:
        with socket.create_connection((address, port), timeout=timeout):
            return {
                "address": address,
                "state": "open",
                "latency_ms": round((time.perf_counter() - started) * 1000, 2),
            }
    except (TimeoutError, OSError) as exc:
        return {
            "address": address,
            "state": "closed_or_filtered",
            "latency_ms": round((time.perf_counter() - started) * 1000, 2),
            "error": exc.__class__.__name__,
        }


def infer_service(port: int) -> str:
    return {
        21: "ftp",
        22: "ssh",
        25: "smtp",
        53: "dns",
        80: "http",
        110: "pop3",
        143: "imap",
        443: "https",
        445: "smb",
        587: "smtp-submission",
        993: "imaps",
        995: "pop3s",
        1433: "mssql",
        1521: "oracle",
        3306: "mysql",
        3389: "rdp",
        5432: "postgresql",
        5900: "vnc",
        6379: "redis",
        8080: "http",
        8443: "https",
        9200: "elasticsearch",
    }.get(port, "unknown")


def inspect_http(host: str, address: str, port: int, use_tls: bool, timeout: float) -> dict | None:
    connection_cls = HTTPSConnection if use_tls else HTTPConnection
    context = None
    if use_tls:
        context = ssl.create_default_context()

    try:
        if use_tls:
            connection = connection_cls(host=host, port=port, timeout=timeout, context=context)
        else:
            connection = connection_cls(host=address, port=port, timeout=timeout)

        connection.request("HEAD", "/", headers={"Host": host, "User-Agent": "Garuda-Authorized-Scanner/0.1"})
        response = connection.getresponse()
        headers = {key.lower(): value for key, value in response.getheaders()}
        result = {
            "status": response.status,
            "reason": response.reason,
            "headers": summarize_headers(headers),
            "security_headers": evaluate_security_headers(headers, use_tls),
        }
        if use_tls:
            tls = inspect_tls(host, address, port, timeout)
            if tls:
                result["tls"] = tls
        connection.close()
        return result
    except (ssl.SSLError, OSError, TimeoutError):
        return None


def summarize_headers(headers: dict[str, str]) -> dict[str, str]:
    interesting = ["server", "x-powered-by", "content-type", "location"]
    return {key: headers[key] for key in interesting if key in headers}


def evaluate_security_headers(headers: dict[str, str], use_tls: bool) -> dict:
    expected = {
        "strict-transport-security": use_tls,
        "content-security-policy": True,
        "x-content-type-options": True,
        "x-frame-options": True,
        "referrer-policy": True,
        "permissions-policy": True,
    }
    present = sorted(name for name in expected if name in headers)
    missing = sorted(name for name, required in expected.items() if required and name not in headers)
    return {"present": present, "missing": missing}


def inspect_tls(host: str, address: str, port: int, timeout: float) -> dict | None:
    context = ssl.create_default_context()
    try:
        with socket.create_connection((address, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as wrapped:
                certificate = wrapped.getpeercert()
                not_after = certificate.get("notAfter")
                issuer = _name_tuple_to_dict(certificate.get("issuer", ()))
                subject = _name_tuple_to_dict(certificate.get("subject", ()))
                return {
                    "version": wrapped.version(),
                    "cipher": wrapped.cipher()[0] if wrapped.cipher() else None,
                    "certificate": {
                        "subject": subject,
                        "issuer": issuer,
                        "not_after": not_after,
                    },
                }
    except (ssl.SSLError, OSError, TimeoutError):
        return None


def _name_tuple_to_dict(items: tuple) -> dict[str, str]:
    parsed: dict[str, str] = {}
    for group in items:
        for key, value in group:
            parsed[key] = value
    return parsed


def build_findings(open_ports: list[dict]) -> list[dict]:
    findings: list[dict] = []
    for item in open_ports:
        service = item.get("service", "unknown")
        severity = "info"
        title = f"Open {service} service on TCP/{item['port']}"
        if service in {"smb", "rdp", "vnc", "redis", "elasticsearch", "mysql", "postgresql", "mssql"}:
            severity = "medium"
        findings.append({
            "severity": severity,
            "title": title,
            "evidence": f"{item['address']}:{item['port']} accepted a TCP connection.",
            "recommendation": recommendation_for_service(service),
        })

        http = item.get("http")
        missing_headers = (http or {}).get("security_headers", {}).get("missing", [])
        if missing_headers:
            findings.append({
                "severity": "low",
                "title": f"Missing HTTP security headers on TCP/{item['port']}",
                "evidence": ", ".join(missing_headers),
                "recommendation": "Add the missing response headers where compatible with the application.",
            })
    return findings


def recommendation_for_service(service: str) -> str:
    if service in {"smb", "rdp", "vnc"}:
        return "Restrict administrative services to VPN or allowlisted management networks."
    if service in {"redis", "elasticsearch", "mysql", "postgresql", "mssql"}:
        return "Avoid exposing data services directly to the internet; require private networking and strong authentication."
    if service in {"http", "https"}:
        return "Confirm the service is intended to be public, patched, and protected by appropriate access controls."
    return "Confirm business need, patch level, and firewall exposure."
