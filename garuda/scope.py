from __future__ import annotations

import ipaddress
import socket
from collections.abc import Iterable
from urllib.parse import urlsplit

from .models import ResolvedTarget

DEFAULT_PORTS = [21, 22, 25, 53, 80, 110, 143, 443, 445, 587, 993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 9200]
MAX_PORTS_PER_SCAN = 256


class ScopeError(ValueError):
    """Raised when a target or scan option violates the configured scope."""


def parse_target(raw_target: str) -> tuple[str | None, str, int | None, str]:
    value = raw_target.strip()
    if not value:
        raise ScopeError("Target is required.")

    parsed = urlsplit(value if "://" in value else f"//{value}")
    host = parsed.hostname
    if not host:
        raise ScopeError("Target host could not be parsed.")

    scheme = parsed.scheme.lower() or None
    if scheme not in {None, "http", "https"}:
        raise ScopeError("Only HTTP, HTTPS, hostnames, and IP targets are supported.")

    try:
        requested_port = parsed.port
    except ValueError as exc:
        raise ScopeError("Target contains an invalid port.") from exc

    path = parsed.path or "/"
    if parsed.query:
        path = f"{path}?{parsed.query}"
    return scheme, host.strip("[]").rstrip("."), requested_port, path


def is_public_address(address: str) -> bool:
    try:
        return ipaddress.ip_address(address).is_global
    except ValueError:
        return False


def resolve_public_target(raw_target: str) -> ResolvedTarget:
    scheme, host, requested_port, path = parse_target(raw_target)
    addresses: set[str] = set()

    try:
        addresses.add(str(ipaddress.ip_address(host)))
    except ValueError:
        try:
            for record in socket.getaddrinfo(host, None, type=socket.SOCK_STREAM):
                if record[4]:
                    addresses.add(record[4][0])
        except socket.gaierror as exc:
            raise ScopeError(f"Target could not be resolved: {exc}") from exc

    if not addresses:
        raise ScopeError("Target did not resolve to an IP address.")

    blocked = sorted(address for address in addresses if not is_public_address(address))
    if blocked:
        raise ScopeError(f"Target resolves to non-public address(es): {', '.join(blocked)}")

    return ResolvedTarget(
        original=raw_target.strip(),
        scheme=scheme,
        host=host,
        requested_port=requested_port,
        path=path,
        addresses=tuple(sorted(addresses)),
    )


def parse_ports(raw_ports: str | Iterable[int] | None, *, requested_port: int | None = None) -> list[int]:
    if raw_ports is None or raw_ports == "":
        ports = set(DEFAULT_PORTS)
        if requested_port:
            ports.add(requested_port)
        return sorted(ports)

    ports: set[int] = set()
    if isinstance(raw_ports, str):
        chunks = [chunk.strip() for chunk in raw_ports.split(",") if chunk.strip()]
        for chunk in chunks:
            try:
                if "-" in chunk:
                    start_text, end_text = chunk.split("-", 1)
                    start, end = int(start_text), int(end_text)
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
        except (TypeError, ValueError) as exc:
            raise ScopeError("Port values must be integers.") from exc

    invalid = sorted(port for port in ports if not 1 <= port <= 65535)
    if invalid:
        raise ScopeError(f"Invalid port(s): {', '.join(map(str, invalid))}")
    if len(ports) > MAX_PORTS_PER_SCAN:
        raise ScopeError(f"Port list is limited to {MAX_PORTS_PER_SCAN} ports per scan.")
    return sorted(ports)
