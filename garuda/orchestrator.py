from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Iterable

from .models import ModuleResult, ScanContext, ScanReport, ScanRequest
from .modules import HttpProbeModule, NmapAdapter, NucleiAdapter, TcpConnectModule
from .modules.base import ScanModule
from .scope import ScopeError, parse_ports, resolve_public_target


@dataclass(frozen=True, slots=True)
class ScanProfile:
    name: str
    description: str
    modules: tuple[str, ...]


PROFILES = {
    "external-safe": ScanProfile(
        "external-safe",
        "Fast external surface assessment with TCP and pinned HTTP/TLS inspection.",
        ("tcp-connect", "http-probe"),
    ),
    "web-safe": ScanProfile(
        "web-safe",
        "External web assessment plus optional reviewed Nuclei safe templates.",
        ("tcp-connect", "http-probe", "nuclei-safe-templates"),
    ),
    "red-team-readonly": ScanProfile(
        "red-team-readonly",
        "Read-only service fingerprinting and safe template validation. No exploitation, brute force, or DoS.",
        ("tcp-connect", "http-probe", "nmap-service-detection", "nuclei-safe-templates"),
    ),
}


class Orchestrator:
    def __init__(self, modules: Iterable[ScanModule] | None = None) -> None:
        configured = modules or [TcpConnectModule(), HttpProbeModule(), NmapAdapter(), NucleiAdapter()]
        self.modules = {module.name: module for module in configured}

    def profiles(self) -> list[dict[str, object]]:
        return [
            {"name": profile.name, "description": profile.description, "modules": list(profile.modules)}
            for profile in PROFILES.values()
        ]

    def capabilities(self) -> list[dict[str, object]]:
        return [module.capability() for module in self.modules.values()]

    def scan(self, *, target: str, raw_ports: str | list[int] | None, profile: str, authorized: bool) -> dict[str, object]:
        if not authorized:
            raise ScopeError("Explicit authorization is required before scanning a target.")
        if profile not in PROFILES:
            raise ScopeError(f"Unknown scan profile: {profile}")

        resolved = resolve_public_target(target)
        ports = parse_ports(raw_ports, requested_port=resolved.requested_port)
        request = ScanRequest(target=target, ports=ports, profile=profile, authorized=True)
        context = ScanContext(request=request, target=resolved)
        started = time.perf_counter()
        results: list[ModuleResult] = []

        for module_name in PROFILES[profile].modules:
            module = self.modules.get(module_name)
            if module is None:
                results.append(ModuleResult(module_name, "failed", 0.0, message="Configured module was not registered."))
                continue
            try:
                results.append(module.run(context))
            except Exception as exc:
                results.append(ModuleResult(module_name, "failed", 0.0, message=f"{exc.__class__.__name__}: {exc}"))

        report = ScanReport.now(
            target=resolved,
            profile=profile,
            duration_ms=round((time.perf_counter() - started) * 1000, 2),
            modules=results,
            policy={
                "scope": "public-internet-addresses-only",
                "authorization_required": True,
                "dns_pinning": True,
                "max_ports": 256,
                "destructive_tests": False,
                "exploit_payloads": False,
                "brute_force": False,
                "denial_of_service": False,
            },
        )
        return report.to_dict()
