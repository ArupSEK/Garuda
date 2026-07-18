from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Literal

Severity = Literal["info", "low", "medium", "high", "critical"]
Confidence = Literal["suspected", "probable", "confirmed"]
ModuleStatus = Literal["completed", "skipped", "failed"]


@dataclass(slots=True)
class Evidence:
    summary: str
    details: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class Finding:
    module: str
    title: str
    severity: Severity
    confidence: Confidence
    asset: str
    category: str
    evidence: Evidence
    recommendation: str
    references: list[str] = field(default_factory=list)
    fingerprint: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class ModuleResult:
    module: str
    status: ModuleStatus
    duration_ms: float
    findings: list[Finding] = field(default_factory=list)
    artifacts: dict[str, Any] = field(default_factory=dict)
    message: str | None = None

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["findings"] = [item.to_dict() for item in self.findings]
        return payload


@dataclass(slots=True)
class ScanRequest:
    target: str
    ports: list[int]
    profile: str
    authorized: bool


@dataclass(slots=True)
class ResolvedTarget:
    original: str
    scheme: str | None
    host: str
    requested_port: int | None
    path: str
    addresses: tuple[str, ...]

    @property
    def display_url(self) -> str:
        scheme = self.scheme or "https"
        port = f":{self.requested_port}" if self.requested_port else ""
        return f"{scheme}://{self.host}{port}{self.path}"


@dataclass(slots=True)
class ScanContext:
    request: ScanRequest
    target: ResolvedTarget
    shared: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class ScanReport:
    target: ResolvedTarget
    profile: str
    started_at: str
    duration_ms: float
    modules: list[ModuleResult]
    policy: dict[str, Any]

    @classmethod
    def now(
        cls,
        *,
        target: ResolvedTarget,
        profile: str,
        duration_ms: float,
        modules: list[ModuleResult],
        policy: dict[str, Any],
    ) -> "ScanReport":
        return cls(
            target=target,
            profile=profile,
            started_at=datetime.now(timezone.utc).isoformat(),
            duration_ms=duration_ms,
            modules=modules,
            policy=policy,
        )

    def to_dict(self) -> dict[str, Any]:
        findings = [finding for result in self.modules for finding in result.findings]
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        findings.sort(key=lambda item: (severity_order[item.severity], item.title))
        counts = {severity: 0 for severity in severity_order}
        for finding in findings:
            counts[finding.severity] += 1

        return {
            "target": asdict(self.target),
            "profile": self.profile,
            "started_at": self.started_at,
            "duration_ms": self.duration_ms,
            "policy": self.policy,
            "summary": {
                "modules_total": len(self.modules),
                "modules_completed": sum(result.status == "completed" for result in self.modules),
                "modules_skipped": sum(result.status == "skipped" for result in self.modules),
                "modules_failed": sum(result.status == "failed" for result in self.modules),
                "findings_total": len(findings),
                "severity": counts,
                "open_ports": len(self._open_ports()),
            },
            "open_ports": self._open_ports(),
            "findings": [item.to_dict() for item in findings],
            "modules": [result.to_dict() for result in self.modules],
        }

    def _open_ports(self) -> list[dict[str, Any]]:
        for result in self.modules:
            ports = result.artifacts.get("open_ports")
            if isinstance(ports, list):
                return ports
        return []
