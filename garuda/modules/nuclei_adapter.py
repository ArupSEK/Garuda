from __future__ import annotations

import json
import os
import time
from typing import Any

from garuda.models import Evidence, Finding, ModuleResult, ScanContext
from garuda.modules.base import ScanModule
from garuda.process import executable_available, run_command

SEVERITIES = {"info", "low", "medium", "high", "critical"}


class NucleiAdapter(ScanModule):
    name = "nuclei-safe-templates"
    description = "Optional safe-template checks with rate limits and destructive categories excluded."

    def capability(self) -> dict[str, object]:
        enabled = os.getenv("GARUDA_ENABLE_NUCLEI", "0") == "1"
        return {
            **super().capability(),
            "available": enabled and executable_available("nuclei"),
            "required_binary": "nuclei",
            "enabled": enabled,
        }

    def run(self, context: ScanContext) -> ModuleResult:
        started = time.perf_counter()
        if os.getenv("GARUDA_ENABLE_NUCLEI", "0") != "1":
            return ModuleResult(self.name, "skipped", 0.0, message="Set GARUDA_ENABLE_NUCLEI=1 to enable reviewed safe-template execution.")
        if not executable_available("nuclei"):
            return ModuleResult(self.name, "skipped", 0.0, message="Nuclei is not installed or not in PATH.")

        command = [
            "nuclei", "-u", context.target.display_url, "-jsonl", "-silent",
            "-disable-update-check", "-no-interactsh", "-rate-limit", "20", "-bulk-size", "10", "-c", "5",
            "-exclude-tags", "dos,fuzz,bruteforce,default-login,headless,code",
        ]
        completed = run_command(command, timeout=300)
        if completed.returncode not in {0, 1}:
            return ModuleResult(
                self.name, "failed", round((time.perf_counter() - started) * 1000, 2),
                message=(completed.stderr.strip() or "Nuclei execution failed.")[:500],
            )

        raw: list[dict[str, Any]] = []
        findings: list[Finding] = []
        for line in completed.stdout.splitlines():
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue
            raw.append(item)
            info = item.get("info") or {}
            severity = str(info.get("severity", "info")).lower()
            if severity not in SEVERITIES:
                severity = "info"
            template_id = item.get("template-id") or item.get("templateID") or "unknown-template"
            matched = item.get("matched-at") or item.get("matched") or context.target.display_url
            findings.append(Finding(
                module=self.name,
                title=info.get("name") or str(template_id),
                severity=severity,
                confidence="probable",
                asset=context.target.host,
                category="template-detection",
                evidence=Evidence(
                    summary=f"Template {template_id} matched at {matched}.",
                    details={"template_id": template_id, "matched_at": matched, "matcher": item.get("matcher-name")},
                ),
                recommendation=info.get("remediation") or "Validate the finding manually and apply the vendor or application-specific remediation.",
                references=list(info.get("reference") or []),
                fingerprint=f"{context.target.host}:nuclei:{template_id}:{matched}",
            ))

        return ModuleResult(
            module=self.name,
            status="completed",
            duration_ms=round((time.perf_counter() - started) * 1000, 2),
            findings=findings,
            artifacts={"matches": len(raw)},
        )
