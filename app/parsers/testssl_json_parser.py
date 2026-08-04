"""Parse testssl.sh JSON findings."""

import json
from typing import Any


def parse_testssl_json(text: str) -> list[dict[str, Any]]:
    data = json.loads(text or "[]")
    rows = data if isinstance(data, list) else data.get("scanResult", data.get("findings", []))
    findings = []
    for row in rows:
        severity = str(row.get("severity", "INFO")).lower()
        if severity in {"ok", "good"}:
            continue
        findings.append(
            {
                "title": row.get("id", "TLS observation").replace("_", " "),
                "description": row.get("finding", ""),
                "severity": {
                    "warn": "medium",
                    "warning": "medium",
                    "low": "low",
                    "medium": "medium",
                    "high": "high",
                    "critical": "critical",
                }.get(severity, "info"),
                "scanner": "testssl.sh",
                "scanner_rule_id": row.get("id", "tls-observation"),
                "evidence": row.get("finding", ""),
                "confidence": "confirmed",
                "confidence_reason": "testssl.sh completed a direct TLS negotiation check.",
            }
        )
    return findings
