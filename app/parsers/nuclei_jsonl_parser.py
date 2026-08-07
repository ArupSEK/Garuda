"""Parse Nuclei JSONL into raw normalized-finding inputs."""

import json
from urllib.parse import urlsplit


def parse_nuclei_jsonl(text: str) -> list[dict]:
    findings = []
    for line in text.splitlines():
        if not line.strip():
            continue
        item = json.loads(line)
        info = item.get("info", {})
        parsed = urlsplit(item.get("matched-at") or item.get("host") or "")
        classification = info.get("classification", {})
        cvss_vector = classification.get("cvss-metrics")
        cvss_score = classification.get("cvss-score")
        is_cvss_v4 = str(cvss_vector or "").startswith("CVSS:4.0")
        findings.append(
            {
                "asset_ip": item.get("ip") or parsed.hostname,
                "hostname": parsed.hostname,
                "port": parsed.port,
                "protocol": item.get("type") or parsed.scheme,
                "title": info.get("name") or item.get("template-id"),
                "description": info.get("description", ""),
                "severity": info.get("severity", "info"),
                "confidence": "confirmed" if item.get("matcher-status") is True else "high",
                "confidence_reason": "A trusted Nuclei template matched the live service.",
                "cve": classification.get("cve-id", []),
                "cwe": classification.get("cwe-id", []),
                "cpe": classification.get("cpe", []),
                "cvss_v31_score": None if is_cvss_v4 else cvss_score,
                "cvss_v31_vector": None if is_cvss_v4 else cvss_vector,
                "cvss_v40_score": cvss_score if is_cvss_v4 else None,
                "cvss_v40_vector": cvss_vector if is_cvss_v4 else None,
                "scanner": "nuclei",
                "scanner_rule_id": item.get("template-id", "unknown"),
                "matched_at": item.get("matched-at"),
                "evidence": item.get("matcher-name")
                or item.get("extracted-results")
                or item.get("matched-at"),
                "remediation": info.get(
                    "remediation", "Review the referenced advisory and update or reconfigure the service."
                ),
                "references": info.get("reference", []),
            }
        )
    return findings
