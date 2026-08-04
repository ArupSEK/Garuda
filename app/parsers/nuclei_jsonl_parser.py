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
                "cvss_v31_score": classification.get("cvss-score"),
                "cvss_v31_vector": classification.get("cvss-metrics"),
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
