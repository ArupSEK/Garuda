"""Parse ssh-audit JSON output."""

import json


def parse_ssh_audit(text: str) -> list[dict]:
    data = json.loads(text or "{}")
    findings = []
    for section in ("kex", "key", "enc", "mac"):
        algorithms = data.get(section, [])
        if isinstance(algorithms, dict):
            algorithms = algorithms.get("algorithms", [])
        for algorithm in algorithms:
            if not isinstance(algorithm, dict) or not (algorithm.get("fail") or algorithm.get("warn")):
                continue
            findings.append(
                {
                    "title": f"Weak SSH {section} algorithm: {algorithm.get('name', 'unknown')}",
                    "severity": "medium" if algorithm.get("fail") else "low",
                    "scanner": "ssh-audit",
                    "scanner_rule_id": f"ssh-{section}-{algorithm.get('name', 'unknown')}",
                    "evidence": "; ".join(algorithm.get("fail") or algorithm.get("warn") or []),
                    "confidence": "confirmed",
                }
            )
    return findings
