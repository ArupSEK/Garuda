"""Merge corroborating findings with the same stable fingerprint."""

from typing import Any

CONFIDENCE = {"confirmed": 5, "high": 4, "probable": 3, "version-based": 2, "potential": 1}


def deduplicate(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    merged: dict[str, dict[str, Any]] = {}
    for finding in findings:
        key = finding["finding_id"]
        if key not in merged:
            merged[key] = dict(finding)
            continue
        current = merged[key]
        if CONFIDENCE.get(str(finding.get("confidence", "potential")).lower(), 0) > CONFIDENCE.get(
            str(current.get("confidence", "potential")).lower(), 0
        ):
            primary = dict(finding)
            primary["source_references"] = current.get("source_references", [])
            current = merged[key] = primary
        current["source_references"] = sorted(
            set(current.get("source_references", [])) | {finding["scanner"]}
        )
        for field in ("cve", "cwe", "cpe", "references"):
            current[field] = sorted(set(current.get(field, [])) | set(finding.get(field, [])))
        if len(str(finding.get("evidence", ""))) > len(str(current.get("evidence", ""))):
            current["evidence"] = finding["evidence"]
    return list(merged.values())
