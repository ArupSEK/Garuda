"""Configurable contextual risk scoring."""

from typing import Any


def calculate_risk(finding: dict[str, Any], asset_criticality: float = 5.0) -> tuple[float, str]:
    cvss = float(finding.get("cvss_v40_score") or finding.get("cvss_v31_score") or 0)
    confidence = {"confirmed": 10, "high": 8, "probable": 6, "version-based": 4, "potential": 2}.get(
        str(finding.get("confidence", "potential")).lower(), 2
    )
    score = (
        cvss * 0.35
        + 10 * 0.15
        + (10 if finding.get("cisa_kev") else 0) * 0.20
        + (10 if finding.get("exploit_available") else 0) * 0.10
        + confidence * 0.10
        + max(0, min(asset_criticality, 10)) * 0.10
    )
    score = round(min(score, 10), 2)
    priority = (
        "P1"
        if score >= 8.5
        else "P2"
        if score >= 7
        else "P3"
        if score >= 4
        else "P4"
        if score > 0
        else "Informational"
    )
    return score, priority
