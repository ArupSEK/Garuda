"""Configurable contextual risk scoring beyond CVSS alone."""

from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml


@lru_cache
def _policy(path: str = "config/risk_scoring.yaml") -> dict[str, Any]:
    return yaml.safe_load(Path(path).read_text(encoding="utf-8"))


def calculate_risk(finding: dict[str, Any], asset_criticality: float = 5.0) -> tuple[float, str]:
    policy = _policy()
    weights = policy["weights"]
    cvss = float(finding.get("cvss_v40_score") or finding.get("cvss_v31_score") or 0)
    confidence = {"confirmed": 10, "high": 8, "probable": 6, "version-based": 4, "potential": 2}.get(
        str(finding.get("confidence", "potential")).lower(), 2
    )
    patch_available = finding.get("patch_available")
    patch_signal = 3.0 if patch_available is True else 10.0 if patch_available is False else 5.0
    signals = {
        "cvss": cvss,
        "internet_exposure": 10.0,
        "cisa_kev": 10.0 if finding.get("cisa_kev") else 0.0,
        "exploit_available": 10.0 if finding.get("exploit_available") else 0.0,
        "confidence": float(confidence),
        "asset_criticality": max(0.0, min(float(asset_criticality), 10.0)),
        "authentication_requirement": 10.0
        if finding.get("authentication_required") is False
        else 5.0,
        "product_eol": 10.0 if finding.get("product_eol") else 0.0,
        "patch_availability": patch_signal,
        "business_impact": max(0.0, min(float(finding.get("business_impact", 5.0)), 10.0)),
    }
    score = round(
        min(sum(signals.get(name, 0.0) * float(weight) for name, weight in weights.items()), 10.0),
        2,
    )
    thresholds = policy["priority_thresholds"]
    priority = (
        "P1"
        if score >= float(thresholds["P1"])
        else "P2"
        if score >= float(thresholds["P2"])
        else "P3"
        if score >= float(thresholds["P3"])
        else "P4"
        if score >= float(thresholds["P4"])
        else "Informational"
    )
    return score, priority
