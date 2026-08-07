"""Normalize heterogeneous scanner output."""

from datetime import UTC, datetime
from typing import Any

from app.utils.hashing import stable_fingerprint
from app.utils.redaction import redact

SEVERITIES = {"critical", "high", "medium", "low", "info", "informational"}


def _list(value: Any) -> list[str]:
    if value in (None, ""):
        return []
    if isinstance(value, (list, tuple, set)):
        return [str(item) for item in value if item not in (None, "")]
    return [str(value)]


def normalize_finding(raw: dict[str, Any], *, scan_id: str, engagement_id: str) -> dict[str, Any]:
    now = datetime.now(UTC)
    severity = str(raw.get("severity", "info")).lower()
    if severity not in SEVERITIES:
        severity = "info"
    if severity == "informational":
        severity = "info"
    ip = str(raw.get("asset_ip") or raw.get("ip") or "")
    hostname = raw.get("hostname")
    port = raw.get("port")
    protocol = raw.get("protocol") or raw.get("service") or "unknown"
    rule_id = str(
        raw.get("scanner_rule_id") or raw.get("template_id") or raw.get("id") or raw.get("title") or "unknown"
    )
    cves = sorted({value.upper() for value in _list(raw.get("cve"))})
    matched = raw.get("matched_at") or raw.get("matched") or raw.get("location") or ""
    finding_id = (
        stable_fingerprint(ip, hostname, port, protocol, *cves)
        if cves
        else stable_fingerprint(ip, hostname, port, protocol, rule_id, matched)
    )
    return {
        "finding_id": finding_id,
        "scan_id": scan_id,
        "engagement_id": engagement_id,
        "asset_ip": ip,
        "hostname": hostname,
        "port": int(port) if port not in (None, "") else None,
        "transport": raw.get("transport", "tcp"),
        "protocol": protocol,
        "service": raw.get("service"),
        "service_version": raw.get("service_version") or raw.get("version"),
        "title": str(raw.get("title") or raw.get("name") or "Scanner observation"),
        "description": str(raw.get("description") or ""),
        "severity": severity,
        "priority": raw.get("priority", "Informational"),
        "confidence": raw.get("confidence", "potential"),
        "confidence_reason": raw.get(
            "confidence_reason", "Scanner observation requires correlation or manual verification."
        ),
        "cve": cves,
        "cwe": _list(raw.get("cwe")),
        "cpe": _list(raw.get("cpe")),
        "cvss_v31_score": raw.get("cvss_v31_score"),
        "cvss_v31_vector": raw.get("cvss_v31_vector"),
        "cvss_v40_score": raw.get("cvss_v40_score"),
        "cvss_v40_vector": raw.get("cvss_v40_vector"),
        "cisa_kev": bool(raw.get("cisa_kev", False)),
        "exploit_available": bool(raw.get("exploit_available", False)),
        "authentication_required": raw.get("authentication_required"),
        "product_eol": bool(raw.get("product_eol", False)),
        "patch_available": raw.get("patch_available"),
        "business_impact": raw.get("business_impact", 5.0),
        "scanner": raw.get("scanner", "unknown"),
        "scanner_rule_id": rule_id,
        "evidence": redact(str(raw.get("evidence") or matched)),
        "remediation": str(raw.get("remediation") or "Review and remediate according to vendor guidance."),
        "references": _list(raw.get("references")),
        "source_references": [str(raw.get("scanner", "unknown"))],
        "first_seen": raw.get("first_seen", now),
        "last_seen": now,
        "status": raw.get("status", "new"),
    }
