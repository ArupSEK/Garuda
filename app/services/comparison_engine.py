"""Compare normalized findings and service exposure."""

from collections import Counter
from typing import Any


def compare_scans(previous: dict[str, Any], current: dict[str, Any]) -> dict[str, Any]:
    old_findings = {item["finding_id"]: item for item in previous.get("findings", [])}
    new_findings = {item["finding_id"]: item for item in current.get("findings", [])}
    old_services = {
        (item["ip"], item["port"], item.get("transport", "tcp")): item
        for item in previous.get("services", [])
    }
    new_services = {
        (item["ip"], item["port"], item.get("transport", "tcp")): item
        for item in current.get("services", [])
    }
    old_ports, new_ports = set(old_services), set(new_services)
    common = old_findings.keys() & new_findings.keys()
    common_services = old_ports & new_ports
    management_ports = {21, 22, 23, 445, 2375, 3389, 5900, 6443, 8080, 8443}
    new_items = [new_findings[key] for key in sorted(new_findings.keys() - old_findings.keys())]
    resolved_items = [old_findings[key] for key in sorted(old_findings.keys() - new_findings.keys())]

    def severities(items: list[dict[str, Any]]) -> dict[str, int]:
        counts = Counter(str(item.get("severity", "info")).lower() for item in items)
        return {level: counts[level] for level in ("critical", "high", "medium", "low", "info")}

    evidence_changed = [
        {
            "finding_id": key,
            "scanner": new_findings[key].get("scanner"),
            "scanner_rule_id": new_findings[key].get("scanner_rule_id"),
            "from": old_findings[key].get("evidence"),
            "to": new_findings[key].get("evidence"),
        }
        for key in sorted(common)
        if old_findings[key].get("evidence") != new_findings[key].get("evidence")
    ]
    tls_certificate_changed = [
        item
        for item in evidence_changed
        if item.get("scanner") == "testssl.sh"
        and "cert" in str(item.get("scanner_rule_id", "")).lower()
    ]

    return {
        "new": new_items,
        "still_open": [new_findings[key] for key in sorted(common)],
        "resolved": resolved_items,
        "reopened": [new_findings[key] for key in common if old_findings[key].get("status") == "resolved"],
        "severity_changed": [
            {
                "finding_id": key,
                "from": old_findings[key].get("severity"),
                "to": new_findings[key].get("severity"),
            }
            for key in common
            if old_findings[key].get("severity") != new_findings[key].get("severity")
        ],
        "new_ports": sorted(new_ports - old_ports),
        "closed_ports": sorted(old_ports - new_ports),
        "confidence_changed": [
            {
                "finding_id": key,
                "from": old_findings[key].get("confidence"),
                "to": new_findings[key].get("confidence"),
            }
            for key in sorted(common)
            if old_findings[key].get("confidence") != new_findings[key].get("confidence")
        ],
        "evidence_changed": evidence_changed,
        "tls_certificate_changed": tls_certificate_changed,
        "certificate_expiry_changed": [
            item
            for item in tls_certificate_changed
            if any(
                marker in str(item.get("scanner_rule_id", "")).lower()
                for marker in ("expir", "notafter", "validity")
            )
        ],
        "service_changed": [
            {
                "ip": key[0],
                "port": key[1],
                "transport": key[2],
                "from_protocol": old_services[key].get("protocol"),
                "to_protocol": new_services[key].get("protocol"),
                "from_product": old_services[key].get("product"),
                "to_product": new_services[key].get("product"),
                "from_version": old_services[key].get("version"),
                "to_version": new_services[key].get("version"),
            }
            for key in sorted(common_services)
            if any(
                old_services[key].get(field) != new_services[key].get(field)
                for field in ("protocol", "product", "version", "encryption", "cpe")
            )
        ],
        "new_management_services": [
            {"ip": ip, "port": port, "transport": transport}
            for ip, port, transport in sorted(new_ports - old_ports)
            if port in management_ports
        ],
        "totals": {
            "previous": severities(list(old_findings.values())),
            "current": severities(list(new_findings.values())),
            "new": severities(new_items),
            "resolved": severities(resolved_items),
        },
    }
