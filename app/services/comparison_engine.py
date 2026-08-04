"""Compare normalized findings and service exposure."""

from typing import Any


def compare_scans(previous: dict[str, Any], current: dict[str, Any]) -> dict[str, Any]:
    old_findings = {item["finding_id"]: item for item in previous.get("findings", [])}
    new_findings = {item["finding_id"]: item for item in current.get("findings", [])}
    old_ports = {
        (item["ip"], item["port"], item.get("transport", "tcp")) for item in previous.get("services", [])
    }
    new_ports = {
        (item["ip"], item["port"], item.get("transport", "tcp")) for item in current.get("services", [])
    }
    common = old_findings.keys() & new_findings.keys()
    return {
        "new": [new_findings[key] for key in sorted(new_findings.keys() - old_findings.keys())],
        "still_open": [new_findings[key] for key in sorted(common)],
        "resolved": [old_findings[key] for key in sorted(old_findings.keys() - new_findings.keys())],
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
    }
