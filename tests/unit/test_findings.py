from app.services.comparison_engine import compare_scans
from app.services.deduplicator import deduplicate
from app.services.finding_normalizer import normalize_finding
from app.services.risk_engine import calculate_risk
from app.utils.hashing import stable_fingerprint
from app.utils.redaction import redact


def test_stable_fingerprint_and_normalization():
    assert stable_fingerprint("A", 443) == stable_fingerprint("a", 443)
    item = normalize_finding(
        {"ip": "8.8.8.8", "port": 443, "title": "X", "scanner": "nuclei", "template_id": "x"},
        scan_id="SCAN-1",
        engagement_id="ENG-1",
    )
    assert len(item["finding_id"]) == 64 and item["asset_ip"] == "8.8.8.8"


def test_deduplication_prefers_confidence_and_merges_sources():
    base = {
        "finding_id": "x",
        "confidence": "potential",
        "scanner": "nmap",
        "cve": [],
        "cwe": [],
        "cpe": [],
        "references": [],
        "evidence": "a",
        "source_references": ["nmap"],
    }
    strong = {**base, "confidence": "confirmed", "scanner": "nuclei", "evidence": "detailed evidence"}
    result = deduplicate([base, strong])[0]
    assert result["confidence"] == "confirmed" and result["source_references"] == ["nmap", "nuclei"]


def test_same_cve_from_different_scanners_gets_one_stable_fingerprint():
    left = normalize_finding(
        {
            "ip": "8.8.8.8",
            "port": 443,
            "protocol": "https",
            "cve": ["CVE-2024-0001"],
            "scanner": "nuclei",
            "scanner_rule_id": "nuclei-rule",
        },
        scan_id="S1",
        engagement_id="E1",
    )
    right = normalize_finding(
        {
            "ip": "8.8.8.8",
            "port": 443,
            "protocol": "https",
            "cve": "CVE-2024-0001",
            "scanner": "openvas",
            "scanner_rule_id": "oid-123",
        },
        scan_id="S1",
        engagement_id="E1",
    )
    assert left["finding_id"] == right["finding_id"]
    assert len(deduplicate([left, right])) == 1


def test_risk_and_comparison():
    score, priority = calculate_risk(
        {"cvss_v31_score": 9.8, "confidence": "confirmed", "cisa_kev": True, "exploit_available": True}
    )
    assert score >= 8.5 and priority == "P1"
    old = {
        "findings": [{"finding_id": "a", "status": "open", "severity": "low"}],
        "services": [{"ip": "8.8.8.8", "port": 80}],
    }
    new = {
        "findings": [{"finding_id": "b", "status": "new", "severity": "high"}],
        "services": [{"ip": "8.8.8.8", "port": 443}],
    }
    result = compare_scans(old, new)
    assert result["new"][0]["finding_id"] == "b" and result["closed_ports"]


def test_comparison_reports_version_confidence_and_management_changes():
    old = {
        "findings": [{"finding_id": "a", "severity": "low", "confidence": "potential"}],
        "services": [
            {
                "ip": "8.8.8.8",
                "port": 443,
                "transport": "tcp",
                "protocol": "https",
                "product": "nginx",
                "version": "1.0",
            }
        ],
    }
    new = {
        "findings": [{"finding_id": "a", "severity": "high", "confidence": "confirmed"}],
        "services": [
            {
                "ip": "8.8.8.8",
                "port": 443,
                "transport": "tcp",
                "protocol": "https",
                "product": "nginx",
                "version": "2.0",
            },
            {
                "ip": "8.8.8.8",
                "port": 3389,
                "transport": "tcp",
                "protocol": "rdp",
            },
        ],
    }
    result = compare_scans(old, new)
    assert result["severity_changed"] and result["confidence_changed"]
    assert result["service_changed"][0]["from_version"] == "1.0"
    assert result["new_management_services"][0]["port"] == 3389


def test_redaction():
    output = redact("Authorization: Bearer abc.def\npassword=hunter2\nCookie: session=xyz")
    assert "hunter2" not in output and "abc.def" not in output and "session=xyz" not in output
