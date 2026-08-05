from __future__ import annotations

import json

from app.services.intelligence_service import CISA_KEV_SOURCE, VulnerabilityIntelligence


def _write_catalog(tmp_path):
    path = tmp_path / "kev.json"
    path.write_text(
        json.dumps(
            {
                "title": "CISA Known Exploited Vulnerabilities Catalog",
                "vulnerabilities": [
                    {
                        "cveID": "CVE-2024-0001",
                        "vendorProject": "Example Vendor",
                        "product": "Example Product",
                        "vulnerabilityName": "Example vulnerability",
                        "dateAdded": "2026-01-01",
                        "dueDate": "2026-01-22",
                        "requiredAction": "Apply the vendor update.",
                        "knownRansomwareCampaignUse": "Known",
                        "notes": "",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    return path


def test_loads_catalog_and_matches_case_insensitively(tmp_path):
    intelligence = VulnerabilityIntelligence(_write_catalog(tmp_path))

    assert intelligence.available is True
    assert intelligence.entry_count == 1
    assert intelligence.lookup("cve-2024-0001") is not None


def test_enriches_kev_finding_without_mutating_input(tmp_path):
    intelligence = VulnerabilityIntelligence(_write_catalog(tmp_path))
    finding = {
        "cve": ["cve-2024-0001", "CVE-2024-0001"],
        "cisa_kev": False,
        "exploit_available": False,
        "references": [],
        "confidence_reason": "Confirmed by a safe scanner probe.",
        "remediation": "",
    }

    enriched = intelligence.enrich(finding)

    assert finding["cisa_kev"] is False
    assert enriched["cve"] == ["CVE-2024-0001"]
    assert enriched["cisa_kev"] is True
    assert enriched["exploit_available"] is True
    assert CISA_KEV_SOURCE in enriched["references"]
    assert enriched["remediation"] == "Apply the vendor update."
    assert "CISA KEV match: CVE-2024-0001" in enriched["confidence_reason"]


def test_unknown_cve_remains_non_kev(tmp_path):
    intelligence = VulnerabilityIntelligence(_write_catalog(tmp_path))

    enriched = intelligence.enrich({"cve": ["CVE-2099-9999"], "references": []})

    assert enriched["cisa_kev"] is False
    assert enriched.get("exploit_available") is None


def test_missing_or_invalid_cache_fails_closed(tmp_path):
    missing = VulnerabilityIntelligence(tmp_path / "missing.json")
    assert missing.available is False

    invalid_path = tmp_path / "invalid.json"
    invalid_path.write_text("not-json", encoding="utf-8")
    invalid = VulnerabilityIntelligence(invalid_path)
    assert invalid.available is False
    assert invalid.enrich({"cve": ["CVE-2024-0001"]})["cisa_kev"] is False
