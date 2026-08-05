"""Offline-first vulnerability intelligence enrichment.

The scanner never depends on an online feed during an assessment. Administrators may
refresh a local CISA Known Exploited Vulnerabilities (KEV) cache before an engagement;
normalization then performs deterministic, read-only enrichment from that cache.
"""

from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any, Iterable

logger = logging.getLogger(__name__)

DEFAULT_KEV_CACHE = Path("data/cisa_kev.json")
CISA_KEV_SOURCE = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


@dataclass(frozen=True, slots=True)
class KevEntry:
    cve_id: str
    vendor_project: str = ""
    product: str = ""
    vulnerability_name: str = ""
    date_added: str = ""
    due_date: str = ""
    required_action: str = ""
    known_ransomware_campaign_use: str = "Unknown"
    notes: str = ""

    @classmethod
    def from_mapping(cls, item: dict[str, Any]) -> "KevEntry | None":
        cve_id = str(item.get("cveID") or item.get("cve_id") or "").strip().upper()
        if not cve_id.startswith("CVE-"):
            return None
        return cls(
            cve_id=cve_id,
            vendor_project=str(item.get("vendorProject") or item.get("vendor_project") or ""),
            product=str(item.get("product") or ""),
            vulnerability_name=str(item.get("vulnerabilityName") or item.get("vulnerability_name") or ""),
            date_added=str(item.get("dateAdded") or item.get("date_added") or ""),
            due_date=str(item.get("dueDate") or item.get("due_date") or ""),
            required_action=str(item.get("requiredAction") or item.get("required_action") or ""),
            known_ransomware_campaign_use=str(
                item.get("knownRansomwareCampaignUse")
                or item.get("known_ransomware_campaign_use")
                or "Unknown"
            ),
            notes=str(item.get("notes") or ""),
        )


class VulnerabilityIntelligence:
    """Read-only CVE enrichment backed by a locally cached KEV catalog."""

    def __init__(self, cache_path: Path | str | None = None) -> None:
        configured = cache_path or os.getenv("GARUDA_KEV_CACHE") or DEFAULT_KEV_CACHE
        self.cache_path = Path(configured)
        self._entries = self._load_entries()

    @property
    def available(self) -> bool:
        return bool(self._entries)

    @property
    def entry_count(self) -> int:
        return len(self._entries)

    def lookup(self, cve_id: str) -> KevEntry | None:
        return self._entries.get(str(cve_id).strip().upper())

    def enrich(self, finding: dict[str, Any]) -> dict[str, Any]:
        """Return a model-compatible copy enriched with KEV state."""
        enriched = dict(finding)
        cves = _normalise_cves(enriched.get("cve") or [])
        enriched["cve"] = cves

        matches = [entry for cve in cves if (entry := self.lookup(cve)) is not None]
        if not matches:
            enriched.setdefault("cisa_kev", False)
            return enriched

        enriched["cisa_kev"] = True
        enriched["exploit_available"] = True

        references = list(enriched.get("references") or [])
        if CISA_KEV_SOURCE not in references:
            references.append(CISA_KEV_SOURCE)
        enriched["references"] = references

        actions = [entry.required_action for entry in matches if entry.required_action]
        if actions and not str(enriched.get("remediation") or "").strip():
            enriched["remediation"] = actions[0]

        reason = str(enriched.get("confidence_reason") or "").strip()
        kev_ids = ", ".join(entry.cve_id for entry in matches)
        marker = f"CISA KEV match: {kev_ids}."
        if marker not in reason:
            enriched["confidence_reason"] = f"{reason} {marker}".strip()
        return enriched

    def _load_entries(self) -> dict[str, KevEntry]:
        if not self.cache_path.exists():
            logger.info("CISA KEV cache not found at %s; enrichment disabled", self.cache_path)
            return {}
        try:
            payload = json.loads(self.cache_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            logger.warning("Unable to load CISA KEV cache %s: %s", self.cache_path, exc)
            return {}

        raw_items = payload.get("vulnerabilities", []) if isinstance(payload, dict) else payload
        if not isinstance(raw_items, list):
            logger.warning("Invalid CISA KEV cache format in %s", self.cache_path)
            return {}

        entries: dict[str, KevEntry] = {}
        for item in raw_items:
            if not isinstance(item, dict):
                continue
            entry = KevEntry.from_mapping(item)
            if entry:
                entries[entry.cve_id] = entry
        return entries


def _normalise_cves(values: Iterable[Any]) -> list[str]:
    normalised: list[str] = []
    for value in values:
        candidate = str(value).strip().upper()
        if candidate.startswith("CVE-") and candidate not in normalised:
            normalised.append(candidate)
    return normalised


@lru_cache(maxsize=1)
def get_vulnerability_intelligence() -> VulnerabilityIntelligence:
    return VulnerabilityIntelligence()


def enrich_finding(finding: dict[str, Any]) -> dict[str, Any]:
    return get_vulnerability_intelligence().enrich(finding)


def reload_vulnerability_intelligence() -> VulnerabilityIntelligence:
    get_vulnerability_intelligence.cache_clear()
    return get_vulnerability_intelligence()
