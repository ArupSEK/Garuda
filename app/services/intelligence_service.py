"""Trusted, failure-tolerant CISA KEV enrichment with a local cache."""

import asyncio
import json
import logging
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import httpx

logger = logging.getLogger(__name__)
CISA_KEV_CATALOG = "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"


@dataclass(slots=True)
class EnrichmentStatus:
    available: bool
    matched: int = 0
    detail: str = ""


class CisaKevProvider:
    """Enrich CVE-bearing findings from CISA's authoritative KEV JSON feed."""

    def __init__(
        self,
        *,
        url: str,
        cache_path: Path,
        refresh_hours: int = 24,
        timeout: int = 15,
    ) -> None:
        self.url = url
        self.cache_path = cache_path
        self.refresh_after = timedelta(hours=refresh_hours)
        self.timeout = timeout
        self._refresh_lock = asyncio.Lock()

    def _read_cache(self) -> dict[str, Any] | None:
        try:
            data = json.loads(self.cache_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return None
        return data if isinstance(data, dict) and isinstance(data.get("vulnerabilities"), list) else None

    def _cache_is_fresh(self) -> bool:
        try:
            modified = datetime.fromtimestamp(self.cache_path.stat().st_mtime, UTC)
        except OSError:
            return False
        return datetime.now(UTC) - modified <= self.refresh_after

    async def _download(self) -> dict[str, Any]:
        async with httpx.AsyncClient(
            timeout=self.timeout,
            follow_redirects=True,
            headers={"User-Agent": "Garuda-External-VA/1.0"},
        ) as client:
            response = await client.get(self.url)
            response.raise_for_status()
            data = response.json()
        if not isinstance(data, dict) or not isinstance(data.get("vulnerabilities"), list):
            raise TypeError("CISA KEV response did not contain a vulnerabilities list")
        self.cache_path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.cache_path.with_suffix(".tmp")
        temporary.write_text(json.dumps(data), encoding="utf-8")
        temporary.replace(self.cache_path)
        return data

    async def catalog(self) -> tuple[dict[str, dict[str, Any]], str]:
        data = self._read_cache()
        if not self._cache_is_fresh():
            async with self._refresh_lock:
                data = self._read_cache()
                if not self._cache_is_fresh():
                    try:
                        data = await self._download()
                    except (httpx.HTTPError, OSError, TypeError, json.JSONDecodeError) as exc:
                        logger.warning("cisa_kev_refresh_failed error=%s", exc.__class__.__name__)
                        if data is None:
                            return {}, f"CISA KEV feed unavailable: {exc.__class__.__name__}"
        if data is None:
            return {}, "CISA KEV cache is unavailable"
        index = {
            str(item.get("cveID", "")).upper(): item
            for item in data.get("vulnerabilities", [])
            if item.get("cveID")
        }
        version = data.get("catalogVersion") or data.get("dateReleased") or "cached catalog"
        return index, f"CISA KEV {version}; {len(index)} catalog entries"

    async def enrich_many(
        self, findings: list[dict[str, Any]]
    ) -> tuple[list[dict[str, Any]], EnrichmentStatus]:
        index, detail = await self.catalog()
        if not index:
            return findings, EnrichmentStatus(False, detail=detail)
        matched = 0
        for finding in findings:
            raw_cves = finding.get("cve", [])
            if isinstance(raw_cves, str):
                raw_cves = [raw_cves]
            cves = {str(cve).upper() for cve in raw_cves}
            kev_rows = [index[cve] for cve in cves if cve in index]
            if not kev_rows:
                continue
            matched += 1
            finding["cisa_kev"] = True
            references = list(finding.get("references") or [])
            if CISA_KEV_CATALOG not in references:
                references.append(CISA_KEV_CATALOG)
            finding["references"] = references
            actions = sorted(
                {str(row.get("requiredAction", "")).strip() for row in kev_rows if row.get("requiredAction")}
            )
            if actions:
                finding["remediation"] = (
                    f"{finding.get('remediation', '').strip()} CISA KEV action: {'; '.join(actions)}"
                ).strip()
            finding["confidence_reason"] = (
                f"{finding.get('confidence_reason', '').strip()} CVE is listed in the CISA KEV catalog."
            ).strip()
        return findings, EnrichmentStatus(True, matched=matched, detail=detail)


class NoOpIntelligenceProvider:
    """Compatibility provider used when enrichment is explicitly disabled."""

    async def enrich(self, finding: dict[str, Any]) -> dict[str, Any]:
        return finding
