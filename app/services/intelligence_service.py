"""Offline-safe vulnerability intelligence interface."""

from typing import Any, Protocol


class IntelligenceProvider(Protocol):
    async def enrich(self, finding: dict[str, Any]) -> dict[str, Any]: ...


class NoOpIntelligenceProvider:
    """Leaves findings unchanged when no trusted local feed is configured."""

    async def enrich(self, finding: dict[str, Any]) -> dict[str, Any]:
        return finding
