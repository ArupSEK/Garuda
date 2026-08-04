"""Scan orchestration resilience tests."""

from pathlib import Path

import pytest

from app.core.exceptions import CommandExecutionError
from app.scanners.base import ScanContext
from app.services.scan_orchestrator import ScanOrchestrator


class FailingOptionalScanner:
    name = "optional-test"

    async def scan(self, context: ScanContext) -> list[dict]:
        raise CommandExecutionError("recoverable probe failure")


@pytest.mark.asyncio
async def test_optional_scanner_failure_does_not_abort_scan():
    context = ScanContext("SCAN-1", ["203.0.113.10"], Path("evidence/SCAN-1"), "standard")
    result = await ScanOrchestrator._run_optional("SCAN-1", FailingOptionalScanner(), context)
    assert result == []
