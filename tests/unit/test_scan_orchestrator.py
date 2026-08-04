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
async def test_optional_scanner_failure_does_not_abort_scan(monkeypatch):
    context = ScanContext("SCAN-1", ["203.0.113.10"], Path("evidence/SCAN-1"), "standard")
    orchestrator = ScanOrchestrator()
    monkeypatch.setattr(orchestrator, "_set_coverage", lambda *args, **kwargs: None)
    result = await orchestrator._run_optional("SCAN-1", FailingOptionalScanner(), context)
    assert result == []


def test_confirmed_endpoints_feed_only_confirmed_services_to_follow_up_tools():
    result = ScanOrchestrator._confirmed_endpoints(
        {
            "assets": [
                {
                    "ip": "203.0.113.10",
                    "hostname": "edge.example.test",
                    "services": [
                        {"port": 443, "protocol": "https"},
                        {"port": 22, "protocol": "ssh"},
                    ],
                }
            ]
        }
    )
    assert result["http_urls"] == ["https://203.0.113.10:443"]
    assert result["ssh_endpoints"] == [{"ip": "203.0.113.10", "port": 22}]
    assert set(result["nuclei_targets"]) == {
        "https://203.0.113.10:443",
        "203.0.113.10:443",
        "203.0.113.10:22",
    }
