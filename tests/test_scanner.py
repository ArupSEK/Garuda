import unittest
from unittest.mock import patch

from garuda.models import Evidence, Finding, ModuleResult, ResolvedTarget, ScanReport
from garuda.modules.base import ScanModule
from garuda.orchestrator import Orchestrator
from garuda.scope import MAX_PORTS_PER_SCAN, ScopeError, parse_ports, parse_target, resolve_public_target


class DummyTcp(ScanModule):
    name = "tcp-connect"
    description = "dummy"

    def run(self, context):
        context.shared["open_ports"] = []
        return ModuleResult(self.name, "completed", 0.1, artifacts={"open_ports": []})


class DummyHttp(ScanModule):
    name = "http-probe"
    description = "dummy"

    def run(self, context):
        return ModuleResult(self.name, "completed", 0.1)


class GarudaPlatformTests(unittest.TestCase):
    def test_parse_url_preserves_path(self):
        self.assertEqual(
            parse_target("https://example.com:8443/api?q=1"),
            ("https", "example.com", 8443, "/api?q=1"),
        )

    def test_private_target_is_rejected(self):
        with self.assertRaises(ScopeError):
            resolve_public_target("127.0.0.1")

    @patch("garuda.scope.socket.getaddrinfo")
    def test_mixed_public_private_dns_is_rejected(self, getaddrinfo):
        getaddrinfo.return_value = [
            (2, 1, 6, "", ("93.184.216.34", 0)),
            (2, 1, 6, "", ("10.0.0.8", 0)),
        ]
        with self.assertRaises(ScopeError):
            resolve_public_target("example.test")

    def test_ports_accept_ranges(self):
        self.assertEqual(parse_ports("443,8080-8082"), [443, 8080, 8081, 8082])

    def test_ports_reject_oversized_sets(self):
        with self.assertRaises(ScopeError):
            parse_ports(",".join(str(item) for item in range(1, MAX_PORTS_PER_SCAN + 2)))

    def test_authorization_is_required(self):
        with self.assertRaises(ScopeError):
            Orchestrator([]).scan(target="example.com", raw_ports="80", profile="external-safe", authorized=False)

    @patch("garuda.orchestrator.resolve_public_target")
    def test_external_profile_runs_registered_modules(self, resolver):
        resolver.return_value = ResolvedTarget("example.com", "https", "example.com", None, "/", ("93.184.216.34",))
        report = Orchestrator([DummyTcp(), DummyHttp()]).scan(
            target="example.com", raw_ports="80", profile="external-safe", authorized=True
        )
        self.assertEqual(report["summary"]["modules_completed"], 2)
        self.assertEqual(report["summary"]["modules_failed"], 0)

    def test_report_sorts_findings_by_severity(self):
        target = ResolvedTarget("example.com", "https", "example.com", None, "/", ("93.184.216.34",))
        low = Finding("test", "Low", "low", "confirmed", "example.com", "test", Evidence("low"), "fix")
        high = Finding("test", "High", "high", "confirmed", "example.com", "test", Evidence("high"), "fix")
        report = ScanReport.now(
            target=target,
            profile="external-safe",
            duration_ms=1.0,
            modules=[ModuleResult("test", "completed", 1.0, [low, high], {"open_ports": []})],
            policy={},
        ).to_dict()
        self.assertEqual(report["findings"][0]["severity"], "high")


if __name__ == "__main__":
    unittest.main()
