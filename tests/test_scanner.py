import unittest

from garuda.scanner import (
    MAX_PORTS_PER_SCAN,
    ScopeError,
    build_findings,
    is_public_address,
    normalize_target,
    parse_ports,
    resolve_public_target,
)


class ScannerSafetyTests(unittest.TestCase):
    def test_normalize_target_accepts_urls_and_hosts(self):
        self.assertEqual(normalize_target("https://example.com/path"), "example.com")
        self.assertEqual(normalize_target("example.com:443"), "example.com")
        self.assertEqual(normalize_target("93.184.216.34"), "93.184.216.34")

    def test_public_address_detection(self):
        self.assertTrue(is_public_address("8.8.8.8"))
        self.assertFalse(is_public_address("127.0.0.1"))
        self.assertFalse(is_public_address("10.0.0.1"))
        self.assertFalse(is_public_address("192.168.1.1"))

    def test_private_direct_targets_are_blocked(self):
        with self.assertRaises(ScopeError):
            resolve_public_target("127.0.0.1")

    def test_parse_ports_defaults_and_ranges(self):
        self.assertIn(443, parse_ports(None))
        self.assertEqual(parse_ports("80,443,8080-8082"), [80, 443, 8080, 8081, 8082])

    def test_parse_ports_rejects_invalid_and_large_sets(self):
        with self.assertRaises(ScopeError):
            parse_ports("abc")
        with self.assertRaises(ScopeError):
            parse_ports("0")
        with self.assertRaises(ScopeError):
            parse_ports(",".join(str(port) for port in range(1, MAX_PORTS_PER_SCAN + 2)))

    def test_build_findings_flags_exposed_data_services(self):
        findings = build_findings([
            {"port": 6379, "address": "203.0.113.20", "service": "redis"},
        ])
        self.assertEqual(findings[0]["severity"], "medium")
        self.assertIn("Redis".lower(), findings[0]["title"].lower())


if __name__ == "__main__":
    unittest.main()
