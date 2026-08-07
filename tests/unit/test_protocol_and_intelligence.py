"""Protocol assessment, intelligence, and bounded-profile tests."""

import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from pydantic import ValidationError

from app.config import Settings
from app.parsers.nuclei_jsonl_parser import parse_nuclei_jsonl
from app.scanners.base import ScanContext
from app.scanners.naabu_scanner import NaabuScanner
from app.scanners.nmap_scanner import NmapScanner
from app.schemas.scan import ScanCreate
from app.services.intelligence_service import CISA_KEV_CATALOG, CisaKevProvider
from app.services.protocol_check_service import evaluate_protocol_checks


class RecordingRunner:
    def __init__(self, stdout: str = "") -> None:
        self.stdout = stdout
        self.calls: list[list[str]] = []

    def dependency_available(self, executable: str) -> bool:
        return True

    async def run(self, scan_id: str, args: list[str], timeout: float):
        self.calls.append(args)
        return SimpleNamespace(stdout=self.stdout, stderr="", returncode=0)


def _scan(**changes) -> ScanCreate:
    values = {
        "engagement_id": "ENG-1",
        "targets": ["8.8.8.8"],
        "profile": "custom",
        "authorized": True,
        "initiated_by": "analyst",
    }
    values.update(changes)
    return ScanCreate(**values)


def test_custom_scan_rejects_unbounded_udp_and_unknown_severity():
    with pytest.raises(ValidationError, match="explicit approved UDP port list"):
        _scan(enable_udp=True)
    with pytest.raises(ValidationError, match="approved severity"):
        _scan(nuclei_severity="high,urgent")


def test_production_rejects_placeholder_secret():
    with pytest.raises(ValidationError, match="Production SECRET_KEY"):
        Settings(
            _env_file=None,
            environment="production",
            secret_key="replace-with-a-long-random-secret",
        )


def test_custom_port_spec_is_canonical_and_bounded():
    scan = _scan(tcp_ports="22, 80,443,8000-8100", udp_ports=[161, 53, 53])
    assert scan.tcp_ports == "22,80,443,8000-8100"
    assert scan.udp_ports == [53, 161]
    with pytest.raises(ValidationError, match="between 1 and 65535"):
        _scan(tcp_ports="70000")


@pytest.mark.asyncio
async def test_naabu_full_profile_requests_all_ports(tmp_path: Path):
    runner = RecordingRunner()
    context = ScanContext("S1", ["192.0.2.10"], tmp_path, "full")
    await NaabuScanner("naabu", runner=runner).scan(context)
    args = runner.calls[0]
    assert args[args.index("-top-ports") + 1] == "full"
    assert "-rate" in args and "-c" in args


def test_nmap_udp_scan_uses_only_configured_ports_and_allowlisted_scripts(tmp_path: Path):
    context = ScanContext(
        "S1",
        ["192.0.2.10"],
        tmp_path,
        "custom",
        {"enable_udp": True, "udp_ports": [53, 123], "rate_limit": 20},
    )
    args = NmapScanner("nmap").build_udp_args(context, tmp_path / "udp.xml")
    assert args is not None
    assert args[args.index("-p") + 1] == "53,123"
    scripts = args[args.index("--script") + 1]
    assert "dns-recursion" in scripts and "all" not in scripts.split(",")
    assert "snmp-info" not in scripts
    assert args[-1] == "192.0.2.10"


def test_snmp_default_community_probe_requires_explicit_opt_in(tmp_path: Path):
    context = ScanContext(
        "S1",
        ["192.0.2.10"],
        tmp_path,
        "custom",
        {
            "enable_udp": True,
            "udp_ports": [161],
            "enable_snmp_default_community": True,
        },
    )
    args = NmapScanner("nmap").build_udp_args(context, tmp_path / "udp.xml")
    assert args is not None
    assert "snmp-info" in args[args.index("--script") + 1].split(",")


def test_protocol_checks_report_confirmed_risks_without_inventing_cves():
    findings, checklist = evaluate_protocol_checks(
        {
            "assets": [
                {
                    "ip": "192.0.2.20",
                    "hostname": "edge.example.test",
                    "services": [
                        {
                            "port": 21,
                            "transport": "tcp",
                            "protocol": "ftp",
                            "scripts": {
                                "ftp-anon": "Anonymous FTP login allowed (FTP code 230)"
                            },
                        },
                        {
                            "port": 53,
                            "transport": "udp",
                            "protocol": "domain",
                            "scripts": {"dns-recursion": "Recursion appears to be enabled"},
                        },
                        {
                            "port": 445,
                            "transport": "tcp",
                            "protocol": "microsoft-ds",
                            "scripts": {
                                "smb-protocols": "NT LM 0.12 (SMBv1)",
                                "smb2-security-mode": "Message signing enabled but not required",
                            },
                        },
                    ],
                }
            ]
        }
    )
    rules = {item["scanner_rule_id"] for item in findings}
    assert {
        "protocol.ftp.anonymous-access",
        "protocol.dns.open-recursion",
        "protocol.smb.smbv1-enabled",
        "protocol.smb.signing-not-required",
    } <= rules
    assert all("cve" not in item for item in findings)
    assert checklist["protocol.192.0.2.20.tcp.21.anonymous"]["status"] == "FAIL"


@pytest.mark.asyncio
async def test_cisa_kev_cache_enriches_existing_cve_only(tmp_path: Path):
    cache = tmp_path / "kev.json"
    cache.write_text(
        json.dumps(
            {
                "catalogVersion": "test",
                "vulnerabilities": [
                    {
                        "cveID": "CVE-2024-0001",
                        "requiredAction": "Apply mitigations per vendor instructions",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    provider = CisaKevProvider(
        url="https://invalid.example/unused",
        cache_path=cache,
        refresh_hours=24,
        timeout=2,
    )
    findings, status = await provider.enrich_many(
        [
            {
                "title": "Trusted match",
                "cve": ["CVE-2024-0001"],
                "references": [],
                "remediation": "Patch.",
            },
            {"title": "Banner only", "cve": [], "references": []},
        ]
    )
    assert status.available and status.matched == 1
    assert findings[0]["cisa_kev"] is True
    assert CISA_KEV_CATALOG in findings[0]["references"]
    assert not findings[1].get("cisa_kev", False)


def test_nuclei_parser_distinguishes_cvss_v4():
    finding = parse_nuclei_jsonl(
        json.dumps(
            {
                "ip": "192.0.2.30",
                "matched-at": "https://192.0.2.30",
                "template-id": "CVE-TEST",
                "info": {
                    "name": "Test",
                    "severity": "high",
                    "classification": {
                        "cve-id": ["CVE-2024-0001"],
                        "cvss-score": 8.7,
                        "cvss-metrics": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N",
                        "cpe": "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*",
                    },
                },
            }
        )
    )[0]
    assert finding["cvss_v40_score"] == 8.7
    assert finding["cvss_v31_score"] is None
    assert finding["cpe"].startswith("cpe:2.3")
