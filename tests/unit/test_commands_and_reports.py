import asyncio
from types import SimpleNamespace

import pytest

from app.core.exceptions import CommandExecutionError, ScanCancelled
from app.scanners.base import ScanContext
from app.scanners.gowitness_scanner import GoWitnessScanner
from app.scanners.nmap_scanner import NmapScanner
from app.scanners.nuclei_scanner import NucleiScanner
from app.scanners.ssh_audit_scanner import SshAuditScanner
from app.services.report_generator import ReportGenerator
from app.utils.command_runner import CommandRunner


class RecordingRunner:
    def __init__(self, stdout: str = "") -> None:
        self.stdout = stdout
        self.calls: list[list[str]] = []

    def dependency_available(self, executable: str) -> bool:
        return True

    async def run(self, scan_id: str, args: list[str], timeout: float):
        self.calls.append(args)
        return SimpleNamespace(stdout=self.stdout, stderr="", returncode=0)


def test_nmap_arguments_are_fixed_array(tmp_path):
    context = ScanContext("S1", ["8.8.8.8;touch /tmp/pwn"], tmp_path, "quick")
    args = NmapScanner("nmap").build_args(context, tmp_path / "out.xml")
    assert isinstance(args, list) and args[-1] == "8.8.8.8;touch /tmp/pwn"


def test_report_generation():
    payload = {
        "scan": {"public_id": "S1", "profile": "quick", "targets": ["8.8.8.8"]},
        "services": [],
        "findings": [],
    }
    generator = ReportGenerator()
    assert b"S1" in generator.html(payload) and generator.csv(payload).startswith(b"\xef\xbb\xbf")


@pytest.mark.asyncio
async def test_nuclei_uses_pinned_signed_safe_policy(tmp_path):
    runner = RecordingRunner()
    context = ScanContext(
        "S1",
        ["192.0.2.10"],
        tmp_path,
        "standard",
        {"nuclei_templates_path": "/home/scanner/nuclei-templates"},
    )
    await NucleiScanner("nuclei", runner=runner).scan(context)
    args = runner.calls[0]
    assert "-disable-unsigned-templates" in args
    assert "/home/scanner/nuclei-templates" in args
    excluded = args[args.index("-exclude-tags") + 1].split(",")
    assert {"dos", "brute-force", "intrusive", "exploit", "code"} <= set(excluded)


@pytest.mark.asyncio
async def test_gowitness_uses_bundled_chromium_and_local_evidence(tmp_path):
    runner = RecordingRunner()
    context = ScanContext(
        "S1",
        ["192.0.2.10"],
        tmp_path,
        "standard",
        {"http_urls": ["https://192.0.2.10:443"]},
    )
    await GoWitnessScanner("gowitness", runner=runner).scan(context)
    args = runner.calls[0]
    assert args[args.index("--chrome-path") + 1] == "/usr/bin/chromium"
    assert args[args.index("--screenshot-format") + 1] == "png"
    assert "--log-scan-errors" in args
    assert args[args.index("--write-jsonl-file") + 1] == str(
        (tmp_path / "gowitness.jsonl").resolve()
    )


@pytest.mark.asyncio
async def test_ssh_audit_disables_connection_rate_test(tmp_path):
    runner = RecordingRunner(stdout="{}")
    context = ScanContext(
        "S1",
        ["192.0.2.10"],
        tmp_path,
        "standard",
        {"ssh_endpoints": [{"ip": "192.0.2.10", "port": 22}]},
    )
    await SshAuditScanner("ssh-audit", runner=runner).scan(context)
    assert "--skip-rate-test" in runner.calls[0]


@pytest.mark.asyncio
async def test_command_timeout():
    runner = CommandRunner()
    executable = "python" if runner.dependency_available("python") else "python3"
    with pytest.raises(Exception, match="timed out"):
        await runner.run("timeout-test", [executable, "-c", "import time; time.sleep(2)"], timeout=0.05)


@pytest.mark.asyncio
async def test_command_failure_uses_stdout_when_stderr_is_empty():
    runner = CommandRunner()
    executable = "python" if runner.dependency_available("python") else "python3"
    with pytest.raises(CommandExecutionError, match="scanner diagnostic"):
        await runner.run(
            "failure-test",
            [executable, "-c", "print('scanner diagnostic'); raise SystemExit(7)"],
            timeout=5,
        )


@pytest.mark.asyncio
async def test_scan_cancellation():
    runner = CommandRunner()
    executable = "python" if runner.dependency_available("python") else "python3"
    task = asyncio.create_task(
        runner.run("cancel-test", [executable, "-c", "import time; time.sleep(10)"], timeout=20)
    )
    await asyncio.sleep(0.1)
    assert await runner.cancel("cancel-test")
    with pytest.raises((ScanCancelled, CommandExecutionError)):
        await task
