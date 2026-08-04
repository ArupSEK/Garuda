import asyncio

import pytest

from app.core.exceptions import CommandExecutionError, ScanCancelled
from app.scanners.base import ScanContext
from app.scanners.nmap_scanner import NmapScanner
from app.services.report_generator import ReportGenerator
from app.utils.command_runner import CommandRunner


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
