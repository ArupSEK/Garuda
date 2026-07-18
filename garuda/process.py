from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass


@dataclass(slots=True)
class CommandResult:
    returncode: int
    stdout: str
    stderr: str


def executable_available(name: str) -> bool:
    return shutil.which(name) is not None


def run_command(args: list[str], *, timeout: int = 180) -> CommandResult:
    if not args or not all(isinstance(item, str) and item for item in args):
        raise ValueError("Command arguments must be non-empty strings.")
    completed = subprocess.run(
        args,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
        shell=False,
    )
    return CommandResult(completed.returncode, completed.stdout, completed.stderr)
