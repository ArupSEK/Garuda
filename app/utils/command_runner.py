"""Cancellable, timeout-bound subprocess execution without a shell."""

import asyncio
import os
import shutil
from dataclasses import dataclass
from pathlib import Path

from app.core.exceptions import CommandExecutionError, ScanCancelled, ToolUnavailableError
from app.utils.redaction import redact


@dataclass(slots=True)
class CommandResult:
    args: tuple[str, ...]
    returncode: int
    stdout: str
    stderr: str


class CommandRunner:
    """Runs only adapter-built argument arrays and tracks active children."""

    def __init__(self) -> None:
        self._processes: dict[str, asyncio.subprocess.Process] = {}
        self._lock = asyncio.Lock()

    @staticmethod
    def dependency_available(executable: str) -> bool:
        return bool(shutil.which(executable) or Path(executable).is_file())

    async def run(
        self,
        job_id: str,
        args: list[str],
        *,
        timeout: float,
        cwd: Path | None = None,
        env: dict[str, str] | None = None,
    ) -> CommandResult:
        if not args or not self.dependency_available(args[0]):
            raise ToolUnavailableError(
                f"Scanner is not installed or executable: {args[0] if args else '(empty)'}"
            )
        process = await asyncio.create_subprocess_exec(
            *args,
            cwd=str(cwd) if cwd else None,
            env={**os.environ, **(env or {})},
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        async with self._lock:
            self._processes[job_id] = process
        try:
            stdout_b, stderr_b = await asyncio.wait_for(process.communicate(), timeout=timeout)
        except TimeoutError as exc:
            process.terminate()
            try:
                await asyncio.wait_for(process.wait(), timeout=5)
            except TimeoutError:
                process.kill()
                await process.wait()
            raise CommandExecutionError(f"Command timed out after {timeout:g} seconds") from exc
        finally:
            async with self._lock:
                self._processes.pop(job_id, None)
        stdout = redact(stdout_b.decode("utf-8", errors="replace"))
        stderr = redact(stderr_b.decode("utf-8", errors="replace"))
        if process.returncode in {-15, -9, 1_073_741_515}:
            raise ScanCancelled("Scan process was cancelled")
        if process.returncode != 0:
            detail = stderr[-1000:].strip() or stdout[-1000:].strip() or "no diagnostic output"
            raise CommandExecutionError(f"Scanner exited with {process.returncode}: {detail}")
        return CommandResult(tuple(args), process.returncode or 0, stdout, stderr)

    async def cancel(self, job_id: str) -> bool:
        async with self._lock:
            process = self._processes.get(job_id)
        if not process or process.returncode is not None:
            return False
        process.terminate()
        return True


command_runner = CommandRunner()
