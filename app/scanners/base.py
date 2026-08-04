"""Scanner adapter contract."""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from app.utils.command_runner import CommandRunner, command_runner


@dataclass(slots=True)
class ScanContext:
    scan_id: str
    targets: list[str]
    work_dir: Path
    profile: str
    options: dict[str, Any] = field(default_factory=dict)


class ScannerAdapter(ABC):
    name = "scanner"

    def __init__(self, executable: str, runner: CommandRunner = command_runner) -> None:
        self.executable = executable
        self.runner = runner

    @property
    def available(self) -> bool:
        return self.runner.dependency_available(self.executable)

    @abstractmethod
    async def scan(self, context: ScanContext) -> Any: ...
