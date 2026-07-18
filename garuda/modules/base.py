from __future__ import annotations

from abc import ABC, abstractmethod

from garuda.models import ModuleResult, ScanContext


class ScanModule(ABC):
    name = "base"
    description = "Base module"

    @abstractmethod
    def run(self, context: ScanContext) -> ModuleResult:
        raise NotImplementedError

    def capability(self) -> dict[str, object]:
        return {
            "name": self.name,
            "description": self.description,
            "available": True,
        }
