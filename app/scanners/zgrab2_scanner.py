"""Version 2 extension point for structured ZGrab2 banner collection."""

from app.core.exceptions import ToolUnavailableError
from app.scanners.base import ScanContext, ScannerAdapter


class Zgrab2Scanner(ScannerAdapter):
    """Reserved adapter contract; Version 1 never invokes this scanner."""

    name = "zgrab2"

    async def scan(self, context: ScanContext) -> list[dict]:
        raise ToolUnavailableError("ZGrab2 integration is reserved for Version 2")
