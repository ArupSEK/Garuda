"""Version 2 extension point for Greenbone/OpenVAS."""

from app.core.exceptions import ToolUnavailableError
from app.scanners.base import ScanContext, ScannerAdapter


class OpenvasScanner(ScannerAdapter):
    name = "openvas"

    async def scan(self, context: ScanContext) -> list[dict]:
        raise ToolUnavailableError("OpenVAS integration is reserved for Version 2")
