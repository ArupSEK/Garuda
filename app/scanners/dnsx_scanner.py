"""dnsx passive record-query adapter."""

from app.parsers.dnsx_json_parser import parse_dnsx_json
from app.scanners.base import ScanContext, ScannerAdapter


class DnsxScanner(ScannerAdapter):
    name = "dnsx"

    async def scan(self, context: ScanContext) -> list[dict]:
        hostnames = context.options.get("hostnames", [])
        if not hostnames:
            return []
        args = [
            self.executable,
            "-silent",
            "-json",
            "-a",
            "-aaaa",
            "-cname",
            "-ns",
            "-mx",
            "-txt",
            "-soa",
            "-caa",
        ]
        for hostname in hostnames:
            args += ["-d", hostname]
        result = await self.runner.run(context.scan_id, args, timeout=300)
        return parse_dnsx_json(result.stdout)
