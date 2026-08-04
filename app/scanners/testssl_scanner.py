"""testssl.sh adapter."""

from app.parsers.testssl_json_parser import parse_testssl_json
from app.scanners.base import ScanContext, ScannerAdapter


class TestsslScanner(ScannerAdapter):
    name = "testssl.sh"

    async def scan(self, context: ScanContext) -> list[dict]:
        findings = []
        for endpoint in context.options.get("tls_endpoints", []):
            target = endpoint["ip"]
            port = int(endpoint["port"])
            output = context.work_dir / f"testssl-{target}-{port}.json"
            args = [
                self.executable,
                "--quiet",
                "--warnings",
                "off",
                "--jsonfile",
                str(output),
                f"{target}:{port}",
            ]
            await self.runner.run(context.scan_id, args, timeout=context.options.get("timeout", 900))
            parsed = parse_testssl_json(output.read_text(encoding="utf-8"))
            for item in parsed:
                item.update(asset_ip=target, port=port, protocol="tls")
            findings.extend(parsed)
        return findings
