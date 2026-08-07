"""dnsx passive record-query adapter."""

from app.parsers.dnsx_json_parser import parse_dnsx_json
from app.scanners.base import ScanContext, ScannerAdapter


class DnsxScanner(ScannerAdapter):
    name = "dnsx"

    async def scan(self, context: ScanContext) -> list[dict]:
        hostnames = context.options.get("hostnames", [])
        targets = hostnames or context.targets
        target_file = (context.work_dir / "dnsx-targets.txt").resolve()
        target_file.write_text("\n".join(targets) + "\n", encoding="utf-8")
        args = [
            self.executable,
            "-silent",
            "-json",
            "-l",
            str(target_file),
        ]
        if hostnames:
            args += [
                "-a",
                "-aaaa",
                "-cname",
                "-ns",
                "-mx",
                "-txt",
                "-soa",
                "-srv",
                "-caa",
                "-axfr",
                "-auto-wildcard",
            ]
        else:
            args += ["-ptr"]
        args += [
            "-threads",
            str(context.options.get("concurrency", 2)),
            "-rate-limit",
            str(context.options.get("rate_limit", 100)),
            "-disable-update-check",
            "-no-color",
        ]
        result = await self.runner.run(context.scan_id, args, timeout=300)
        (context.work_dir / "dnsx.jsonl").write_text(result.stdout, encoding="utf-8")
        return parse_dnsx_json(result.stdout)
