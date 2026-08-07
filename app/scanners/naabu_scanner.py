"""Naabu discovery adapter; results require Nmap confirmation."""

from app.parsers.naabu_json_parser import parse_naabu_json
from app.scanners.base import ScanContext, ScannerAdapter


class NaabuScanner(ScannerAdapter):
    name = "naabu"

    async def scan(self, context: ScanContext) -> list[dict]:
        if context.profile == "full":
            ports = ("-top-ports", "full")
        elif context.profile == "custom" and context.options.get("tcp_ports"):
            ports = ("-p", str(context.options["tcp_ports"]))
        else:
            ports = ("-top-ports", "100" if context.profile == "quick" else "1000")
        target_file = (context.work_dir / "targets.txt").resolve()
        target_file.write_text("\n".join(context.targets) + "\n", encoding="utf-8")
        args = [
            self.executable,
            "-silent",
            "-json",
            "-rate",
            str(context.options.get("rate_limit", 100)),
            "-c",
            str(context.options.get("concurrency", 2)),
            *ports,
            "-list",
            str(target_file),
        ]
        result = await self.runner.run(context.scan_id, args, timeout=context.options.get("timeout", 1800))
        (context.work_dir / "naabu.jsonl").write_text(result.stdout, encoding="utf-8")
        return parse_naabu_json(result.stdout)
