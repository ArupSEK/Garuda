"""ProjectDiscovery httpx adapter."""

from app.parsers.httpx_json_parser import parse_httpx_json
from app.scanners.base import ScanContext, ScannerAdapter


class HttpxScanner(ScannerAdapter):
    name = "httpx"

    async def scan(self, context: ScanContext) -> list[dict]:
        targets = context.options.get("http_urls") or context.targets
        target_file = (context.work_dir / "http-targets.txt").resolve()
        target_file.write_text("\n".join(targets) + "\n", encoding="utf-8")
        args = [
            self.executable,
            "-silent",
            "-json",
            "-sc",
            "-title",
            "-server",
            "-td",
            "-location",
            "-favicon",
            "-hash",
            "sha256",
            "-rt",
            "-cpe",
            "-ip",
            "-cname",
            "-asn",
            "-cdn",
            "-tls-grab",
            "-jarm",
            "-tls-probe",
            "-fhr",
            "-maxr",
            "5",
            "-duc",
            "-no-color",
            "-threads",
            str(context.options.get("concurrency", 2)),
            "-rate-limit",
            str(context.options.get("rate_limit", 100)),
            "-l",
            str(target_file),
        ]
        result = await self.runner.run(context.scan_id, args, timeout=context.options.get("timeout", 900))
        (context.work_dir / "httpx.jsonl").write_text(result.stdout, encoding="utf-8")
        return parse_httpx_json(result.stdout)
