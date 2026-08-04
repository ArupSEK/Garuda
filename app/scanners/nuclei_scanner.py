"""Nuclei adapter constrained to signed, approved, non-intrusive templates."""

from app.parsers.nuclei_jsonl_parser import parse_nuclei_jsonl
from app.scanners.base import ScanContext, ScannerAdapter


class NucleiScanner(ScannerAdapter):
    name = "nuclei"

    async def scan(self, context: ScanContext) -> list[dict]:
        severities = context.options.get("nuclei_severity", "info,low,medium,high,critical")
        targets = context.options.get("nuclei_targets") or context.options.get("http_urls") or context.targets
        target_file = (context.work_dir / "nuclei-targets.txt").resolve()
        target_file.write_text("\n".join(targets) + "\n", encoding="utf-8")
        args = [
            self.executable,
            "-silent",
            "-jsonl",
            "-no-color",
            "-disable-update-check",
            "-disable-unsigned-templates",
            "-templates",
            str(context.options.get("nuclei_templates_path", "/home/scanner/nuclei-templates")),
            "-severity",
            severities,
            "-tags",
            "cve,misconfig,exposure,tech,ssl,network",
            "-exclude-tags",
            "dos,brute-force,fuzz,intrusive,exploit,headless,code",
            "-rate-limit",
            str(context.options.get("rate_limit", 50)),
            "-l",
            str(target_file),
        ]
        result = await self.runner.run(context.scan_id, args, timeout=context.options.get("timeout", 1800))
        (context.work_dir / "nuclei.jsonl").write_text(result.stdout, encoding="utf-8")
        return parse_nuclei_jsonl(result.stdout)
