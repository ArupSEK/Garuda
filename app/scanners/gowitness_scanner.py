"""GoWitness screenshot adapter."""

from app.scanners.base import ScanContext, ScannerAdapter


class GoWitnessScanner(ScannerAdapter):
    name = "gowitness"

    async def scan(self, context: ScanContext) -> list[str]:
        urls = context.options.get("http_urls", [])
        if not urls:
            return []
        output = context.work_dir / "screenshots"
        output.mkdir(exist_ok=True)
        target_file = (context.work_dir / "gowitness-targets.txt").resolve()
        jsonl_file = (context.work_dir / "gowitness.jsonl").resolve()
        target_file.write_text("\n".join(urls) + "\n", encoding="utf-8")
        args = [
            self.executable,
            "scan",
            "file",
            "-f",
            str(target_file),
            "--screenshot-path",
            str(output),
            "--screenshot-format",
            "png",
            "--chrome-path",
            str(context.options.get("chromium_path", "/usr/bin/chromium")),
            "--log-scan-errors",
            "--write-jsonl",
            "--write-jsonl-file",
            str(jsonl_file),
            "--quiet",
        ]
        await self.runner.run(context.scan_id, args, timeout=600)
        return [str(path) for path in output.glob("*.png")]
