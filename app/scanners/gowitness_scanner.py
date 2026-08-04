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
        args = [self.executable, "scan", "single", "--screenshot-path", str(output)]
        for url in urls:
            args += ["--url", url]
        await self.runner.run(context.scan_id, args, timeout=600)
        return [str(path) for path in output.glob("*.png")]
