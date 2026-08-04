"""Nmap confirmation and safe service detection adapter."""

from pathlib import Path

import yaml

from app.parsers.nmap_xml_parser import parse_nmap_xml
from app.scanners.base import ScanContext, ScannerAdapter


class NmapScanner(ScannerAdapter):
    name = "nmap"

    def _scripts(self) -> str:
        policy = yaml.safe_load(Path("config/nmap_scripts.yaml").read_text(encoding="utf-8"))
        return ",".join(policy["nmap"]["allowed_scripts"])

    def build_args(self, context: ScanContext, output: Path) -> list[str]:
        profile = context.profile
        args = [self.executable, "-n", "-Pn", "-sV", "--version-light", "--host-timeout", "15m"]
        if profile == "quick":
            args += ["--top-ports", "100"]
        elif profile == "full":
            args += ["-p-"]
        else:
            args += ["--top-ports", "1000"]
        if profile != "quick":
            args += ["--script", self._scripts()]
        args += ["-oX", str(output), *context.targets]
        return args

    async def scan(self, context: ScanContext) -> dict:
        output = (context.work_dir / "nmap.xml").resolve()
        await self.runner.run(
            context.scan_id,
            self.build_args(context, output),
            timeout=context.options.get("timeout", 1800),
            cwd=context.work_dir,
        )
        return parse_nmap_xml(output)
