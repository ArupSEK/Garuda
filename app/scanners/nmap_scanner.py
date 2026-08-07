"""Nmap confirmation and safe service detection adapter."""

import re
from pathlib import Path

import yaml

from app.parsers.nmap_xml_parser import parse_nmap_xml
from app.scanners.base import ScanContext, ScannerAdapter


class NmapScanner(ScannerAdapter):
    name = "nmap"

    def _scripts(self, context: ScanContext) -> str:
        policy = yaml.safe_load(Path("config/nmap_scripts.yaml").read_text(encoding="utf-8"))
        scripts = list(policy["nmap"]["allowed_scripts"])
        if not context.options.get("enable_snmp_default_community", False):
            scripts = [script for script in scripts if script != "snmp-info"]
        blocked = set(policy["nmap"].get("blocked_categories", [])) | {"all"}
        if any(
            script in blocked or not re.fullmatch(r"[a-z0-9][a-z0-9-]*", script)
            for script in scripts
        ):
            raise ValueError("Nmap policy contains a blocked or malformed script name")
        return ",".join(scripts)

    @staticmethod
    def _profile(profile: str) -> dict:
        policies = yaml.safe_load(Path("config/scan_profiles.yaml").read_text(encoding="utf-8"))
        return policies["profiles"].get(profile, policies["profiles"]["standard"])

    @staticmethod
    def _discovery_args(context: ScanContext) -> list[str]:
        mode = context.options.get("discovery_mode", "assume-up")
        if mode == "icmp":
            return ["-PE"]
        if mode == "tcp":
            return ["-PS80,443"]
        return ["-Pn"]

    def _base_args(self, context: ScanContext) -> list[str]:
        host_timeout = int(context.options.get("host_timeout", 900))
        rate_limit = int(context.options.get("rate_limit", 100))
        return [
            self.executable,
            "-n",
            *self._discovery_args(context),
            "--host-timeout",
            f"{host_timeout}s",
            "--max-rate",
            str(rate_limit),
        ]

    def build_args(self, context: ScanContext, output: Path) -> list[str]:
        profile = context.profile
        args = [*self._base_args(context), "-sT", "-sV", "--version-light"]
        if profile == "quick":
            args += ["--top-ports", "100"]
        elif profile == "full":
            args += ["-p-"]
        elif profile == "custom" and context.options.get("tcp_ports"):
            args += ["-p", str(context.options["tcp_ports"])]
        else:
            args += ["--top-ports", "1000"]
        if profile != "quick":
            args += ["--script", self._scripts(context)]
        if profile == "full" or context.options.get("enable_os_detection", False):
            args += ["-O", "--osscan-limit"]
        args += ["-oX", str(output), *context.targets]
        return args

    def build_udp_args(self, context: ScanContext, output: Path) -> list[str] | None:
        if context.profile == "quick":
            return None
        policy_ports = self._profile(context.profile).get("udp_ports", [])
        custom_ports = context.options.get("udp_ports", []) if context.profile == "custom" else []
        ports = custom_ports or policy_ports
        udp_enabled = (
            context.profile in {"standard", "full"}
            or context.options.get("enable_udp", False)
            or bool(custom_ports)
        )
        if not udp_enabled or not ports:
            return None
        return [
            *self._base_args(context),
            "-sU",
            "-sV",
            "--version-light",
            "--script",
            self._scripts(context),
            "-p",
            ",".join(str(port) for port in ports),
            "-oX",
            str(output),
            *context.targets,
        ]

    @staticmethod
    def _merge(primary: dict, secondary: dict) -> dict:
        by_ip = {asset["ip"]: asset for asset in primary.get("assets", [])}
        for incoming in secondary.get("assets", []):
            current = by_ip.get(incoming["ip"])
            if current is None:
                primary.setdefault("assets", []).append(incoming)
                by_ip[incoming["ip"]] = incoming
                continue
            existing = {
                (service["port"], service.get("transport", "tcp"))
                for service in current.get("services", [])
            }
            current.setdefault("services", []).extend(
                service
                for service in incoming.get("services", [])
                if (service["port"], service.get("transport", "udp")) not in existing
            )
            if not current.get("os") and incoming.get("os"):
                current["os"] = incoming["os"]
        return primary

    async def scan(self, context: ScanContext) -> dict:
        output = (context.work_dir / "nmap.xml").resolve()
        await self.runner.run(
            context.scan_id,
            self.build_args(context, output),
            timeout=context.options.get("timeout", 1800),
            cwd=context.work_dir,
        )
        result = parse_nmap_xml(output)
        udp_output = (context.work_dir / "nmap-udp.xml").resolve()
        udp_args = self.build_udp_args(context, udp_output)
        if udp_args:
            await self.runner.run(
                context.scan_id,
                udp_args,
                timeout=context.options.get("timeout", 1800),
                cwd=context.work_dir,
            )
            result = self._merge(result, parse_nmap_xml(udp_output))
        return result
