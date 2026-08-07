"""ssh-audit adapter, invoked only for Nmap-confirmed SSH endpoints."""

from app.parsers.ssh_audit_parser import parse_ssh_audit
from app.scanners.base import ScanContext, ScannerAdapter


class SshAuditScanner(ScannerAdapter):
    name = "ssh-audit"

    async def scan(self, context: ScanContext) -> list[dict]:
        findings = []
        for endpoint in context.options.get("ssh_endpoints", []):
            args = [
                self.executable,
                "-j",
                "-n",
                "--skip-rate-test",
                "-p",
                str(endpoint["port"]),
                endpoint["ip"],
            ]
            result = await self.runner.run(context.scan_id, args, timeout=120)
            (context.work_dir / f"ssh-audit-{endpoint['ip']}-{endpoint['port']}.json").write_text(
                result.stdout, encoding="utf-8"
            )
            for item in parse_ssh_audit(result.stdout):
                item.update(asset_ip=endpoint["ip"], port=endpoint["port"], protocol="ssh")
                findings.append(item)
        return findings
