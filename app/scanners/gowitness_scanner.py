"""GoWitness screenshot adapter."""

import json
from urllib.parse import urlsplit

from app.scanners.base import ScanContext, ScannerAdapter
from app.utils.redaction import redact


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
            "--threads",
            str(context.options.get("concurrency", 2)),
            "--write-jsonl",
            "--write-jsonl-file",
            str(jsonl_file),
            "--quiet",
        ]
        await self.runner.run(context.scan_id, args, timeout=600)
        index: list[dict] = []
        if jsonl_file.exists():
            for line in jsonl_file.read_text(encoding="utf-8").splitlines():
                if not line.strip():
                    continue
                record = json.loads(line)
                parsed = urlsplit(record.get("url", ""))
                classifier_text = " ".join(
                    str(value or "")
                    for value in (
                        record.get("url"),
                        record.get("final_url"),
                        record.get("title"),
                    )
                ).lower()
                classifications = [
                    label
                    for label, terms in {
                        "login-interface": ("login", "log in", "sign in", "signin"),
                        "administrative-interface": ("admin", "management", "console"),
                        "dashboard": ("dashboard", "grafana", "kibana", "jenkins"),
                        "default-page": ("welcome to nginx", "apache2 default", "iis windows server"),
                    }.items()
                    if any(term in classifier_text for term in terms)
                ]
                index.append(
                    {
                        "asset_ip": parsed.hostname,
                        "url": redact(str(record.get("url", ""))),
                        "final_url": redact(str(record.get("final_url", ""))),
                        "response_code": record.get("response_code"),
                        "title": record.get("title"),
                        "file_name": record.get("file_name"),
                        "failed": bool(record.get("failed", False)),
                        "failed_reason": redact(str(record.get("failed_reason", ""))),
                        "technologies": [
                            item.get("value")
                            for item in record.get("technologies") or []
                            if isinstance(item, dict) and item.get("value")
                        ],
                        "classifications": classifications,
                    }
                )
        (context.work_dir / "screenshots-index.json").write_text(
            json.dumps(index, indent=2), encoding="utf-8"
        )
        return [str(path) for path in output.glob("*.png")]
