"""HTML, CSV, JSON, JSONL, and optional PDF report generation."""

import csv
import io
import json
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape


class ReportGenerator:
    def __init__(self, template_dir: Path = Path("templates")) -> None:
        self.environment = Environment(
            loader=FileSystemLoader(template_dir), autoescape=select_autoescape(["html", "xml"])
        )

    def json(self, payload: dict[str, Any]) -> bytes:
        return json.dumps(payload, indent=2, default=str).encode()

    def jsonl(self, payload: dict[str, Any]) -> bytes:
        return (
            "\n".join(json.dumps(item, default=str) for item in payload.get("findings", [])) + "\n"
        ).encode()

    def csv(self, payload: dict[str, Any]) -> bytes:
        fields = [
            "finding_id",
            "asset_ip",
            "hostname",
            "port",
            "protocol",
            "title",
            "severity",
            "priority",
            "confidence",
            "status",
        ]
        output = io.StringIO(newline="")
        writer = csv.DictWriter(output, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(payload.get("findings", []))
        return output.getvalue().encode("utf-8-sig")

    def html(self, payload: dict[str, Any], executive: bool = False) -> bytes:
        template = self.environment.get_template(
            "executive_report.html" if executive else "technical_report.html"
        )
        return template.render(report=payload).encode()

    def pdf(self, payload: dict[str, Any], executive: bool = False) -> bytes:
        try:
            from weasyprint import HTML
        except ImportError as exc:
            raise RuntimeError("PDF support requires the optional WeasyPrint dependency") from exc
        return HTML(string=self.html(payload, executive).decode()).write_pdf()


report_generator = ReportGenerator()
