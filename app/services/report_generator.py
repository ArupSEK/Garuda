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

    def jsonl(self, payload: dict[str, Any], dataset: str = "findings") -> bytes:
        return (
            "\n".join(json.dumps(item, default=str) for item in payload.get(dataset, [])) + "\n"
        ).encode()

    def csv(self, payload: dict[str, Any], dataset: str = "findings") -> bytes:
        fields_by_dataset = {
            "findings": [
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
                "cve",
                "cisa_kev",
                "remediation",
            ],
            "assets": [
                "ip",
                "hostname",
                "reachability",
                "operating_system",
                "asn",
                "risk_score",
                "last_scanned",
            ],
            "services": [
                "ip",
                "port",
                "transport",
                "protocol",
                "product",
                "version",
                "cpe",
                "encryption",
                "confidence",
                "source_scanner",
            ],
        }
        if dataset not in fields_by_dataset:
            raise ValueError("CSV dataset must be findings, assets, or services")
        fields = fields_by_dataset[dataset]
        output = io.StringIO(newline="")
        writer = csv.DictWriter(output, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(
            {
                key: json.dumps(value) if isinstance(value, (list, dict)) else value
                for key, value in row.items()
            }
            for row in payload.get(dataset, [])
        )
        return output.getvalue().encode("utf-8-sig")

    def html(self, payload: dict[str, Any], executive: bool = False) -> bytes:
        template = self.environment.get_template(
            "executive_report.html" if executive else "technical_report.html"
        )
        report = {
            "engagement": {
                "name": "Not provided",
                "public_id": "Not provided",
                "customer": "Not provided",
                "authorization_reference": "Not provided",
            },
            "scan": {
                "public_id": "Not provided",
                "profile": "unknown",
                "targets": [],
                "start_time": None,
                "end_time": None,
                "scanner_versions": {},
                "options": {},
            },
            "assets": [],
            "services": [],
            "findings": [],
            **payload,
        }
        report["engagement"] = {
            "name": "Not provided",
            "public_id": "Not provided",
            "customer": "Not provided",
            "authorization_reference": "Not provided",
            **payload.get("engagement", {}),
        }
        report["scan"] = {
            "public_id": "Not provided",
            "profile": "unknown",
            "targets": [],
            "start_time": None,
            "end_time": None,
            "scanner_versions": {},
            "options": {},
            **payload.get("scan", {}),
        }
        return template.render(report=report).encode()

    def pdf(self, payload: dict[str, Any], executive: bool = False) -> bytes:
        try:
            from weasyprint import HTML
        except ImportError as exc:
            raise RuntimeError("PDF support requires the optional WeasyPrint dependency") from exc
        return HTML(string=self.html(payload, executive).decode()).write_pdf()

    def comparison_html(self, payload: dict[str, Any]) -> bytes:
        template = self.environment.get_template("comparison_report.html")
        return template.render(report=payload).encode()

    def comparison_csv(self, payload: dict[str, Any]) -> bytes:
        output = io.StringIO(newline="")
        fields = ["category", "finding_id", "asset_ip", "port", "severity", "title", "detail"]
        writer = csv.DictWriter(output, fieldnames=fields)
        writer.writeheader()
        for category in ("new", "still_open", "resolved", "reopened"):
            for finding in payload.get(category, []):
                writer.writerow(
                    {
                        "category": category,
                        "finding_id": finding.get("finding_id"),
                        "asset_ip": finding.get("asset_ip"),
                        "port": finding.get("port"),
                        "severity": finding.get("severity"),
                        "title": finding.get("title"),
                        "detail": finding.get("confidence_reason", ""),
                    }
                )
        for category in ("new_ports", "closed_ports"):
            for ip, port, transport in payload.get(category, []):
                writer.writerow(
                    {
                        "category": category,
                        "asset_ip": ip,
                        "port": port,
                        "detail": transport,
                    }
                )
        return output.getvalue().encode("utf-8-sig")

    def comparison_pdf(self, payload: dict[str, Any]) -> bytes:
        try:
            from weasyprint import HTML
        except ImportError as exc:
            raise RuntimeError("PDF support requires the optional WeasyPrint dependency") from exc
        return HTML(string=self.comparison_html(payload).decode()).write_pdf()


report_generator = ReportGenerator()
