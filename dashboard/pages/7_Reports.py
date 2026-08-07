"""Professional report generation center."""

import httpx
import streamlit as st

from dashboard.client import API_URL, api, headers, require_login
from dashboard.ui import configure_page, empty_state, logout_control, metric_card, page_header, panel_heading

configure_page("Report Center", "07")
require_login()
logout_control()

page_header(
    "DELIVERABLES",
    "Report center",
    "Package validated assessment data for executives, engineers, and downstream systems.",
)

try:
    scans = api("GET", "/api/scans")
except RuntimeError as exc:
    st.error(str(exc))
    scans = []

complete = [scan for scan in scans if scan.get("status") == "completed"]
m1, m2, m3 = st.columns(3)
with m1:
    metric_card("Available scans", len(scans), "Assessment history", "▤")
with m2:
    metric_card("Report ready", len(complete), "Completed assessments", "✓", "positive")
with m3:
    metric_card("Export formats", 5, "Human and machine readable", "⇩")

if not scans:
    empty_state("No reportable scans", "Complete an assessment before generating a deliverable.")
    st.stop()

format_info = {
    "pdf": ("PDF report", "Polished, portable stakeholder deliverable"),
    "html": ("Interactive HTML", "Browser-ready report with rich navigation"),
    "csv": ("CSV workbook feed", "Finding data for analyst workflows"),
    "json": ("Structured JSON", "Complete machine-readable assessment object"),
    "jsonl": ("Streaming JSONL", "Pipeline-friendly record export"),
}

left, right = st.columns([1.1, 0.9], gap="large")
with left:
    with st.container(border=True):
        panel_heading("Build deliverable", "Select a source assessment and audience-ready format.")
        report_modes = ["Scan report", "Comparison report"] if len(scans) > 1 else ["Scan report"]
        report_mode = st.radio("Deliverable", report_modes, horizontal=True)
        scan_id = st.selectbox(
            "Assessment" if report_mode == "Scan report" else "Current assessment",
            [scan["public_id"] for scan in scans],
        )
        previous_id = None
        if report_mode == "Comparison report":
            previous_id = st.selectbox(
                "Previous assessment",
                [scan["public_id"] for scan in scans if scan["public_id"] != scan_id],
            )
        available_formats = (
            ["pdf", "html", "csv", "json"]
            if report_mode == "Comparison report"
            else list(format_info)
        )
        fmt = st.selectbox(
            "Output format",
            available_formats,
            format_func=lambda key: format_info[key][0],
        )
        report_type = st.selectbox(
            "Report audience",
            ["executive", "technical"],
            format_func=lambda value: value.title(),
            disabled=fmt not in {"pdf", "html"} or report_mode == "Comparison report",
        )
        dataset = st.selectbox(
            "Data set",
            ["full", "findings", "assets", "services"],
            format_func=lambda value: {
                "full": "Complete assessment",
                "findings": "Vulnerability report",
                "assets": "Asset inventory",
                "services": "Open-port inventory",
            }[value],
            disabled=fmt in {"pdf", "html"} or report_mode == "Comparison report",
        )
        st.caption(format_info[fmt][1])
        include_evidence = st.checkbox("Include technical evidence", value=True, disabled=True)
        generate = st.button("Generate secure report", type="primary", use_container_width=True)

with right:
    with st.container(border=True):
        panel_heading("Delivery assurance", "Reports are generated from the normalized evidence store.")
        st.markdown(
            """
            **Included by default**

            - Engagement and scope context
            - Asset and service inventory
            - Prioritized vulnerability findings
            - Evidence and remediation guidance
            - Stable finding identifiers for retesting
            """
        )
        st.info("Review classification and client handling requirements before external distribution.")

if generate:
    with st.spinner("Compiling assessment deliverable…"):
        try:
            response = httpx.get(
                (
                    f"{API_URL}/api/reports/compare/{previous_id}/{scan_id}.{fmt}"
                    if report_mode == "Comparison report"
                    else f"{API_URL}/api/reports/{scan_id}.{fmt}"
                ),
                params={"report_type": report_type, "dataset": dataset},
                headers=headers(),
                timeout=60,
            )
        except httpx.HTTPError as exc:
            st.error(f"Report service unavailable: {exc}")
        else:
            if response.is_success:
                st.success("Report generated and ready for controlled download.")
                st.download_button(
                    "Download report",
                    response.content,
                    file_name=(
                        f"garuda-comparison-{previous_id}-{scan_id}.{fmt}"
                        if report_mode == "Comparison report"
                        else f"garuda-{scan_id}-{report_type}-{dataset}.{fmt}"
                    ),
                    mime=response.headers.get("content-type"),
                    type="primary",
                )
            else:
                st.error(response.text)
