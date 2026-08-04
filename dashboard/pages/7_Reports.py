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
    "pdf": ("Executive PDF", "Polished, portable stakeholder deliverable"),
    "html": ("Interactive HTML", "Browser-ready report with rich navigation"),
    "csv": ("CSV workbook feed", "Finding data for analyst workflows"),
    "json": ("Structured JSON", "Complete machine-readable assessment object"),
    "jsonl": ("Streaming JSONL", "Pipeline-friendly record export"),
}

left, right = st.columns([1.1, 0.9], gap="large")
with left:
    with st.container(border=True):
        panel_heading("Build deliverable", "Select a source assessment and audience-ready format.")
        scan_id = st.selectbox("Assessment", [scan["public_id"] for scan in scans])
        fmt = st.selectbox("Output format", list(format_info), format_func=lambda key: format_info[key][0])
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
            response = httpx.get(f"{API_URL}/api/reports/{scan_id}.{fmt}", headers=headers(), timeout=60)
        except httpx.HTTPError as exc:
            st.error(f"Report service unavailable: {exc}")
        else:
            if response.is_success:
                st.success("Report generated and ready for controlled download.")
                st.download_button(
                    "Download report",
                    response.content,
                    file_name=f"garuda-{scan_id}.{fmt}",
                    mime=response.headers.get("content-type"),
                    type="primary",
                )
            else:
                st.error(response.text)
