"""Premium vulnerability triage workbench."""

import streamlit as st

from dashboard.client import api, require_login
from dashboard.ui import (
    configure_page,
    empty_state,
    logout_control,
    metric_card,
    page_header,
    panel_heading,
    severity_chip,
)

configure_page("Vulnerability Workbench", "05")
require_login()
logout_control()

page_header(
    "TRIAGE",
    "Vulnerability workbench",
    "Prioritize exposure, validate evidence, and move findings through the remediation lifecycle.",
)

with st.container(border=True):
    panel_heading("Analyst filters", "Focus the queue by risk, workflow state, or affected host.")
    f1, f2, f3 = st.columns([1, 1, 1.4])
    severity = f1.selectbox("Severity", ["All", "critical", "high", "medium", "low", "info"])
    status = f2.selectbox(
        "Workflow status", ["All", "open", "validated", "accepted", "resolved", "false_positive"]
    )
    asset_ip = f3.text_input("Asset IP", placeholder="203.0.113.10")

params = {
    key: value
    for key, value in {
        "severity": "" if severity == "All" else severity,
        "status": "" if status == "All" else status,
        "asset_ip": asset_ip.strip(),
    }.items()
    if value
}

try:
    findings = api("GET", "/api/findings", params=params)
except RuntimeError as exc:
    st.error(str(exc))
    findings = []

counts = {
    level: sum(item.get("severity") == level for item in findings) for level in ("critical", "high", "medium")
}
open_count = sum(item.get("status", "open") not in {"resolved", "false_positive"} for item in findings)
m1, m2, m3, m4 = st.columns(4)
with m1:
    metric_card("Visible findings", len(findings), "Current filtered queue", "◇")
with m2:
    metric_card("Critical", counts["critical"], "Immediate attention", "!", "danger")
with m3:
    metric_card("High", counts["high"], "Priority remediation", "▲", "danger")
with m4:
    metric_card("Active exposure", open_count, "Not yet closed", "◎")

if not findings:
    empty_state("No findings in this view", "Adjust the filters or complete a scan to populate the queue.")
    st.stop()

table_rows = [
    {
        "Severity": item.get("severity", "unknown").upper(),
        "Finding": item.get("title", item.get("finding_id", "Untitled")),
        "Asset": item.get("asset_ip", "—"),
        "Port": item.get("port", "—"),
        "Status": item.get("status", "open").replace("_", " ").title(),
        "CVSS": item.get("cvss_score", "—"),
    }
    for item in findings
]

left, right = st.columns([1.55, 1], gap="large")
with left:
    with st.container(border=True):
        panel_heading("Prioritized queue", f"{len(findings)} findings match the active filters.")
        st.dataframe(table_rows, use_container_width=True, hide_index=True)

with right:
    with st.container(border=True):
        panel_heading("Finding intelligence", "Review technical evidence and remediation guidance.")
        labels = {
            f"{item.get('severity', 'unknown').upper()} · {item.get('title', item.get('finding_id'))} · {item.get('asset_ip', '—')}": item
            for item in findings
        }
        selected = labels[st.selectbox("Select finding", list(labels))]
        st.markdown(severity_chip(selected.get("severity", "unknown")), unsafe_allow_html=True)
        st.markdown(f"### {selected.get('title', selected.get('finding_id', 'Finding'))}")
        st.caption(f"Finding ID · {selected.get('finding_id', '—')}")
        d1, d2 = st.columns(2)
        d1.metric("Affected asset", selected.get("asset_ip", "—"))
        d2.metric("Port / protocol", f"{selected.get('port', '—')} / {selected.get('protocol', '—')}")
        st.markdown("**Description**")
        st.write(selected.get("description") or "No description was recorded.")
        st.markdown("**Remediation**")
        st.write(selected.get("remediation") or "Remediation guidance is not available.")
        evidence = selected.get("evidence")
        if evidence:
            with st.expander("Technical evidence"):
                st.code(str(evidence))
