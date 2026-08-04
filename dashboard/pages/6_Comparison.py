"""Scan-to-scan exposure comparison."""

import streamlit as st

from dashboard.client import api, require_login
from dashboard.ui import configure_page, empty_state, logout_control, metric_card, page_header, panel_heading

configure_page("Change Intelligence", "06")
require_login()
logout_control()

page_header(
    "DELTA ANALYSIS",
    "Change intelligence",
    "Measure remediation progress and identify newly introduced exposure between assessments.",
)

try:
    scans = api("GET", "/api/scans")
except RuntimeError as exc:
    st.error(str(exc))
    scans = []

if len(scans) < 2:
    empty_state("Two scans are required", "Complete another assessment to unlock change intelligence.")
    st.stop()

scan_map = {scan["public_id"]: scan for scan in scans}
ids = list(scan_map)
with st.container(border=True):
    panel_heading("Comparison baseline", "Select the earlier baseline and the current assessment.")
    c1, c2, c3 = st.columns([1, 1, 0.55])
    previous_id = c1.selectbox("Previous scan", ids, index=1)
    current_id = c2.selectbox("Current scan", ids, index=0)
    c3.write("")
    c3.write("")
    compare = c3.button("Run comparison", type="primary", use_container_width=True)

if previous_id == current_id:
    st.warning("Choose two different scans to calculate meaningful change.")
    st.stop()

if not compare:
    empty_state("Ready to compare", "Run the comparison to calculate finding and service deltas.")
    st.stop()

try:
    delta = api("GET", f"/api/scans/{previous_id}/compare/{current_id}")
except RuntimeError as exc:
    st.error(str(exc))
    st.stop()

m1, m2, m3, m4 = st.columns(4)
with m1:
    metric_card("New exposure", len(delta.get("new", [])), "Introduced findings", "+", "danger")
with m2:
    metric_card("Resolved", len(delta.get("resolved", [])), "Remediation wins", "✓", "positive")
with m3:
    metric_card("Still open", len(delta.get("still_open", [])), "Persistent risk", "◷", "danger")
with m4:
    metric_card("New services", len(delta.get("new_ports", [])), "Attack surface growth", "↗")

tabs = st.tabs(["New findings", "Resolved", "Persistent", "Service changes", "Severity shifts"])
with tabs[0]:
    panel_heading("Newly introduced findings", f"Observed in {current_id}, absent from {previous_id}.")
    if delta.get("new"):
        st.dataframe(delta["new"], use_container_width=True, hide_index=True)
    else:
        st.success("No newly introduced findings were detected.")
with tabs[1]:
    panel_heading("Resolved findings", "Exposure removed since the baseline.")
    if delta.get("resolved"):
        st.dataframe(delta["resolved"], use_container_width=True, hide_index=True)
    else:
        st.info("No resolved findings in this comparison.")
with tabs[2]:
    panel_heading("Persistent exposure", "Findings present in both assessments.")
    st.dataframe(delta.get("still_open", []), use_container_width=True, hide_index=True)
with tabs[3]:
    p1, p2 = st.columns(2)
    with p1:
        panel_heading("Newly exposed services", "Ports opened since the baseline.")
        st.dataframe(
            [
                {"IP": ip, "Port": port, "Transport": transport}
                for ip, port, transport in delta.get("new_ports", [])
            ],
            use_container_width=True,
            hide_index=True,
        )
    with p2:
        panel_heading("Closed services", "Ports no longer observed.")
        st.dataframe(
            [
                {"IP": ip, "Port": port, "Transport": transport}
                for ip, port, transport in delta.get("closed_ports", [])
            ],
            use_container_width=True,
            hide_index=True,
        )
with tabs[4]:
    panel_heading("Severity movement", "Risk ratings that changed between scans.")
    st.dataframe(delta.get("severity_changed", []), use_container_width=True, hide_index=True)
