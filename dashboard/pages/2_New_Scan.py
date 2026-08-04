"""Authorized assessment launch workflow."""

import streamlit as st

from dashboard.client import api, require_login
from dashboard.ui import (
    authorization_banner,
    configure_page,
    empty_state,
    logout_control,
    page_header,
    panel_heading,
)

configure_page("Launch Assessment", "◎")
require_login()
logout_control()
page_header(
    "Assessment operations",
    "Launch assessment",
    "Configure a bounded, rate-controlled assessment against engagement-approved public scope.",
)
authorization_banner()

try:
    engagements = [item for item in api("GET", "/api/engagements") if not item.get("closed")]
except Exception as exc:
    st.error(f"Unable to load engagement scope: {exc}")
    st.stop()

if not engagements:
    empty_state(
        "No active engagement", "Create an authorized engagement before launching an assessment.", "▣"
    )
    st.stop()

labels = {f"{item['public_id']} · {item['name']}": item["public_id"] for item in engagements}
profile_copy = {
    "quick": "Top 100 TCP ports · service discovery · no vulnerability templates",
    "standard": "Top 1,000 TCP ports · HTTP/TLS/SSH · safe signed checks",
    "full": "All TCP ports · detailed service assessment · screenshots when enabled",
    "custom": "Controlled options within policy-enforced limits",
}

with st.form("scan"):
    scope_col, config_col = st.columns([1.1, 0.9], gap="large")
    with scope_col:
        panel_heading("1 · Scope", "Targets are revalidated against the selected engagement")
        engagement_label = st.selectbox("Authorized engagement", list(labels))
        targets = st.text_area(
            "Public IPv4 addresses or CIDRs",
            placeholder="203.0.113.10\n203.0.113.32/28",
            height=170,
        )
        upload = st.file_uploader("Import CSV or TXT scope", type=["csv", "txt"])
        initiated = st.text_input("Operator / analyst", placeholder="Name or operator ID")
    with config_col:
        panel_heading("2 · Assessment policy", "No arbitrary scanner arguments are accepted")
        profile = st.radio(
            "Scan profile",
            list(profile_copy),
            format_func=lambda value: value.title(),
            horizontal=True,
        )
        st.caption(profile_copy[profile])
        rate = st.slider(
            "Maximum request rate", 10, 500, 100, 10, help="Lower rates reduce operational impact."
        )
        opt_a, opt_b = st.columns(2)
        with opt_a:
            udp = st.checkbox("Common UDP", help="Runs only the approved UDP set.")
            tls = st.checkbox("TLS assessment", True)
        with opt_b:
            ssh = st.checkbox("SSH assessment", True)
            shots = st.checkbox("Web screenshots")
        st.markdown("---")
        authorized = st.checkbox(
            "I confirm written authorization for every submitted target.",
            help="This acknowledgement and operator identity are written to the audit trail.",
        )
    submitted = st.form_submit_button("Queue authorized assessment", type="primary", use_container_width=True)
    if submitted:
        lines = targets.splitlines()
        if upload:
            lines += upload.getvalue().decode("utf-8-sig").replace(",", "\n").splitlines()
        try:
            result = api(
                "POST",
                "/api/scans",
                json={
                    "engagement_id": labels[engagement_label],
                    "targets": lines,
                    "profile": profile,
                    "authorized": authorized,
                    "initiated_by": initiated,
                    "rate_limit": rate,
                    "enable_udp": udp,
                    "enable_tls": tls,
                    "enable_ssh": ssh,
                    "enable_screenshots": shots,
                },
            )
            st.success(f"Assessment {result['public_id']} accepted. Open Scan Progress to monitor execution.")
        except Exception as exc:
            st.error(f"Assessment was not accepted: {exc}")
