"""Read-only platform controls and operational posture."""

import streamlit as st

from dashboard.client import API_URL, api, require_login
from dashboard.ui import configure_page, logout_control, metric_card, page_header, panel_heading

configure_page("Platform Controls", "08")
require_login()
logout_control()

page_header(
    "ADMINISTRATION",
    "Platform controls",
    "Review runtime connectivity, security guardrails, and deployment-owned configuration.",
)

try:
    health = api("GET", "/api/health")
    runtime = api("GET", "/api/settings")
    api_online = bool(health.get("ok"))
except Exception:
    api_online = False
    runtime = {}

authenticated = bool(runtime)

m1, m2, m3, m4 = st.columns(4)
with m1:
    metric_card(
        "API service",
        "Online" if api_online else "Offline",
        "Runtime connectivity",
        "●",
        "positive" if api_online else "danger",
    )
with m2:
    metric_card(
        "Identity",
        "Verified" if authenticated else "Check",
        "Authenticated session",
        "◆",
        "positive" if authenticated else "danger",
    )
with m3:
    metric_card("Scope control", "Enforced", "Server-side validation", "⌖", "positive")
with m4:
    metric_card("Audit trail", "Enabled", "Operator accountability", "▤", "positive")

left, right = st.columns(2, gap="large")
with left:
    with st.container(border=True):
        panel_heading("Runtime connection", "Read-only deployment information for troubleshooting.")
        st.text_input("Garuda API endpoint", value=API_URL, disabled=True)
        st.caption("This value is supplied by the API_URL environment variable at deployment time.")
        if runtime:
            st.json(runtime.get("limits", {}), expanded=False)
        if st.button("Recheck connection", use_container_width=True):
            st.rerun()

    with st.container(border=True):
        panel_heading("Operational posture", "Controls applied to every assessment.")
        st.markdown(
            """
            - **Authorization gate** — explicit operator confirmation is required
            - **Scope enforcement** — targets are checked against engagement boundaries
            - **Role controls** — privileged actions require analyst or administrator access
            - **Evidence integrity** — normalized results preserve source context
            - **Auditability** — material actions are recorded for review
            """
        )

with right:
    with st.container(border=True):
        panel_heading("Configuration ownership", "Security-sensitive settings remain outside the browser.")
        st.info(
            "Scanner paths, credentials, network policy, target limits, and YAML profiles are managed through reviewed environment and configuration files."
        )
        if runtime:
            tool_rows = [
                {
                    "Scanner": name,
                    "Path": details.get("path"),
                    "Status": "Installed" if details.get("available") else "Missing",
                }
                for name, details in runtime.get("tools", {}).items()
            ]
            st.dataframe(tool_rows, hide_index=True, use_container_width=True)
        st.markdown(
            """
            **Deployment-owned controls**

            | Control | Source |
            |---|---|
            | Scanner binaries | Environment variables |
            | Scan profiles | `config/scan_profiles.yaml` |
            | Target limits | Server configuration |
            | Secrets | `.env` / secret manager |
            | Retention paths | Deployment volumes |
            """
        )

    with st.container(border=True):
        panel_heading("Production readiness", "Recommended checks before client use.")
        st.checkbox("TLS termination configured", disabled=True)
        st.checkbox("Secrets moved to a managed store", disabled=True)
        st.checkbox("Backups and evidence retention validated", disabled=True)
        if runtime:
            st.caption(
                f"Configured retention: {runtime.get('retention_days')} days · "
                f"Logging: {runtime.get('logging_level')}"
            )
        st.caption("These controls are deployment responsibilities and are intentionally read-only here.")
