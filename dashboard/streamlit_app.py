"""Garuda login and exposure command center."""

from collections import Counter

import httpx
import streamlit as st

from dashboard.client import API_URL, api
from dashboard.ui import (
    authorization_banner,
    configure_page,
    empty_state,
    logout_control,
    metric_card,
    page_header,
    panel_heading,
)

configure_page("Exposure Command Center", "◈")


def login_view() -> None:
    """Render the product login and first-run setup experience."""
    st.markdown('<div class="login-shell">', unsafe_allow_html=True)
    hero, access = st.columns([1.25, 0.75], gap="large")
    with hero:
        st.markdown(
            """
            <div class="login-hero">
              <div class="login-kicker">External attack surface intelligence</div>
              <div class="login-title">See your perimeter.<br><span>Control your exposure.</span></div>
              <p class="login-copy">Garuda unifies authorized discovery, service intelligence, safe validation,
              evidence, and remediation tracking in one analyst-grade workspace.</p>
              <div class="trust-row"><span>◈ Scope enforced</span><span>◈ Evidence retained</span><span>◈ Audit ready</span></div>
            </div>
            """,
            unsafe_allow_html=True,
        )
        authorization_banner()
    with access:
        st.markdown("### Secure workspace")
        st.caption("Authenticate to continue to the assessment console.")
        tab_login, tab_setup = st.tabs(["Sign in", "First-time setup"])
        with tab_login:
            with st.form("login", border=False):
                username = st.text_input("Username", placeholder="analyst")
                password = st.text_input("Password", type="password", placeholder="Enter your password")
                submitted = st.form_submit_button("Enter workspace", type="primary", use_container_width=True)
                if submitted:
                    try:
                        response = httpx.post(
                            f"{API_URL}/api/auth/token",
                            data={"username": username, "password": password},
                            timeout=15,
                        )
                        response.raise_for_status()
                        st.session_state.token = response.json()["access_token"]
                        st.rerun()
                    except Exception:
                        st.error("Authentication failed. Check your username and password.")
        with tab_setup:
            with st.form("setup", border=False):
                su = st.text_input("Administrator username", placeholder="security-admin")
                se = st.text_input("Work email", placeholder="admin@company.com")
                sp = st.text_input("Strong password", type="password", help="Use at least 12 characters.")
                create = st.form_submit_button(
                    "Initialize workspace", type="primary", use_container_width=True
                )
                if create:
                    try:
                        response = httpx.post(
                            f"{API_URL}/api/auth/setup",
                            json={"username": su, "email": se, "password": sp, "role": "admin"},
                            timeout=15,
                        )
                        response.raise_for_status()
                        st.success("Workspace initialized. Sign in to continue.")
                    except Exception as exc:
                        st.error(f"Setup could not be completed: {exc}")
    st.markdown("</div>", unsafe_allow_html=True)


def dashboard_view() -> None:
    """Render the authenticated exposure overview."""
    logout_control()
    page_header(
        "Exposure intelligence",
        "Command center",
        "A live operational view of authorized perimeter assessments, assets, and risk.",
        live=True,
    )
    authorization_banner()
    try:
        scans = api("GET", "/api/scans")
        engagements = api("GET", "/api/engagements")
        assets = api("GET", "/api/assets")
        findings = api("GET", "/api/findings")
    except Exception as exc:
        st.error(f"Platform data is temporarily unavailable: {exc}")
        return

    severity = Counter(str(item.get("severity", "info")).lower() for item in findings)
    active_scans = sum(item.get("status") in {"queued", "running"} for item in scans)
    exposed_services = sum(len(item.get("services", [])) for item in assets)
    high_risk = severity["critical"] + severity["high"]

    cards = st.columns(5)
    with cards[0]:
        metric_card("Managed assets", len(assets), "Across approved scope", "⬡")
    with cards[1]:
        metric_card("Open services", exposed_services, "Confirmed by Nmap", "⌁")
    with cards[2]:
        metric_card(
            "High-risk findings",
            high_risk,
            "Requires analyst attention",
            "▲",
            "danger" if high_risk else "positive",
        )
    with cards[3]:
        metric_card(
            "Active scans",
            active_scans,
            f"{len(scans)} total assessments",
            "◌",
            "positive" if active_scans else "",
        )
    with cards[4]:
        metric_card("Engagements", len(engagements), "Authorization-backed", "▣")

    st.write("")
    left, right = st.columns([1.55, 1], gap="large")
    with left:
        panel_heading("Exposure trend", "Current findings grouped by validated severity")
        chart_data = {
            "Critical": severity["critical"],
            "High": severity["high"],
            "Medium": severity["medium"],
            "Low": severity["low"],
            "Info": severity["info"],
        }
        if findings:
            st.bar_chart(chart_data, color="#4F7CFF", height=260)
        else:
            empty_state(
                "No findings recorded",
                "Complete an authorized assessment to populate exposure analytics.",
                "◫",
            )
    with right:
        panel_heading("Risk distribution", "Prioritized analyst workload")
        risk_rows = [
            {"Severity": "Critical", "Findings": severity["critical"], "Response": "Immediate"},
            {"Severity": "High", "Findings": severity["high"], "Response": "24 hours"},
            {"Severity": "Medium", "Findings": severity["medium"], "Response": "7 days"},
            {"Severity": "Low", "Findings": severity["low"], "Response": "30 days"},
        ]
        st.dataframe(risk_rows, hide_index=True, use_container_width=True, height=260)

    st.write("")
    panel_heading("Recent assessments", "Latest scan operations and their current stage")
    if scans:
        rows = [
            {
                "Scan ID": scan.get("public_id"),
                "Profile": str(scan.get("profile", "")).replace("_", " ").title(),
                "Status": str(scan.get("status", "")).upper(),
                "Progress": f"{scan.get('progress', 0)}%",
                "Stage": scan.get("current_stage", "—"),
            }
            for scan in scans[:10]
        ]
        st.dataframe(rows, hide_index=True, use_container_width=True)
    else:
        empty_state(
            "No assessments yet", "Create an engagement, approve its scope, and launch Quick Discovery.", "◎"
        )


if st.session_state.get("token"):
    dashboard_view()
else:
    login_view()
