"""Engagement portfolio and authorization management."""

from datetime import UTC, datetime, timedelta

import streamlit as st

from dashboard.client import api, require_login
from dashboard.ui import configure_page, empty_state, logout_control, metric_card, page_header, panel_heading

configure_page("Engagements", "▣")
require_login()
logout_control()
page_header(
    "Governance",
    "Engagement portfolio",
    "Bind every assessment to a documented owner, authorization reference, validity period, and approved scope.",
)

try:
    engagements = api("GET", "/api/engagements")
except Exception as exc:
    st.error(f"Unable to load engagements: {exc}")
    st.stop()

today = datetime.now(UTC).date()
active = [
    item for item in engagements if not item.get("closed") and str(item.get("expiry_date", "")) >= str(today)
]
expiring = [
    item
    for item in active
    if item.get("expiry_date") and str(item["expiry_date"]) <= str(today + timedelta(days=14))
]

cards = st.columns(4)
with cards[0]:
    metric_card("Total engagements", len(engagements), "Complete authorization register", "▣")
with cards[1]:
    metric_card("Active", len(active), "Eligible for assessment", "●", "positive")
with cards[2]:
    metric_card("Expiring soon", len(expiring), "Within the next 14 days", "◷", "danger" if expiring else "")
with cards[3]:
    metric_card("Closed", sum(bool(item.get("closed")) for item in engagements), "Retained for audit", "□")

st.write("")
portfolio, create = st.tabs(["Portfolio", "New engagement"])
with portfolio:
    panel_heading("Authorization register", "Approved scope and engagement validity at a glance")
    if engagements:
        rows = [
            {
                "Engagement": item.get("name"),
                "ID": item.get("public_id"),
                "Customer": item.get("customer"),
                "Authorization": item.get("authorization_reference"),
                "Scope entries": len(item.get("approved_targets", [])),
                "Valid until": item.get("expiry_date"),
                "Status": "CLOSED" if item.get("closed") else "ACTIVE",
            }
            for item in engagements
        ]
        st.dataframe(rows, hide_index=True, use_container_width=True)
        selected_label = st.selectbox(
            "Inspect engagement",
            [f"{item.get('public_id')} · {item.get('name')}" for item in engagements],
        )
        selected_id = selected_label.split(" · ", 1)[0]
        selected = next(item for item in engagements if item.get("public_id") == selected_id)
        detail_left, detail_right = st.columns(2)
        with detail_left:
            st.markdown("#### Approved perimeter")
            st.code("\n".join(selected.get("approved_targets", [])) or "No scope recorded")
        with detail_right:
            st.markdown("#### Operating controls")
            st.write(f"**Scan window:** {selected.get('scan_window') or 'Not restricted'}")
            st.write(f"**Emergency contact:** {selected.get('emergency_contact') or 'Not recorded'}")
            st.write(f"**Exclusions:** {', '.join(selected.get('exclusions', [])) or 'None'}")
    else:
        empty_state(
            "No engagements registered", "Create the first authorization-backed engagement to begin.", "▣"
        )

with create:
    panel_heading(
        "Create engagement", "Authorization is validated before any target can enter the scan queue"
    )
    with st.form("engagement"):
        identity, authority = st.columns(2, gap="large")
        with identity:
            name = st.text_input("Engagement name", placeholder="Q3 External Perimeter Review")
            customer = st.text_input("Customer / asset owner", placeholder="Example Corporation")
            auth = st.text_input("Authorization reference", placeholder="SOW-2026-042 / Approval ticket")
            contact = st.text_input("Emergency contact", placeholder="soc@example.com · +1 555 0100")
        with authority:
            start = st.date_input("Authorization starts", today)
            expiry = st.date_input("Authorization expires", today + timedelta(days=30))
            window = st.text_input("Permitted scan window", placeholder="Sat 22:00–Sun 04:00 UTC")
            exclusions = st.text_area("Explicit exclusions", placeholder="198.51.100.25/32", height=100)
        scope = st.text_area(
            "Approved public IPv4/CIDR scope",
            placeholder="203.0.113.10\n203.0.113.32/28",
            help="One address or CIDR per line. External mode rejects private and special-use addresses.",
            height=130,
        )
        submitted = st.form_submit_button(
            "Create authorized engagement", type="primary", use_container_width=True
        )
        if submitted:
            try:
                api(
                    "POST",
                    "/api/engagements",
                    json={
                        "name": name,
                        "customer": customer,
                        "authorization_reference": auth,
                        "start_date": str(start),
                        "expiry_date": str(expiry),
                        "approved_targets": scope.splitlines(),
                        "exclusions": exclusions.splitlines(),
                        "scan_window": window or None,
                        "emergency_contact": contact or None,
                    },
                )
                st.success("Engagement created and added to the authorization register.")
                st.rerun()
            except Exception as exc:
                st.error(f"Engagement could not be created: {exc}")
