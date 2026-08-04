from datetime import date, timedelta

import streamlit as st

from dashboard.client import api, require_login

require_login()
st.title("Engagements")
with st.form("engagement"):
    name = st.text_input("Engagement name")
    customer = st.text_input("Customer / asset owner")
    auth = st.text_input("Authorization reference")
    start = st.date_input("Authorization start", date.today())
    expiry = st.date_input("Authorization expiry", date.today() + timedelta(days=30))
    scope = st.text_area("Approved public IPv4/CIDR scope (one per line)")
    exclusions = st.text_area("Exclusions")
    window = st.text_input("Permitted scan window (optional)")
    contact = st.text_input("Emergency contact (optional)")
    if st.form_submit_button("Create engagement"):
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
            st.success("Engagement created")
        except Exception as exc:
            st.error(str(exc))
st.dataframe(api("GET", "/api/engagements"), use_container_width=True)
