"""Login and overview page."""

import streamlit as st

from dashboard.client import API_URL, api

st.set_page_config(page_title="External Network VA Scanner", page_icon="🛡️", layout="wide")
st.title("External Network VA Scanner")
st.error(
    "Only scan systems that you own or have explicit written authorization to assess. Unauthorized scanning may be illegal and may disrupt third-party services."
)

if not st.session_state.get("token"):
    tab_login, tab_setup = st.tabs(["Login", "Initial setup"])
    with tab_login:
        with st.form("login"):
            username = st.text_input("Username")
            password = st.text_input("Password", type="password")
            if st.form_submit_button("Login"):
                try:
                    response = __import__("httpx").post(
                        f"{API_URL}/api/auth/token",
                        data={"username": username, "password": password},
                        timeout=15,
                    )
                    response.raise_for_status()
                    st.session_state.token = response.json()["access_token"]
                    st.rerun()
                except Exception as exc:
                    st.error(f"Login failed: {exc}")
    with tab_setup:
        with st.form("setup"):
            su = st.text_input("Admin username")
            se = st.text_input("Admin email")
            sp = st.text_input("Admin password (12+ characters)", type="password")
            if st.form_submit_button("Create first admin"):
                try:
                    __import__("httpx").post(
                        f"{API_URL}/api/auth/setup",
                        json={"username": su, "email": se, "password": sp, "role": "admin"},
                        timeout=15,
                    ).raise_for_status()
                    st.success("Admin created. Use the Login tab.")
                except Exception as exc:
                    st.error(str(exc))
else:
    if st.button("Logout"):
        st.session_state.clear()
        st.rerun()
    try:
        scans, engagements, assets, findings = (
            api("GET", "/api/scans"),
            api("GET", "/api/engagements"),
            api("GET", "/api/assets"),
            api("GET", "/api/findings"),
        )
        cols = st.columns(4)
        cols[0].metric("Engagements", len(engagements))
        cols[1].metric("Scans", len(scans))
        cols[2].metric("Assets", len(assets))
        cols[3].metric("High/Critical", sum(f["severity"] in {"high", "critical"} for f in findings))
        st.subheader("Recent scans")
        st.dataframe(scans[:10], use_container_width=True)
    except Exception as exc:
        st.error(str(exc))
