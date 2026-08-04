import streamlit as st

from dashboard.client import api, require_login

require_login()
st.title("Scan Progress")
scans = api("GET", "/api/scans")
ids = [s["public_id"] for s in scans]
if not ids:
    st.info("No scans yet")
    st.stop()
scan_id = st.selectbox("Scan", ids)
if st.button("Refresh") or scan_id:
    data = api("GET", f"/api/scans/{scan_id}")["scan"]
    st.progress(data["progress"])
    st.json(data)
if st.button("Stop Scan", type="primary"):
    st.json(api("POST", f"/api/scans/{scan_id}/stop"))
