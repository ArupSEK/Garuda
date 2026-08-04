import streamlit as st

from dashboard.client import api, require_login

require_login()
st.title("Scan Comparison")
ids = [s["public_id"] for s in api("GET", "/api/scans")]
if len(ids) < 2:
    st.info("At least two scans are required")
    st.stop()
old = st.selectbox("Previous scan", ids, index=1)
new = st.selectbox("Current scan", ids, index=0)
if st.button("Compare"):
    st.json(api("GET", f"/api/scans/{old}/compare/{new}"))
