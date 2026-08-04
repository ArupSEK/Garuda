import httpx
import streamlit as st

from dashboard.client import API_URL, api, headers, require_login

require_login()
st.title("Reports")
ids = [s["public_id"] for s in api("GET", "/api/scans")]
if not ids:
    st.stop()
scan = st.selectbox("Scan", ids)
fmt = st.selectbox("Format", ["html", "csv", "json", "jsonl", "pdf"])
if st.button("Generate"):
    response = httpx.get(f"{API_URL}/api/reports/{scan}.{fmt}", headers=headers(), timeout=60)
    if response.is_success:
        st.download_button("Download", response.content, file_name=f"{scan}.{fmt}")
    else:
        st.error(response.text)
