import streamlit as st

from dashboard.client import api, require_login

require_login()
st.title("Vulnerabilities")
c1, c2, c3 = st.columns(3)
severity = c1.selectbox("Severity", ["", "critical", "high", "medium", "low", "info"])
status = c2.text_input("Status")
ip = c3.text_input("Asset IP")
params = {k: v for k, v in {"severity": severity, "status": status, "asset_ip": ip}.items() if v}
st.dataframe(api("GET", "/api/findings", params=params), use_container_width=True)
