import streamlit as st

from dashboard.client import API_URL, require_login

require_login()
st.title("Settings")
st.info(
    "Security-sensitive scanner paths and policy files are managed through environment variables and reviewed YAML configuration, not arbitrary browser input."
)
st.code(f"API_URL={API_URL}")
