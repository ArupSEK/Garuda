import streamlit as st

from dashboard.client import api, require_login

require_login()
st.title("Assets and Services")
st.dataframe(api("GET", "/api/assets"), use_container_width=True)
