"""Authenticated API client helpers for Streamlit pages."""

import os

import httpx
import streamlit as st

API_URL = os.getenv("API_URL", "http://127.0.0.1:8000")


def headers() -> dict[str, str]:
    token = st.session_state.get("token")
    return {"Authorization": f"Bearer {token}"} if token else {}


def api(method: str, path: str, **kwargs):
    response = httpx.request(method, f"{API_URL}{path}", headers=headers(), timeout=30, **kwargs)
    if response.is_error:
        raise RuntimeError(response.json().get("detail", response.text))
    return response.json()


def require_login() -> None:
    if not st.session_state.get("token"):
        st.warning("Log in from the main page first.")
        st.stop()
