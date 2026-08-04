"""Shared visual system for the Garuda Streamlit console."""

from __future__ import annotations

from html import escape
from typing import Any

import streamlit as st

SEVERITY_COLORS = {
    "critical": "#FF4D6D",
    "high": "#FF7A59",
    "medium": "#F6C453",
    "low": "#4F9CF9",
    "info": "#7C8DAA",
}

GLOBAL_CSS = """
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@500&display=swap');
:root {
  --bg: #070b14; --panel: #0d1424; --panel-2: #111a2d; --line: #1d2a43;
  --text: #e8eef9; --muted: #8797b2; --brand: #4f7cff; --cyan: #25d0e6;
  --green: #37d49b; --yellow: #f6c453; --red: #ff4d6d;
}
.stApp { background: radial-gradient(circle at 80% -10%, rgba(79,124,255,.12), transparent 30%), var(--bg); }
html, body, [class*="css"] { font-family: 'Inter', sans-serif; }
.main .block-container { max-width: 1500px; padding: 2rem 2.6rem 5rem; }
[data-testid="stSidebar"] { background: #090f1c; border-right: 1px solid var(--line); }
[data-testid="stSidebar"] .block-container { padding-top: 1.4rem; }
[data-testid="stSidebarNav"] span { font-weight: 550; letter-spacing: -.01em; }
[data-testid="stSidebarNav"] a { border-radius: 8px; margin: 2px 8px; }
[data-testid="stSidebarNav"] a:hover { background: rgba(79,124,255,.1); }
h1, h2, h3 { letter-spacing: -.035em !important; }
h1 { font-size: 2rem !important; font-weight: 700 !important; }
h2 { font-size: 1.15rem !important; }
p { color: var(--muted); }
.garuda-brand { padding: .35rem .7rem 1.2rem; border-bottom: 1px solid var(--line); margin-bottom: .7rem; }
.garuda-mark { display:inline-flex; width:31px; height:31px; align-items:center; justify-content:center; margin-right:.6rem;
  border-radius:9px; background:linear-gradient(135deg,var(--brand),var(--cyan)); color:white; font-weight:800; box-shadow:0 8px 24px rgba(79,124,255,.3); }
.garuda-name { font-weight:700; color:var(--text); letter-spacing:.08em; font-size:.88rem; }
.garuda-tier { margin:.65rem 0 0 2.65rem; color:#637492; font-size:.65rem; letter-spacing:.13em; text-transform:uppercase; }
.page-head { display:flex; justify-content:space-between; align-items:flex-end; gap:2rem; padding:.4rem 0 1.5rem; }
.page-kicker { color:var(--cyan); text-transform:uppercase; letter-spacing:.14em; font-weight:700; font-size:.68rem; margin-bottom:.45rem; }
.page-title { color:var(--text); font-size:2rem; font-weight:700; letter-spacing:-.045em; line-height:1.1; }
.page-subtitle { color:var(--muted); margin-top:.55rem; font-size:.92rem; max-width:760px; }
.live-pill { display:inline-flex; align-items:center; gap:.45rem; color:#a6f2d4; background:rgba(55,212,155,.08); border:1px solid rgba(55,212,155,.25); border-radius:100px; padding:.38rem .68rem; font-size:.72rem; font-weight:600; }
.live-dot { width:7px; height:7px; border-radius:50%; background:var(--green); box-shadow:0 0 0 4px rgba(55,212,155,.12); }
.metric-card { background:linear-gradient(145deg,rgba(17,26,45,.96),rgba(11,18,32,.96)); border:1px solid var(--line); border-radius:13px; padding:1.05rem 1.15rem; min-height:116px; box-shadow:0 12px 35px rgba(0,0,0,.14); }
.metric-top { display:flex; justify-content:space-between; color:var(--muted); text-transform:uppercase; letter-spacing:.08em; font-size:.65rem; font-weight:700; }
.metric-icon { color:var(--brand); font-size:.9rem; }
.metric-value { color:var(--text); font-size:1.9rem; font-weight:700; letter-spacing:-.05em; margin-top:.75rem; line-height:1; }
.metric-note { color:#697b98; font-size:.7rem; margin-top:.48rem; }
.metric-note.positive { color:var(--green); }
.metric-note.danger { color:var(--red); }
.panel-title { color:var(--text); font-size:.94rem; font-weight:650; letter-spacing:-.01em; }
.panel-subtitle { color:var(--muted); font-size:.73rem; margin-top:.2rem; margin-bottom:.75rem; }
.risk-banner { display:flex; align-items:center; gap:.8rem; border:1px solid rgba(246,196,83,.25); background:rgba(246,196,83,.06); border-radius:10px; padding:.8rem 1rem; color:#d7c78f; font-size:.78rem; margin:.15rem 0 1.2rem; }
.risk-banner strong { color:#f8df89; }
.severity-chip { display:inline-block; padding:.22rem .5rem; border-radius:100px; font-size:.65rem; font-weight:700; text-transform:uppercase; letter-spacing:.05em; }
.empty-state { border:1px dashed #25344f; border-radius:13px; padding:2.4rem; text-align:center; background:rgba(13,20,36,.55); }
.empty-icon { font-size:1.8rem; color:#4f7cff; margin-bottom:.65rem; }
.empty-title { color:var(--text); font-weight:650; }
.empty-copy { color:var(--muted); font-size:.8rem; margin-top:.35rem; }
.stage-row { display:grid; grid-template-columns:repeat(4,1fr); gap:.55rem; margin:1rem 0 1.35rem; }
.stage { border-top:3px solid #23324d; padding:.6rem .2rem; color:#60718e; font-size:.68rem; font-weight:600; text-transform:uppercase; letter-spacing:.05em; }
.stage.done { border-color:var(--green); color:#a6f2d4; }
.stage.active { border-color:var(--brand); color:#a9bcff; }
.login-shell { padding:2.2rem 0; }
.login-hero { padding:3rem 2rem 2rem 0; }
.login-kicker { color:var(--cyan); font-size:.7rem; font-weight:700; text-transform:uppercase; letter-spacing:.18em; }
.login-title { color:var(--text); font-size:3.3rem; font-weight:750; letter-spacing:-.065em; line-height:1.02; margin:1rem 0; max-width:620px; }
.login-title span { color:var(--brand); }
.login-copy { font-size:1rem; line-height:1.65; max-width:560px; }
.trust-row { display:flex; gap:1.5rem; margin-top:2rem; color:#6f819d; font-size:.72rem; text-transform:uppercase; letter-spacing:.08em; font-weight:650; }
.mono { font-family:'JetBrains Mono', monospace; }
div[data-testid="stForm"] { background:rgba(13,20,36,.82); border:1px solid var(--line); border-radius:15px; padding:1.35rem 1.35rem .55rem; box-shadow:0 20px 60px rgba(0,0,0,.25); }
div[data-testid="stMetric"] { background:var(--panel); border:1px solid var(--line); border-radius:12px; padding:.8rem 1rem; }
div[data-baseweb="input"] > div, div[data-baseweb="select"] > div, textarea { background:#0a1120 !important; border-color:#24324d !important; }
.stButton > button, .stDownloadButton > button { border-radius:8px; font-weight:650; border:1px solid #2a3a5b; min-height:2.55rem; }
.stButton > button[kind="primary"], .stDownloadButton > button[kind="primary"] { background:linear-gradient(135deg,#426ef1,#5d84ff); border:0; box-shadow:0 8px 22px rgba(79,124,255,.23); }
[data-testid="stDataFrame"] { border:1px solid var(--line); border-radius:11px; overflow:hidden; }
[data-testid="stProgressBar"] > div > div { background:linear-gradient(90deg,var(--brand),var(--cyan)); }
[data-testid="stAlert"] { border-radius:10px; border-width:1px; }
hr { border-color:var(--line) !important; }
@media (max-width: 900px) { .main .block-container{padding:1.2rem 1rem 4rem}.page-head{display:block}.login-title{font-size:2.35rem}.stage-row{grid-template-columns:1fr 1fr} }
</style>
"""


def configure_page(title: str, icon: str = "◈") -> None:
    """Configure a page and apply the product-wide visual system."""
    st.set_page_config(
        page_title=f"{title} · Garuda", page_icon=icon, layout="wide", initial_sidebar_state="expanded"
    )
    st.markdown(GLOBAL_CSS, unsafe_allow_html=True)
    sidebar_brand()


def sidebar_brand() -> None:
    st.sidebar.markdown(
        """
        <div class="garuda-brand">
          <div><span class="garuda-mark">G</span><span class="garuda-name">GARUDA</span></div>
          <div class="garuda-tier">External VA Platform</div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def page_header(kicker: str, title: str, subtitle: str, *, live: bool = False) -> None:
    status = (
        '<div class="live-pill"><span class="live-dot"></span> Platform operational</div>' if live else ""
    )
    st.markdown(
        f"""
        <div class="page-head">
          <div><div class="page-kicker">{escape(kicker)}</div><div class="page-title">{escape(title)}</div>
          <div class="page-subtitle">{escape(subtitle)}</div></div>{status}
        </div>
        """,
        unsafe_allow_html=True,
    )


def metric_card(label: str, value: Any, note: str, icon: str = "◆", tone: str = "") -> None:
    tone_class = "danger" if tone == "danger" else "positive" if tone == "positive" else ""
    st.markdown(
        f"""
        <div class="metric-card"><div class="metric-top"><span>{escape(label)}</span><span class="metric-icon">{escape(icon)}</span></div>
        <div class="metric-value">{escape(str(value))}</div><div class="metric-note {tone_class}">{escape(note)}</div></div>
        """,
        unsafe_allow_html=True,
    )


def panel_heading(title: str, subtitle: str = "") -> None:
    st.markdown(
        f'<div class="panel-title">{escape(title)}</div><div class="panel-subtitle">{escape(subtitle)}</div>',
        unsafe_allow_html=True,
    )


def authorization_banner() -> None:
    st.markdown(
        """
        <div class="risk-banner"><span>⚠</span><div><strong>Authorized assessment only.</strong>
        Scan only assets you own or have explicit written permission to assess. Every action is logged.</div></div>
        """,
        unsafe_allow_html=True,
    )


def empty_state(title: str, copy: str, icon: str = "◇") -> None:
    st.markdown(
        f'<div class="empty-state"><div class="empty-icon">{escape(icon)}</div><div class="empty-title">{escape(title)}</div><div class="empty-copy">{escape(copy)}</div></div>',
        unsafe_allow_html=True,
    )


def severity_chip(severity: str) -> str:
    level = (severity or "info").lower()
    color = SEVERITY_COLORS.get(level, SEVERITY_COLORS["info"])
    return f'<span class="severity-chip" style="color:{color};background:{color}18;border:1px solid {color}45">{escape(level)}</span>'


def scan_stages(progress: int) -> None:
    stages = [("Scope validation", 10), ("Discovery", 35), ("Assessment", 70), ("Normalization", 95)]
    markup = []
    for label, threshold in stages:
        state = "done" if progress > threshold else "active" if progress >= max(0, threshold - 25) else ""
        markup.append(f'<div class="stage {state}">{escape(label)}</div>')
    st.markdown(f'<div class="stage-row">{"".join(markup)}</div>', unsafe_allow_html=True)


def logout_control() -> None:
    st.sidebar.markdown("---")
    st.sidebar.caption("SECURE ANALYST SESSION")
    if st.sidebar.button("Sign out", use_container_width=True):
        st.session_state.clear()
        st.rerun()
