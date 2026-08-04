"""Asset and service exposure inventory."""

import streamlit as st

from dashboard.client import api, require_login
from dashboard.ui import configure_page, empty_state, logout_control, metric_card, page_header, panel_heading

configure_page("Assets", "⬡")
require_login()
logout_control()
page_header(
    "Attack surface",
    "Asset inventory",
    "A consolidated view of reachable perimeter assets, confirmed services, technology, and risk concentration.",
)

try:
    assets = api("GET", "/api/assets")
except Exception as exc:
    st.error(f"Unable to load asset inventory: {exc}")
    st.stop()

reachable = sum(item.get("reachability") == "up" for item in assets)
services_total = sum(len(item.get("services", [])) for item in assets)
management_ports = {22, 3389, 5900, 445, 2375, 6443}
management = sum(
    service.get("port") in management_ports for asset in assets for service in asset.get("services", [])
)

cards = st.columns(4)
with cards[0]:
    metric_card("Discovered assets", len(assets), "Across completed scans", "⬡")
with cards[1]:
    metric_card("Reachable", reachable, "Responded during assessment", "●", "positive")
with cards[2]:
    metric_card("Open services", services_total, "Nmap-confirmed exposure", "⌁")
with cards[3]:
    metric_card(
        "Management exposure",
        management,
        "Administrative service ports",
        "▲",
        "danger" if management else "positive",
    )

st.write("")
filters = st.columns([2, 1, 1])
query = filters[0].text_input("Search inventory", placeholder="IP, hostname, product, or protocol")
reach_filter = filters[1].selectbox("Reachability", ["All", "Up", "Unknown", "Down"])
min_risk = filters[2].number_input("Minimum risk", 0.0, 10.0, 0.0, 0.5)


def matches(asset: dict) -> bool:
    searchable = " ".join(
        [str(asset.get("ip", "")), str(asset.get("hostname", ""))]
        + [
            f"{service.get('protocol', '')} {service.get('product', '')}"
            for service in asset.get("services", [])
        ]
    ).lower()
    reach_ok = (
        reach_filter == "All" or str(asset.get("reachability", "unknown")).lower() == reach_filter.lower()
    )
    return query.lower() in searchable and reach_ok and float(asset.get("risk_score") or 0) >= min_risk


filtered = [asset for asset in assets if matches(asset)]
panel_heading("Exposure inventory", f"Showing {len(filtered)} of {len(assets)} assets")
if filtered:
    rows = [
        {
            "IP address": item.get("ip"),
            "Hostname": item.get("hostname") or "—",
            "Reachability": str(item.get("reachability", "unknown")).upper(),
            "Operating system": item.get("operating_system") or "Unknown",
            "Open services": len(item.get("services", [])),
            "Risk score": item.get("risk_score", 0),
        }
        for item in filtered
    ]
    st.dataframe(rows, hide_index=True, use_container_width=True)
    selected_ip = st.selectbox("Inspect asset", [item["ip"] for item in filtered])
    selected = next(item for item in filtered if item["ip"] == selected_ip)
    with st.expander(f"Service intelligence · {selected_ip}", expanded=True):
        service_rows = selected.get("services", [])
        if service_rows:
            st.dataframe(service_rows, hide_index=True, use_container_width=True)
        else:
            st.caption("No open services were confirmed for this asset.")
else:
    empty_state(
        "No assets match these filters", "Adjust the search, reachability, or minimum-risk criteria.", "⬡"
    )
