"""Asset and service exposure inventory."""

import httpx
import streamlit as st

from dashboard.client import API_URL, api, headers, require_login
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
    labels = {f"{item['ip']} · {item.get('scan_id', 'unknown scan')}": item for item in filtered}
    selected = labels[st.selectbox("Inspect asset", list(labels))]
    selected_ip = selected["ip"]
    try:
        details = api("GET", f"/api/assets/{selected['id']}")
    except Exception as exc:
        st.error(f"Asset details are unavailable: {exc}")
        details = selected
    with st.expander(f"Service intelligence · {selected_ip}", expanded=True):
        service_rows = details.get("services", [])
        if service_rows:
            st.dataframe(service_rows, hide_index=True, use_container_width=True)
        else:
            st.caption("No open services were confirmed for this asset.")
    service_tab, finding_tab, visual_tab, history_tab = st.tabs(
        ["Services", "Vulnerabilities", "Screenshots", "History"]
    )
    with service_tab:
        st.dataframe(details.get("services", []), hide_index=True, use_container_width=True)
    with finding_tab:
        if details.get("findings"):
            st.dataframe(details["findings"], hide_index=True, use_container_width=True)
        else:
            st.info("No normalized findings are linked to this asset in the selected scan.")
    with visual_tab:
        screenshots = details.get("screenshots", [])
        if not screenshots:
            st.info("No screenshot evidence was collected for this asset.")
        for shot in screenshots:
            response = httpx.get(
                f"{API_URL}/api/assets/{selected['id']}/screenshots/{shot['file_name']}",
                headers=headers(),
                timeout=30,
            )
            if response.is_success:
                classifications = ", ".join(shot.get("classifications") or []) or "unclassified"
                st.image(
                    response.content,
                    caption=(
                        f"{shot.get('title') or shot.get('url')} · "
                        f"{shot.get('response_code')} · {classifications}"
                    ),
                )
            else:
                st.warning(f"Screenshot evidence could not be loaded: {shot.get('file_name')}")
    with history_tab:
        st.dataframe(details.get("history", []), hide_index=True, use_container_width=True)
else:
    empty_state(
        "No assets match these filters", "Adjust the search, reachability, or minimum-risk criteria.", "⬡"
    )
