"""Authorized assessment launch workflow."""

import csv
import io

import streamlit as st

from dashboard.client import api, require_login
from dashboard.ui import (
    authorization_banner,
    configure_page,
    empty_state,
    logout_control,
    page_header,
    panel_heading,
)

configure_page("Launch Assessment", "◎")
require_login()
logout_control()
page_header(
    "Assessment operations",
    "Launch assessment",
    "Configure a bounded, rate-controlled assessment against engagement-approved public scope.",
)
authorization_banner()

try:
    engagements = [item for item in api("GET", "/api/engagements") if not item.get("closed")]
except Exception as exc:
    st.error(f"Unable to load engagement scope: {exc}")
    st.stop()

if not engagements:
    empty_state(
        "No active engagement", "Create an authorized engagement before launching an assessment.", "▣"
    )
    st.stop()

labels = {f"{item['public_id']} · {item['name']}": item["public_id"] for item in engagements}
profile_copy = {
    "quick": "Top 100 TCP ports · service discovery · no vulnerability templates",
    "standard": "Top 1,000 TCP ports · HTTP/TLS/SSH · safe signed checks",
    "full": "All TCP ports · detailed service assessment · TLS/SSH · screenshots",
    "custom": "Controlled options within policy-enforced limits",
}


def parse_upload(file) -> tuple[list[str], dict[str, str]]:
    text = file.getvalue().decode("utf-8-sig")
    if file.name.lower().endswith(".txt"):
        return text.replace(",", "\n").splitlines(), {}
    rows = list(csv.reader(io.StringIO(text)))
    if not rows:
        return [], {}
    header = [value.strip().lower() for value in rows[0]]
    target_column = next(
        (index for index, value in enumerate(header) if value in {"ip", "ip_address", "target", "cidr"}),
        0,
    )
    hostname_column = next(
        (index for index, value in enumerate(header) if value in {"hostname", "host", "domain"}),
        None,
    )
    has_header = any(value in {"ip", "ip_address", "target", "cidr"} for value in header)
    targets: list[str] = []
    hostnames: dict[str, str] = {}
    for row in rows[1:] if has_header else rows:
        if len(row) <= target_column or not row[target_column].strip():
            continue
        target = row[target_column].strip()
        targets.append(target)
        if hostname_column is not None and len(row) > hostname_column and row[hostname_column].strip():
            hostnames[target] = row[hostname_column].strip()
    return targets, hostnames

with st.form("scan"):
    scope_col, config_col = st.columns([1.1, 0.9], gap="large")
    with scope_col:
        panel_heading("1 · Scope", "Targets are revalidated against the selected engagement")
        engagement_label = st.selectbox("Authorized engagement", list(labels))
        targets = st.text_area(
            "Public IPv4 addresses or CIDRs",
            placeholder="203.0.113.10\n203.0.113.32/28",
            height=170,
        )
        upload = st.file_uploader("Import CSV or TXT scope", type=["csv", "txt"])
        hostname_map = st.text_area(
            "Optional IP-to-hostname associations",
            placeholder="203.0.113.10,portal.example.com",
            help="One public IPv4 address and hostname per line, separated by a comma.",
            height=90,
        )
        initiated = st.text_input("Operator / analyst", placeholder="Name or operator ID")
    with config_col:
        panel_heading("2 · Assessment policy", "No arbitrary scanner arguments are accepted")
        profile = st.radio(
            "Scan profile",
            list(profile_copy),
            format_func=lambda value: value.title(),
            horizontal=True,
        )
        st.caption(profile_copy[profile])
        rate = st.slider(
            "Maximum request rate", 10, 500, 100, 10, help="Lower rates reduce operational impact."
        )
        opt_a, opt_b = st.columns(2)
        with opt_a:
            udp = st.checkbox(
                "Common UDP",
                value=profile in {"standard", "full"},
                disabled=profile in {"quick", "standard", "full"},
                help="Standard and Full profiles always use only the approved UDP set.",
            )
            tls = st.checkbox(
                "TLS assessment",
                profile != "quick",
                disabled=profile in {"quick", "standard", "full"},
            )
        with opt_b:
            ssh = st.checkbox(
                "SSH assessment",
                profile != "quick",
                disabled=profile in {"quick", "standard", "full"},
            )
            shots = st.checkbox(
                "Web screenshots",
                value=profile == "full",
                disabled=profile in {"quick", "standard", "full"},
            )
        with st.expander("Controlled advanced options", expanded=profile == "custom"):
            tcp_ports = st.text_input(
                "Custom TCP ports",
                placeholder="22,80,443,8000-8100",
                disabled=profile != "custom",
            )
            udp_ports_text = st.text_input(
                "Custom UDP ports",
                placeholder="53,123,161",
                disabled=profile != "custom",
            )
            host_timeout = st.slider("Per-host timeout (seconds)", 30, 3600, 900, 30)
            scan_timeout = st.slider("Scanner timeout (seconds)", 60, 86400, 1800, 60)
            concurrency = st.slider("Worker concurrency", 1, 10, 2)
            discovery_mode = st.selectbox(
                "Host discovery mode",
                ["assume-up", "icmp", "tcp"],
                help="Assume-up avoids relying on ICMP. TCP discovery uses safe probes on ports 80 and 443.",
            )
            enable_os = st.checkbox("Nmap OS fingerprinting", value=profile == "full")
            snmp_default = st.checkbox(
                "Approved default-public SNMP check",
                value=False,
                help=(
                    "Runs only the single allowlisted public-community information probe. "
                    "No community-string brute force is ever performed."
                ),
            )
            nuclei_severity = st.multiselect(
                "Nuclei severities",
                ["info", "low", "medium", "high", "critical"],
                default=["info", "low", "medium", "high", "critical"],
                disabled=profile != "custom",
            )
        st.markdown("---")
        authorized = st.checkbox(
            "I confirm written authorization for every submitted target.",
            help="This acknowledgement and operator identity are written to the audit trail.",
        )
    submitted = st.form_submit_button("Queue authorized assessment", type="primary", use_container_width=True)
    if submitted:
        lines = targets.splitlines()
        submitted_hostnames: dict[str, str] = {}
        if upload:
            uploaded_targets, uploaded_hostnames = parse_upload(upload)
            lines += uploaded_targets
            submitted_hostnames.update(uploaded_hostnames)
        for mapping in hostname_map.splitlines():
            if not mapping.strip():
                continue
            ip, separator, hostname = mapping.partition(",")
            if not separator:
                st.error(f"Hostname association must use IP,hostname: {mapping}")
                st.stop()
            submitted_hostnames[ip.strip()] = hostname.strip()
        try:
            udp_ports = [int(value.strip()) for value in udp_ports_text.split(",") if value.strip()]
            result = api(
                "POST",
                "/api/scans",
                json={
                    "engagement_id": labels[engagement_label],
                    "targets": lines,
                    "profile": profile,
                    "authorized": authorized,
                    "initiated_by": initiated,
                    "rate_limit": rate,
                    "timeout": scan_timeout,
                    "host_timeout": host_timeout,
                    "concurrency": concurrency,
                    "enable_udp": udp,
                    "udp_ports": udp_ports,
                    "tcp_ports": tcp_ports or None,
                    "enable_tls": tls,
                    "enable_ssh": ssh,
                    "enable_screenshots": shots,
                    "enable_os_detection": enable_os,
                    "enable_snmp_default_community": snmp_default,
                    "discovery_mode": discovery_mode,
                    "nuclei_severity": ",".join(nuclei_severity),
                    "hostnames": submitted_hostnames,
                },
            )
            st.success(f"Assessment {result['public_id']} accepted. Open Scan Progress to monitor execution.")
        except Exception as exc:
            st.error(f"Assessment was not accepted: {exc}")
