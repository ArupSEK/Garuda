"""Premium vulnerability triage workbench."""

from datetime import date, timedelta

import streamlit as st

from dashboard.client import api, require_login
from dashboard.ui import (
    configure_page,
    empty_state,
    logout_control,
    metric_card,
    page_header,
    panel_heading,
    severity_chip,
)

configure_page("Vulnerability Workbench", "05")
require_login()
logout_control()

page_header(
    "TRIAGE",
    "Vulnerability workbench",
    "Prioritize exposure, validate evidence, and move findings through the remediation lifecycle.",
)


def as_date(value, default: date) -> date:
    if isinstance(value, date):
        return value
    try:
        return date.fromisoformat(str(value))
    except (TypeError, ValueError):
        return default

with st.container(border=True):
    panel_heading("Analyst filters", "Focus the queue by risk, workflow state, or affected host.")
    f1, f2, f3, f4 = st.columns([1, 1, 1.2, 1.2])
    severity = f1.selectbox("Severity", ["All", "critical", "high", "medium", "low", "info"])
    status = f2.selectbox(
        "Workflow status",
        [
            "All",
            "new",
            "open",
            "still open",
            "reopened",
            "resolved",
            "mitigated",
            "accepted risk",
            "false positive",
            "duplicate",
            "not applicable",
            "manual review required",
            "unable to verify",
        ],
    )
    asset_ip = f3.text_input("Asset IP", placeholder="203.0.113.10")
    cve = f4.text_input("CVE", placeholder="CVE-2026-1234")
    advanced = st.columns(6)
    priority = advanced[0].selectbox("Priority", ["All", "P1", "P2", "P3", "P4", "Informational"])
    scanner = advanced[1].text_input("Scanner")
    protocol = advanced[2].text_input("Protocol")
    hostname = advanced[3].text_input("Hostname")
    port = advanced[4].number_input("Port", 0, 65535, 0)
    kev_only = advanced[5].checkbox("CISA KEV only")
    context_filters = st.columns(3)
    confidence = context_filters[0].selectbox(
        "Confidence",
        ["All", "confirmed", "high", "probable", "version-based", "potential"],
    )
    engagement_id = context_filters[1].text_input("Engagement ID", placeholder="ENG-XXXX")
    scan_id = context_filters[2].text_input("Scan ID", placeholder="SCAN-YYYYMMDD-XXXX")

params = {
    key: value
    for key, value in {
        "severity": "" if severity == "All" else severity,
        "status": "" if status == "All" else status,
        "asset_ip": asset_ip.strip(),
        "cve": cve.strip(),
        "priority": "" if priority == "All" else priority,
        "scanner": scanner.strip(),
        "protocol": protocol.strip(),
        "hostname": hostname.strip(),
        "port": port or "",
        "confidence": "" if confidence == "All" else confidence,
        "engagement_id": engagement_id.strip(),
        "scan_id": scan_id.strip(),
        "cisa_kev": "true" if kev_only else "",
    }.items()
    if value
}

try:
    findings = api("GET", "/api/findings", params=params)
except RuntimeError as exc:
    st.error(str(exc))
    findings = []

counts = {
    level: sum(item.get("severity") == level for item in findings) for level in ("critical", "high", "medium")
}
open_count = sum(
    item.get("status", "open")
    not in {"resolved", "mitigated", "false positive", "duplicate", "not applicable"}
    for item in findings
)
m1, m2, m3, m4 = st.columns(4)
with m1:
    metric_card("Visible findings", len(findings), "Current filtered queue", "◇")
with m2:
    metric_card("Critical", counts["critical"], "Immediate attention", "!", "danger")
with m3:
    metric_card("High", counts["high"], "Priority remediation", "▲", "danger")
with m4:
    metric_card("Active exposure", open_count, "Not yet closed", "◎")

if not findings:
    empty_state("No findings in this view", "Adjust the filters or complete a scan to populate the queue.")
    st.stop()

table_rows = [
    {
        "Severity": item.get("severity", "unknown").upper(),
        "Finding": item.get("title", item.get("finding_id", "Untitled")),
        "Asset": item.get("asset_ip", "—"),
        "Port": item.get("port", "—"),
        "Status": item.get("status", "open").replace("_", " ").title(),
        "CVSS": item.get("cvss_v40_score") or item.get("cvss_v31_score") or "—",
        "KEV": "Yes" if item.get("cisa_kev") else "No",
    }
    for item in findings
]

left, right = st.columns([1.55, 1], gap="large")
with left:
    with st.container(border=True):
        panel_heading("Prioritized queue", f"{len(findings)} findings match the active filters.")
        st.dataframe(table_rows, use_container_width=True, hide_index=True)

with right:
    with st.container(border=True):
        panel_heading("Finding intelligence", "Review technical evidence and remediation guidance.")
        labels = {
            f"{item.get('severity', 'unknown').upper()} · {item.get('title', item.get('finding_id'))} · {item.get('asset_ip', '—')}": item
            for item in findings
        }
        selected = labels[st.selectbox("Select finding", list(labels))]
        try:
            selected = api(
                "GET",
                f"/api/findings/{selected['finding_id']}",
                params={"record_id": selected["record_id"]},
            )
        except Exception as exc:
            st.warning(f"Detailed finding history is temporarily unavailable: {exc}")
        st.markdown(severity_chip(selected.get("severity", "unknown")), unsafe_allow_html=True)
        st.markdown(f"### {selected.get('title', selected.get('finding_id', 'Finding'))}")
        st.caption(f"Finding ID · {selected.get('finding_id', '—')}")
        d1, d2 = st.columns(2)
        d1.metric("Affected asset", selected.get("asset_ip", "—"))
        d2.metric("Port / protocol", f"{selected.get('port', '—')} / {selected.get('protocol', '—')}")
        st.write(
            f"**Priority:** {selected.get('priority')} · **Confidence:** "
            f"{selected.get('confidence')} · **CISA KEV:** "
            f"{'Yes' if selected.get('cisa_kev') else 'No'}"
        )
        st.write(
            f"**CVE:** {', '.join(selected.get('cve') or []) or 'None'} · "
            f"**CWE:** {', '.join(selected.get('cwe') or []) or 'None'} · "
            f"**CVSS:** {selected.get('cvss_v40_score') or selected.get('cvss_v31_score') or 'Not provided'}"
        )
        st.caption(selected.get("confidence_reason") or "No confidence rationale was recorded.")
        st.markdown("**Description**")
        st.write(selected.get("description") or "No description was recorded.")
        st.markdown("**Remediation**")
        st.write(selected.get("remediation") or "Remediation guidance is not available.")
        evidence = selected.get("evidence")
        if evidence:
            with st.expander("Technical evidence"):
                st.code(str(evidence))
        if selected.get("references"):
            st.markdown("**References**")
            for reference in selected["references"]:
                st.markdown(f"- {reference}")
        st.markdown("---")
        st.markdown("#### Analyst workflow")
        workflow_statuses = [
            "new",
            "open",
            "still open",
            "reopened",
            "resolved",
            "mitigated",
            "accepted risk",
            "false positive",
            "duplicate",
            "not applicable",
            "manual review required",
            "unable to verify",
        ]
        current_status = selected.get("status", "new")
        new_status = st.selectbox(
            "Status",
            workflow_statuses,
            index=workflow_statuses.index(current_status) if current_status in workflow_statuses else 0,
        )
        owner = st.text_input("Assigned owner", value=selected.get("assigned_owner") or "")
        validation_notes = st.text_area(
            "Validation notes / false-positive justification",
            value=selected.get("validation_notes") or "",
        )
        remediation_notes = st.text_area(
            "Remediation notes", value=selected.get("remediation_notes") or ""
        )
        target_date = st.date_input(
            "Target remediation date",
            value=as_date(
                selected.get("target_remediation_date"),
                date.today() + timedelta(days=30),
            ),
        )
        risk_expiry = st.date_input(
            "Risk-acceptance expiry",
            value=as_date(
                selected.get("risk_acceptance_expiry"),
                date.today() + timedelta(days=90),
            ),
            disabled=new_status != "accepted risk",
        )
        if st.button("Save analyst workflow", type="primary", use_container_width=True):
            if new_status == "false positive" and not validation_notes.strip():
                st.error("A false-positive justification is required.")
            else:
                try:
                    api(
                        "PATCH",
                        f"/api/findings/{selected['finding_id']}",
                        json={
                            "status": new_status,
                            "assigned_owner": owner or None,
                            "validation_notes": validation_notes or None,
                            "remediation_notes": remediation_notes or None,
                            "target_remediation_date": str(target_date),
                            "risk_acceptance_expiry": (
                                str(risk_expiry) if new_status == "accepted risk" else None
                            ),
                        },
                        params={"record_id": selected["record_id"]},
                    )
                    st.success("Finding workflow updated and written to the audit trail.")
                    st.rerun()
                except Exception as exc:
                    st.error(f"Finding could not be updated: {exc}")
        with st.expander("Evidence sources and status history"):
            st.markdown("**Evidence sources**")
            st.dataframe(selected.get("evidence_items", []), hide_index=True, use_container_width=True)
            st.markdown("**Status history**")
            st.dataframe(selected.get("status_history", []), hide_index=True, use_container_width=True)
