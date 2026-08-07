"""Live scan operations console."""

from datetime import UTC, datetime

import httpx
import streamlit as st

from dashboard.client import API_URL, api, headers, require_login
from dashboard.ui import (
    configure_page,
    empty_state,
    logout_control,
    metric_card,
    page_header,
    panel_heading,
    scan_stages,
)

configure_page("Scan Operations", "◌")
require_login()
logout_control()
page_header(
    "Live operations",
    "Scan operations",
    "Track assessment stage, progress, coverage, evidence production, and controlled cancellation.",
    live=True,
)

try:
    scans = api("GET", "/api/scans")
except Exception as exc:
    st.error(f"Unable to load scan operations: {exc}")
    st.stop()

if not scans:
    empty_state("No scan operations", "Launch an authorized assessment to begin collecting evidence.", "◌")
    st.stop()

selector, refresh = st.columns([5, 1])
with selector:
    scan_id = st.selectbox(
        "Assessment",
        [item["public_id"] for item in scans],
        format_func=lambda value: (
            f"{value} · {next(item.get('profile', '') for item in scans if item['public_id'] == value).title()}"
        ),
    )
with refresh:
    st.write("")
    st.write("")
    if st.button("Refresh", use_container_width=True):
        st.rerun()

try:
    snapshot = api("GET", f"/api/scans/{scan_id}")
    data = snapshot["scan"]
except Exception as exc:
    st.error(f"Unable to retrieve scan state: {exc}")
    st.stop()

progress = int(data.get("progress", 0))
coverage = data.get("options", {}).get("coverage", {})
checklist = data.get("options", {}).get("checklist", {})
target_progress = data.get("options", {}).get("target_progress", {})
completed_tools = sum(item.get("status") == "completed" for item in coverage.values())
coverage_failures = sum(item.get("status") in {"failed", "unavailable"} for item in coverage.values())
cards = st.columns(4)
with cards[0]:
    metric_card(
        "Status",
        str(data.get("status", "unknown")).upper(),
        "Current lifecycle state",
        "●",
        "positive" if data.get("status") == "completed" else "",
    )
with cards[1]:
    metric_card("Progress", f"{progress}%", data.get("current_stage", "Queued"), "◌")
with cards[2]:
    metric_card("Targets", len(data.get("targets", [])), "Validated public assets", "⬡")
with cards[3]:
    metric_card(
        "Scanner coverage",
        f"{completed_tools}/{len(coverage) or 8}",
        f"{coverage_failures} unavailable or failed",
        "◇",
        "danger" if coverage_failures else "positive",
    )

st.write("")
panel_heading("Execution pipeline", f"Current stage · {data.get('current_stage', 'Queued')}")
st.progress(progress / 100)
scan_stages(progress)

overview, services, findings, evidence = st.tabs(["Overview", "Services", "Findings", "Evidence & errors"])
with overview:
    meta_left, meta_right = st.columns(2)
    with meta_left:
        st.markdown("#### Approved targets")
        st.code("\n".join(data.get("targets", [])) or "No targets")
    with meta_right:
        st.markdown("#### Execution metadata")
        st.write(f"**Started:** {data.get('start_time') or 'Pending'}")
        st.write(f"**Completed:** {data.get('end_time') or 'In progress'}")
        st.write(f"**Scanner versions:** {data.get('scanner_versions') or 'Not recorded for this assessment'}")
        if data.get("start_time"):
            started = datetime.fromisoformat(str(data["start_time"]))
            ended = (
                datetime.fromisoformat(str(data["end_time"]))
                if data.get("end_time")
                else datetime.now(UTC)
            )
            st.write(f"**Elapsed:** {str(ended - started).split('.')[0]}")
        st.write(
            f"**Targets:** {len(target_progress.get('completed', []))} completed · "
            f"{len(target_progress.get('pending', data.get('targets', [])))} pending"
        )
    st.markdown("#### Scanner coverage")
    if coverage:
        coverage_rows = [
            {
                "Scanner": name,
                "Status": details.get("status", "unknown").replace("_", " ").title(),
                "Evidence": details.get("evidence_count", "—"),
                "Detail": details.get("detail", ""),
            }
            for name, details in coverage.items()
        ]
        st.dataframe(coverage_rows, hide_index=True, use_container_width=True)
    else:
        st.info("Coverage telemetry was not recorded for this older assessment.")
    st.markdown("#### Security checklist")
    if checklist:
        st.dataframe(
            [
                {
                    "Check": name,
                    "Status": details.get("status"),
                    "Coverage": details.get("coverage_status"),
                    "Detail": details.get("detail", ""),
                }
                for name, details in checklist.items()
            ],
            hide_index=True,
            use_container_width=True,
        )
with services:
    service_rows = snapshot.get("services", [])
    if service_rows:
        st.dataframe(service_rows, hide_index=True, use_container_width=True)
    else:
        empty_state("No confirmed services yet", "Service evidence appears after Nmap confirmation.", "⌁")
with findings:
    finding_rows = snapshot.get("findings", [])
    if finding_rows:
        st.dataframe(finding_rows, hide_index=True, use_container_width=True)
    else:
        nuclei_status = coverage.get("nuclei", {}).get("status")
        if data.get("status") == "completed" and nuclei_status == "completed":
            empty_state(
                "No validated findings",
                "The enabled vulnerability checks completed without producing a match. Review coverage and service evidence before concluding the asset is secure.",
                "◇",
            )
        else:
            st.warning(
                "No findings are available, but vulnerability coverage is incomplete or still running. This is not a clean security result."
            )
with evidence:
    if data.get("error_message"):
        st.error(data["error_message"])
    else:
        st.info("No scan errors recorded. Raw evidence is retained under the scan evidence directory.")
    coverage_issues = {
        name: details
        for name, details in coverage.items()
        if details.get("status") in {"failed", "unavailable"}
    }
    if coverage_issues:
        st.warning("Some scanner coverage was unavailable. Completed evidence remains valid.")
        st.json(coverage_issues)
    manifest = snapshot.get("evidence_manifest", [])
    st.markdown("#### Raw scanner evidence")
    if manifest:
        for entry in manifest:
            if int(entry["size"]) > 20 * 1024 * 1024:
                st.caption(
                    f"{entry['name']} is {entry['size']} bytes and is too large for an inline "
                    "dashboard download. Retrieve it through the authenticated evidence API."
                )
                continue
            response = httpx.get(
                f"{API_URL}/api/scans/{scan_id}/evidence/{entry['name']}",
                headers=headers(),
                timeout=30,
            )
            if response.is_success:
                st.download_button(
                    f"Download {entry['name']} ({entry['size']} bytes)",
                    response.content,
                    file_name=entry["name"],
                    key=f"evidence-{scan_id}-{entry['name']}",
                )
    else:
        st.caption("No raw evidence files are available yet.")

if data.get("status") in {"queued", "running"}:
    st.markdown("---")
    if st.button("Stop assessment", type="primary"):
        result = api("POST", f"/api/scans/{scan_id}/stop")
        st.warning("Cancellation requested." if result.get("stopped") else "No running process was found.")
