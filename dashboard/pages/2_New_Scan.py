import streamlit as st

from dashboard.client import api, require_login

require_login()
st.title("New Authorized Scan")
st.error(
    "Only scan systems that you own or have explicit written authorization to assess. Unauthorized scanning may be illegal and may disrupt third-party services."
)
engagements = [e for e in api("GET", "/api/engagements") if not e["closed"]]
if not engagements:
    st.info("Create an active engagement first.")
    st.stop()
labels = {f"{e['public_id']} — {e['name']}": e["public_id"] for e in engagements}
with st.form("scan"):
    engagement = st.selectbox("Engagement", labels)
    targets = st.text_area("Public IPv4 addresses or CIDRs")
    upload = st.file_uploader("Optional CSV/TXT targets", type=["csv", "txt"])
    profile = st.selectbox("Profile", ["quick", "standard", "full", "custom"])
    initiated = st.text_input("Initiated by")
    rate = st.number_input("Rate limit", 1, 1000, 100)
    udp = st.checkbox("Common UDP checks")
    tls = st.checkbox("TLS checks", True)
    ssh = st.checkbox("SSH checks", True)
    shots = st.checkbox("Screenshots")
    authorized = st.checkbox("I own these assets or have explicit written authorization")
    if st.form_submit_button("Start scan"):
        lines = targets.splitlines()
        if upload:
            lines += upload.getvalue().decode("utf-8-sig").replace(",", "\n").splitlines()
        try:
            result = api(
                "POST",
                "/api/scans",
                json={
                    "engagement_id": labels[engagement],
                    "targets": lines,
                    "profile": profile,
                    "authorized": authorized,
                    "initiated_by": initiated,
                    "rate_limit": rate,
                    "enable_udp": udp,
                    "enable_tls": tls,
                    "enable_ssh": ssh,
                    "enable_screenshots": shots,
                },
            )
            st.success(f"Accepted {result['public_id']}")
        except Exception as exc:
            st.error(str(exc))
