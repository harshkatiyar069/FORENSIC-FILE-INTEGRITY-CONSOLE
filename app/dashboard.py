"""Streamlit dashboard for the File Integrity Manager.

Run from the project root:

    streamlit run app/dashboard.py
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

# Streamlit runs this file from the app/ folder, so add the project root to the path.
ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import pandas as pd  # noqa: E402
import streamlit as st  # noqa: E402

from fim import dashboard_data  # noqa: E402
from fim.config import DEFAULT_SETTINGS  # noqa: E402
from fim.scan_service import NoBaselineError, run_scan  # noqa: E402
from fim.theme import HERO_HTML, THEME_CSS  # noqa: E402

DB = DEFAULT_SETTINGS.db_path

st.set_page_config(page_title="FIM // Integrity Console", page_icon="🛡️", layout="wide")
st.markdown(THEME_CSS, unsafe_allow_html=True)
st.markdown(HERO_HTML, unsafe_allow_html=True)

# Handle the scan button first, so the status below reflects the new scan.
if st.button("⚡ Run scan now", type="primary"):
    try:
        with st.spinner("Scanning monitored folders..."):
            summary = run_scan(DB)
        st.success(
            f"Scan #{summary.scan_id} complete: {len(summary.changes)} change(s) found."
        )
    except NoBaselineError as exc:
        st.error(str(exc))

status = dashboard_data.build_status(DB)

banner = {"ok": st.success, "warning": st.warning, "error": st.error, "info": st.info}
banner[status.integrity_level](f"CASE STATUS: {status.integrity_label.upper()}")

if not status.has_baseline:
    st.info("No baseline yet. Create one with: python -m app.main init <folder>")
    st.stop()

counts = status.counts
c1, c2, c3, c4, c5 = st.columns(5)
c1.metric("Evidence files", status.monitored_files)
c2.metric("Modified", counts.get("modified", 0))
c3.metric("New", counts.get("new", 0))
c4.metric("Deleted", counts.get("deleted", 0))
c5.metric("Renamed", counts.get("renamed", 0))

last = status.last_scan
if last:
    st.caption(
        f"LAST SCAN #{last['id']}  |  FINISHED {last['finished_at'] or 'N/A'}  |  "
        f"STATUS {last['status'].upper()}"
    )
else:
    st.caption("NO SCAN HAS BEEN RUN YET")

st.subheader("Evidence table: changes in latest scan")
changes = dashboard_data.latest_changes(DB)
if changes:
    st.dataframe(pd.DataFrame(changes), hide_index=True)
else:
    st.write("No changes in the latest scan. All evidence matches the trusted baseline.")

if counts:
    st.subheader("Change distribution")
    st.bar_chart(pd.Series(counts, name="count"))

st.subheader("Export evidence")
col_a, col_b, col_c, col_d = st.columns(4)
if changes:
    col_a.download_button(
        "Latest scan (CSV)",
        pd.DataFrame(changes).to_csv(index=False).encode("utf-8"),
        "latest-scan.csv",
        "text/csv",
    )
    col_b.download_button(
        "Latest scan (JSON)",
        json.dumps(changes, indent=2).encode("utf-8"),
        "latest-scan.json",
        "application/json",
    )

all_events = list(reversed(dashboard_data.search_events(DB, limit=None)))  # chronological
if all_events:
    col_c.download_button(
        "Audit log (CSV)",
        pd.DataFrame(all_events).to_csv(index=False).encode("utf-8"),
        "security-log.csv",
        "text/csv",
    )
    col_d.download_button(
        "Audit log (JSON)",
        json.dumps(all_events, indent=2).encode("utf-8"),
        "security-log.json",
        "application/json",
    )

st.subheader("Audit trail")
report = dashboard_data.log_integrity(DB)
if report.valid:
    st.success(f"Chain of custody verified: {report.events_checked} events intact.")
else:
    st.error(
        f"CHAIN BROKEN at event #{report.broken_at_id}: {report.reason}"
    )

query = st.text_input("Search audit entries (for example, a file name)", "")
events = dashboard_data.search_events(DB, contains=query or None, limit=50)
if events:
    view = pd.DataFrame(events)[["id", "created_at", "event_type", "details"]]
    st.dataframe(view, hide_index=True)
else:
    st.write("No matching audit entries.")

st.caption("Evidence sealed with SHA-256  |  Audit entries linked by hash chain")
