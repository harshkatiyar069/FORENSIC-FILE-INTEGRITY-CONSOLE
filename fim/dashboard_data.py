"""Read-only data for the dashboard. Contains no Streamlit code, so it can be tested."""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from . import database
from .security_log import ChainReport, verify_chain


@dataclass
class DashboardStatus:
    has_baseline: bool
    baseline_id: int | None
    monitored_files: int
    last_scan: dict | None
    counts: dict[str, int] = field(default_factory=dict)
    integrity_label: str = ""
    integrity_level: str = "info"  # info | ok | warning | error


def build_status(db_path: Path) -> DashboardStatus:
    conn = database.connect(db_path)
    try:
        baseline_id = database.latest_baseline_id(conn)
        if baseline_id is None:
            return DashboardStatus(False, None, 0, None, {}, "No baseline", "info")

        monitored = database.count_baseline_files(conn, baseline_id)
        last = database.load_latest_scan(conn)
        if last is None:
            return DashboardStatus(True, baseline_id, monitored, None, {}, "No scans yet", "info")
        if last["status"] == "failed":
            return DashboardStatus(True, baseline_id, monitored, last, {}, "Last scan failed", "error")
        if last["status"] == "running":
            return DashboardStatus(True, baseline_id, monitored, last, {}, "Scan in progress", "info")

        counts = database.count_changes_by_type(conn, last["id"])
        if sum(counts.values()) == 0:
            label, level = "Intact", "ok"
        else:
            label, level = "Changes detected", "warning"
        return DashboardStatus(True, baseline_id, monitored, last, counts, label, level)
    finally:
        conn.close()


def latest_changes(db_path: Path) -> list[dict]:
    conn = database.connect(db_path)
    try:
        last = database.load_latest_scan(conn)
        if last is None:
            return []
        return database.load_changes(conn, last["id"])
    finally:
        conn.close()


def search_events(db_path: Path, contains: str | None = None, limit: int | None = 50) -> list[dict]:
    """Newest events first. Searches event details only."""
    conn = database.connect(db_path)
    try:
        return database.load_security_events(
            conn, contains=contains, limit=limit, newest_first=True
        )
    finally:
        conn.close()


def log_integrity(db_path: Path) -> ChainReport:
    conn = database.connect(db_path)
    try:
        return verify_chain(conn)
    finally:
        conn.close()