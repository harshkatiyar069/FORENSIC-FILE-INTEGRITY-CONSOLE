"""Scheduled scans and debounced event-driven scans.

This module holds the logic only. monitor.py connects it to watchdog.
"""
from __future__ import annotations

import fnmatch
import os
import time
from pathlib import Path
from typing import Callable

from . import database
from .config import DEFAULT_SETTINGS, Settings
from .paths import is_within_root
from .reporting import generate_reports
from .scan_service import NoBaselineError, ScanSummary, run_scan
from .security_log import log_event

DEFAULT_REPORT_FORMATS = ("csv", "json", "pdf")


class Debouncer:
    """Becomes due only after a quiet period with no new activity."""

    def __init__(self, quiet_seconds: float, clock: Callable[[], float] = time.monotonic):
        self.quiet_seconds = quiet_seconds
        self._clock = clock
        self._last_activity: float | None = None

    def touch(self) -> None:
        self._last_activity = self._clock()

    def due(self) -> bool:
        if self._last_activity is None:
            return False
        if self._clock() - self._last_activity >= self.quiet_seconds:
            self._last_activity = None  # fire once per burst of activity
            return True
        return False


def should_ignore(path: str, ignored_dirs: tuple[Path, ...], patterns: tuple[str, ...]) -> bool:
    """True for activity the monitor should disregard.

    Ignores the database and report folders, and any path containing an
    excluded name such as .venv, __pycache__, or *.db-journal.
    """
    full = Path(os.path.abspath(path))
    if any(is_within_root(full, folder) for folder in ignored_dirs):
        return True
    return any(
        fnmatch.fnmatch(part, pattern)
        for part in full.parts
        for pattern in patterns
    )


def describe_run(summary: ScanSummary, reports: list[Path]) -> str:
    text = f"Scan #{summary.scan_id} finished: {len(summary.changes)} change(s)."
    if reports:
        text += " Reports written: " + ", ".join(p.name for p in reports)
    return text


def scan_and_report(
    db_path: Path,
    report_dir: Path,
    trigger: str,
    settings: Settings = DEFAULT_SETTINGS,
    report_formats: tuple[str, ...] = DEFAULT_REPORT_FORMATS,
) -> tuple[ScanSummary, list[Path]]:
    """Run one scan. Write reports only when the scan found changes."""
    conn = database.connect(db_path)
    try:
        if database.latest_baseline_id(conn) is None:
            raise NoBaselineError("No baseline found. Run: python -m app.main init <folder>")
        log_event(conn, "scan_triggered", {"trigger": trigger})
        conn.commit()
    finally:
        conn.close()

    summary = run_scan(db_path, settings)
    reports: list[Path] = []
    if summary.changes:
        reports = generate_reports(
            db_path, report_dir, list(report_formats), scan_id=summary.scan_id
        )
    return summary, reports


def run_interval(
    every_seconds: float,
    db_path: Path,
    report_dir: Path,
    max_runs: int | None = None,
    sleep: Callable[[float], None] = time.sleep,
    on_result: Callable[[str], None] = print,
    settings: Settings = DEFAULT_SETTINGS,
) -> None:
    """Scan now, then again every N seconds. A failed run is reported and the schedule continues."""
    runs = 0
    while max_runs is None or runs < max_runs:
        try:
            summary, reports = scan_and_report(db_path, report_dir, "scheduled", settings)
            on_result(describe_run(summary, reports))
        except Exception as exc:
            on_result(f"Scheduled scan failed: {exc}")
        runs += 1
        if max_runs is not None and runs >= max_runs:
            break
        sleep(every_seconds) 