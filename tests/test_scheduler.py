from pathlib import Path

import pytest

from fim import database
from fim.baseline import create_initial_baseline
from fim.config import DEFAULT_SETTINGS
from fim.scheduler import Debouncer, run_interval, scan_and_report, should_ignore


class FakeClock:
    def __init__(self):
        self.now = 0.0

    def __call__(self):
        return self.now


def _project(tmp_path):
    src = tmp_path / "watched"
    src.mkdir()
    (src / "a.txt").write_text("a")
    db = tmp_path / "data" / "fim.db"
    reports = tmp_path / "reports"
    create_initial_baseline(db, [src])
    return src, db, reports


def test_debouncer_waits_for_quiet_period():
    clock = FakeClock()
    d = Debouncer(5.0, clock=clock)
    assert not d.due()
    d.touch()
    clock.now = 4.0
    assert not d.due()
    clock.now = 5.0
    assert d.due()
    assert not d.due()  # fires once per burst


def test_debouncer_restarts_on_new_activity():
    clock = FakeClock()
    d = Debouncer(5.0, clock=clock)
    d.touch()
    clock.now = 4.0
    d.touch()
    clock.now = 8.0
    assert not d.due()  # only 4 seconds since the latest activity
    clock.now = 9.0
    assert d.due()


def test_ignores_database_and_report_folders(tmp_path):
    data = tmp_path / "data"
    reports = tmp_path / "reports"
    ignored = (data, reports)
    patterns = DEFAULT_SETTINGS.exclude_patterns
    assert should_ignore(str(data / "fim.db"), ignored, patterns)
    assert should_ignore(str(reports / "report.pdf"), ignored, patterns)


def test_ignores_excluded_names_anywhere_in_path(tmp_path):
    ignored = (tmp_path / "data",)
    patterns = DEFAULT_SETTINGS.exclude_patterns
    assert should_ignore(str(tmp_path / "proj" / ".venv" / "lib" / "x.py"), ignored, patterns)
    assert should_ignore(str(tmp_path / "proj" / "app.log"), ignored, patterns)
    assert not should_ignore(str(tmp_path / "proj" / "notes.txt"), ignored, patterns)


def test_no_changes_writes_no_reports(tmp_path):
    _, db, reports = _project(tmp_path)
    summary, written = scan_and_report(db, reports, "scheduled")
    assert summary.changes == []
    assert written == []
    assert not reports.exists()


def test_changes_write_reports_and_log_trigger(tmp_path):
    src, db, reports = _project(tmp_path)
    (src / "a.txt").write_text("changed")

    summary, written = scan_and_report(db, reports, "realtime")
    assert len(written) == 3
    assert all(p.exists() for p in written)

    conn = database.connect(db)
    try:
        triggers = database.load_security_events(conn, event_type="scan_triggered")
    finally:
        conn.close()
    assert len(triggers) == 1
    assert '"trigger":"realtime"' in triggers[0]["details"]


def test_interval_runs_requested_number_of_scans(tmp_path):
    _, db, reports = _project(tmp_path)
    sleeps: list[float] = []
    results: list[str] = []

    run_interval(60, db, reports, max_runs=3, sleep=sleeps.append, on_result=results.append)

    assert len(results) == 3
    assert sleeps == [60, 60]  # no sleep after the final run
    conn = database.connect(db)
    try:
        completed = database.load_security_events(conn, event_type="scan_completed")
    finally:
        conn.close()
    assert len(completed) == 3
