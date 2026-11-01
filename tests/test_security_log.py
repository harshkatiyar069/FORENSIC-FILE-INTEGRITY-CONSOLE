import csv
import json
import sqlite3

import pytest

from fim import database
from fim.baseline import BaselineExistsError, create_initial_baseline
from fim.scan_service import run_scan
from fim.security_log import GENESIS_HASH, export_events, log_event, verify_chain


def _conn(tmp_path):
    return database.connect(tmp_path / "fim.db")


def _events(db):
    conn = database.connect(db)
    try:
        return database.load_security_events(conn)
    finally:
        conn.close()


def _watched(tmp_path):
    src = tmp_path / "watched"
    src.mkdir()
    (src / "a.txt").write_text("a")
    return src


def test_empty_log_verifies(tmp_path):
    report = verify_chain(_conn(tmp_path))
    assert report.valid
    assert report.events_checked == 0


def test_events_form_a_chain(tmp_path):
    conn = _conn(tmp_path)
    for i in range(3):
        log_event(conn, "test_event", {"n": i})
    conn.commit()

    events = database.load_security_events(conn)
    assert events[0]["prev_hash"] == GENESIS_HASH
    assert events[1]["prev_hash"] == events[0]["entry_hash"]
    assert events[2]["prev_hash"] == events[1]["entry_hash"]
    assert verify_chain(conn).valid


def test_edited_event_is_detected(tmp_path):
    conn = _conn(tmp_path)
    for i in range(3):
        log_event(conn, "test_event", {"n": i})
    conn.commit()

    # Simulate an attacker who bypasses the append-only triggers.
    conn.execute("DROP TRIGGER security_events_no_update")
    conn.execute("UPDATE security_events SET details = ? WHERE id = 2", ('{"n":99}',))
    conn.commit()

    report = verify_chain(conn)
    assert not report.valid
    assert report.broken_at_id == 2


def test_deleted_event_breaks_the_link(tmp_path):
    conn = _conn(tmp_path)
    for i in range(3):
        log_event(conn, "test_event", {"n": i})
    conn.commit()

    conn.execute("DROP TRIGGER security_events_no_delete")
    conn.execute("DELETE FROM security_events WHERE id = 2")
    conn.commit()

    report = verify_chain(conn)
    assert not report.valid
    assert report.broken_at_id == 3


def test_triggers_block_normal_edits(tmp_path):
    conn = _conn(tmp_path)
    log_event(conn, "test_event", {})
    conn.commit()

    with pytest.raises(sqlite3.DatabaseError):
        conn.execute("UPDATE security_events SET details = '{}'")
    conn.rollback()


def test_export_csv_and_json(tmp_path):
    conn = _conn(tmp_path)
    log_event(conn, "alpha", {"x": 1})
    log_event(conn, "beta", {"y": 2})
    conn.commit()
    events = database.load_security_events(conn)

    csv_path = tmp_path / "out" / "events.csv"
    assert export_events(events, csv_path) == 2
    with csv_path.open(newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    assert [row["event_type"] for row in rows] == ["alpha", "beta"]

    json_path = tmp_path / "events.json"
    export_events(events, json_path)
    assert len(json.loads(json_path.read_text(encoding="utf-8"))) == 2


def test_export_rejects_unknown_extension(tmp_path):
    with pytest.raises(ValueError):
        export_events([], tmp_path / "events.txt")


def test_baseline_creation_is_logged(tmp_path):
    src = _watched(tmp_path)
    db = tmp_path / "fim.db"
    create_initial_baseline(db, [src])

    assert [e["event_type"] for e in _events(db)] == ["baseline_created"]


def test_refused_baseline_is_logged(tmp_path):
    src = _watched(tmp_path)
    db = tmp_path / "fim.db"
    create_initial_baseline(db, [src])

    with pytest.raises(BaselineExistsError):
        create_initial_baseline(db, [src])

    types = [e["event_type"] for e in _events(db)]
    assert types == ["baseline_created", "baseline_refused"]


def test_scan_logs_start_changes_and_completion(tmp_path):
    src = _watched(tmp_path)
    db = tmp_path / "fim.db"
    create_initial_baseline(db, [src])
    (src / "a.txt").write_text("changed content")

    run_scan(db)

    events = _events(db)
    assert [e["event_type"] for e in events] == [
        "baseline_created", "scan_started", "change_detected", "scan_completed",
    ]
    change = json.loads(events[2]["details"])
    assert change["change_type"] == "modified"


def test_full_log_verifies_after_real_activity(tmp_path):
    src = _watched(tmp_path)
    db = tmp_path / "fim.db"
    create_initial_baseline(db, [src])
    run_scan(db)
    run_scan(db)

    conn = database.connect(db)
    try:
        report = verify_chain(conn)
    finally:
        conn.close()
    assert report.valid
    assert report.events_checked > 0