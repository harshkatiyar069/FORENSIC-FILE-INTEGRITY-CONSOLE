import pytest

from fim import database
from fim.baseline import (
    BASELINE_UPDATE_PHRASE,
    UnauthorizedBaselineUpdate,
    create_initial_baseline,
    replace_baseline,
)
from fim.scan_service import run_scan


def _setup(tmp_path):
    src = tmp_path / "watched"
    src.mkdir()
    (src / "a.txt").write_text("a")
    db = tmp_path / "fim.db"
    create_initial_baseline(db, [src])
    (src / "a.txt").write_text("approved change")
    return src, db


def test_update_without_authorization_is_refused(tmp_path):
    _, db = _setup(tmp_path)
    with pytest.raises(UnauthorizedBaselineUpdate):
        replace_baseline(db, confirmation=None)

    conn = database.connect(db)
    try:
        assert database.latest_baseline_id(conn) == 1
        types = [e["event_type"] for e in database.load_security_events(conn)]
    finally:
        conn.close()
    assert "baseline_update_refused" in types


def test_wrong_phrase_is_refused(tmp_path):
    _, db = _setup(tmp_path)
    with pytest.raises(UnauthorizedBaselineUpdate):
        replace_baseline(db, confirmation="yes please")


def test_authorized_update_replaces_active_baseline_and_keeps_history(tmp_path):
    _, db = _setup(tmp_path)
    summary = replace_baseline(db, confirmation=BASELINE_UPDATE_PHRASE, note="approved edit")
    assert summary.baseline_id == 2

    conn = database.connect(db)
    try:
        assert database.latest_baseline_id(conn) == 2
        count = conn.execute("SELECT COUNT(*) FROM baselines").fetchone()[0]
        old_files = database.load_baseline_files(conn, 1)
    finally:
        conn.close()
    assert count == 2
    assert len(old_files) == 1


def test_scan_after_authorized_update_is_clean(tmp_path):
    _, db = _setup(tmp_path)
    replace_baseline(db, confirmation=BASELINE_UPDATE_PHRASE)
    assert run_scan(db).changes == []
