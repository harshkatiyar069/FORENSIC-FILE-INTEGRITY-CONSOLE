from fim import dashboard_data
from fim.baseline import create_initial_baseline
from fim.scan_service import run_scan


def _watched(tmp_path):
    src = tmp_path / "watched"
    src.mkdir()
    (src / "a.txt").write_text("a")
    (src / "b.txt").write_text("b")
    return src


def test_no_baseline_status(tmp_path):
    status = dashboard_data.build_status(tmp_path / "fim.db")
    assert not status.has_baseline
    assert status.integrity_label == "No baseline"


def test_baseline_without_scan(tmp_path):
    src = _watched(tmp_path)
    db = tmp_path / "fim.db"
    create_initial_baseline(db, [src])

    status = dashboard_data.build_status(db)
    assert status.monitored_files == 2
    assert status.integrity_label == "No scans yet"


def test_clean_scan_is_intact(tmp_path):
    src = _watched(tmp_path)
    db = tmp_path / "fim.db"
    create_initial_baseline(db, [src])
    run_scan(db)

    status = dashboard_data.build_status(db)
    assert status.integrity_label == "Intact"
    assert status.integrity_level == "ok"


def test_modified_file_shows_as_changes(tmp_path):
    src = _watched(tmp_path)
    db = tmp_path / "fim.db"
    create_initial_baseline(db, [src])
    (src / "a.txt").write_text("changed")
    run_scan(db)

    status = dashboard_data.build_status(db)
    assert status.integrity_label == "Changes detected"
    assert status.counts == {"modified": 1}

    changes = dashboard_data.latest_changes(db)
    assert len(changes) == 1
    assert changes[0]["change_type"] == "modified"


def test_recent_events_newest_first(tmp_path):
    src = _watched(tmp_path)
    db = tmp_path / "fim.db"
    create_initial_baseline(db, [src])
    run_scan(db)

    events = dashboard_data.search_events(db, limit=10)
    assert events[0]["event_type"] == "scan_completed"