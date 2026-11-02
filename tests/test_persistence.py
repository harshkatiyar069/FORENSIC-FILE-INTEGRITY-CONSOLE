from fim import database
from fim.baseline import create_initial_baseline
from fim.scan_service import run_scan
from fim.security_log import verify_chain


def test_baseline_survives_restart_and_detects_change(tmp_path):
    src = tmp_path / "watched"
    src.mkdir()
    (src / "a.txt").write_text("before")
    db = tmp_path / "fim.db"
    create_initial_baseline(db, [src])

    # Nothing from the first run is kept in memory; the scan works from the file on disk.
    (src / "a.txt").write_text("after restart")
    summary = run_scan(db)
    assert [c["change_type"] for c in summary.changes] == ["modified"]


def test_security_log_survives_restart_and_still_verifies(tmp_path):
    src = tmp_path / "watched"
    src.mkdir()
    (src / "a.txt").write_text("a")
    db = tmp_path / "fim.db"
    create_initial_baseline(db, [src])
    run_scan(db)

    conn = database.connect(db)
    try:
        report = verify_chain(conn)
    finally:
        conn.close()
    assert report.valid
    assert report.events_checked == 3  # baseline_created, scan_started, scan_completed
