import os

from fim import database
from fim.baseline import create_initial_baseline
from fim.scan_service import NoBaselineError, run_scan
import pytest


def _setup(tmp_path):
    src = tmp_path / "watched"
    src.mkdir()
    (src / "keep.txt").write_text("keep")
    (src / "edit.txt").write_text("before")
    (src / "gone.txt").write_text("gone")
    (src / "old_name.txt").write_text("moving")
    db = tmp_path / "fim.db"
    create_initial_baseline(db, [src])
    return src, db


def test_clean_scan_has_no_changes(tmp_path):
    _, db = _setup(tmp_path)
    summary = run_scan(db)
    assert summary.changes == []


def test_detects_each_real_change(tmp_path):
    src, db = _setup(tmp_path)
    (src / "edit.txt").write_text("after")
    (src / "gone.txt").unlink()
    (src / "fresh.txt").write_text("new")
    (src / "old_name.txt").rename(src / "new_name.txt")

    summary = run_scan(db)
    kinds = {c["change_type"] for c in summary.changes}
    assert kinds == {"modified", "deleted", "new", "renamed"}

    modified = next(c for c in summary.changes if c["change_type"] == "modified")
    assert modified["path"].endswith("edit.txt")
    assert modified["old_sha256"] != modified["new_sha256"]

    renamed = next(c for c in summary.changes if c["change_type"] == "renamed")
    assert renamed["old_path"].endswith("old_name.txt")
    assert renamed["path"].endswith("new_name.txt")


def test_touch_without_content_change_is_metadata(tmp_path):
    src, db = _setup(tmp_path)
    target = src / "keep.txt"
    st = target.stat()
    os.utime(target, ns=(st.st_atime_ns, st.st_mtime_ns + 10_000_000_000))

    summary = run_scan(db)
    assert [c["change_type"] for c in summary.changes] == ["metadata"]


def test_scan_is_recorded_as_complete(tmp_path):
    _, db = _setup(tmp_path)
    summary = run_scan(db)

    conn = database.connect(db)
    try:
        status = conn.execute(
            "SELECT status FROM scans WHERE id = ?", (summary.scan_id,)
        ).fetchone()[0]
    finally:
        conn.close()
    assert status == "complete"


def test_scan_without_baseline_raises(tmp_path):
    with pytest.raises(NoBaselineError):
        run_scan(tmp_path / "empty.db")