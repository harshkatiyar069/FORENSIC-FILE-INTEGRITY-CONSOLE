import os

from fim import scanner
from fim.baseline import create_initial_baseline
from fim.hasher import hash_file_safe as real_hash_file_safe
from fim.scan_service import run_scan


def _deny(name: str):
    """Make hashing fail for one file name, as if Windows had locked it."""
    def fake(path, chunk_size=1024 * 1024):
        if os.path.basename(str(path)) == name:
            return None, f"permission denied: {path}"
        return real_hash_file_safe(path, chunk_size)
    return fake


def test_locked_file_is_reported_unreadable_not_deleted(tmp_path, monkeypatch):
    src = tmp_path / "watched"
    src.mkdir()
    (src / "secret.txt").write_text("s")
    (src / "other.txt").write_text("o")
    db = tmp_path / "fim.db"
    create_initial_baseline(db, [src])

    monkeypatch.setattr(scanner, "hash_file_safe", _deny("secret.txt"))
    summary = run_scan(db)

    assert [c["change_type"] for c in summary.changes] == ["unreadable"]
    assert summary.changes[0]["path"].endswith("secret.txt")


def test_locked_file_during_baseline_is_listed_and_others_recorded(tmp_path, monkeypatch):
    src = tmp_path / "watched"
    src.mkdir()
    (src / "secret.txt").write_text("s")
    (src / "other.txt").write_text("o")
    db = tmp_path / "fim.db"

    monkeypatch.setattr(scanner, "hash_file_safe", _deny("secret.txt"))
    summary = create_initial_baseline(db, [src])

    assert summary.files_recorded == 1
    assert len(summary.files_failed) == 1
    assert summary.files_failed[0][0].endswith("secret.txt")
