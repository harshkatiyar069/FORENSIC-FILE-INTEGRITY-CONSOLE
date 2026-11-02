import hashlib
import os

from fim import database
from fim.baseline import create_initial_baseline
from fim.scan_service import run_scan


def _baseline(tmp_path, build):
    src = tmp_path / "watched"
    src.mkdir()
    build(src)
    db = tmp_path / "fim.db"
    create_initial_baseline(db, [src])
    return src, db


def _stored(db, baseline_id=1):
    conn = database.connect(db)
    try:
        return database.load_baseline_files(conn, baseline_id)
    finally:
        conn.close()


def test_large_file_is_hashed_correctly_and_changes_are_detected(tmp_path):
    data = os.urandom(5 * 1024 * 1024 + 123)
    src, db = _baseline(tmp_path, lambda s: (s / "big.bin").write_bytes(data))

    assert _stored(db)[0]["sha256"] == hashlib.sha256(data).hexdigest()
    assert run_scan(db).changes == []

    changed = bytearray(data)
    changed[-1] ^= 0xFF  # flip only the last byte
    (src / "big.bin").write_bytes(bytes(changed))
    assert [c["change_type"] for c in run_scan(db).changes] == ["modified"]


def test_empty_file_is_baselined_and_detected_when_filled(tmp_path):
    src, db = _baseline(tmp_path, lambda s: (s / "empty.txt").write_bytes(b""))
    assert run_scan(db).changes == []

    (src / "empty.txt").write_text("now has text")
    assert [c["change_type"] for c in run_scan(db).changes] == ["modified"]


def test_identical_files_do_not_create_false_changes(tmp_path):
    def build(s):
        (s / "dup1.txt").write_text("same\n")
        (s / "dup2.txt").write_text("same\n")

    src, db = _baseline(tmp_path, build)
    assert run_scan(db).changes == []

    (src / "dup1.txt").unlink()
    assert [c["change_type"] for c in run_scan(db).changes] == ["deleted"]


def test_unusual_file_names_are_handled(tmp_path):
    name = "R&D (final) #2 - notes.txt"
    src, db = _baseline(tmp_path, lambda s: (s / name).write_text("v1"))
    assert run_scan(db).changes == []

    (src / name).write_text("v2")
    changes = run_scan(db).changes
    assert [c["change_type"] for c in changes] == ["modified"]
    assert changes[0]["path"].endswith(name)


def test_excluded_folder_is_ignored_in_baseline_and_scan(tmp_path):
    def build(s):
        (s / "__pycache__").mkdir()
        (s / "__pycache__" / "x.pyc").write_bytes(b"cache")
        (s / "keep.txt").write_text("k")

    src, db = _baseline(tmp_path, build)
    assert [f["path"].endswith("keep.txt") for f in _stored(db)] == [True]

    (src / "__pycache__" / "x.pyc").write_bytes(b"changed cache")
    assert run_scan(db).changes == []
