from fim.comparator import compare
from fim.scanner import FileRecord


def _base(path, sha, mtime=100, file_id=None):
    return {"path": path, "sha256": sha, "size_bytes": 1,
            "mtime_ns": mtime, "file_id": file_id}


def _cur(path, sha, mtime=100, error=None, unstable=False):
    return FileRecord(path=path, size_bytes=1, mtime_ns=mtime,
                      sha256=sha, error=error, unstable=unstable)


def test_identical_scan_reports_nothing():
    base = [_base("/w/a.txt", "h1")]
    assert compare(base, [_cur("/w/a.txt", "h1")]) == []


def test_modified_file_shows_both_hashes():
    base = [_base("/w/a.txt", "old")]
    changes = compare(base, [_cur("/w/a.txt", "new")])
    assert len(changes) == 1
    assert changes[0].change_type == "modified"
    assert changes[0].old_sha256 == "old"
    assert changes[0].new_sha256 == "new"


def test_same_hash_new_mtime_is_metadata_change():
    base = [_base("/w/a.txt", "h1", mtime=100)]
    changes = compare(base, [_cur("/w/a.txt", "h1", mtime=999)])
    assert [c.change_type for c in changes] == ["metadata"]


def test_new_file_detected():
    changes = compare([], [_cur("/w/new.txt", "h9")])
    assert [c.change_type for c in changes] == ["new"]
    assert changes[0].new_sha256 == "h9"


def test_deleted_file_detected():
    changes = compare([_base("/w/gone.txt", "h2")], [])
    assert [c.change_type for c in changes] == ["deleted"]
    assert changes[0].old_sha256 == "h2"


def test_unreadable_file_is_not_reported_as_deleted():
    base = [_base("/w/locked.txt", "h3")]
    current = [_cur("/w/locked.txt", None, error="permission denied: /w/locked.txt")]
    changes = compare(base, current)
    assert [c.change_type for c in changes] == ["unreadable"]


def test_unique_content_match_is_rename():
    base = [_base("/w/old.txt", "same")]
    changes = compare(base, [_cur("/w/new.txt", "same")])
    assert [c.change_type for c in changes] == ["renamed"]
    assert changes[0].old_path == "/w/old.txt"
    assert changes[0].path == "/w/new.txt"


def test_ambiguous_duplicates_are_not_guessed_as_renames():
    base = [_base("/w/one.txt", "same"), _base("/w/two.txt", "same")]
    changes = compare(base, [_cur("/w/three.txt", "same")])
    kinds = sorted(c.change_type for c in changes)
    assert kinds == ["deleted", "deleted", "new"]


def test_unstable_file_is_flagged_not_judged():
    base = [_base("/w/busy.txt", "h4")]
    changes = compare(base, [_cur("/w/busy.txt", "h4", unstable=True)])
    assert [c.change_type for c in changes] == ["unreadable"]