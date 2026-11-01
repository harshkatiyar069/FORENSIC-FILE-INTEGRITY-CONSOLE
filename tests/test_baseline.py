from fim import database
from fim.baseline import BaselineExistsError, create_initial_baseline
from fim.hasher import hash_file


def test_baseline_records_every_file(tmp_path):
    src = tmp_path / "watched"
    (src / "sub").mkdir(parents=True)
    (src / "a.txt").write_text("a")
    (src / "sub" / "b.txt").write_text("b")

    summary = create_initial_baseline(tmp_path / "fim.db", [src])

    assert summary.files_recorded == 2
    assert summary.files_failed == []


def test_baseline_stores_correct_hashes(tmp_path):
    src = tmp_path / "watched"
    src.mkdir()
    target = src / "data.txt"
    target.write_bytes(b"abc")
    db = tmp_path / "fim.db"

    create_initial_baseline(db, [src])

    conn = database.connect(db)
    try:
        files = database.load_baseline_files(conn, database.latest_baseline_id(conn))
    finally:
        conn.close()
    assert len(files) == 1
    assert files[0]["sha256"] == hash_file(target)
    assert files[0]["size_bytes"] == 3


def test_second_baseline_is_refused(tmp_path):
    src = tmp_path / "watched"
    src.mkdir()
    (src / "a.txt").write_text("a")
    db = tmp_path / "fim.db"

    create_initial_baseline(db, [src])
    try:
        create_initial_baseline(db, [src])
        assert False, "expected BaselineExistsError"
    except BaselineExistsError:
        pass


def test_overlapping_roots_do_not_duplicate_files(tmp_path):
    src = tmp_path / "watched"
    (src / "sub").mkdir(parents=True)
    (src / "sub" / "b.txt").write_text("b")

    summary = create_initial_baseline(tmp_path / "fim.db", [src, src / "sub"])

    assert summary.files_recorded == 1


def test_baseline_persists_after_reopening(tmp_path):
    src = tmp_path / "watched"
    src.mkdir()
    (src / "a.txt").write_text("a")
    db = tmp_path / "fim.db"

    summary = create_initial_baseline(db, [src])

    conn = database.connect(db)
    try:
        assert database.latest_baseline_id(conn) == summary.baseline_id
    finally:
        conn.close()