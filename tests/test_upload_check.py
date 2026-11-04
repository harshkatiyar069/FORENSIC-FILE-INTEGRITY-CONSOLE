import hashlib

from fim import database
from fim.baseline import create_initial_baseline
from fim.upload_check import check_upload, record_upload_check, scan_pdf_structure

CLEAN_PDF = b"%PDF-1.4\n1 0 obj << /Type /Catalog >> endobj\n%%EOF\n"
RISKY_PDF = (
    b"%PDF-1.4\n"
    b"1 0 obj << /Type /Catalog /OpenAction 2 0 R >> endobj\n"
    b"2 0 obj << /S /JavaScript /JS (app.alert(1)) >> endobj\n"
    b"%%EOF\n"
)


def _baseline(tmp_path, files):
    src = tmp_path / "watched"
    src.mkdir()
    for name, data in files.items():
        (src / name).write_bytes(data)
    db = tmp_path / "fim.db"
    create_initial_baseline(db, [src])
    return db


def _event_count(db):
    conn = database.connect(db)
    try:
        return len(database.load_security_events(conn))
    finally:
        conn.close()


def test_sha256_matches_hashlib(tmp_path):
    db = _baseline(tmp_path, {"a.txt": b"x"})
    result = check_upload(db, "upload.pdf", CLEAN_PDF)
    assert result.sha256 == hashlib.sha256(CLEAN_PDF).hexdigest()


def test_clean_pdf_structure_has_no_findings():
    assert scan_pdf_structure(CLEAN_PDF) == []


def test_risky_pdf_is_flagged_as_high_severity():
    findings = scan_pdf_structure(RISKY_PDF)
    details = {f.detail for f in findings}
    assert "contains JavaScript" in details
    assert "runs an action automatically" in details
    assert any(f.severity == "high" for f in findings)


def test_non_pdf_is_detected(tmp_path):
    db = _baseline(tmp_path, {"a.txt": b"x"})
    result = check_upload(db, "photo.pdf", b"hello, not a pdf")
    assert result.looks_like_pdf is False
    assert result.severity == "warning"


def test_identical_file_matches_baseline(tmp_path):
    db = _baseline(tmp_path, {"report.pdf": CLEAN_PDF})
    result = check_upload(db, "anything.pdf", CLEAN_PDF)
    assert len(result.baseline_matches) == 1
    assert result.severity == "ok"


def test_same_name_different_content_is_flagged(tmp_path):
    db = _baseline(tmp_path, {"report.pdf": CLEAN_PDF})
    result = check_upload(db, "report.pdf", RISKY_PDF)
    assert result.baseline_matches == []
    assert len(result.name_matches) == 1
    assert result.severity == "warning"


def test_expected_hash_mismatch_is_an_error(tmp_path):
    db = _baseline(tmp_path, {"a.txt": b"x"})
    result = check_upload(db, "upload.pdf", CLEAN_PDF, expected_sha256="0" * 64)
    assert result.expected_match is False
    assert result.severity == "error"


def test_check_writes_nothing_to_the_audit_trail(tmp_path):
    db = _baseline(tmp_path, {"a.txt": b"x"})
    before = _event_count(db)
    check_upload(db, "upload.pdf", RISKY_PDF)
    assert _event_count(db) == before


def test_recording_adds_one_audit_event(tmp_path):
    db = _baseline(tmp_path, {"a.txt": b"x"})
    before = _event_count(db)
    result = check_upload(db, "upload.pdf", RISKY_PDF)
    record_upload_check(db, result)

    conn = database.connect(db)
    try:
        last = database.load_security_events(conn)[-1]
    finally:
        conn.close()
    assert _event_count(db) == before + 1
    assert last["event_type"] == "upload_checked"
    assert result.sha256 in last["details"]
