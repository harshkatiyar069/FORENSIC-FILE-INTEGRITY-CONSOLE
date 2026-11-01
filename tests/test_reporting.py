import json

import pytest

from fim import database
from fim.baseline import create_initial_baseline
from fim.reporting import ReportError, build_report_data, generate_reports
from fim.scan_service import run_scan


def _setup_with_change(tmp_path):
    src = tmp_path / "watched"
    src.mkdir()
    # The ampersand tests that special characters survive every report format.
    (src / "R&D notes.txt").write_text("before")
    (src / "keep.txt").write_text("keep")
    db = tmp_path / "fim.db"
    create_initial_baseline(db, [src])
    (src / "R&D notes.txt").write_text("after")
    run_scan(db)
    return db, tmp_path / "reports"


def test_generates_csv_json_and_pdf(tmp_path):
    db, out = _setup_with_change(tmp_path)
    paths = generate_reports(db, out, ["csv", "json", "pdf"])

    assert len(paths) == 3
    assert all(p.exists() and p.stat().st_size > 0 for p in paths)

    csv_text = next(p for p in paths if p.suffix == ".csv").read_text(encoding="utf-8")
    assert "modified" in csv_text
    assert "R&D notes.txt" in csv_text

    json_file = next(p for p in paths if p.suffix == ".json")
    payload = json.loads(json_file.read_text(encoding="utf-8"))
    assert payload["summary"] == {"modified": 1}
    assert payload["changes"][0]["change_type"] == "modified"

    pdf_file = next(p for p in paths if p.suffix == ".pdf")
    assert pdf_file.read_bytes()[:4] == b"%PDF"


def test_no_scans_raises(tmp_path):
    with pytest.raises(ReportError):
        build_report_data(tmp_path / "empty.db")


def test_unknown_scan_id_raises(tmp_path):
    db, _ = _setup_with_change(tmp_path)
    with pytest.raises(ReportError):
        build_report_data(db, scan_id=999)


def test_unknown_format_is_rejected(tmp_path):
    db, out = _setup_with_change(tmp_path)
    with pytest.raises(ReportError):
        generate_reports(db, out, ["xml"])


def test_report_generation_is_logged(tmp_path):
    db, out = _setup_with_change(tmp_path)
    generate_reports(db, out, ["csv"])

    conn = database.connect(db)
    try:
        events = database.load_security_events(conn)
    finally:
        conn.close()
    assert events[-1]["event_type"] == "report_generated" 