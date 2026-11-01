"""Report generation: CSV, JSON, and PDF files for a single scan."""
from __future__ import annotations

import csv
import json
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from xml.sax.saxutils import escape

from . import database
from .security_log import log_event

CSV_FIELDS = ("change_type", "path", "old_path", "old_sha256", "new_sha256", "detail")
SUMMARY_TYPES = ("modified", "new", "deleted", "renamed", "metadata", "unreadable")
FORMATS = ("csv", "json", "pdf")


class ReportError(RuntimeError):
    """A report could not be produced."""


@dataclass
class ReportData:
    scan: dict
    changes: list[dict]
    generated_at: str
    counts: dict[str, int] = field(default_factory=dict)


def build_report_data(db_path: Path, scan_id: int | None = None) -> ReportData:
    """Collect one scan and its changes. Uses the latest scan if no id is given."""
    conn = database.connect(db_path)
    try:
        if scan_id is None:
            scan = database.load_latest_scan(conn)
            if scan is None:
                raise ReportError("No scans have been run yet. Run: python -m app.main scan")
        else:
            scan = database.load_scan(conn, scan_id)
            if scan is None:
                raise ReportError(f"No scan with id {scan_id}.")
        changes = database.load_changes(conn, scan["id"])
    finally:
        conn.close()

    counts: dict[str, int] = {}
    for change in changes:
        kind = change["change_type"]
        counts[kind] = counts.get(kind, 0) + 1
    return ReportData(
        scan=scan,
        changes=changes,
        generated_at=database.utc_now(),
        counts=counts,
    )


def default_path(report_dir: Path, scan_id: int, fmt: str) -> Path:
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    return Path(report_dir) / f"fim-report-scan{scan_id}-{stamp}.{fmt}"


def write_csv(data: ReportData, path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=CSV_FIELDS)
        writer.writeheader()
        for change in data.changes:
            writer.writerow({key: change.get(key) for key in CSV_FIELDS})
    return path


def write_json(data: ReportData, path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "generated_at": data.generated_at,
        "scan": data.scan,
        "summary": data.counts,
        "changes": data.changes,
    }
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return path


def write_pdf(data: ReportData, path: Path) -> Path:
    try:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import A4, landscape
        from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
        from reportlab.platypus import (
            Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle,
        )
    except ImportError as exc:
        raise ReportError(
            "PDF reports need reportlab. Run: pip install -r requirements.txt"
        ) from exc

    def cell_text(value) -> str:
        # Escape text so file names containing & or < don't break the PDF layout.
        return escape(str(value)) if value else "-"

    styles = getSampleStyleSheet()
    small = ParagraphStyle("small", parent=styles["BodyText"], fontSize=7, leading=9)
    grid = TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
        ("GRID", (0, 0), (-1, -1), 0.25, colors.grey),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ])

    scan = data.scan
    story = [
        Paragraph("File Integrity Manager: Scan Report", styles["Title"]),
        Paragraph(
            f"Scan #{scan['id']} against baseline #{scan['baseline_id']}",
            styles["Normal"],
        ),
        Paragraph(
            f"Status: {cell_text(scan['status'])} | "
            f"Started: {cell_text(scan['started_at'])} | "
            f"Finished: {cell_text(scan['finished_at'])}",
            styles["Normal"],
        ),
        Paragraph(f"Report generated: {cell_text(data.generated_at)}", styles["Normal"]),
        Spacer(1, 12),
        Paragraph("Summary", styles["Heading2"]),
    ]

    summary_rows = [["Change type", "Count"]]
    summary_rows += [[kind.capitalize(), str(data.counts.get(kind, 0))] for kind in SUMMARY_TYPES]
    summary_table = Table(summary_rows, colWidths=[160, 80])
    summary_table.setStyle(grid)
    story += [summary_table, Spacer(1, 12), Paragraph("Changes", styles["Heading2"])]

    if not data.changes:
        story.append(Paragraph(
            "No changes detected in this scan. All files match the trusted baseline.",
            styles["Normal"],
        ))
    else:
        rows = [["Type", "File", "Previous SHA-256", "Current SHA-256"]]
        for change in data.changes:
            if change["change_type"] == "renamed":
                file_text = f"{change['old_path']} -> {change['path']}"
            else:
                file_text = change["path"]
            rows.append([
                Paragraph(cell_text(change["change_type"].upper()), small),
                Paragraph(cell_text(file_text), small),
                Paragraph(cell_text(change["old_sha256"]), small),
                Paragraph(cell_text(change["new_sha256"]), small),
            ])
        changes_table = Table(rows, colWidths=[80, 300, 200, 200], repeatRows=1)
        changes_table.setStyle(grid)
        story.append(changes_table)

    path.parent.mkdir(parents=True, exist_ok=True)
    doc = SimpleDocTemplate(
        str(path),
        pagesize=landscape(A4),
        leftMargin=30, rightMargin=30, topMargin=30, bottomMargin=30,
        title="File Integrity Manager scan report",
    )
    doc.build(story)
    return path


WRITERS = {"csv": write_csv, "json": write_json, "pdf": write_pdf}


def generate_reports(
    db_path: Path,
    report_dir: Path,
    formats: list[str],
    scan_id: int | None = None,
) -> list[Path]:
    """Write one report per format and record the action in the security log."""
    unknown = [fmt for fmt in formats if fmt not in FORMATS]
    if unknown:
        raise ReportError(
            f"Unknown format(s): {', '.join(unknown)}. Choose from csv, json, pdf."
        )

    data = build_report_data(db_path, scan_id)
    written = [
        WRITERS[fmt](data, default_path(Path(report_dir), data.scan["id"], fmt))
        for fmt in formats
    ]

    conn = database.connect(db_path)
    try:
        log_event(conn, "report_generated", {
            "scan_id": data.scan["id"],
            "formats": list(formats),
            "files": [p.name for p in written],
        })
        conn.commit()
    finally:
        conn.close()
    return written 