"""Runs a scan against the latest baseline and stores the results.

A scan never changes the baseline. It only records what it found.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from . import database
from .comparator import compare
from .config import DEFAULT_SETTINGS, Settings
from .scanner import FileRecord, scan_directory
from .security_log import log_event


class NoBaselineError(RuntimeError):
    """No usable baseline exists yet."""


@dataclass
class ScanSummary:
    scan_id: int
    baseline_id: int
    files_seen: int
    skipped: int
    changes: list[dict] = field(default_factory=list)

    def count(self, change_type: str) -> int:
        return sum(1 for c in self.changes if c["change_type"] == change_type)


def run_scan(
    db_path: Path = DEFAULT_SETTINGS.db_path,
    settings: Settings = DEFAULT_SETTINGS,
) -> ScanSummary:
    conn = database.connect(db_path)
    try:
        baseline_id = database.latest_baseline_id(conn)
        if baseline_id is None:
            raise NoBaselineError("No baseline found. Run: python -m app.main init <folder>")

        roots = database.load_baseline_roots(conn, baseline_id)
        if not roots:
            raise NoBaselineError(
                "This baseline has no recorded folders. Recreate it with init."
            )

        baseline_files = database.load_baseline_files(conn, baseline_id)
        scan_id = database.create_scan(conn, baseline_id)
        # Logged before scanning starts. If the program crashes mid-scan, the log
        # shows a scan_started with no matching scan_completed.
        log_event(conn, "scan_started", {
            "scan_id": scan_id,
            "baseline_id": baseline_id,
            "roots": roots,
        })
        conn.commit()

        skipped = 0
        by_path: dict[str, FileRecord] = {}
        try:
            for root in roots:
                result = scan_directory(
                    root,
                    exclude_patterns=settings.exclude_patterns,
                    chunk_size=settings.chunk_size,
                )
                skipped += len(result.skipped)
                for rec in result.records:
                    by_path.setdefault(rec.path, rec)  # overlapping roots

            changes = compare(baseline_files, list(by_path.values()))
            database.insert_changes(conn, scan_id, [c.as_row() for c in changes])
            database.finish_scan(conn, scan_id, len(by_path), "complete")

            for change in changes:
                log_event(conn, "change_detected", {
                    "scan_id": scan_id,
                    "change_type": change.change_type,
                    "path": change.path,
                    "old_path": change.old_path,
                    "old_sha256": change.old_sha256,
                    "new_sha256": change.new_sha256,
                })
            log_event(conn, "scan_completed", {
                "scan_id": scan_id,
                "files_seen": len(by_path),
                "skipped": skipped,
                "changes": len(changes),
            })
            conn.commit()
        except Exception as exc:
            conn.rollback()
            database.finish_scan(conn, scan_id, 0, "failed")
            log_event(conn, "scan_failed", {"scan_id": scan_id, "error": str(exc)})
            conn.commit()
            raise

        return ScanSummary(
            scan_id=scan_id,
            baseline_id=baseline_id,
            files_seen=len(by_path),
            skipped=skipped,
            changes=database.load_changes(conn, scan_id),
        )
    finally:
        conn.close()