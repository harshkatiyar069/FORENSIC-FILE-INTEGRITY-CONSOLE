"""End-to-end demonstration of the platform in a separate folder.

It never touches the project's own data or reports folders.
"""
from __future__ import annotations

import os
import sqlite3
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from . import database
from .baseline import create_initial_baseline
from .config import Settings
from .reporting import generate_reports
from .scan_service import run_scan
from .security_log import verify_chain


@dataclass
class DemoResult:
    clean_scan_changes: int = 0
    changes: dict[str, int] = field(default_factory=dict)
    reports: list[Path] = field(default_factory=list)
    log_valid_before_attack: bool = False
    tamper_detected: bool = False


def _count(changes: list[dict]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for change in changes:
        kind = change["change_type"]
        counts[kind] = counts.get(kind, 0) + 1
    return counts


def run_demo(work_dir: Path, say: Callable[[str], None] = print) -> DemoResult:
    work_dir = Path(work_dir)
    watched = work_dir / "watched"
    report_dir = work_dir / "reports"
    db = work_dir / "data" / "fim.db"
    settings = Settings(db_path=db, report_dir=report_dir)
    result = DemoResult()

    say(f"Demo folder: {work_dir}")

    say("\n1. Creating sample files")
    (watched / "sub").mkdir(parents=True, exist_ok=True)
    (watched / "a.txt").write_text("alpha\n")
    (watched / "b.txt").write_text("bravo\n")
    (watched / "empty.txt").write_bytes(b"")
    (watched / "dup1.txt").write_text("same content\n")
    (watched / "dup2.txt").write_text("same content\n")
    (watched / "sub" / "c.txt").write_text("charlie\n")
    (watched / "large.bin").write_bytes(os.urandom(5 * 1024 * 1024))
    say("   Created files, including an empty file, two identical files, and a 5 MB file.")

    say("\n2. Creating the trusted baseline")
    summary = create_initial_baseline(db, [watched], settings=settings, note="demo")
    say(f"   Baseline #{summary.baseline_id} recorded {summary.files_recorded} files.")

    say("\n3. Scanning with nothing changed")
    clean = run_scan(db, settings)
    result.clean_scan_changes = len(clean.changes)
    say(f"   Changes found: {result.clean_scan_changes}")

    say("\n4. Changing files: edit a.txt, delete b.txt, add d.txt, rename sub/c.txt")
    (watched / "a.txt").write_text("alpha, edited\n")
    (watched / "b.txt").unlink()
    (watched / "d.txt").write_text("delta\n")
    (watched / "sub" / "c.txt").rename(watched / "sub" / "c-renamed.txt")

    say("\n5. Scanning again")
    scan = run_scan(db, settings)
    result.changes = _count(scan.changes)
    for change in scan.changes:
        if change["change_type"] == "renamed":
            say(f"   [RENAMED]  {change['old_path']} -> {change['path']}")
        else:
            say(f"   [{change['change_type'].upper()}]  {change['path']}")

    say("\n6. Writing CSV, JSON, and PDF reports")
    result.reports = generate_reports(db, report_dir, ["csv", "json", "pdf"], scan_id=scan.scan_id)
    for path in result.reports:
        say(f"   {path}")

    say("\n7. Checking the security log")
    conn = database.connect(db)
    try:
        before = verify_chain(conn)
    finally:
        conn.close()
    result.log_valid_before_attack = before.valid
    say(f"   Log integrity: {'OK' if before.valid else 'FAILED'} ({before.events_checked} events)")

    say("\n8. Simulating an attacker who edits the log directly")
    raw = sqlite3.connect(db)
    try:
        raw.execute("DROP TRIGGER security_events_no_update")
        raw.execute("UPDATE security_events SET details = '{}' WHERE id = 1")
        raw.commit()
    finally:
        raw.close()
    say("   Event #1 was rewritten and the append-only protection was bypassed.")

    say("\n9. Checking the security log again")
    conn = database.connect(db)
    try:
        after = verify_chain(conn)
    finally:
        conn.close()
    result.tamper_detected = not after.valid
    if after.valid:
        say("   Log integrity: OK (the edit was NOT detected)")
    else:
        say(f"   Log integrity: FAILED at event #{after.broken_at_id}")
        say(f"   Reason: {after.reason}")
    return result
