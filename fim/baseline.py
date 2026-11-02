"""Trusted baseline creation, and authorized replacement of an existing baseline."""
from __future__ import annotations

import getpass
import os
from dataclasses import dataclass, field
from pathlib import Path

from . import database
from .config import DEFAULT_SETTINGS, Settings
from .paths import normalize_root
from .scanner import scan_directory
from .security_log import log_event

# The user must type this exact phrase. It records intent and gives the audit trail
# a clear authorization step. It is not strong authentication: anyone who can run
# the program can type it.
BASELINE_UPDATE_PHRASE = "I AUTHORIZE BASELINE UPDATE"


class BaselineExistsError(RuntimeError):
    """A baseline is already in place. Replacing it needs explicit authorization."""


class UnauthorizedBaselineUpdate(RuntimeError):
    """A baseline update was attempted without the correct authorization phrase."""


@dataclass
class BaselineSummary:
    baseline_id: int
    files_recorded: int
    files_skipped: int
    files_failed: list[tuple[str, str]] = field(default_factory=list)


def _current_user() -> str:
    try:
        return getpass.getuser()
    except Exception:
        return "unknown"


def _file_identity(path: str) -> str | None:
    try:
        st = os.stat(path)
    except OSError:
        return None
    return f"{st.st_dev}:{st.st_ino}"


def _scan_roots(roots: list[Path], settings: Settings):
    normalized = [str(normalize_root(root)) for root in roots]
    rows: list[tuple] = []
    failed: list[tuple[str, str]] = []
    seen: set[str] = set()
    skipped = 0
    for root in roots:
        result = scan_directory(
            root,
            exclude_patterns=settings.exclude_patterns,
            chunk_size=settings.chunk_size,
        )
        skipped += len(result.skipped)
        for rec in result.records:
            if rec.path in seen:  # overlapping roots would list a file twice
                continue
            seen.add(rec.path)
            if rec.error or rec.unstable or rec.sha256 is None:
                failed.append((rec.path, rec.error or "file changed while being hashed"))
                continue
            rows.append(
                (rec.path, rec.sha256, rec.size_bytes, rec.mtime_ns, _file_identity(rec.path))
            )
    return normalized, rows, failed, skipped


def _store_baseline(conn, user, note, normalized, rows, failed, event_type, extra) -> int:
    with conn:  # the baseline and its log entry are saved together
        baseline_id = database.create_baseline(conn, user, note)
        database.insert_baseline_roots(conn, baseline_id, normalized)
        database.insert_baseline_files(conn, baseline_id, rows)
        log_event(conn, event_type, {
            "baseline_id": baseline_id,
            "roots": normalized,
            "files_recorded": len(rows),
            "files_failed": len(failed),
            "created_by": user,
            **extra,
        })
    return baseline_id


def create_initial_baseline(
    db_path: Path,
    roots: list[Path],
    settings: Settings = DEFAULT_SETTINGS,
    created_by: str | None = None,
    note: str | None = None,
) -> BaselineSummary:
    user = created_by or _current_user()
    conn = database.connect(db_path)
    try:
        if database.latest_baseline_id(conn) is not None:
            log_event(conn, "baseline_refused", {
                "reason": "a baseline already exists",
                "requested_by": user,
            })
            conn.commit()
            raise BaselineExistsError(
                "A baseline already exists. To replace it, run: "
                f'python -m app.main update-baseline --confirm "{BASELINE_UPDATE_PHRASE}"'
            )
        normalized, rows, failed, skipped = _scan_roots(roots, settings)
        baseline_id = _store_baseline(
            conn, user, note, normalized, rows, failed, "baseline_created", {}
        )
        return BaselineSummary(baseline_id, len(rows), skipped, failed)
    finally:
        conn.close()


def replace_baseline(
    db_path: Path,
    confirmation: str | None,
    settings: Settings = DEFAULT_SETTINGS,
    created_by: str | None = None,
    note: str | None = None,
) -> BaselineSummary:
    """Replace the active baseline. Requires the exact authorization phrase.

    Old baselines are kept, so the history of trusted states is preserved.
    """
    user = created_by or _current_user()
    conn = database.connect(db_path)
    try:
        previous_id = database.latest_baseline_id(conn)
        if previous_id is None:
            raise RuntimeError("No baseline exists yet. Create one first with: python -m app.main init <folder>")

        if confirmation != BASELINE_UPDATE_PHRASE:
            log_event(conn, "baseline_update_refused", {
                "reason": "authorization phrase missing or incorrect",
                "requested_by": user,
                "previous_baseline_id": previous_id,
            })
            conn.commit()
            raise UnauthorizedBaselineUpdate(
                "Baseline update not authorized. Type the exact phrase after --confirm."
            )

        roots = [Path(p) for p in database.load_baseline_roots(conn, previous_id)]
        if not roots:
            raise RuntimeError("The current baseline has no recorded folders. Recreate it with init.")

        normalized, rows, failed, skipped = _scan_roots(roots, settings)
        baseline_id = _store_baseline(
            conn, user, note, normalized, rows, failed, "baseline_updated",
            {"previous_baseline_id": previous_id, "authorized_by": user},
        )
        return BaselineSummary(baseline_id, len(rows), skipped, failed)
    finally:
        conn.close()
