"""Creates the trusted baseline. Refuses to overwrite an existing one."""
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


class BaselineExistsError(RuntimeError):
    """A baseline is already in place. Replacing it needs explicit authorization."""


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
    """Device and inode pair, used later to recognize renamed files."""
    try:
        st = os.stat(path)
    except OSError:
        return None
    return f"{st.st_dev}:{st.st_ino}"


def create_initial_baseline(
    db_path: Path,
    roots: list[Path],
    settings: Settings = DEFAULT_SETTINGS,
    created_by: str | None = None,
    note: str | None = None,
) -> BaselineSummary:
    normalized_roots = [str(normalize_root(root)) for root in roots]
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
                "A baseline already exists. Replacing it requires explicit "
                "authorization, which is added in a later stage."
            )

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
                    reason = rec.error or "file changed while being hashed"
                    failed.append((rec.path, reason))
                    continue
                rows.append(
                    (rec.path, rec.sha256, rec.size_bytes, rec.mtime_ns,
                     _file_identity(rec.path))
                )

        with conn:  # one transaction: the baseline and its log entry are saved together
            baseline_id = database.create_baseline(conn, user, note)
            database.insert_baseline_roots(conn, baseline_id, normalized_roots)
            database.insert_baseline_files(conn, baseline_id, rows)
            log_event(conn, "baseline_created", {
                "baseline_id": baseline_id,
                "roots": normalized_roots,
                "files_recorded": len(rows),
                "files_failed": len(failed),
                "created_by": user,
            })

        return BaselineSummary(
            baseline_id=baseline_id,
            files_recorded=len(rows),
            files_skipped=skipped,
            files_failed=failed,
        )
    finally:
        conn.close()