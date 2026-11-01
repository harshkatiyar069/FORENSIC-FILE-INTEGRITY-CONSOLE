"""SQLite access. All SQL for the project lives in this file."""
from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS baselines (
    id          INTEGER PRIMARY KEY,
    created_at  TEXT NOT NULL,
    created_by  TEXT NOT NULL,
    note        TEXT
);

CREATE TABLE IF NOT EXISTS baseline_roots (
    id           INTEGER PRIMARY KEY,
    baseline_id  INTEGER NOT NULL REFERENCES baselines(id) ON DELETE CASCADE,
    root_path    TEXT NOT NULL,
    UNIQUE (baseline_id, root_path)
);

CREATE TABLE IF NOT EXISTS baseline_files (
    id           INTEGER PRIMARY KEY,
    baseline_id  INTEGER NOT NULL REFERENCES baselines(id) ON DELETE CASCADE,
    path         TEXT NOT NULL,
    sha256       TEXT NOT NULL,
    size_bytes   INTEGER NOT NULL,
    mtime_ns     INTEGER NOT NULL,
    file_id      TEXT,
    UNIQUE (baseline_id, path)
);

CREATE TABLE IF NOT EXISTS scans (
    id           INTEGER PRIMARY KEY,
    started_at   TEXT NOT NULL,
    finished_at  TEXT,
    baseline_id  INTEGER NOT NULL REFERENCES baselines(id),
    files_seen   INTEGER NOT NULL DEFAULT 0,
    status       TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS changes (
    id           INTEGER PRIMARY KEY,
    scan_id      INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    change_type  TEXT NOT NULL,
    path         TEXT NOT NULL,
    old_path     TEXT,
    old_sha256   TEXT,
    new_sha256   TEXT,
    detail       TEXT
);

CREATE TABLE IF NOT EXISTS security_events (
    id          INTEGER PRIMARY KEY,
    created_at  TEXT NOT NULL,
    event_type  TEXT NOT NULL,
    details     TEXT NOT NULL,
    prev_hash   TEXT NOT NULL,
    entry_hash  TEXT NOT NULL
);

CREATE TRIGGER IF NOT EXISTS security_events_no_update
BEFORE UPDATE ON security_events
BEGIN
    SELECT RAISE(ABORT, 'security_events is append-only');
END;

CREATE TRIGGER IF NOT EXISTS security_events_no_delete
BEFORE DELETE ON security_events
BEGIN
    SELECT RAISE(ABORT, 'security_events is append-only');
END;
"""


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def connect(db_path: Path) -> sqlite3.Connection:
    """Open the database, creating the folder and tables if needed."""
    db_path = Path(db_path)
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA foreign_keys = ON")
    conn.executescript(SCHEMA)
    conn.commit()
    return conn


def latest_baseline_id(conn: sqlite3.Connection) -> int | None:
    row = conn.execute("SELECT id FROM baselines ORDER BY id DESC LIMIT 1").fetchone()
    return row[0] if row else None


def create_baseline(conn: sqlite3.Connection, created_by: str, note: str | None) -> int:
    cur = conn.execute(
        "INSERT INTO baselines (created_at, created_by, note) VALUES (?, ?, ?)",
        (utc_now(), created_by, note),
    )
    return int(cur.lastrowid)


def insert_baseline_roots(conn: sqlite3.Connection, baseline_id: int, roots: list[str]) -> None:
    conn.executemany(
        "INSERT INTO baseline_roots (baseline_id, root_path) VALUES (?, ?)",
        [(baseline_id, root) for root in roots],
    )


def load_baseline_roots(conn: sqlite3.Connection, baseline_id: int) -> list[str]:
    cur = conn.execute(
        "SELECT root_path FROM baseline_roots WHERE baseline_id = ? ORDER BY root_path",
        (baseline_id,),
    )
    return [row[0] for row in cur.fetchall()]


def insert_baseline_files(
    conn: sqlite3.Connection, baseline_id: int, rows: list[tuple]
) -> None:
    """rows: (path, sha256, size_bytes, mtime_ns, file_id) tuples."""
    conn.executemany(
        "INSERT INTO baseline_files "
        "(baseline_id, path, sha256, size_bytes, mtime_ns, file_id) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        [(baseline_id, *row) for row in rows],
    )


def load_baseline_files(conn: sqlite3.Connection, baseline_id: int) -> list[dict]:
    cur = conn.execute(
        "SELECT path, sha256, size_bytes, mtime_ns, file_id "
        "FROM baseline_files WHERE baseline_id = ? ORDER BY path",
        (baseline_id,),
    )
    return [
        {"path": p, "sha256": h, "size_bytes": s, "mtime_ns": m, "file_id": f}
        for p, h, s, m, f in cur.fetchall()
    ]


def create_scan(conn: sqlite3.Connection, baseline_id: int) -> int:
    cur = conn.execute(
        "INSERT INTO scans (started_at, baseline_id, status) VALUES (?, ?, 'running')",
        (utc_now(), baseline_id),
    )
    return int(cur.lastrowid)


def finish_scan(conn: sqlite3.Connection, scan_id: int, files_seen: int, status: str) -> None:
    conn.execute(
        "UPDATE scans SET finished_at = ?, files_seen = ?, status = ? WHERE id = ?",
        (utc_now(), files_seen, status, scan_id),
    )


def insert_changes(conn: sqlite3.Connection, scan_id: int, rows: list[tuple]) -> None:
    """rows: (change_type, path, old_path, old_sha256, new_sha256, detail) tuples."""
    conn.executemany(
        "INSERT INTO changes "
        "(scan_id, change_type, path, old_path, old_sha256, new_sha256, detail) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        [(scan_id, *row) for row in rows],
    )


def load_changes(conn: sqlite3.Connection, scan_id: int) -> list[dict]:
    cur = conn.execute(
        "SELECT change_type, path, old_path, old_sha256, new_sha256, detail "
        "FROM changes WHERE scan_id = ? ORDER BY id",
        (scan_id,),
    )
    keys = ("change_type", "path", "old_path", "old_sha256", "new_sha256", "detail")
    return [dict(zip(keys, row)) for row in cur.fetchall()]


def last_event_hash(conn: sqlite3.Connection) -> str | None:
    row = conn.execute(
        "SELECT entry_hash FROM security_events ORDER BY id DESC LIMIT 1"
    ).fetchone()
    return row[0] if row else None


def insert_security_event(
    conn: sqlite3.Connection,
    created_at: str,
    event_type: str,
    details: str,
    prev_hash: str,
    entry_hash: str,
) -> int:
    cur = conn.execute(
        "INSERT INTO security_events "
        "(created_at, event_type, details, prev_hash, entry_hash) "
        "VALUES (?, ?, ?, ?, ?)",
        (created_at, event_type, details, prev_hash, entry_hash),
    )
    return int(cur.lastrowid)


def load_security_events(
    conn: sqlite3.Connection,
    event_type: str | None = None,
    contains: str | None = None,
    limit: int | None = None,
    newest_first: bool = False,
) -> list[dict]:
    clauses: list[str] = []
    params: list = []
    if event_type:
        clauses.append("event_type = ?")
        params.append(event_type)
    if contains:
        clauses.append("details LIKE ?")
        params.append(f"%{contains}%")

    sql = "SELECT id, created_at, event_type, details, prev_hash, entry_hash FROM security_events"
    if clauses:
        sql += " WHERE " + " AND ".join(clauses)
    sql += " ORDER BY id DESC" if newest_first else " ORDER BY id ASC"
    if limit is not None:
        sql += " LIMIT ?"
        params.append(limit)

    keys = ("id", "created_at", "event_type", "details", "prev_hash", "entry_hash")
    cur = conn.execute(sql, params)
    return [dict(zip(keys, row)) for row in cur.fetchall()]