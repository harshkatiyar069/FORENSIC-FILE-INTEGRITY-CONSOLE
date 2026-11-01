"""Tamper-evident security event log.

Each event stores a SHA-256 hash of its own contents plus the hash of the
previous event. Changing or removing an event breaks the chain from that
point onward, and verify_chain() reports where.

Limitation: the chain detects tampering; it cannot prevent it. Someone with
full administrator rights on this computer can rebuild the whole chain.
"""
from __future__ import annotations

import csv
import hashlib
import json
from dataclasses import dataclass
from pathlib import Path

from . import database

GENESIS_HASH = "0" * 64  # the "previous hash" of the very first event
EXPORT_FIELDS = ("id", "created_at", "event_type", "details", "prev_hash", "entry_hash")


def _entry_hash(created_at: str, event_type: str, details_json: str, prev_hash: str) -> str:
    payload = json.dumps(
        [created_at, event_type, details_json, prev_hash], separators=(",", ":")
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def log_event(conn, event_type: str, details: dict | None = None) -> int:
    """Append an event. The caller commits, so the event is saved with the work it records."""
    created_at = database.utc_now()
    details_json = json.dumps(details or {}, sort_keys=True, separators=(",", ":"))
    prev_hash = database.last_event_hash(conn) or GENESIS_HASH
    entry_hash = _entry_hash(created_at, event_type, details_json, prev_hash)
    return database.insert_security_event(
        conn, created_at, event_type, details_json, prev_hash, entry_hash
    )


@dataclass(frozen=True)
class ChainReport:
    valid: bool
    events_checked: int
    broken_at_id: int | None = None
    reason: str | None = None


def verify_chain(conn) -> ChainReport:
    """Recompute every hash in order and report the first place the chain fails."""
    expected_prev = GENESIS_HASH
    checked = 0
    for event in database.load_security_events(conn):
        checked += 1
        if event["prev_hash"] != expected_prev:
            return ChainReport(
                False, checked, event["id"],
                "link to the previous event is broken (an earlier event was changed or removed)",
            )
        recomputed = _entry_hash(
            event["created_at"], event["event_type"], event["details"], event["prev_hash"]
        )
        if recomputed != event["entry_hash"]:
            return ChainReport(
                False, checked, event["id"],
                "event contents do not match their stored hash (this event was edited)",
            )
        expected_prev = event["entry_hash"]
    return ChainReport(True, checked)


def export_events(events: list[dict], path: Path) -> int:
    """Write events to a .csv or .json file. Returns the number of events written."""
    path = Path(path)
    suffix = path.suffix.lower()
    if suffix not in (".csv", ".json"):
        raise ValueError("Export file must end in .csv or .json")
    path.parent.mkdir(parents=True, exist_ok=True)

    if suffix == ".json":
        path.write_text(json.dumps(events, indent=2), encoding="utf-8")
    else:
        with path.open("w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=EXPORT_FIELDS)
            writer.writeheader()
            for event in events:
                writer.writerow({key: event[key] for key in EXPORT_FIELDS})
    return len(events)