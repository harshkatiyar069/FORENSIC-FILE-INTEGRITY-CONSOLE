"""Compares the trusted baseline with a current scan and classifies differences.

Change types:
  new        file exists now but was not in the baseline
  deleted    file was in the baseline and no longer exists
  modified   file exists in both, and its content hash differs
  metadata   content is identical but the modification time differs
  renamed    a deleted file and a new file are the same file under a new name
  unreadable file could not be hashed reliably, so it cannot be judged
"""
from __future__ import annotations

import os
from collections import defaultdict
from dataclasses import dataclass

from .scanner import FileRecord


@dataclass(frozen=True)
class Change:
    change_type: str
    path: str
    old_path: str | None = None
    old_sha256: str | None = None
    new_sha256: str | None = None
    detail: str | None = None

    def as_row(self) -> tuple:
        return (
            self.change_type,
            self.path,
            self.old_path,
            self.old_sha256,
            self.new_sha256,
            self.detail,
        )


def file_identity(path: str) -> str | None:
    """Current device:inode pair for a file, or None if unavailable."""
    try:
        st = os.stat(path)
    except OSError:
        return None
    return f"{st.st_dev}:{st.st_ino}"


def _usable(file_id: str | None) -> str | None:
    """Some Windows filesystems report inode 0, which cannot identify a file."""
    if not file_id or file_id.endswith(":0"):
        return None
    return file_id


def _match_renames(
    deleted: list[str],
    new_paths: list[str],
    base: dict[str, dict],
    cur: dict[str, FileRecord],
) -> list[tuple[str, str, str]]:
    """Return (old_path, new_path, reason) for each detected rename."""
    matches: list[tuple[str, str, str]] = []
    used_old: set[str] = set()
    used_new: set[str] = set()

    # Pass 1: same file identity AND same content. Most reliable.
    new_by_key: dict[tuple[str, str], list[str]] = defaultdict(list)
    for new in new_paths:
        fid = _usable(file_identity(new))
        if fid:
            new_by_key[(fid, cur[new].sha256)].append(new)

    for old in deleted:
        fid = _usable(base[old].get("file_id"))
        if not fid:
            continue
        candidates = [n for n in new_by_key.get((fid, base[old]["sha256"]), [])
                      if n not in used_new]
        if len(candidates) == 1:
            matches.append((old, candidates[0], "same file identity"))
            used_old.add(old)
            used_new.add(candidates[0])

    # Pass 2: same content, but only when the match is unambiguous.
    # Several files with identical content (for example empty files)
    # produce no rename, which avoids guessing wrongly.
    deleted_by_hash: dict[str, list[str]] = defaultdict(list)
    for old in deleted:
        if old not in used_old:
            deleted_by_hash[base[old]["sha256"]].append(old)

    new_by_hash: dict[str, list[str]] = defaultdict(list)
    for new in new_paths:
        if new not in used_new:
            new_by_hash[cur[new].sha256].append(new)

    for digest, olds in deleted_by_hash.items():
        news = new_by_hash.get(digest, [])
        if len(olds) == 1 and len(news) == 1:
            matches.append((olds[0], news[0], "same content, unique match"))

    return matches


def compare(baseline_files: list[dict], current: list[FileRecord]) -> list[Change]:
    """Classify every difference between the baseline and the current scan."""
    base = {f["path"]: f for f in baseline_files}

    unreadable: dict[str, str] = {}
    cur: dict[str, FileRecord] = {}
    for rec in current:
        if rec.error or rec.unstable or rec.sha256 is None:
            unreadable[rec.path] = rec.error or "file changed while being hashed"
        else:
            cur[rec.path] = rec

    changes: list[Change] = []
    deleted_paths: list[str] = []

    for path, old in base.items():
        if path in unreadable:
            changes.append(Change("unreadable", path, old_sha256=old["sha256"],
                                  detail=unreadable[path]))
        elif path in cur:
            new = cur[path]
            if new.sha256 != old["sha256"]:
                changes.append(Change("modified", path,
                                      old_sha256=old["sha256"],
                                      new_sha256=new.sha256))
            elif new.mtime_ns != old["mtime_ns"]:
                changes.append(Change("metadata", path,
                                      old_sha256=old["sha256"],
                                      new_sha256=new.sha256,
                                      detail="modification time changed, content identical"))
        else:
            deleted_paths.append(path)

    new_paths = [p for p in cur if p not in base]
    for path, reason in unreadable.items():
        if path not in base:
            changes.append(Change("unreadable", path, detail=reason))

    deleted_paths.sort()
    new_paths.sort()

    renames = _match_renames(deleted_paths, new_paths, base, cur)
    renamed_old = {old for old, _, _ in renames}
    renamed_new = {new for _, new, _ in renames}

    for old, new, reason in renames:
        changes.append(Change("renamed", new,
                              old_path=old,
                              old_sha256=base[old]["sha256"],
                              new_sha256=cur[new].sha256,
                              detail=reason))

    for path in deleted_paths:
        if path not in renamed_old:
            changes.append(Change("deleted", path, old_sha256=base[path]["sha256"]))

    for path in new_paths:
        if path not in renamed_new:
            changes.append(Change("new", path, new_sha256=cur[path].sha256))

    return changes