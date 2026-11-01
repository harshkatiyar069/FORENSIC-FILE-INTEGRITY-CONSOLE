"""Recursive file discovery with exclusions, link protection, and race detection."""
from __future__ import annotations

import fnmatch
import os
import stat
from dataclasses import dataclass, field
from pathlib import Path

from .hasher import DEFAULT_CHUNK_SIZE, hash_file_safe
from .paths import is_within_root, normalize_root

# Windows marks symbolic links, junctions, and similar reparse points with this flag.
FILE_ATTRIBUTE_REPARSE_POINT = 0x0400


@dataclass
class FileRecord:
    path: str                  # absolute path
    size_bytes: int
    mtime_ns: int
    sha256: str | None = None
    error: str | None = None   # set if the file could not be read
    unstable: bool = False     # True if the file changed while we were hashing it


@dataclass
class ScanResult:
    root: str
    records: list[FileRecord] = field(default_factory=list)
    skipped: list[tuple[str, str]] = field(default_factory=list)  # (path, reason)


def is_link_like(path: str) -> bool:
    """True for symlinks, Windows junctions, and other reparse points."""
    try:
        st = os.lstat(path)
    except OSError:
        return True  # if we cannot inspect it, treat it as unsafe
    if stat.S_ISLNK(st.st_mode):
        return True
    return bool(getattr(st, "st_file_attributes", 0) & FILE_ATTRIBUTE_REPARSE_POINT)


def matches_exclusion(name: str, rel_path: str, patterns: tuple[str, ...]) -> bool:
    """Match a pattern against the file or folder name, or its relative path."""
    return any(
        fnmatch.fnmatch(name, pattern) or fnmatch.fnmatch(rel_path, pattern)
        for pattern in patterns
    )


def _relative(full: str, root: Path) -> str:
    return os.path.relpath(full, root).replace(os.sep, "/")


def _build_record(path: str, before: os.stat_result, chunk_size: int, compute_hashes: bool) -> FileRecord:
    record = FileRecord(
        path=os.path.abspath(path),
        size_bytes=before.st_size,
        mtime_ns=before.st_mtime_ns,
    )
    if not compute_hashes:
        return record

    digest, error = hash_file_safe(path, chunk_size)
    record.sha256 = digest
    record.error = error

    # Race detection: if size or mtime changed during hashing, the hash may be mixed.
    try:
        after = os.lstat(path)
    except OSError:
        record.unstable = True  # file disappeared mid-scan
        return record
    if (after.st_size, after.st_mtime_ns) != (before.st_size, before.st_mtime_ns):
        record.unstable = True
    return record


def scan_directory(
    root: str | os.PathLike,
    exclude_patterns: tuple[str, ...] = (),
    chunk_size: int = DEFAULT_CHUNK_SIZE,
    compute_hashes: bool = True,
) -> ScanResult:
    """Walk a folder tree and return a record for every regular file."""
    root_path = normalize_root(root)
    patterns = tuple(exclude_patterns)
    result = ScanResult(root=str(root_path))

    def on_walk_error(err: OSError) -> None:
        location = getattr(err, "filename", None) or str(root_path)
        result.skipped.append((str(location), f"walk error: {err.strerror}"))

    for dirpath, dirnames, filenames in os.walk(
        root_path, topdown=True, followlinks=False, onerror=on_walk_error
    ):
        # Prune folders in place so os.walk never descends into them.
        kept_dirs: list[str] = []
        for dirname in dirnames:
            full = os.path.join(dirpath, dirname)
            rel = _relative(full, root_path)
            if is_link_like(full):
                result.skipped.append((full, "link or reparse point"))
            elif matches_exclusion(dirname, rel, patterns):
                result.skipped.append((full, "excluded"))
            elif not is_within_root(full, root_path):
                result.skipped.append((full, "outside monitored root"))
            else:
                kept_dirs.append(dirname)
        dirnames[:] = kept_dirs

        for filename in filenames:
            full = os.path.join(dirpath, filename)
            rel = _relative(full, root_path)

            if matches_exclusion(filename, rel, patterns):
                result.skipped.append((full, "excluded"))
                continue
            if is_link_like(full):
                result.skipped.append((full, "link or reparse point"))
                continue
            try:
                before = os.lstat(full)
            except OSError as exc:
                result.skipped.append((full, f"stat failed: {exc.strerror}"))
                continue
            if not stat.S_ISREG(before.st_mode):
                result.skipped.append((full, "special file"))
                continue

            result.records.append(_build_record(full, before, chunk_size, compute_hashes))

    return result