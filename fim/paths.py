"""Path validation. Keeps all scanning inside the folders the user chose."""
from __future__ import annotations

import os
from pathlib import Path


class UnsafePathError(ValueError):
    """Raised when a path falls outside the allowed root."""


def normalize_root(raw: str | os.PathLike) -> Path:
    """Return an absolute path to a monitored root folder, or raise an error."""
    path = Path(raw).expanduser()
    if not path.exists():
        raise FileNotFoundError(f"Path does not exist: {raw}")
    if not path.is_dir():
        raise NotADirectoryError(f"Not a directory: {raw}")
    return Path(os.path.abspath(path))


def is_within_root(candidate: str | os.PathLike, root: Path) -> bool:
    """True if candidate is root itself or lies somewhere inside it."""
    cand = os.path.normcase(os.path.abspath(candidate))
    base = os.path.normcase(os.path.abspath(root))
    try:
        return os.path.commonpath([cand, base]) == base
    except ValueError:  # paths on different Windows drives
        return False


def ensure_within_root(candidate: str | os.PathLike, root: Path) -> None:
    """Raise UnsafePathError if candidate is outside root."""
    if not is_within_root(candidate, root):
        raise UnsafePathError(f"Path escapes monitored root: {candidate}")