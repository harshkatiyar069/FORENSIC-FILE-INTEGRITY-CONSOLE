"""SHA-256 hashing. Files are read in chunks so large files never fill memory."""
from __future__ import annotations

import hashlib
import os

DEFAULT_CHUNK_SIZE = 1024 * 1024  # 1 MB


def hash_file(path: str | os.PathLike, chunk_size: int = DEFAULT_CHUNK_SIZE) -> str:
    """Return the SHA-256 hex digest of a file. Raises OSError on read problems."""
    if chunk_size <= 0:
        raise ValueError("chunk_size must be a positive integer")
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(chunk_size), b""):
            digest.update(chunk)
    return digest.hexdigest()


def hash_file_safe(
    path: str | os.PathLike, chunk_size: int = DEFAULT_CHUNK_SIZE
) -> tuple[str | None, str | None]:
    """
    Return (digest, None) on success, or (None, error_message) on failure.
    Read errors are reported, not raised, so one bad file cannot stop a scan.
    """
    try:
        return hash_file(path, chunk_size), None
    except PermissionError:
        return None, f"permission denied: {path}"
    except OSError as exc:
        return None, f"read error: {exc.strerror or exc}"