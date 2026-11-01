"""Default settings. Later stages can load these from a JSON file."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Settings:
    chunk_size: int = 1024 * 1024  # 1 MB reads when hashing
    exclude_patterns: tuple[str, ...] = (
        "*.tmp",
        "*.log",
        "*.db",
        "*.db-journal",
        "__pycache__",
        ".git",
        ".venv",
        "Thumbs.db",
    )
    db_path: Path = Path("data") / "fim.db"
    report_dir: Path = Path("reports")


DEFAULT_SETTINGS = Settings()