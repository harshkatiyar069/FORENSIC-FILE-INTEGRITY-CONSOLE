"""Real-time monitoring with watchdog.

Activity marks the folders as "dirty". Once activity has been quiet for the
chosen number of seconds, one scan runs. This avoids a scan for every
individual write when a program saves a file in several steps.
"""
from __future__ import annotations

import time
from pathlib import Path
from typing import Callable

from .config import DEFAULT_SETTINGS, Settings
from .scheduler import Debouncer, describe_run, scan_and_report, should_ignore


def watch_and_scan(
    roots: list[Path],
    db_path: Path,
    report_dir: Path,
    quiet_seconds: float = 5.0,
    settings: Settings = DEFAULT_SETTINGS,
    on_result: Callable[[str], None] = print,
    poll_seconds: float = 1.0,
) -> None:
    try:
        from watchdog.events import FileSystemEventHandler
        from watchdog.observers import Observer
    except ImportError as exc:
        raise RuntimeError(
            "Real-time monitoring needs watchdog. Run: pip install -r requirements.txt"
        ) from exc

    debouncer = Debouncer(quiet_seconds)
    ignored_dirs = (Path(db_path).resolve().parent, Path(report_dir).resolve())
    patterns = settings.exclude_patterns

    class ChangeHandler(FileSystemEventHandler):
        def on_any_event(self, event):
            paths = [event.src_path]
            dest = getattr(event, "dest_path", "")
            if dest:
                paths.append(dest)
            if any(isinstance(p, str) and not should_ignore(p, ignored_dirs, patterns)
                   for p in paths):
                debouncer.touch()

    observer = Observer()
    handler = ChangeHandler()
    for root in roots:
        observer.schedule(handler, str(root), recursive=True)
    observer.start()
    on_result(f"Watching {len(roots)} folder(s). Press Ctrl+C to stop.")

    try:
        while True:
            time.sleep(poll_seconds)
            if debouncer.due():
                on_result("Activity detected, running scan...")
                try:
                    summary, reports = scan_and_report(db_path, report_dir, "realtime", settings)
                    on_result(describe_run(summary, reports))
                except Exception as exc:
                    on_result(f"Scan failed: {exc}")
    except KeyboardInterrupt:
        on_result("Monitoring stopped.")
    finally:
        observer.stop()
        observer.join()  