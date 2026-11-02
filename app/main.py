"""Command-line entry point. Run from the project root:

    python -m app.main init <folder> [<folder> ...] [--note "text"]
    python -m app.main scan
    python -m app.main status
    python -m app.main report [--scan-id N] [--format csv|json|pdf|all]
    python -m app.main schedule [--every SECONDS]
    python -m app.main monitor [--quiet SECONDS]
    python -m app.main logs [--type TYPE] [--contains TEXT] [--limit N] [--export FILE]
    python -m app.main verify-log
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from fim import database
from fim.baseline import BaselineExistsError, create_initial_baseline
from fim.config import DEFAULT_SETTINGS
from fim.monitor import watch_and_scan
from fim.reporting import ReportError, generate_reports
from fim.scan_service import NoBaselineError, ScanSummary, run_scan
from fim.scheduler import run_interval
from fim.security_log import export_events, verify_chain


def _baseline_roots() -> list[Path]:
    conn = database.connect(DEFAULT_SETTINGS.db_path)
    try:
        baseline_id = database.latest_baseline_id(conn)
        if baseline_id is None:
            return []
        return [Path(p) for p in database.load_baseline_roots(conn, baseline_id)]
    finally:
        conn.close()


def cmd_init(args: argparse.Namespace) -> int:
    try:
        summary = create_initial_baseline(
            DEFAULT_SETTINGS.db_path,
            [Path(p) for p in args.folders],
            note=args.note,
        )
    except (FileNotFoundError, NotADirectoryError, BaselineExistsError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    print(f"Baseline #{summary.baseline_id} created.")
    print(f"  Files recorded : {summary.files_recorded}")
    print(f"  Files skipped  : {summary.files_skipped}")
    print(f"  Files failed   : {len(summary.files_failed)}")
    for path, reason in summary.files_failed[:20]:
        print(f"    - {path}: {reason}")
    return 0


def _short(digest: str | None) -> str:
    return digest if digest else "-"


def _print_change(c: dict) -> None:
    kind = c["change_type"].upper()
    if c["change_type"] == "renamed":
        print(f"  [{kind}] {c['old_path']}")
        print(f"      -> {c['path']}  ({c['detail']})")
    elif c["change_type"] == "modified":
        print(f"  [{kind}] {c['path']}")
        print(f"      previous SHA-256: {_short(c['old_sha256'])}")
        print(f"      current  SHA-256: {_short(c['new_sha256'])}")
    else:
        extra = f"  ({c['detail']})" if c["detail"] else ""
        print(f"  [{kind}] {c['path']}{extra}")


def _print_summary(summary: ScanSummary) -> None:
    print(f"Scan #{summary.scan_id} against baseline #{summary.baseline_id} complete.")
    print(f"  Files scanned : {summary.files_seen}")
    print(f"  Skipped       : {summary.skipped}")
    print(f"  Modified      : {summary.count('modified')}")
    print(f"  New           : {summary.count('new')}")
    print(f"  Deleted       : {summary.count('deleted')}")
    print(f"  Renamed       : {summary.count('renamed')}")
    print(f"  Metadata only : {summary.count('metadata')}")
    print(f"  Unreadable    : {summary.count('unreadable')}")
    if summary.changes:
        print()
        print("Details:")
        for change in summary.changes:
            _print_change(change)
    else:
        print("\nNo changes detected. Files match the trusted baseline.")


def cmd_scan(_args: argparse.Namespace) -> int:
    try:
        summary = run_scan()
    except (NoBaselineError, FileNotFoundError, NotADirectoryError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    _print_summary(summary)
    return 0


def cmd_status(_args: argparse.Namespace) -> int:
    conn = database.connect(DEFAULT_SETTINGS.db_path)
    try:
        baseline_id = database.latest_baseline_id(conn)
        if baseline_id is None:
            print("No baseline yet. Run: python -m app.main init <folder>")
            return 0
        files = database.load_baseline_files(conn, baseline_id)
        print(f"Current baseline: #{baseline_id} ({len(files)} files)")
    finally:
        conn.close()
    return 0


def cmd_report(args: argparse.Namespace) -> int:
    formats = ["csv", "json", "pdf"] if args.format == "all" else [args.format]
    try:
        paths = generate_reports(
            DEFAULT_SETTINGS.db_path,
            DEFAULT_SETTINGS.report_dir,
            formats,
            scan_id=args.scan_id,
        )
    except ReportError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    for path in paths:
        print(f"Wrote {path}")
    return 0


def cmd_schedule(args: argparse.Namespace) -> int:
    if args.every < 10:
        print("Error: --every must be at least 10 seconds.", file=sys.stderr)
        return 1
    if not _baseline_roots():
        print("Error: no baseline with monitored folders. Run init first.", file=sys.stderr)
        return 1

    print(f"Scheduled scans every {args.every} seconds. Press Ctrl+C to stop.")
    try:
        run_interval(args.every, DEFAULT_SETTINGS.db_path, DEFAULT_SETTINGS.report_dir)
    except KeyboardInterrupt:
        print("\nScheduled scans stopped.")
    return 0


def cmd_monitor(args: argparse.Namespace) -> int:
    roots = _baseline_roots()
    if not roots:
        print("Error: no baseline with monitored folders. Run init first.", file=sys.stderr)
        return 1
    try:
        watch_and_scan(
            roots=roots,
            db_path=DEFAULT_SETTINGS.db_path,
            report_dir=DEFAULT_SETTINGS.report_dir,
            quiet_seconds=args.quiet,
        )
    except RuntimeError as exc:  # watchdog not installed
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    return 0


def cmd_logs(args: argparse.Namespace) -> int:
    conn = database.connect(DEFAULT_SETTINGS.db_path)
    try:
        events = database.load_security_events(
            conn,
            event_type=args.type,
            contains=args.contains,
            limit=None if args.export else args.limit,
            newest_first=True,
        )
    finally:
        conn.close()
    events.reverse()  # display in chronological order

    if args.export:
        try:
            count = export_events(events, Path(args.export))
        except ValueError as exc:
            print(f"Error: {exc}", file=sys.stderr)
            return 1
        print(f"Exported {count} events to {args.export}")
        return 0

    if not events:
        print("No matching events.")
        return 0

    for event in events:
        details = json.loads(event["details"])
        summary = ", ".join(
            f"{key}={value}" for key, value in details.items()
            if not isinstance(value, (list, dict))
        )
        print(f"#{event['id']:<4} {event['created_at']}  {event['event_type']:<18} {summary}")
    return 0


def cmd_verify(_args: argparse.Namespace) -> int:
    conn = database.connect(DEFAULT_SETTINGS.db_path)
    try:
        report = verify_chain(conn)
    finally:
        conn.close()

    if report.valid:
        print(f"Log integrity OK: {report.events_checked} events verified.")
        return 0

    print(f"Log integrity FAILED at event #{report.broken_at_id}.", file=sys.stderr)
    print(f"  Reason: {report.reason}", file=sys.stderr)
    print(f"  Events checked: {report.events_checked}", file=sys.stderr)
    return 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="fim", description="File Integrity Manager")
    sub = parser.add_subparsers(dest="command", required=True)

    init = sub.add_parser("init", help="create the initial trusted baseline")
    init.add_argument("folders", nargs="+", help="folders to monitor")
    init.add_argument("--note", default=None, help="optional description")
    init.set_defaults(func=cmd_init)

    scan = sub.add_parser("scan", help="compare current files with the baseline")
    scan.set_defaults(func=cmd_scan)

    status = sub.add_parser("status", help="show the current baseline")
    status.set_defaults(func=cmd_status)

    report = sub.add_parser("report", help="write CSV, JSON, and/or PDF reports")
    report.add_argument("--scan-id", type=int, default=None, help="scan to report (default: latest)")
    report.add_argument("--format", choices=["csv", "json", "pdf", "all"], default="all")
    report.set_defaults(func=cmd_report)

    schedule = sub.add_parser("schedule", help="run scans repeatedly at a fixed interval")
    schedule.add_argument("--every", type=int, default=3600, help="seconds between scans (default 3600)")
    schedule.set_defaults(func=cmd_schedule)

    monitor = sub.add_parser("monitor", help="watch folders in real time and scan after changes settle")
    monitor.add_argument("--quiet", type=float, default=5.0, help="seconds of inactivity before scanning")
    monitor.set_defaults(func=cmd_monitor)

    logs = sub.add_parser("logs", help="view or export the security log")
    logs.add_argument("--type", default=None, help="filter by event type, e.g. scan_completed")
    logs.add_argument("--contains", default=None, help="text to search for in event details")
    logs.add_argument("--limit", type=int, default=20, help="show the newest N events")
    logs.add_argument("--export", default=None, help="write matching events to a .csv or .json file")
    logs.set_defaults(func=cmd_logs)

    verify = sub.add_parser("verify-log", help="check that the security log has not been altered")
    verify.set_defaults(func=cmd_verify)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
