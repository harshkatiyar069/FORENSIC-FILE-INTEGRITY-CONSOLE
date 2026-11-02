# File Integrity Manager (FIM)

A Python tool that records trusted SHA-256 fingerprints of files and folders, then detects modified, new, deleted, renamed, and unreadable files. Every important action is written to a tamper-evident security log.

## Features

- Trusted baseline for one or more folders
- SHA-256 hashing in chunks, so large files use little memory
- Change detection: modified, new, deleted, renamed, metadata-only, and unreadable files
- Authorized baseline update, with an audit record
- Tamper-evident security log (hash chain plus append-only database triggers)
- Reports in CSV, JSON, and PDF
- Scheduled scans and real-time monitoring (watchdog)
- Streamlit dashboard
- Automated tests (pytest) and a one-command demo

## Requirements

- Windows 10 or 11 (tested)
- Python 3.12 or newer (tested on Python 3.15)
- Packages listed in `requirements.txt`

## Setup

```powershell
cd C:\Projects\file-integrity-manager
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python -m pytest -v
```

## Quick start

```powershell
python -m app.main init C:\path\to\folder --note "first baseline"
python -m app.main scan
python -m app.main report
python -m app.main logs
python -m app.main verify-log
streamlit run app/dashboard.py
python -m app.main demo
```

## Commands

| Command | Purpose |
|---|---|
| `init <folder> [...] [--note]` | Create the first trusted baseline |
| `scan` | Compare current files with the baseline and print changes |
| `status` | Show the active baseline |
| `report [--format csv\|json\|pdf\|all]` | Write reports for the latest scan |
| `schedule [--every SECONDS]` | Scan repeatedly; minimum interval is 10 seconds |
| `monitor [--quiet SECONDS]` | Watch the baseline folders and scan after changes settle |
| `update-baseline --confirm "I AUTHORIZE BASELINE UPDATE"` | Replace the active baseline, with an audit record |
| `logs [--type TYPE] [--contains TEXT] [--export FILE]` | View or export the security log |
| `verify-log` | Check the security log's hash chain |
| `demo` | Run the full platform in a temporary folder |

## How it works

1. `init` scans the chosen folders and stores each file's path, SHA-256 hash, size, modification time, and file identity in SQLite.
2. `scan` hashes the current files and compares them with the active baseline. A file is "renamed" only when its file identity and content both match, or when its content is unique and unchanged. Otherwise a missing file is reported as deleted and a new file as new.
3. Every action writes an entry to the security log. Each entry stores a SHA-256 hash of its own contents plus the previous entry's hash, so editing or deleting an old entry breaks the chain.
4. `monitor` waits for file activity to settle before scanning, so one save produces one scan. It ignores its own database and report folders to prevent a scan loop.

## Security design

- SHA-256 only. MD5 and SHA-1 are not used.
- Links, junctions, and special files are not followed.
- Paths are checked so scanning never leaves the chosen folders.
- Unreadable files are reported, never silently skipped.
- The baseline is never replaced by a scan. Replacement needs the exact authorization phrase, and the attempt is logged either way.
- The security log is append-only at the database level, and the hash chain detects edits that bypass that protection.
- File contents are never stored, only hashes and metadata.

## Limitations

These limits are important for interpreting results:

- **Detection, not prevention.** The tool can show that a file differs from the trusted baseline. It cannot prove who changed it or whether the change was authorized.
- **The log chain is tamper-evident, not tamper-proof.** Someone with administrator rights on this computer can delete the database or rebuild the entire chain. Stronger protection would need storage outside the machine, such as a write-once remote log or signed entries.
- **The authorization phrase is a procedural check.** Anyone who can run the program can type it. It records intent for the audit trail; it is not authentication.
- **No encryption.** The database and reports are plain files. Protect them with Windows file permissions or disk encryption (BitLocker).
- **Permission changes are not classified.** The brief asked for permission and metadata changes where supported. The tool detects modification-time changes, but not Windows permission (ACL) changes. This is planned future work.
- **Rename detection depends on the filesystem.** File identity is reliable on local NTFS drives. It may be missing or unreliable on some network or external drives, in which case renames appear as deleted plus new.
- **Real-time monitoring runs in the foreground.** `monitor` and `schedule` stop when their window closes. They are not installed as Windows services.
- **Single machine.** The baseline and log are local. There is no central server or multi-user access control.

## Future enhancements (not implemented)

- Windows ACL and permission change classification
- Email or desktop notifications for changes
- Risk scoring for changes
- Digitally signed baselines and reports
- Role-based access control for baseline updates
- Comparison of integrity status across multiple scans
- Installation as a Windows service, or scheduling through Task Scheduler

## Running the tests

```powershell
python -m pytest -v
```

The symlink test is skipped on Windows unless Developer Mode is enabled. Expected result: all tests pass, with one skipped.

## Project structure

