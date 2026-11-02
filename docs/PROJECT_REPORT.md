# File Integrity Manager (FIM): Project Report

Prepared by: Aarchie Mathur
Institution: [Your institution]
Guide: [Guide name]
Date: [Submission date]

## 1. Abstract

The File Integrity Manager (FIM) is a Python application that detects unexpected changes to files and folders. It records a trusted baseline of SHA-256 hashes, metadata, and file identities for the folders the user selects, then compares later scans against that baseline. Each difference is classified as modified, new, deleted, renamed, metadata-only, or unreadable. Results are available through a command-line interface, a Streamlit dashboard, and CSV, JSON, and PDF reports. Every significant action is recorded in a hash-chained security log, so later edits to that log can be detected. The system supports manual scans, scheduled scans, and real-time monitoring. Replacing a trusted baseline requires an explicit authorization phrase, and the attempt is logged. The project includes 82 automated tests (81 pass, and one symlink test is skipped on Windows without Developer Mode) and a demonstration command. FIM detects change. It does not prove who made a change, and its log is tamper-evident rather than tamper-proof. Section 13 describes these limits.

## 2. Problem Statement

Important files can change by accident, through software errors, or through malicious software, and the owner often notices only after the damage is done. Operating systems can record some change information, but auditing is not always enabled, the records are difficult to read, and they are not compared against a stored trusted state. What is needed is a simple, verifiable way to answer the question: has this file changed since I last trusted it, and when did it change?

## 3. Objectives

The project aimed to:

- monitor selected files and folders recursively;
- compute SHA-256 hashes efficiently, including for large files;
- maintain a trusted baseline that is never replaced automatically;
- detect and classify new, modified, deleted, and renamed files, showing old and new hashes for modified files;
- keep timestamped security logs that can be searched, exported, and checked for tampering;
- provide a dashboard showing integrity status and recent events;
- generate CSV, JSON, and PDF reports;
- support manual scans, scheduled scans, and real-time monitoring;
- handle permission errors, links, unsafe paths, and files that change during a scan;
- document the design, testing, and limitations.

## 4. Scope

The project covers local monitoring of Windows folders, SHA-256 hashing, baseline creation and authorized replacement, change classification, SQLite storage, the hash-chained security log, reports, the Streamlit dashboard, scheduled scans, real-time monitoring, automated tests, and a demonstration command.

The following are out of scope: classification of Windows permission (ACL) changes, email or desktop notifications, digitally signed baselines, multi-user access control, remote or centralized logging, installation as a Windows service, encryption of stored data, and risk scoring. Comparing integrity status across many scans is also not implemented.

## 5. Existing System and Proposed System

Existing approaches include operating system auditing, manual checksum comparison, and commercial endpoint integrity products. Operating system auditing can record file access and changes, but it must be configured carefully, produces large volumes of events, and does not compare files against a stored trusted state. Manual checksum comparison with command-line tools shows whether a file differs at one moment, but it provides no ongoing monitoring, no change classification, and no record of events. Commercial products are capable but complex and costly for a student project or a small office.

The proposed system is a focused and transparent tool. It stores a trusted baseline, compares the current state with it, classifies every difference, records each action in a tamper-evident log, and presents the results in a form that is easy to read and to share. The design favors clarity and verifiability over breadth, and each part is built as a separate module so it can be tested on its own.

## 6. System Architecture

The system is organized in four layers. The presentation layer consists of the command-line interface (app/main.py) and the Streamlit dashboard (app/dashboard.py). The application layer coordinates the work: creating and replacing baselines, running scans, generating reports, scheduling, and monitoring. The domain layer contains the scanner, the hasher, the comparator, and the security log. The infrastructure layer handles SQLite access through database.py and file-system events through the watchdog library. A configuration module holds the settings and exclusion rules.

When a scan runs, the scanner walks each folder in the baseline. It skips excluded names and link-like entries, and it hashes each regular file in 1 MB chunks. Before and after hashing, it compares the file's size and modification time. If they changed, the file is marked as unstable and is not judged. The comparator then matches the current files against the baseline. It first matches by path. For files that are missing from their old path, it looks for a rename using two checks: first, the same file identity and the same content; second, content that is unique among both the missing and new files. A file with duplicate content is never guessed to be a rename. The results are written to the changes table, each action is appended to the security log, and the reports and dashboard read from the database.

## 7. Software and Hardware Requirements

**Hardware:** a Windows 10 or Windows 11 computer with enough free disk space for the database and reports. Memory use is modest, because files are read in 1 MB chunks.

**Software:** Windows 10 or 11; Python 3.12 or newer (the project was developed and tested on Python 3.15.0); Visual Studio Code with the Python extension; Git for version control (optional).

**Python packages:** the minimum versions are listed in requirements.txt. They are pytest, streamlit, pandas, reportlab (for PDF reports), and watchdog (for real-time monitoring). The core logic uses only the Python standard library: hashlib, sqlite3, os, pathlib, json, csv, and argparse.

## 8. Module Descriptions

| Module | Responsibility |
|---|---|
| fim/config.py | Settings: chunk size, exclusion patterns, database and report paths |
| fim/paths.py | Path validation and containment checks |
| fim/hasher.py | SHA-256 hashing in chunks; errors are returned, not raised |
| fim/scanner.py | Recursive directory walk, exclusions, link checks, race detection |
| fim/baseline.py | Creates the baseline; replaces it only with the authorization phrase |
| fim/comparator.py | Classifies differences and detects renames |
| fim/scan_service.py | Runs a scan against the active baseline and stores the results |
| fim/database.py | All SQLite reads and writes, including the schema |
| fim/security_log.py | Writes hash-chained events and verifies the chain; exports logs |
| fim/reporting.py | CSV, JSON, and PDF report generation |
| fim/scheduler.py | Scheduled scans and the debouncer used by real-time monitoring |
| fim/monitor.py | Real-time monitoring with watchdog |
| fim/dashboard_data.py | Read-only data layer used by the dashboard |
| fim/demo.py | End-to-end demonstration in a temporary folder |
| app/main.py | Command-line interface |
| app/dashboard.py | Streamlit dashboard |

## 9. Database Design

The database is a single SQLite file, data/fim.db. It contains six tables.

- **baselines** records each trusted state: its creation time, the user who authorized it, and an optional note.
- **baseline_roots** records the folders each baseline covers, so scans know where to look.
- **baseline_files** records each file in a baseline: path, SHA-256 hash, size, modification time, and file identity.
- **scans** records each scan: start and finish times, the baseline it used, the number of files seen, and its status (running, complete, or failed).
- **changes** records each difference found by a scan, with the change type and both hashes where relevant.
- **security_events** records every logged action. Each row stores its own hash and the hash of the previous row. Triggers block ordinary UPDATE and DELETE statements on this table.

Old baselines are kept when a new one is authorized, so the history of trusted states is preserved.

## 10. Security Design

The system uses SHA-256 only, as specified in NIST FIPS 180-4. MD5 and SHA-1 are not used because practical collision attacks exist for them. Links, junctions, and special files are not followed, so the scanner cannot be redirected outside the monitored folders. Paths are normalized and checked before use. Unreadable files are reported as unreadable rather than silently skipped or treated as deleted. The baseline is never replaced by a scan. Replacement requires the exact authorization phrase, and every attempt, successful or not, is written to the log. File contents are never stored, only hashes and metadata. The monitor ignores activity inside its own database and report folders, because otherwise writing a report would trigger another scan.

**Threat model summary:**

| Threat | Control | Remaining risk |
|---|---|---|
| Malware modifies a monitored file | Hash comparison detects the change and shows old and new hashes | Detection is delayed until the next scan |
| Attacker changes the baseline | Replacement needs authorization and is logged | Anyone who can run the program can type the phrase |
| Attacker edits or deletes log entries | Hash chain and append-only triggers | An administrator can rebuild the chain |
| Link redirects scanning outside the folder | Links are not followed | Hard links are not detected | 
| Scan service (end-to-end scans) | 5 | Clean scans, each real change type detected, metadata-only changes, scan status recorded, error when no baseline exists |
| Path traversal in configuration | Path normalization and containment checks | Depends on correct configuration |
| File changes during hashing | Size and modification-time check marks the file unstable | A very fast change between the two checks can be missed |
| Locked or unreadable file hides a change | Reported as unreadable, never as clean | Its contents remain unverified until it is readable |

## 11. Testing Documentation

The test suite uses pytest and contains 82 tests. Tests are grouped by the part of the system they check.

| Test group | Tests | Purpose |
|---|---|---|
| Hashing | 7 | Known SHA-256 values, empty files, large files, chunk handling, error reporting |
| Scanning | 10 | Recursive discovery, exclusions, links (one skipped on Windows), metadata, empty files, duplicates |
| Change classification | 9 | Modified, new, deleted, metadata-only, renamed, ambiguous duplicates, unreadable and unstable files |
| Baseline creation | 5 | All files recorded, correct hashes, refusal of a second baseline, overlapping folders, persistence |
| Baseline authorization | 4 | Refusal without the phrase, refusal of a wrong phrase, authorized replacement with history kept, clean scan afterward |
| Security log | 11 | Chain creation, detection of edits and deletions, trigger protection, export, logging of baseline and scan events |
| Reporting | 5 | CSV, JSON, and PDF output; special characters in file names; error handling; logging |
| Scheduling and monitoring logic | 7 | Debounce timing, ignored locations, report creation rules, interval runs |
| Dashboard data | 5 | Status labels, change counts, recent events |
| Permissions | 2 | Locked files reported as unreadable during scans and baseline creation |
| Edge cases | 5 | 5 MB file, empty file, identical files, unusual names, excluded folders |
| Persistence | 2 | Baseline and log remain valid across a restart |
| Command-line interface | 4 | Full flow from init to verify-log, tamper detection, exact-phrase requirement |
| Demonstration | 1 | The full demonstration runs end to end and detects the simulated tampering |

**Result:** 81 passed, 1 skipped. The skipped test checks symbolic links, which Windows allows only with Developer Mode or administrator rights.

**Notes on the permission tests.** These tests simulate a locked file by replacing the hashing function for one file name. They do not lock a real file. Behavior with real locked files was observed only in general use, not in the automated suite.

**Manual verification.** The following were run on the author's Windows laptop and observed directly:

- A baseline was created, then a scan showed a modified file with its previous and current hashes, a renamed file, a deleted file, and a new file.
- The scheduled scan detected a change on its next run and wrote the CSV, JSON, and PDF reports.
- The real-time monitor reacted to a single edit with one scan and one set of reports, and then stayed quiet. It did not start scanning its own writes.
- The log was altered directly in the database. The verification command reported the failure at the correct event number, with the reason.
- The Streamlit dashboard showed the integrity status, change counts, reports, and log integrity check.

**Not tested:** network shares, very large folder trees with millions of files, real locked files, Windows ACL changes, and performance benchmarks beyond a single 5 MB file.

## 12. Results and Demonstration

The command `python -m app.main demo` builds a sample folder in a temporary location and runs the whole platform on it. It creates files, including an empty file, two identical files, and a 5 MB random file. It then records a baseline and confirms that a scan with no changes reports nothing. It edits one file, deletes one, adds one, and renames one. The next scan reports each change correctly. The demonstration writes three reports and checks the security log, which is valid. It then rewrites one log entry directly in the database, bypassing the protection, and the next verification reports the tampering. The demonstration does not touch the project's own data folder.

## 13. Limitations

The limitations below are part of the design and should be read with the results.

1. **Detection, not prevention.** The system shows that a file differs from the trusted baseline. It cannot prevent a change.
2. **No attribution.** A hash mismatch does not identify who changed a file or whether the change was authorized. Proving unauthorized change needs operating system audit logs and access controls.
3. **Tamper-evident, not tamper-proof.** Someone with administrator rights on the computer can delete the database or rebuild the entire hash chain. Stronger protection needs a log stored elsewhere, such as a write-once remote log or signed entries.
4. **The authorization phrase is procedural.** Anyone who can run the program can type it. It records intent in the audit trail, but it is not authentication.
5. **No encryption.** The database and reports are ordinary files. Windows file permissions or BitLocker should protect them.
6. **Permission changes are not classified.** Windows ACL changes are not detected. Only modification-time changes are reported as metadata changes.
7. **Rename detection depends on file identity.** It is reliable on local NTFS drives. On some network or removable drives, renames may appear as a deletion plus a new file.
8. **Delayed reporting.** Real-time monitoring waits for a quiet period before scanning, so a change is reported a few seconds after it happens, not instantly.
9. **Manual baseline updates.** After an approved change, the baseline must be updated explicitly. Until then, every scan reports the change.
10. **Foreground operation.** The schedule and monitor commands stop when their window closes. They are not installed as Windows services.
11. **Single computer.** The baseline and log are local, and there is no central server or multi-user access control.
12. **Tested on one configuration.** The project was verified on Windows with Python 3.15.0. Other Windows versions and Python 3.12 were not separately tested.

## 14. Future Enhancements

The following features are proposed and not implemented: classification of Windows permission (ACL) changes; email or desktop notifications; risk scoring for changes; digitally signed baselines and reports; role-based access control for baseline updates; storage of the security log on a separate machine; comparison of integrity status across multiple scans; installation as a Windows service or scheduling through Windows Task Scheduler; and support for Linux and macOS.

## 15. Conclusion

FIM delivers a working, tested tool for detecting unexpected changes to files on a Windows computer. It records a trusted state, compares against it, classifies every difference, and keeps a log that reveals tampering with its history. The project was built in stages, and each stage was verified before the next began. The most important design decisions were to never replace the trusted baseline automatically, to report unreadable files rather than ignore them, and to be explicit about what the system cannot prove. Those limits are what make the results trustworthy: a changed hash is a fact the user can act on, while attribution and prevention require other controls. The project provides a foundation that can be extended with notifications, permission classification, and stronger log protection.

## 16. References

1. National Institute of Standards and Technology. FIPS PUB 180-4, Secure Hash Standard (SHS). August 2015.
2. Python Software Foundation. Python 3 documentation: hashlib, sqlite3, argparse, pathlib.
3. SQLite Consortium. SQLite documentation: CREATE TRIGGER.
4. Watchdog project documentation: file system event monitoring for Python.
5. Streamlit documentation: st.dataframe, st.download_button, st.metric.
6. pytest documentation: writing and running tests.
7. ReportLab documentation: PDF generation with Platypus.
8. Project README (README.md in the repository) for setup and command reference.
