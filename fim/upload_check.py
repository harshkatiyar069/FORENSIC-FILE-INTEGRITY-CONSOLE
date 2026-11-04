"""Checks an uploaded file without opening or running it.

The bytes are read into memory, fingerprinted with SHA-256, compared with the
trusted baseline, and searched for risky PDF features as plain text. Nothing is
written to disk, and the file is never opened by a PDF reader or executed.
"""
from __future__ import annotations

import hashlib
import os
import re
from dataclasses import dataclass, field

from . import database
from .security_log import log_event

# Text patterns that often appear in PDFs with active content.
# Matching is a warning sign, not proof of malicious intent.
RISK_PATTERNS: list[tuple[bytes, str, str]] = [
    (rb"/JavaScript|/JS(?![A-Za-z])", "high", "contains JavaScript"),
    (rb"/Launch", "high", "can start another program"),
    (rb"/EmbeddedFile", "medium", "contains an embedded file"),
    (rb"/OpenAction|/AA(?![A-Za-z])", "medium", "runs an action automatically"),
    (rb"/XFA", "medium", "uses XFA forms, which can run scripts"),
    (rb"/RichMedia", "medium", "contains rich media"),
    (rb"/SubmitForm", "low", "can send form data to a web address"),
    (rb"/URI", "info", "contains web links"),
]


@dataclass
class Finding:
    severity: str
    detail: str
    count: int


@dataclass
class UploadCheck:
    file_name: str
    size_bytes: int
    sha256: str
    looks_like_pdf: bool
    expected_match: bool | None
    baseline_matches: list[str] = field(default_factory=list)
    name_matches: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    severity: str = "info"  # ok | info | warning | error
    verdict: str = ""


def scan_pdf_structure(data: bytes) -> list[Finding]:
    """Search the raw bytes for risky PDF keywords. The file is never parsed or run."""
    findings: list[Finding] = []
    for pattern, severity, detail in RISK_PATTERNS:
        count = len(re.findall(pattern, data))
        if count:
            findings.append(Finding(severity, detail, count))
    return findings


def _judge(r: UploadCheck) -> tuple[str, str]:
    high = any(f.severity == "high" for f in r.findings)
    note = (
        " It contains active content (JavaScript or program launch). "
        "Do not open it without a security review."
        if high else ""
    )

    if r.expected_match is False:
        return "error", "The SHA-256 does not match the value you expected. This is not the same file."
    if not r.looks_like_pdf:
        return "warning", "This file does not start with a PDF header, so it may not be a PDF." + note
    if r.baseline_matches:
        if high:
            return "warning", f"Identical to trusted baseline file {r.baseline_matches[0]}." + note
        return "ok", f"Identical to trusted baseline file {r.baseline_matches[0]}."
    if r.name_matches:
        return "warning", (
            "A baseline file has this name but different content. "
            "It is a changed or different version." + note
        )
    if high:
        return "warning", "Not in the trusted baseline." + note
    return "info", (
        "Not in the trusted baseline, so there is nothing to compare it with. "
        "The structure scan found no high-risk features."
    )


def check_upload(
    db_path,
    file_name: str,
    data: bytes,
    expected_sha256: str | None = None,
) -> UploadCheck:
    """Read-only check. It compares the file with the baseline but writes nothing."""
    digest = hashlib.sha256(data).hexdigest()
    is_pdf = data[:5] == b"%PDF-"

    conn = database.connect(db_path)
    try:
        baseline_id = database.latest_baseline_id(conn)
        files = database.load_baseline_files(conn, baseline_id) if baseline_id is not None else []
    finally:
        conn.close()

    wanted = os.path.basename(file_name).lower()
    same = [f["path"] for f in files if f["sha256"] == digest]
    same_name = [
        f["path"] for f in files
        if os.path.basename(f["path"]).lower() == wanted and f["sha256"] != digest
    ]
    expected = None
    if expected_sha256:
        expected = digest == expected_sha256.strip().lower()

    result = UploadCheck(
        file_name=file_name,
        size_bytes=len(data),
        sha256=digest,
        looks_like_pdf=is_pdf,
        expected_match=expected,
        baseline_matches=same,
        name_matches=same_name,
        findings=scan_pdf_structure(data) if is_pdf else [],
    )
    result.severity, result.verdict = _judge(result)
    return result


def record_upload_check(db_path, result: UploadCheck) -> None:
    """Write the check to the audit trail. Only the file name and hash are stored, never the contents."""
    conn = database.connect(db_path)
    try:
        log_event(conn, "upload_checked", {
            "file_name": result.file_name,
            "size_bytes": result.size_bytes,
            "sha256": result.sha256,
            "looks_like_pdf": result.looks_like_pdf,
            "baseline_matches": result.baseline_matches,
            "verdict": result.verdict,
            "findings": [f"{f.severity}: {f.detail} ({f.count})" for f in result.findings],
        })
        conn.commit()
    finally:
        conn.close()
