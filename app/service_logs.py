#!/usr/bin/env python3
"""Scoped, sanitized access to a fixed allowlist of systemd unit logs.

The web UI used to shell out to ``journalctl -u alderpointdns`` directly as
the unprivileged web service user, which has no journal group membership on
a fresh install, so it printed journald's own permission-denied hint text
straight into the page instead of any actual log content. Fixing that by
adding the web user to ``systemd-journal`` would grant it every unit's logs
(including ones outside Alderpoint DNS's own services). Instead, a narrowly
scoped root helper (invoked the same way every other privileged action in
this app is invoked: a fixed, sudoers-enumerated subcommand of
``alderpointdns_compiler.py``) fetches only the four units this page cares
about, always with the same fixed journalctl flags, and hands back
sanitized, structured JSON. Line-count and severity filtering happen
afterwards on that already-fetched, already-sanitized buffer -- never as
additional arguments threaded through to the privileged call.
"""

from __future__ import annotations

import json
import re
import subprocess
from datetime import datetime, timezone

ALLOWED_UNITS = ("alderpointdns", "alderpointdns-analytics", "named", "dnsdist")
MAX_LINES_FETCHED = 500

SEVERITY_LEVELS = {
    "error": (0, 1, 2, 3),
    "warning": (4,),
    "info": (5, 6),
    "debug": (7,),
}

PRIORITY_LABELS = {
    0: "emerg", 1: "alert", 2: "crit", 3: "err",
    4: "warning", 5: "notice", 6: "info", 7: "debug",
}

# A conservative subset of the diagnostics bundle's redaction patterns,
# applied to every log line before it ever leaves the root helper process.
REDACTION_PATTERNS = [
    (re.compile(r"(?i)(authorization:\s*basic\s+)[A-Za-z0-9+/=._:-]+"), r"\1[REDACTED]"),
    (re.compile(r"(?i)(authorization:\s*bearer\s+)[A-Za-z0-9._:-]+"), r"\1[REDACTED]"),
    (re.compile(r"(?i)(x-api-key:\s*)\S+"), r"\1[REDACTED]"),
    (re.compile(r"(?i)\b(api[_-]?key\s*[=:]\s*)(['\"]?)[^'\"\s,;]+\2"), r"\1[REDACTED]"),
    (re.compile(r"(?i)\b(password\s*[=:]\s*)(['\"]?)[^'\"\s,;]+\2"), r"\1[REDACTED]"),
    (re.compile(r"(?i)\b(secret\s*[=:]\s*)(['\"]?)[^'\"\s,;]+\2"), r"\1[REDACTED]"),
    (re.compile(r"(?i)\b(token\s*[=:]\s*)(['\"]?)[^'\"\s,;]+\2"), r"\1[REDACTED]"),
    (re.compile(r"(?i)\b(private[_-]?key\s*[=:]\s*)(['\"]?)[^'\"\s,;]+\2"), r"\1[REDACTED]"),
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S), "[REDACTED PRIVATE KEY]"),
]


def sanitize(message: str) -> str:
    text = message
    for pattern, replacement in REDACTION_PATTERNS:
        text = pattern.sub(replacement, text)
    return text


def _priority_int(raw) -> int:
    try:
        return max(0, min(7, int(raw)))
    except (TypeError, ValueError):
        return 6


def _message_text(raw) -> str:
    if isinstance(raw, list):
        try:
            return bytes(raw).decode("utf-8", errors="replace")
        except (TypeError, ValueError):
            return str(raw)
    return str(raw)


def _timestamp(raw) -> str:
    try:
        microseconds = int(raw)
    except (TypeError, ValueError):
        return ""
    return datetime.fromtimestamp(microseconds / 1_000_000, tz=timezone.utc).replace(microsecond=0).isoformat()


def fetch_unit_logs(unit: str) -> list[dict]:
    """Run as root. Fetch and sanitize the fixed-size recent log window for
    one allowlisted unit. Raises ValueError for anything outside the
    allowlist so this can never be coerced into reading an arbitrary unit,
    even if called incorrectly."""
    if unit not in ALLOWED_UNITS:
        raise ValueError(f"unit {unit!r} is not in the supported log allowlist")
    proc = subprocess.run(
        [
            "journalctl",
            "-u", unit,
            "-n", str(MAX_LINES_FETCHED),
            "-o", "json",
            "--no-pager",
            "--output-fields=MESSAGE,PRIORITY,__REALTIME_TIMESTAMP,SYSLOG_IDENTIFIER",
        ],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    entries: list[dict] = []
    if proc.returncode != 0:
        return entries
    for line in proc.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        priority = _priority_int(record.get("PRIORITY"))
        entries.append(
            {
                "ts": _timestamp(record.get("__REALTIME_TIMESTAMP")),
                "priority": priority,
                "severity": PRIORITY_LABELS.get(priority, "info"),
                "message": sanitize(_message_text(record.get("MESSAGE", ""))),
            }
        )
    return entries


def filter_entries(entries: list[dict], severity: str = "all", lines: int = 100) -> list[dict]:
    lines = max(10, min(MAX_LINES_FETCHED, lines))
    if severity in SEVERITY_LEVELS:
        allowed = SEVERITY_LEVELS[severity]
        entries = [e for e in entries if e["priority"] in allowed]
    return entries[-lines:]
