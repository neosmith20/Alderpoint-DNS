"""In-app log viewer (beta-rescue priority 3E).

Real, narrowly-scoped `journalctl` access to an explicit allowlist of
V2's own systemd units -- never arbitrary journal/file access. Reuses
app.service_logs's public, already-audited primitives (secret
redaction, severity classification, entry filtering) rather than
reimplementing them, but keeps its own allowlist (V2's real unit names,
not V1's) and its own `journalctl` invocation, since
app.service_logs.fetch_unit_logs hard-checks against V1's own unit
tuple and would reject every V2 unit name outright.

Privilege: the web process reads the systemd journal via membership in
the standard `systemd-journal` group (added for the alderpointdns-v2
service account in postinst) -- real, minimal, read-only access to
journal entries, not root, not sudo, not a general file-read capability.
"""

from __future__ import annotations

import json
import subprocess
from datetime import datetime, timezone

from app.service_logs import PRIORITY_LABELS, SEVERITY_LEVELS, filter_entries, sanitize

ALLOWED_UNITS = (
    "alderpointdns-v2-web",
    "alderpointdns-v2-dnsdist",
    "alderpointdns-v2-bind@ctx0",
    "alderpointdns-v2-analytics",
    "alderpointdns-v2-discovery",
    "alderpointdns-v2-replication",
    "alderpointdns-v2-tierb",
    "alderpointdns-v2-schedule",
)
MAX_LINES_FETCHED = 500


class LogViewerError(ValueError):
    pass


def _priority_int(raw) -> int:
    try:
        return int(raw)
    except (TypeError, ValueError):
        return 6  # "info" -- unrecognized/missing priority is not an error signal


def _message_text(raw) -> str:
    if isinstance(raw, list):
        # journalctl -o json emits MESSAGE as a byte array for
        # non-UTF-8-safe lines -- decode best-effort rather than crash.
        try:
            return bytes(raw).decode("utf-8", errors="replace")
        except (TypeError, ValueError):
            return str(raw)
    return str(raw)


def _timestamp(raw) -> str:
    try:
        micros = int(raw)
        return datetime.fromtimestamp(micros / 1_000_000, tz=timezone.utc).isoformat()
    except (TypeError, ValueError):
        return ""


def fetch_unit_logs(unit: str) -> list[dict]:
    if unit not in ALLOWED_UNITS:
        raise LogViewerError(f"unit {unit!r} is not in the supported log allowlist")
    try:
        proc = subprocess.run(
            [
                "journalctl", "-u", unit, "-n", str(MAX_LINES_FETCHED), "-o", "json", "--no-pager",
                "--output-fields=MESSAGE,PRIORITY,__REALTIME_TIMESTAMP,SYSLOG_IDENTIFIER",
            ],
            text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=15,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise LogViewerError(f"journalctl failed to run: {exc}") from exc
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
        entries.append({
            "ts": _timestamp(record.get("__REALTIME_TIMESTAMP")),
            "priority": priority,
            "severity": PRIORITY_LABELS.get(priority, "info"),
            "message": sanitize(_message_text(record.get("MESSAGE", ""))),
        })
    return entries


def view_logs(unit: str, severity: str = "all", lines: int = 100) -> dict:
    if unit not in ALLOWED_UNITS:
        raise LogViewerError(f"unit {unit!r} is not in the supported log allowlist")
    if severity not in ("all", *SEVERITY_LEVELS.keys()):
        severity = "all"
    lines = max(10, min(MAX_LINES_FETCHED, lines))
    entries = fetch_unit_logs(unit)
    return {"unit": unit, "severity": severity, "lines": lines, "entries": filter_entries(entries, severity, lines)}
