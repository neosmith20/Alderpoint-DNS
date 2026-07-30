#!/usr/bin/env python3
from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from app import service_logs  # noqa: E402


def fake_journal_entry(message: str, priority: int = 6, ts_us: int = 1_800_000_000_000_000) -> str:
    return json.dumps({"MESSAGE": message, "PRIORITY": str(priority), "__REALTIME_TIMESTAMP": str(ts_us)})


class SanitizeTest(unittest.TestCase):
    def test_redacts_common_secret_shapes(self) -> None:
        cases = {
            "password=hunter2 next": "password=[REDACTED] next",
            "api_key: abcdef123456": "api_key: [REDACTED]",
            "Authorization: Basic dXNlcjpwYXNz": "Authorization: Basic [REDACTED]",
            "token='super-secret-value'": "token=[REDACTED]",
        }
        for raw, expected in cases.items():
            self.assertEqual(service_logs.sanitize(raw), expected)

    def test_leaves_ordinary_messages_untouched(self) -> None:
        message = 'INFO:     127.0.0.1:1234 - "GET /status/summary HTTP/1.1" 200 OK'
        self.assertEqual(service_logs.sanitize(message), message)


class FetchUnitLogsTest(unittest.TestCase):
    def test_rejects_units_outside_the_allowlist(self) -> None:
        with self.assertRaises(ValueError):
            service_logs.fetch_unit_logs("sshd")

    def test_parses_and_sanitizes_journal_json(self) -> None:
        stdout = "\n".join(
            [
                fake_journal_entry("startup complete", priority=6),
                fake_journal_entry("password=hunter2 leaked in a log line", priority=3),
                "",  # trailing blank line from journalctl should be ignored
            ]
        )
        fake_proc = mock.Mock(returncode=0, stdout=stdout)
        with mock.patch.object(service_logs.subprocess, "run", return_value=fake_proc) as run_mock:
            entries = service_logs.fetch_unit_logs("alderpointdns")
        (call_args,), _ = run_mock.call_args
        self.assertEqual(call_args[0], "journalctl")
        self.assertIn("-u", call_args)
        self.assertIn("alderpointdns", call_args)
        self.assertEqual(len(entries), 2)
        self.assertEqual(entries[0]["severity"], "info")
        self.assertEqual(entries[1]["severity"], "err")
        self.assertIn("[REDACTED]", entries[1]["message"])
        self.assertNotIn("hunter2", entries[1]["message"])

    def test_nonzero_exit_yields_no_entries_instead_of_raising(self) -> None:
        fake_proc = mock.Mock(returncode=1, stdout="")
        with mock.patch.object(service_logs.subprocess, "run", return_value=fake_proc):
            entries = service_logs.fetch_unit_logs("named")
        self.assertEqual(entries, [])

    def test_malformed_json_lines_are_skipped_not_fatal(self) -> None:
        stdout = "not json\n" + fake_journal_entry("fine line")
        fake_proc = mock.Mock(returncode=0, stdout=stdout)
        with mock.patch.object(service_logs.subprocess, "run", return_value=fake_proc):
            entries = service_logs.fetch_unit_logs("dnsdist")
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["message"], "fine line")


class FilterEntriesTest(unittest.TestCase):
    def setUp(self) -> None:
        self.entries = [
            {"priority": 6, "message": f"line {i}"} for i in range(30)
        ] + [{"priority": 3, "message": "an error happened"}]

    def test_severity_filter_keeps_only_matching_priorities(self) -> None:
        result = service_logs.filter_entries(self.entries, severity="error", lines=100)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["message"], "an error happened")

    def test_lines_are_clamped_and_take_the_most_recent(self) -> None:
        result = service_logs.filter_entries(self.entries, severity="all", lines=15)
        self.assertEqual(len(result), 15)
        self.assertEqual(result[-1]["message"], "an error happened")

    def test_lines_below_minimum_are_clamped_up(self) -> None:
        result = service_logs.filter_entries(self.entries, severity="all", lines=1)
        self.assertEqual(len(result), 10)  # clamped to the 10-line minimum


if __name__ == "__main__":
    unittest.main()
