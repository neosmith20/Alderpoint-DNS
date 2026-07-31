#!/usr/bin/env python3
from __future__ import annotations

import json
import sqlite3
import tempfile
import time
import unittest
import unittest.mock
from pathlib import Path

import sys

# Resolve the application package from this checkout, the way every other
# test module does, so `unittest discover` never mixes modules from an
# installed copy at /opt/alderpointdns with the tree under test.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app import analytics  # noqa: E402
from app import alderpointdns_compiler as compiler  # noqa: E402
from app import local_dns  # noqa: E402


def enc_varint(value: int) -> bytes:
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


def field_varint(number: int, value: int) -> bytes:
    return enc_varint((number << 3) | 0) + enc_varint(value)


def field_bytes(number: int, value: bytes) -> bytes:
    return enc_varint((number << 3) | 2) + enc_varint(len(value)) + value


class AnalyticsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.old_local_dns_db_path = local_dns.DB_PATH
        compiler.DB_PATH = root / "alderpointdns.db"
        compiler.DOWNLOAD_DIR = root / "downloads"
        compiler.STAGING_DIR = root / "staging"
        compiler.COMPILED_RPZ = root / "compiled" / "alderpointdns.rpz"
        analytics.DB_PATH = compiler.DB_PATH
        local_dns.DB_PATH = compiler.DB_PATH
        analytics.SECRET_FILE = root / "analytics.secret"
        analytics.HEARTBEAT_FILE = root / "analytics-writer-heartbeat.json"
        analytics.init_analytics_db()

    def tearDown(self) -> None:
        local_dns.DB_PATH = self.old_local_dns_db_path
        self.tmp.cleanup()

    def test_time_bucketing(self) -> None:
        self.assertEqual(analytics.bucket_start(125), 120)

    def test_counter_reset_never_negative(self) -> None:
        with compiler.connect() as conn:
            analytics.collect_dnsdist_aggregate(conn, {"responses": 10, "cache-hits": 4}, ts=120)
            delta = analytics.collect_dnsdist_aggregate(conn, {"responses": 2, "cache-hits": 1}, ts=180)
            self.assertEqual(delta["responses"], 0)
            self.assertEqual(delta["cache_hits"], 0)

    def test_polled_latency_converts_microseconds_to_milliseconds(self) -> None:
        # dnsdist's latency-avg100 stat is documented in microseconds; a prior
        # bug stored it unconverted, inflating dashboard latency ~1000x
        # (e.g. a real 4.1ms average displayed as 4100ms).
        with compiler.connect() as conn:
            delta = analytics.collect_dnsdist_aggregate(conn, {"latency-avg100": 4058.9}, ts=120)
        self.assertAlmostEqual(delta["latency_sum_ms"], 4.0589)
        self.assertEqual(delta["latency_count"], 1)

    def test_allowed_and_blocked_query_counting(self) -> None:
        with compiler.connect() as conn:
            blocked = analytics.QueryEvent(120, "127.0.0.1", "bad.example", "A", "UDP", "NXDOMAIN", 2.0, True)
            allowed = analytics.QueryEvent(121, "127.0.0.1", "ok.example", "A", "TCP", "NOERROR", 3.0, False)
            analytics.insert_events(conn, [blocked, allowed], True)
            row = conn.execute("SELECT * FROM analytics_aggregate_buckets").fetchone()
            self.assertEqual(row["total_queries"], 2)
            self.assertEqual(row["blocked_queries"], 1)
            self.assertEqual(row["allowed_queries"], 1)
            self.assertEqual(row["udp_queries"], 1)
            self.assertEqual(row["tcp_queries"], 1)

    def test_nxdomain_is_not_automatically_blocked(self) -> None:
        event = analytics.event_from_message(
            {"ts": 120, "client": "127.0.0.1", "domain": "ordinary-nx.example", "qtype": "A", "protocol": "UDP", "rcode": "NXDOMAIN"},
            {},
            {"privacy_mode": "full", "client_anonymization": "truncate"},
        )
        self.assertFalse(event.blocked)

    def test_rpz_policy_match_marks_blocked(self) -> None:
        event = analytics.event_from_message(
            {"ts": 120, "client": "127.0.0.1", "domain": "a.bad.example", "qtype": "A", "protocol": "UDP", "rcode": "NXDOMAIN"},
            {"bad.example": ("fixture", "ads_trackers")},
            {"privacy_mode": "full", "client_anonymization": "truncate"},
        )
        self.assertTrue(event.blocked)
        self.assertEqual(event.blocked_domain, "bad.example")
        self.assertEqual(event.block_category, "ads_trackers")

    def test_privacy_modes(self) -> None:
        self.assertEqual(analytics.normalize_client("192.168.10.42", "anonymized_clients", "truncate"), "192.168.10.0/24")
        self.assertTrue(analytics.normalize_client("192.168.10.42", "anonymized_clients", "hash").startswith("anon-"))

    def test_retention_cleanup(self) -> None:
        with compiler.connect() as conn:
            analytics.insert_events(conn, [analytics.QueryEvent(1, "c", "d", "A", "UDP", "NOERROR", None, False)], True)
            analytics.cleanup(conn, {"detailed_retention_days": "0", "aggregate_retention_days": "1", "db_size_limit_bytes": "268435456"})
            self.assertEqual(conn.execute("SELECT count(*) FROM query_events").fetchone()[0], 0)

    def test_db_size_protection_prunes_old_rows(self) -> None:
        with compiler.connect() as conn:
            events = [analytics.QueryEvent(100 + i, "c", f"{i}.example", "A", "UDP", "NOERROR", None, False) for i in range(20)]
            analytics.insert_events(conn, events, True)
            analytics.cleanup(conn, {"detailed_retention_days": "7", "aggregate_retention_days": "1", "db_size_limit_bytes": "1"})
            self.assertLess(conn.execute("SELECT count(*) FROM query_events").fetchone()[0], 20)

    def test_query_log_filtering(self) -> None:
        with compiler.connect() as conn:
            analytics.insert_events(
                conn,
                [
                    analytics.QueryEvent(120, "10.0.0.2", "alpha.example", "A", "UDP", "NOERROR", None, False),
                    analytics.QueryEvent(121, "10.0.0.3", "blocked.example", "AAAA", "DoH", "NXDOMAIN", None, True),
                ],
                True,
            )
        result = analytics.query_log({"blocked": "1", "domain": "blocked"}, page=1, limit=10)
        self.assertEqual(result["total"], 1)
        self.assertEqual(result["rows"][0]["qtype"], "AAAA")

    def test_malformed_event_handling(self) -> None:
        with self.assertRaises(ValueError):
            analytics.protobuf_fields(b"\xff\xff")

    def test_queue_overflow_behavior(self) -> None:
        collector = analytics.Collector()
        collector.events = __import__("queue").Queue(maxsize=1)
        collector.events.put_nowait(analytics.QueryEvent(1, "c", "d", "A", "UDP", "NOERROR", None, False))
        collector.enqueue_message({"ts": 2, "client": "127.0.0.1", "domain": "x.example", "qtype": "A", "protocol": "UDP", "rcode": "NOERROR"})
        self.assertEqual(collector.dropped, 1)

    def test_protobuf_response_decoding(self) -> None:
        question = field_bytes(1, b"example.com.") + field_varint(2, 1)
        response = field_varint(1, 0) + field_varint(5, 99) + field_varint(6, 500000)
        msg = (
            field_varint(1, 2)
            + field_varint(5, 1)
            + field_bytes(6, b"\x7f\x00\x00\x01")
            + field_varint(9, 100)
            + field_varint(10, 0)
            + field_bytes(12, question)
            + field_bytes(13, response)
        )
        decoded = analytics.decode_dnsdist_message(field_bytes(1, msg))[0]
        self.assertEqual(decoded["client"], "127.0.0.1")
        self.assertEqual(decoded["domain"], "example.com")
        self.assertEqual(decoded["qtype"], "A")
        self.assertEqual(decoded["protocol"], "UDP")
        self.assertEqual(decoded["rcode"], "NOERROR")
        self.assertEqual(decoded["latency_ms"], 500.0)

    def _response_msg(self, *, ts: int, usec: int, query_sec: int, query_usec: int = 0, proto: int = 1, http_version: int = 0) -> bytes:
        question = field_bytes(1, b"example.com.") + field_varint(2, 1)
        response = field_varint(1, 0) + field_varint(5, query_sec) + field_varint(6, query_usec)
        msg = (
            field_varint(1, 2)
            + field_varint(5, proto)
            + field_bytes(6, b"\x7f\x00\x00\x01")
            + field_varint(9, ts)
            + field_varint(10, usec)
            + field_bytes(12, question)
            + field_bytes(13, response)
            + field_varint(24, http_version)
        )
        return field_bytes(1, msg)

    def test_one_second_response_displays_as_1000ms(self) -> None:
        decoded = analytics.decode_dnsdist_message(self._response_msg(ts=101, usec=0, query_sec=100, query_usec=0))[0]
        self.assertEqual(decoded["latency_ms"], 1000.0)

    def test_no_multiplication_error_between_microseconds_and_milliseconds(self) -> None:
        # A 4058.9 microsecond dnsdist average must display as ~4.1ms, never
        # ~4058.9ms (missing conversion) or ~0.0041ms (double conversion).
        with compiler.connect() as conn:
            delta = analytics.collect_dnsdist_aggregate(conn, {"latency-avg100": 4058.9}, ts=120)
        self.assertAlmostEqual(round(delta["latency_sum_ms"], 1), 4.1, places=1)

    def test_negative_latency_from_clock_skew_clamped_to_zero(self) -> None:
        # Response timestamp earlier than the recorded query time (clock skew
        # between dnsdist's internal clock reads) must never surface as a
        # negative latency.
        decoded = analytics.decode_dnsdist_message(self._response_msg(ts=100, usec=0, query_sec=100, query_usec=500000))[0]
        self.assertEqual(decoded["latency_ms"], 0.0)
        self.assertGreaterEqual(decoded["latency_ms"], 0.0)

    def test_implausible_latency_is_discarded_not_recorded(self) -> None:
        # A corrupted/misparsed timestamp field (e.g. query time far in the
        # past) must not be recorded as a real multi-day latency and corrupt
        # aggregate averages; it is dropped instead.
        decoded = analytics.decode_dnsdist_message(self._response_msg(ts=1_000_000, usec=0, query_sec=0, query_usec=0))[0]
        self.assertIsNone(decoded["latency_ms"])

    def test_telemetry_delivery_delay_not_counted_as_dns_latency(self) -> None:
        # Latency must derive solely from timestamps embedded in the protobuf
        # payload by dnsdist, never from when the collector happens to decode
        # the frame, so a delayed/backlogged analytics queue cannot inflate
        # reported DNS latency.
        frame = self._response_msg(ts=100, usec=0, query_sec=99, query_usec=500000)
        immediate = analytics.decode_dnsdist_message(frame)[0]["latency_ms"]
        time.sleep(0.05)
        delayed = analytics.decode_dnsdist_message(frame)[0]["latency_ms"]
        self.assertEqual(immediate, delayed)
        self.assertEqual(immediate, 500.0)

    def test_polled_latency_missing_stat_does_not_crash_or_count(self) -> None:
        # dnsdist may not yet report latency-avg100 (e.g. immediately after
        # (re)start before 100 queries have been served); the poll must not
        # crash and must not fabricate a latency sample.
        with compiler.connect() as conn:
            delta = analytics.collect_dnsdist_aggregate(conn, {"responses": 5}, ts=120)
        self.assertNotIn("latency_sum_ms", delta)
        self.assertNotIn("latency_count", delta)

    def test_protocol_classification_across_transports(self) -> None:
        cases = [
            (1, 0, "UDP"),
            (2, 0, "TCP"),
            (3, 0, "DoT"),
            (4, 0, "DoH"),
            (4, 3, "DoH3"),
            (7, 0, "DoQ"),
        ]
        for proto, http_version, expected in cases:
            decoded = analytics.decode_dnsdist_message(
                self._response_msg(ts=101, usec=0, query_sec=100, query_usec=0, proto=proto, http_version=http_version)
            )[0]
            self.assertEqual(decoded["protocol"], expected, f"proto={proto} http_version={http_version}")

    def _create_upstream_resolver(self, conn, resolver_id: int = 7) -> None:
        conn.execute(
            """
            CREATE TABLE upstream_resolvers (
                id INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                protocol TEXT NOT NULL,
                address TEXT NOT NULL,
                port INTEGER NOT NULL,
                doh_path TEXT NOT NULL DEFAULT '',
                enabled INTEGER NOT NULL DEFAULT 1,
                last_status TEXT NOT NULL DEFAULT 'unknown'
            )
            """
        )
        conn.execute(
            """
            INSERT INTO upstream_resolvers(id, name, protocol, address, port, doh_path, enabled, last_status)
            VALUES (?, 'Quad9 DoT', 'dot', '9.9.9.9', 853, '', 1, 'healthy')
            """,
            (resolver_id,),
        )

    def _server_state(self, *, queries: int, responses: int, failures: int = 0, timeouts: int = 0) -> dict:
        return {
            "servers": [
                {"name": "bind-proxy", "pools": ["alderpointdns_bind"], "queries": 10, "responses": 10},
                {
                    "name": "upstream-7-Quad9-DoT",
                    "pools": ["alderpointdns_upstreams"],
                    "address": "9.9.9.9:853",
                    "protocol": "Do53 UDP",
                    "state": "up",
                    "queries": queries,
                    "responses": responses,
                    "sendErrors": failures,
                    "healthCheckFailures": failures,
                    "healthCheckFailuresTimeout": timeouts,
                    "tcpConnectTimeouts": 0,
                    "tcpReadTimeouts": 0,
                    "tcpWriteTimeouts": 0,
                    "tcpGaveUp": 0,
                    "latency": 12.5,
                },
            ]
        }

    def test_upstream_resolver_first_poll_seeds_without_fabricated_delta(self) -> None:
        with compiler.connect() as conn:
            self._create_upstream_resolver(conn)
            collected = analytics.collect_upstream_resolver_aggregate(conn, self._server_state(queries=100, responses=99), ts=120)
            self.assertEqual(collected[0]["queries_attempted"], 0)
            row = conn.execute("SELECT * FROM upstream_resolver_aggregate_buckets").fetchone()
            self.assertEqual(row["resolver_id"], 7)
            self.assertEqual(row["resolver_name"], "Quad9 DoT")
            self.assertEqual(row["protocol"], "DoT")
            self.assertEqual(row["queries_attempted"], 0)

    def test_upstream_resolver_deltas_and_latency_are_stored(self) -> None:
        with compiler.connect() as conn:
            self._create_upstream_resolver(conn)
            analytics.collect_upstream_resolver_aggregate(conn, self._server_state(queries=100, responses=99), ts=120)
            analytics.collect_upstream_resolver_aggregate(conn, self._server_state(queries=105, responses=103, failures=1, timeouts=1), ts=180)
            row = conn.execute(
                """
                SELECT resolver_name, endpoint, queries_attempted, successful_responses, failures,
                       timeouts, latency_sum_ms, latency_count, recent_latency_ms, last_success_at, last_failure_at
                FROM upstream_resolver_aggregate_buckets
                WHERE bucket_start=180
                """
            ).fetchone()
            self.assertEqual(row["resolver_name"], "Quad9 DoT")
            self.assertEqual(row["endpoint"], "tls://9.9.9.9:853")
            self.assertEqual(row["queries_attempted"], 5)
            self.assertEqual(row["successful_responses"], 4)
            self.assertEqual(row["failures"], 3)
            self.assertEqual(row["timeouts"], 1)
            self.assertEqual(row["latency_count"], 4)
            self.assertAlmostEqual(row["latency_sum_ms"], 50.0)
            self.assertEqual(row["recent_latency_ms"], 12.5)
            self.assertIsNotNone(row["last_success_at"])
            self.assertIsNotNone(row["last_failure_at"])

    def test_deleted_resolver_history_remains_in_dashboard_data(self) -> None:
        with compiler.connect() as conn:
            self._create_upstream_resolver(conn)
            analytics.collect_upstream_resolver_aggregate(conn, self._server_state(queries=100, responses=99), ts=analytics.utc_now())
            analytics.collect_upstream_resolver_aggregate(conn, self._server_state(queries=103, responses=102), ts=analytics.utc_now())
            conn.execute("DROP TABLE upstream_resolvers")
        data = analytics.dashboard_data("1h")
        self.assertEqual(data["top_upstreams"][0]["label"], "Quad9 DoT")
        self.assertEqual(data["top_upstreams"][0]["value"], 3)

    def test_upstream_successes_do_not_exceed_attempts(self) -> None:
        with compiler.connect() as conn:
            self._create_upstream_resolver(conn)
            analytics.collect_upstream_resolver_aggregate(conn, self._server_state(queries=100, responses=100), ts=120)
            analytics.collect_upstream_resolver_aggregate(conn, self._server_state(queries=102, responses=103), ts=180)
            row = conn.execute("SELECT queries_attempted, successful_responses FROM upstream_resolver_aggregate_buckets WHERE bucket_start=180").fetchone()
            self.assertEqual(row["queries_attempted"], 2)
            self.assertEqual(row["successful_responses"], 2)


class WriterResilienceTests(unittest.TestCase):
    """Covers analytics.Collector's writer-loop resilience: transient
    database-lock retry/backoff, cleanup-failure isolation, the writer
    heartbeat used for "active but dead" detection, and the
    consecutive-failure threshold that terminates the process so systemd
    restarts it."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        compiler.DB_PATH = root / "alderpointdns.db"
        analytics.DB_PATH = compiler.DB_PATH
        analytics.SECRET_FILE = root / "analytics.secret"
        analytics.HEARTBEAT_FILE = root / "analytics-writer-heartbeat.json"
        analytics.init_analytics_db()
        self.sleep_patch = unittest.mock.patch("app.analytics.time.sleep")
        self.sleep_patch.start()

    def tearDown(self) -> None:
        self.sleep_patch.stop()
        self.tmp.cleanup()

    def _locked_error(self) -> sqlite3.OperationalError:
        return sqlite3.OperationalError("database is locked")

    def test_retry_on_lock_succeeds_after_transient_locks(self) -> None:
        calls = {"n": 0}

        def flaky():
            calls["n"] += 1
            if calls["n"] < 3:
                raise self._locked_error()
            return "ok"

        result, retries = analytics._retry_on_lock(flaky)
        self.assertEqual(result, "ok")
        self.assertEqual(retries, 2)

    def test_retry_on_lock_reraises_non_lock_errors_immediately(self) -> None:
        def broken():
            raise ValueError("not a lock problem")

        with self.assertRaises(ValueError):
            analytics._retry_on_lock(broken)

    def test_retry_on_lock_gives_up_after_exhausting_attempts(self) -> None:
        def always_locked():
            raise self._locked_error()

        with self.assertRaises(sqlite3.OperationalError):
            analytics._retry_on_lock(always_locked, attempts=3, base_delay=0)

    def test_heartbeat_roundtrip_and_staleness(self) -> None:
        self.assertEqual(analytics.writer_health()["status"], "unknown")
        analytics._write_heartbeat("ok")
        health = analytics.writer_health()
        self.assertEqual(health["status"], "ok")
        self.assertFalse(health["stale"])
        payload = json.loads(analytics.HEARTBEAT_FILE.read_text())
        payload["ts"] -= analytics.WRITER_STALE_SECONDS + 5
        analytics.HEARTBEAT_FILE.write_text(json.dumps(payload))
        self.assertTrue(analytics.writer_health()["stale"])

    def test_cleanup_lock_exhaustion_is_skipped_not_fatal(self) -> None:
        collector = analytics.Collector()
        with unittest.mock.patch.object(collector, "_write_events"):
            with unittest.mock.patch.object(collector, "_run_cleanup", side_effect=self._locked_error()):
                collector._writer_cycle([], {})
        self.assertEqual(collector.writer_consecutive_failures, 1)
        self.assertFalse(collector.fatal_error.is_set())

    def test_writer_recovers_after_transient_failure_resets_counter(self) -> None:
        collector = analytics.Collector()
        collector.writer_consecutive_failures = 3
        with unittest.mock.patch.object(collector, "_write_events"):
            with unittest.mock.patch.object(collector, "_run_cleanup"):
                with unittest.mock.patch.object(collector, "_notify_writer") as notify:
                    collector._writer_cycle([], {})
        self.assertEqual(collector.writer_consecutive_failures, 0)
        notify.assert_called_once()
        self.assertEqual(notify.call_args.kwargs.get("recovered"), True)
        self.assertEqual(analytics.writer_health()["status"], "ok")

    def test_writer_terminates_after_max_consecutive_failures(self) -> None:
        collector = analytics.Collector()
        with unittest.mock.patch.object(collector, "_write_events", side_effect=RuntimeError("db unreachable")):
            with unittest.mock.patch.object(collector, "_notify_writer") as notify:
                for _ in range(analytics.WRITER_MAX_CONSECUTIVE_FAILURES):
                    collector._writer_cycle([], {})
        self.assertTrue(collector.fatal_error.is_set())
        self.assertTrue(collector.stop_event.is_set())
        self.assertEqual(analytics.writer_health()["status"], "dead")
        notify.assert_called_once()
        self.assertEqual(notify.call_args.kwargs.get("recovered"), False)

    def test_writer_does_not_terminate_below_failure_threshold(self) -> None:
        collector = analytics.Collector()
        with unittest.mock.patch.object(collector, "_write_events", side_effect=RuntimeError("db unreachable")):
            for _ in range(analytics.WRITER_MAX_CONSECUTIVE_FAILURES - 1):
                collector._writer_cycle([], {})
        self.assertFalse(collector.fatal_error.is_set())
        self.assertFalse(collector.stop_event.is_set())
        self.assertEqual(analytics.writer_health()["status"], "degraded")


if __name__ == "__main__":
    unittest.main()
