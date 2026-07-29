#!/usr/bin/env python3
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

import sys

sys.path.insert(0, "/opt/bindguard")

from app import analytics  # noqa: E402
from app import bindguard_compiler as compiler  # noqa: E402


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
        compiler.DB_PATH = root / "bindguard.db"
        compiler.DOWNLOAD_DIR = root / "downloads"
        compiler.STAGING_DIR = root / "staging"
        compiler.COMPILED_RPZ = root / "compiled" / "bindguard.rpz"
        analytics.DB_PATH = compiler.DB_PATH
        analytics.SECRET_FILE = root / "analytics.secret"
        analytics.init_analytics_db()

    def tearDown(self) -> None:
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


if __name__ == "__main__":
    unittest.main()
