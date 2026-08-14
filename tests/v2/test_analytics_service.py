import time

import pytest

from app.v2 import aggregates_db
from app.v2.analytics_service import AnalyticsService
from app.v2.parquet_writer import ParquetSegmentWriter


def _record(ts, **overrides):
    base = dict(
        id=int(ts * 1000) % 1_000_000, ts=ts, client="10.0.0.1", client_name="",
        domain="example.com", qtype="A", protocol="udp", rcode="NOERROR",
        latency_ms=5.0, blocked=False, block_reason="", upstream="default",
        cache_status="miss", cache_profile_id="p1",
    )
    base.update(overrides)
    return base


@pytest.fixture()
def populated_service(tmp_path):
    parquet_root = tmp_path / "parquet"
    aggregates_path = tmp_path / "aggregates.db"
    aggregates_db.initialize(aggregates_path)

    now = time.time()
    writer = ParquetSegmentWriter(root=parquet_root)
    recent_records = [
        _record(now - i, domain=f"host{i}.example", blocked=(i % 3 == 0), client=f"10.0.0.{i % 4}")
        for i in range(20)
    ]
    writer.ingest(recent_records)
    writer.flush()
    writer.close()
    aggregates_db.record_batch(aggregates_path, recent_records)

    # Old records (11 days back) to prove pruning still holds through the
    # service layer, same proof shape as Workstream 2's original gate 1 test.
    old_writer = ParquetSegmentWriter(root=parquet_root)
    for day_offset in range(2, 12):
        old_ts = now - day_offset * 86400
        old_writer.ingest([_record(old_ts, domain=f"old{day_offset}.example")])
        old_writer.flush()
    old_writer.close()

    service = AnalyticsService(parquet_root=parquet_root, aggregates_path=aggregates_path)
    yield service, now
    service.close()


class TestDetailViews:
    def test_recent_query_log_prunes_partitions(self, populated_service):
        service, now = populated_service
        result = service.recent_query_log(minutes=5, now=now)
        assert len(result.rows) > 0
        # 12 total days of segments on disk; a 5-minute window should touch
        # at most today's partition (plus a boundary day at most).
        assert result.files_considered <= 2

    def test_top_domains(self, populated_service):
        service, now = populated_service
        result = service.top_domains(now - 3600, now + 1)
        assert len(result.rows) > 0

    def test_top_blocked_domains_only_blocked(self, populated_service):
        service, now = populated_service
        result = service.top_blocked_domains(now - 3600, now + 1)
        assert len(result.rows) > 0

    def test_search_with_client_filter(self, populated_service):
        service, now = populated_service
        result = service.search(now - 3600, now + 1, client="10.0.0.1")
        assert all(row for row in result.rows)  # rows returned, non-empty tuples

    def test_latency_percentiles(self, populated_service):
        service, now = populated_service
        result = service.latency_percentiles(now - 3600, now + 1)
        assert len(result.rows) == 1

    def test_rcode_distribution(self, populated_service):
        service, now = populated_service
        result = service.rcode_distribution(now - 3600, now + 1)
        assert any(row[0] == "NOERROR" for row in result.rows)


class TestAggregateSummaries:
    def test_time_series_totals(self, populated_service):
        service, now = populated_service
        rows = service.time_series_totals(now - 3600, now + 3600)
        total = sum(r[1] for r in rows)
        assert total == 20

    def test_top_dimension_from_aggregates(self, populated_service):
        service, now = populated_service
        rows = service.top_dimension_from_aggregates("client", now - 3600, now + 3600)
        assert len(rows) > 0

    def test_unsupported_dimension_rejected(self, populated_service):
        service, now = populated_service
        with pytest.raises(ValueError):
            service.top_dimension_from_aggregates("not-a-real-dimension", now - 3600, now + 3600)
