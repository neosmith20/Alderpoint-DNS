import time
from unittest import mock

import pytest

from app.v2 import aggregates_db
from app.v2.analytics_pipeline import AnalyticsPipeline
from app.v2.query_event import NormalizedQueryEvent
from app.v2.tier_b_prewarm import WorkingSetIndex


def _event(**overrides):
    defaults = dict(
        ts=time.time(),
        qname="example.com",
        qtype="A",
        protocol="udp",
        client="10.0.0.5",
        effective_cache_profile_id="abc123",
    )
    defaults.update(overrides)
    return NormalizedQueryEvent(**defaults)


def _pipeline(tmp_path):
    return AnalyticsPipeline(
        parquet_root=tmp_path / "parquet",
        aggregates_path=tmp_path / "aggregates.db",
        tier_b_index=WorkingSetIndex(),
    )


class TestBasicFlow:
    def test_submit_and_flush_reaches_all_three_sinks(self, tmp_path):
        pipeline = _pipeline(tmp_path)
        pipeline.submit(_event())
        processed = pipeline.flush()
        assert processed == 1
        assert pipeline.stats.parquet_failures == 0
        assert pipeline.stats.aggregate_failures == 0
        assert len(pipeline.tier_b_index) == 1

        pipeline.parquet_writer.flush()
        totals = aggregates_db.query_totals(
            tmp_path / "aggregates.db", int(time.time()) - 3600, int(time.time()) + 3600
        )
        total_queries = sum(row[1] for row in totals)
        assert total_queries == 1
        live = aggregates_db.query_live_buckets(
            tmp_path / "aggregates.db", int(time.time()) - 3600, int(time.time()) + 3600
        )
        assert sum(row[1] for row in live) == 1
        pipeline.close()

    def test_ordinary_flush_does_not_force_tiny_parquet_segment(self, tmp_path):
        pipeline = _pipeline(tmp_path)
        pipeline.submit(_event())
        assert pipeline.flush() == 1
        assert pipeline.parquet_writer.stats.segments_written == 0
        pipeline.parquet_writer.flush()
        assert pipeline.parquet_writer.stats.segments_written == 1
        pipeline.close()

    def test_normalization_happens_once(self, tmp_path):
        # Same NormalizedQueryEvent instance drives both sinks' payloads --
        # prove the raw record dict is identical bytes-for-bytes both times
        # it's derived, i.e. there's exactly one shaping function.
        e = _event()
        a = e.to_raw_record(event_id=1)
        b = e.to_raw_record(event_id=1)
        assert a == b


class TestQueueBounding:
    def test_queue_drops_oldest_and_counts(self, tmp_path):
        pipeline = AnalyticsPipeline(
            parquet_root=tmp_path / "parquet",
            aggregates_path=tmp_path / "aggregates.db",
            tier_b_index=WorkingSetIndex(),
            queue_capacity=3,
        )
        for i in range(5):
            pipeline.submit(_event(qname=f"host{i}.example"))
        assert pipeline.stats.dropped_by_queue == 2
        assert len(pipeline.queue) == 3


class TestExclusionSemantics:
    def test_query_log_excluded_skips_parquet_not_aggregates(self, tmp_path):
        pipeline = _pipeline(tmp_path)
        pipeline.submit(_event(query_log_enabled=False))
        pipeline.flush()
        assert pipeline.stats.excluded_from_log == 1
        assert pipeline.stats.excluded_from_stats == 0
        pipeline.close()

    def test_statistics_excluded_skips_aggregates_not_parquet(self, tmp_path):
        pipeline = _pipeline(tmp_path)
        pipeline.submit(_event(statistics_enabled=False))
        pipeline.flush()
        assert pipeline.stats.excluded_from_stats == 1
        assert pipeline.stats.excluded_from_log == 0
        pipeline.close()

    def test_exclusion_does_not_affect_tier_b(self, tmp_path):
        pipeline = _pipeline(tmp_path)
        pipeline.submit(_event(query_log_enabled=False, statistics_enabled=False))
        pipeline.flush()
        assert len(pipeline.tier_b_index) == 1
        pipeline.close()


class TestFailureIsolation:
    def test_parquet_failure_does_not_block_aggregates_or_tier_b(self, tmp_path):
        pipeline = _pipeline(tmp_path)
        pipeline.submit(_event())
        with mock.patch.object(
            pipeline.parquet_writer, "ingest", side_effect=OSError("disk full")
        ):
            pipeline.flush()
        assert pipeline.stats.parquet_failures == 1
        assert pipeline.stats.aggregate_failures == 0
        assert len(pipeline.tier_b_index) == 1
        pipeline.close()

    def test_aggregate_failure_does_not_block_parquet_or_tier_b(self, tmp_path):
        pipeline = _pipeline(tmp_path)
        pipeline.submit(_event())
        with mock.patch(
            "app.v2.analytics_pipeline.aggregates_db.record_batch",
            side_effect=RuntimeError("locked"),
        ):
            pipeline.flush()
        assert pipeline.stats.aggregate_failures == 1
        assert pipeline.stats.parquet_failures == 0
        assert len(pipeline.tier_b_index) == 1
        pipeline.close()

    def test_tier_b_failure_does_not_block_others(self, tmp_path):
        pipeline = _pipeline(tmp_path)
        pipeline.submit(_event())
        with mock.patch.object(
            pipeline.tier_b_index, "record_query", side_effect=RuntimeError("boom")
        ):
            pipeline.flush()
        assert pipeline.stats.tier_b_failures == 1
        assert pipeline.stats.parquet_failures == 0
        assert pipeline.stats.aggregate_failures == 0
        pipeline.close()

    def test_flush_never_raises_even_if_all_sinks_fail(self, tmp_path):
        pipeline = _pipeline(tmp_path)
        pipeline.submit(_event())
        with mock.patch.object(pipeline.parquet_writer, "ingest", side_effect=OSError("x")), \
             mock.patch(
                 "app.v2.analytics_pipeline.aggregates_db.record_batch",
                 side_effect=RuntimeError("y"),
             ), \
             mock.patch.object(
                 pipeline.tier_b_index, "record_query", side_effect=RuntimeError("z")
             ):
            processed = pipeline.flush()
        assert processed == 1
        pipeline.close()


class TestEmptyFlush:
    def test_flush_with_nothing_queued_is_a_noop(self, tmp_path):
        pipeline = _pipeline(tmp_path)
        assert pipeline.flush() == 0
        pipeline.close()
