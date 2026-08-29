#!/bin/sh
# Seeds 3 real rows into a Go-native analytics.db's query_events table,
# for chromium_smoke.mjs's Dashboard/Query Log real-data checks.
#
# Replaces the old make_query_log_fixture.py (pyarrow, wrote a Parquet
# segment for internal/rawquerylog's Python-Parquet compatibility
# boundary) -- that boundary is gone (internal/rawquerylog now reads
# straight from this same query_events table, see main.go's
# "RawQueryLog: analyticsReader" wiring), so a plain sqlite3 INSERT is
# the real equivalent now: no pyarrow/dev venv dependency needed.
#
# The three rows are deliberately identical in shape/domain-name/client
# choice to make_query_log_fixture.py's own fixture, so chromium_smoke.mjs's
# existing assertions (3 rows, one client with 2 blocked queries under
# "acceptance-blocked.example.com.", one allowed under
# "acceptance-allowed.example.com.") keep meaning the same thing.
#
# Usage: sh go/tests/fixtures/seed_query_events.sh <path-to-analytics.db>
set -eu
DB="$1"
NOW=$(date +%s)
sqlite3 "$DB" <<SQL
INSERT INTO query_events (ts, domain, qtype, rcode, protocol, client, latency_ms, outcome) VALUES
  ($((NOW - 30)), 'acceptance-blocked.example.com.', 'A', 'NXDOMAIN', 'udp', '10.10.10.5', 0.8, 'blocked'),
  ($((NOW - 20)), 'acceptance-allowed.example.com.', 'AAAA', 'NOERROR', 'udp', '10.10.10.6', 1.5, 'allowed'),
  ($((NOW - 10)), 'acceptance-blocked.example.com.', 'A', 'NXDOMAIN', 'tcp', '10.10.10.5', 0.6, 'blocked');
SQL
echo "seeded 3 rows into $DB"
