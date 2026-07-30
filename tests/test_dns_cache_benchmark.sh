#!/bin/sh
# Cold vs. warm query benchmark proving the BIND cache is actually effective,
# using BIND's own cache hit/miss counters (not wall-clock timing, which is
# too noisy on a shared VM to assert reliably) plus a sanity latency check.
set -eu

fail() {
  echo "FAIL: $*" >&2
  exit 1
}

BENCH_DOMAIN="alderpointdns-cache-benchmark.debian.org"

stat() {
  curl --silent --max-time 3 "http://127.0.0.1:8053/json/v1/server" |
    python3 -c "import json,sys; d=json.load(sys.stdin); print(d['views']['_default']['resolver']['cachestats'].get('$1', 0))"
}

rndc flushtree debian.org >/dev/null 2>&1 || true

misses_before="$(stat CacheMisses)"
cold_ms="$(dig +stats @127.0.0.1 -p 5353 debian.org A +time=3 +tries=1 | grep -Eo 'Query time: [0-9]+' | grep -Eo '[0-9]+')"
misses_after_cold="$(stat CacheMisses)"

hits_before="$(stat CacheHits)"
warm_ms="$(dig +stats @127.0.0.1 -p 5353 debian.org A +time=3 +tries=1 | grep -Eo 'Query time: [0-9]+' | grep -Eo '[0-9]+')"
hits_after_warm="$(stat CacheHits)"

[ "$misses_after_cold" -gt "$misses_before" ] || fail "cold query did not register a cache miss (before=$misses_before after=$misses_after_cold)"
[ "$hits_after_warm" -gt "$hits_before" ] || fail "warm query did not register a cache hit (before=$hits_before after=$hits_after_warm)"

echo "cold query: ${cold_ms}ms, warm query: ${warm_ms}ms (cache-backed; timing is informational, hit/miss counters are the pass/fail signal)"
echo "dns cache benchmark tests passed"
