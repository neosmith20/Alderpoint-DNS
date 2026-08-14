#!/usr/bin/env python3
"""Synthetic Alderpoint DNS query-record generator for the V2 analytics
storage benchmark (V2 Workstream 1).

Produces a list of dict records with fields modeled on v1's `query_events`
table (see docs/v2/storage-audit.md) plus the additional fields the roadmap
calls out (upstream, cache status). Distributions are deliberately skewed
(Zipfian domains/clients, mostly NOERROR, a blocked minority) rather than
uniform, per the workstream brief's "no toy uniform 100-row dataset" rule.
"""
from __future__ import annotations

import random
import time
from typing import Iterator

QTYPES = ["A", "A", "A", "AAAA", "AAAA", "HTTPS", "PTR", "CNAME", "TXT", "SRV"]
PROTOCOLS = ["udp", "udp", "udp", "tcp", "doh", "dot", "doq"]
RCODES = ["NOERROR"] * 92 + ["NXDOMAIN"] * 6 + ["SERVFAIL"] * 1 + ["REFUSED"] * 1
CACHE_STATUS = ["hit", "hit", "hit", "miss", "miss"]
BLOCK_CATEGORIES = ["ads_trackers", "malware", "adult", "social_media", "custom"]
UPSTREAMS = ["upstream-1 (1.1.1.1)", "upstream-2 (9.9.9.9)", "upstream-3 (dot://quad9)"]

_POPULAR_DOMAINS = [
    "www.google.com", "clients4.google.com", "connectivitycheck.gstatic.com",
    "graph.facebook.com", "api.spotify.com", "www.netflix.com", "outlook.office365.com",
    "www.apple.com", "push.apple.com", "cdn.ampproject.org", "s3.amazonaws.com",
    "googleads.g.doubleclick.net", "analytics.google.com", "www.youtube.com",
    "api.github.com", "ntp.org", "time.windows.com", "dns.msftncsi.com",
]
_BLOCKED_POPULAR = [
    "ads.doubleclick.net", "telemetry.microsoft.com", "graph.facebook.com",
    "tracking.example-ad-network.com", "metrics.segment.io",
]


def _zipfian_pool(prefix: str, count: int, seed: int) -> list[str]:
    rnd = random.Random(seed)
    return [f"{prefix}{rnd.randrange(16**8):08x}.example-long-tail.net" for _ in range(count)]


def _weighted_choice(rnd: random.Random, pool: list[str], zipf_s: float) -> str:
    # Approximate a Zipfian pick over a fixed pool using an index drawn from
    # a Zipf distribution, clamped into range.
    idx = min(int(rnd.paretovariate(zipf_s)) , len(pool) - 1)
    return pool[idx]


def generate_records(n: int, *, seed: int = 1337, start_ts: float | None = None) -> Iterator[dict]:
    """Yield ``n`` synthetic query records. Streams (does not build a list in
    memory) so callers can batch-ingest without holding all N in RAM.
    """
    rnd = random.Random(seed)
    start_ts = start_ts if start_ts is not None else time.time() - 86400 * 7

    long_tail_domains = _zipfian_pool("q", max(2000, n // 50), seed)
    domain_pool = _POPULAR_DOMAINS + long_tail_domains
    client_pool = [f"192.168.{rnd.randrange(1, 20)}.{i}" for i in range(1, 61)]
    client_names = {c: (f"client-{i}" if rnd.random() < 0.6 else None) for i, c in enumerate(client_pool)}

    for i in range(n):
        ts = start_ts + rnd.random() * 7 * 86400
        # 85% of traffic concentrated on the popular pool (Zipf-ish), 15% long tail.
        if rnd.random() < 0.85:
            domain = rnd.choice(_POPULAR_DOMAINS)
        else:
            domain = rnd.choice(long_tail_domains)

        client = _weighted_choice(rnd, client_pool, zipf_s=1.8)
        blocked = rnd.random() < 0.07
        if blocked and rnd.random() < 0.5:
            domain = rnd.choice(_BLOCKED_POPULAR)

        rcode = "NXDOMAIN" if blocked else rnd.choice(RCODES)
        latency = round(rnd.gauss(8.0 if rnd.random() < 0.7 else 45.0, 6.0), 2)
        latency = max(0.1, latency)

        yield {
            "id": i,
            "ts": ts,
            "client": client,
            "client_name": client_names.get(client),
            "domain": domain,
            "qtype": rnd.choice(QTYPES),
            "protocol": rnd.choice(PROTOCOLS),
            "rcode": rcode,
            "latency_ms": latency,
            "blocked": blocked,
            "block_reason": rnd.choice(BLOCK_CATEGORIES) if blocked else None,
            "upstream": rnd.choice(UPSTREAMS),
            "cache_status": rnd.choice(CACHE_STATUS),
        }


if __name__ == "__main__":
    import json
    import sys

    n = int(sys.argv[1]) if len(sys.argv) > 1 else 10
    for rec in generate_records(n):
        print(json.dumps(rec))
