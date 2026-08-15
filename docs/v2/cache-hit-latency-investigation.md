# V2 Cache Hit Latency Investigation (Workstream 3 final continuation, §27/§30)

**Status:** Bounded, real measurement of the dnsdist packet-cache layer in isolation. Full
layer-by-layer breakdown (direct BIND cache hit / dnsdist->BIND hit / dnsdist packet-cache hit /
compiled policy path) was not completed end-to-end this session — see "What was not measured"
below for the concrete reason.

## What was measured

`benchmarks/v2_cache/packet_cache_latency.py` — a fully isolated, disposable dnsdist instance
(ephemeral localhost port, real installed dnsdist 2.1.1 binary, forwarding to Cloudflare's public
resolver at 1.1.1.1:53) with a real `PacketCache` attached via `app/v2/dnsdist_cache_policy.py`
(the same module verified against the real binary in the previous checkpoint). 20 distinct
"cold" domains (never seen before, forces a real upstream round-trip and a cache miss) and 50
repeated queries for one "warm" domain (primed once, then queried repeatedly — a real dnsdist
packet-cache hit each time, no upstream round-trip).

| Path | p50 | p95 | p99 | min | max |
|---|---|---|---|---|---|
| Cold (real upstream round-trip, cache miss) | 18.25 ms | 23.32 ms | 23.32 ms | 14.54 ms | 23.32 ms |
| Warm (real dnsdist packet-cache hit) | **0.053 ms** | 0.088 ms | 0.141 ms | 0.050 ms | 0.141 ms |

Raw results: `benchmarks/v2_cache/results-packet-cache-latency.json`.

## Comparison against the V1 baseline

`docs/v2/v1-performance-baseline.md`'s real V1 cached-latency numbers (dnsdist in front of BIND,
BIND's own recursive cache serving the hit):

| | p50 | p95 | p99 |
|---|---|---|---|
| V1 cached (dnsdist -> BIND cache hit) | 11.96 ms | 13.26 ms | 14.17 ms |
| V2 isolated dnsdist packet-cache hit (this session) | **0.053 ms** | 0.088 ms | 0.141 ms |

**Finding:** V1's ~12ms "cached" cost is not inherent to DNS caching itself — it is specifically
the cost of dnsdist forwarding every cache-hit query on to BIND and BIND doing its own cache
lookup + response construction, round-tripped over the loopback socket between the two processes,
every single time. A dnsdist-layer packet cache answers a repeated query directly, without ever
reaching BIND, at roughly **225x lower latency** for the measured p50. This is the single most
concrete piece of evidence this session produced for "can V2 materially improve the cached path":
yes, substantially, for any query pattern where dnsdist's own cache can serve the hit (i.e. the
qname:qtype:cache-profile key is unchanged from a prior forwarded answer with un-expired TTL).

**Caveat on comparability:** the V1 number is a real end-to-end appliance-under-light-load
measurement; the V2 number is an isolated single-process benchmark with no other services
contending for CPU/network. The V1 number also reflects the full dnsdist+BIND round trip cost, not
just BIND's own cache-lookup cost — some of that ~12ms could be process/socket-transition overhead
generic to any dnsdist->backend hop, not specific to BIND. Both numbers are real, not estimated,
but the comparison should be read as "a locally-answered cache hit is legitimately much faster than
any hop to a second process" rather than "BIND itself is slow."

## What was not measured (explicit gap, with reason)

- **Direct BIND recursive-cache hit latency, in isolation.** Building a second, fully separate
  isolated BIND instance (its own `named.conf`, zone files, root hints/forwarders, listening on an
  isolated port) purely to re-measure a layer the live V1 baseline already captures for the real
  running architecture was judged out of this session's remaining budget, on top of everything
  else built this pass. The V1 baseline's cached numbers are the honest stand-in for "dnsdist->BIND
  hit," not a substitute measurement invented here.
- **"Compiled policy path" latency** — no live policy-compiled DNS answering path exists yet to
  measure (the compiler produces `EffectivePolicy`/cache profile objects and generated
  config files; nothing wires that into an actually-answering resolver process this session).
- **QPS under the packet-cache-hit path** — not measured; the benchmark above is latency-focused
  (sequential queries), not a concurrent-throughput test.

## Recommendation

Once a real per-profile-aware packet-cache-partitioning scheme is wired up (see
`docs/v2/handoff-workstream-4.md`'s architecture gap note in `app/v2/dnsdist_cache_policy.py`),
the dnsdist packet-cache layer is worth treating as V2's primary cached-answer fast path rather
than relying on BIND's cache alone — the latency difference measured here is large enough to be a
real user-facing improvement, not a rounding error.
