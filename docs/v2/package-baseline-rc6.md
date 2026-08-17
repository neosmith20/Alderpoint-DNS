# V2 private RC6 — analytics-ingestion wiring, real end-to-end proof (roadmap Priority 6/12)

## Artifact

- Package/version: `alderpointdns-v2` `2.0.0~rc6-1`
- Filename: `alderpointdns-v2_2.0.0~rc6-1_all.deb`
- SHA-256: `0ebbe9f7cf10b21e9809e978a25aaadf30f59e188b9538fb579ef8935c62d460`
- Source SHA: commit "Bump private candidate to rc6 for the
  analytics-ingestion wiring commit" (immediately after "Wire real
  dnsdist query traffic to analytics ingestion")

## Real clean-install acceptance

Fresh Debian 13 container, real `apt-get install` of RC6: exit 0, all
9 services (the new `alderpointdns-v2-analytics-protobuf-receiver`
included) + the reload path unit active, 0 failed units. Real
generated `dnsdist.conf` confirmed to contain the new wiring:

```
query_log_rl = newRemoteLogger("127.0.0.1:5391")
addResponseAction(AllRule(), RemoteLogResponseAction(query_log_rl))
```

## Real end-to-end analytics proof (the actual gap this closes)

Six real DNS queries (five never-seen-before names + `example.com`)
issued against the real installed `dnsdist` -- no test shortcuts, no
direct library calls, no synthetic `--inject-test-event`:

1. Real events landed in `/var/lib/alderpointdns-v2/analytics/inbox/`
   within ~2 seconds (real protobuf receiver decoding real dnsdist
   traffic).
2. Restarting `alderpointdns-v2-analytics` (forcing the current
   in-memory segment to close, since a segment only finalizes to a real
   `.parquet` file on size/time rollover or graceful shutdown by
   design -- confirmed this is the existing, documented rollover
   contract, not a defect found this pass) produced a real closed
   Parquet segment:
   `/var/lib/alderpointdns-v2/analytics/queries/2026/08/17/11-000000.parquet`.
3. `GET /api/analytics/top-domains` through the real HTTPS management
   API returned all six real queried domains with correct counts --
   the first time in this project's history that a real, unmodified
   end-user query through the packaged appliance has ever shown up in
   its own analytics.

## What remains open (real scope, not attempted this pass)

- Cache-status detection (`hit`/`miss`/`prewarm`) isn't populated from
  the protobuf message -- defaults to `"miss"` for every event, since
  no field was empirically verified to carry it this pass (see
  `app/v2/dnsdist_protobuf.py`'s module docstring for exactly what was
  and wasn't verified). Real value, not a placeholder guess, but
  incomplete.
- Per-client `query_log_enabled`/`statistics_enabled` policy exclusions
  aren't consulted by the receiver -- every query is logged
  unconditionally. `NormalizedQueryEvent` already has these fields
  (defaulting to enabled); wiring real per-client policy lookups into
  the receiver (or a later pipeline stage) is a real follow-up, not
  done this pass.
- IPv6 client addresses in the protobuf `from` field are handled by
  code but not independently verified against a real IPv6 query this
  session (only the IPv4 case was captured and confirmed).
- `RemoteLogAction` (pre-resolution query hook) was deliberately never
  wired -- only `RemoteLogResponseAction` -- since the response message
  alone already carries everything needed; this is a scope decision,
  not an oversight, documented in the module itself.
