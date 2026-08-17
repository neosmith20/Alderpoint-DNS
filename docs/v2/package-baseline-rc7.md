# V2 private RC7 — spoofed/blocked traffic now visible in analytics, real proof (roadmap Priority 6)

## Artifact

- Package/version: `alderpointdns-v2` `2.0.0~rc7-1`
- Filename: `alderpointdns-v2_2.0.0~rc7-1_all.deb`
- SHA-256: `904dfac58da0fe0a5d857496007e1cdcd71bb45a478a82d4f8fe49ebec1f2d56`
- Source SHA: commit "Fix real gap in the new analytics wiring: spoofed/
  blocked/local-DNS answers were invisible"

## What this fixes

RC6's own hardware spot-check (a routine dnsperf run against a local
DNS record) surfaced a real gap in the analytics wiring shipped in
RC6: `RemoteLogResponseAction` alone never fires for a terminally
spoofed query. Confirmed with a live capture: dnsdist sends a real
`RemoteLogAction` (query-time) message for a spoofed query but never
a corresponding response-time message at all. Since local DNS records,
blocked domains, and SafeSearch rewrites are all implemented as
`SpoofAction`/`SpoofCNAMEAction`, this meant the single most
filtering-relevant category of traffic on a DNS-filtering appliance --
exactly what got blocked or rewritten -- was invisible to its own
analytics, silently, in RC6.

Fixed by wiring `RemoteLogAction` too and correlating query/response
messages by the real DNS transaction id in the receiver (full detail
in the commit message and `app/v2/dnsdist_protobuf.py`'s module
docstring).

## Real live proof (RC7, fresh clean install)

Fresh Debian 13 container, real `apt-get install`, 0 failed units.

- Real local-DNS query (`rc7-local.test` -> `10.7.7.7`, a real
  `SpoofAction`): **now produces a real analytics event**
  (`{"qname":"rc7-local.test.","rcode":"NOERROR",...}`) -- this exact
  case produced nothing at all under RC6.
- Real backend-forwarded query (`rc7-upstream-test2.example`, real
  `NXDOMAIN` from a real root-server round trip): still produces
  exactly one correct event with the real rcode -- confirms the fix
  didn't disturb the already-working path.
- `GET /api/analytics/top-domains` through the real HTTPS management
  API correctly reflects the local-DNS query with the right count (no
  double-counting from the query+response correlation).

## Residual, unchanged from RC6

Cache-status detection, per-client query-log/statistics exclusions,
and independent IPv6-client verification remain real open follow-up
items (see `docs/v2/package-baseline-rc6.md`) -- not attempted this
pass, unrelated to the spoofed-traffic gap this pass closed.
