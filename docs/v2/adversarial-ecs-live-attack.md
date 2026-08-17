# ECS boundary isolation: live wire-level attack (roadmap Priority 10 continuation)

Closes the last item `docs/v2/adversarial-security-pass.md` and
`docs/v2/adversarial-dns-policy-live-pass.md` both left open: ECS
(EDNS Client Subnet) boundary isolation, attacked live rather than only
unit-tested (`tests/v2/test_ecs_policy.py` covers generation/
`--check-config` correctness, not what actually goes out on the wire).

## Setup

Same real installed `private12` package as the other live passes (fresh
Debian 13 container, real postinst, real services). Built a minimal
real UDP DNS responder (`/tmp/ecs_probe.py`, not committed -- throwaway
test tooling) that parses the real EDNS0 OPT RR of every query it
receives for option code 8 (Client Subnet) and logs the qname + whether
ECS was present + the decoded family/prefix/address bytes, then answers
with a fixed A record so dnsdist gets a valid response. Registered it as
a real `/api/upstreams` profile (`ecs-probe`, plain transport,
`127.0.0.1:5390`) and pointed two real `/api/networks` policies at it:
`net-ecs-on` (127.0.0.4/32, `ecs_mode=preserve`) and `net-ecs-off`
(127.0.0.5/32, `ecs_mode=disabled`).

## Attack

Queried one fresh, never-seen-before qname from each source IP against
the real dnsdist listener, then inspected the probe's real captured
wire-level log (qname-attributed, not inferred):

```
qname=abc-ecs-on-final.example  has_ecs=True  family=1 source_prefix=24 scope=0 addr_bytes=7f0000
qname=xyz-ecs-off-final.example has_ecs=False
```

`family=1` (IPv4), `source_prefix=24`, `addr_bytes=7f0000` decodes to
`127.0.0.0/24` -- the querying client's own real subnet, correctly
truncated to the configured prefix length, attached only for the
`preserve`-mode network. The `disabled`-mode network's query reached
the identical upstream with no ECS option at all -- no leakage of client
subnet information when the policy says not to send it.

(Earlier passes at this same test, before qname-attribution was added to
the probe, saw dnsdist's own periodic backend health-check traffic
interleaved with the real queries in the log and correctly showed the
same has_ecs=True/False split by count, but weren't directly attributable
per-query -- this final run removes that ambiguity.)

## Result

No defect found. ECS boundary isolation holds at the real wire level,
not just at config-generation time.

This closes the full list of DNS/policy items `adversarial-security-pass.md`
flagged as unit-tested-only: cross-policy cache leakage, SafeSearch
isolation, REFUSED correctness (all three: `adversarial-dns-policy-live-pass.md`),
and now ECS boundary isolation. DoH downgrade already has real live
end-to-end coverage (`tests/v2/test_doh_no_downgrade.py`'s
`TestRealEndToEndDoH`, a real dnsdist config performing a real TLS
handshake and resolving over HTTPS against a real public DoH provider) --
not re-attacked separately this pass since that test already is a live
attack, not a mock.

Container removed after verification, not retained as a running service.
