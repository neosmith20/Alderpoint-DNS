# Adversarial DNS/policy live pass (roadmap Priority 10 continuation)

`docs/v2/adversarial-security-pass.md` (private12 session) explicitly listed
cross-policy cache leakage, SafeSearch isolation, and REFUSED-semantics
correctness as "not covered this session (real scope remaining)" -- covered
only by unit tests, not live attack. This closes that gap with real live
attacks against a real installed package.

## Setup

Fresh Debian 13 container (`localhost/apdns-v2-4c-accept-base:trixie`,
`--privileged --systemd=always`), real `apt-get install` of the exact
accepted `private12` artifact
(`alderpointdns-v2_2.0.0~private12-1_all.deb`,
`sha256:5dc83c855269de8ae2523a2b350fabbf06429a2641e4378595e4376a8d5fb966`
-- re-verified against the retained copy before use). All five V2
services came up `active` from the real postinst. Bootstrapped a real
admin account through `/api/setup` + `/api/login` (real Argon2id-hashed
credential, real session cookie + CSRF token, not a test shortcut).

Two extra loopback addresses (`127.0.0.2`, `127.0.0.3`) added so two
distinct real source IPs could be scoped by real `/api/networks` CIDR
policy bindings and queried against the real `dnsdist` listener on
`0.0.0.0:53` -- not a synthetic/mocked resolver.

## Attack 1: SafeSearch isolation + cross-policy packet-cache leakage

`net-strict` (127.0.0.2) set to `safesearch_mode=strict`; `net-open`
(127.0.0.3) set to `safesearch_mode=off`. Both queried `google.com A`
against the real dnsdist, interleaved specifically to try to force a
cache leak (strict first to warm the cache with the CNAME rewrite, then
open immediately after, then both again):

- `net-strict` -> `google.com. CNAME forcesafesearch.google.com.` (both times)
- `net-open` -> `google.com. A 142.251.46.142` (real answer, both times)

No leakage in either direction after the packet cache was warmed by the
other policy. Confirms dnsdist's cache key genuinely includes policy
scoping for this codebase's SafeSearch rewrite, not just qname/qtype.

## Attack 2: REFUSED-semantics correctness + isolation

Seeded a real test service (`policy_store.create_service`) blocking
`blockme.example`, wired it into `net-strict` via a real
`/api/service-rulesets` + `/api/policy/network` call with
`blocking_response_mode=refused`; `net-open` left with no ruleset.

- `net-strict` -> real dnsdist response, `status: REFUSED`, `ANSWER: 0`
- `net-open` -> real `status: NXDOMAIN` from an actual upstream root-server
  round trip (the domain genuinely doesn't exist) -- proves REFUSED
  wasn't a default/fallback rcode leaking across policy, it required the
  actual block rule
- `net-strict` re-queried after `net-open`'s query -> still REFUSED, no
  cache leak

## Attack 3: unscoped-client fallthrough sanity

The container's own default loopback address (127.0.0.1, matching
neither `net-strict` nor `net-open`'s `/32` CIDR) queried both domains:
`google.com` resolved unfiltered and `blockme.example` returned real
NXDOMAIN -- confirms an address outside every configured network falls
through to the global policy layer correctly, rather than inheriting
either test network's policy by accident.

## Result

All three real live attacks confirm correct behavior; no defect found or
fixed this pass. Genuinely still open per the prior session's list: DoH
downgrade and ECS-boundary isolation as *live* attacks specifically
(both remain covered by `tests/v2/test_doh_no_downgrade.py` and
`tests/v2/test_ecs_policy.py` unit/integration coverage, not
independently re-attacked live this session) -- not attempted this pass
due to the additional real-upstream-DoH-server and ECS-echoing-resolver
setup they need, which this session's remaining time did not cover.

Container removed after verification, not retained as a running service.
