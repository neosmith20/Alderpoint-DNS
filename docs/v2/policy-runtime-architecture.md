# V2 Real Per-Effective-Policy DNS Runtime Architecture (Gate #2 Blocker 2 remediation)

**Status:** Implemented and proven with real isolated dnsdist instances and real distinct source
IPs (loopback range addresses, e.g. `127.0.0.2`, `127.0.0.100`, bound without special privileges).

## The real answer path

```
client identity (source network, via NetmaskGroupRule)
  -> ordered, most-specific-network-first client policy binding match (app/v2/dnsdist_policy_runtime.py)
  -> SafeSearch rewrite rule for THIS binding's network+domain (terminal: SpoofCNAMEAction)
  -> parental/security/service block rule for THIS binding's network+domain (terminal: RCodeAction/SpoofAction)
  -> domain-specific routing rule for THIS binding's network+domain (terminal: PoolAction into a routed pool)
  -> catch-all PoolAction into THIS binding's own policy pool (named after its effective cache profile id)
  -> that pool's PacketCache (per-pool -- never shared across incompatible policies)
  -> cache hit: answered directly, no upstream/BIND contact
  -> cache miss: that pool's newServer()s (real transport + ECS setting per this binding's upstream
     profile) -> real upstream query, which may be the shared local BIND recursive resolver
  -> answer flows back through dnsdist, cached in THIS pool's cache only, returned to client
```

**Enforcement layer for every answer-producing feature:**

| Feature | Enforced in |
|---|---|
| SafeSearch | dnsdist (before any pool/cache selection) |
| Parental/adult blocking | dnsdist (before any pool/cache selection) |
| Malware/phishing/security blocking | dnsdist (before any pool/cache selection) |
| Service blocking | dnsdist (before any pool/cache selection) |
| Blocking response mode (NXDOMAIN/REFUSED/null/custom) | dnsdist (the terminal action itself) |
| Upstream profile selection | dnsdist (pool assignment) |
| Domain-specific routing | dnsdist (pool assignment) |
| ECS behavior | dnsdist (per-pool `useClientSubnet` on that pool's servers) |
| Ordinary recursive resolution | BIND (only ever sees queries dnsdist already decided to forward — completely policy-agnostic from BIND's point of view) |

**No duplicated/ambiguous enforcement:** BIND/RPZ (`app/v2/bind_rpz_gen.py`) is retained ONLY as an
optional whole-appliance-wide defense-in-depth layer for domains that should be blocked for
*literally every* client regardless of policy (e.g. a known-universally-malicious domain an
operator wants blocked even if dnsdist were somehow bypassed) — it is explicitly NOT where
per-client/per-profile differentiated policy is enforced. Any domain that should differ by policy
must be expressed as a `ClientPolicyBinding`, never added to the global RPZ zone.

## Why BIND's recursive cache stays maximally shared

BIND is never asked a policy-differentiated question. By the time a query reaches BIND (a cache
miss in dnsdist's per-pool packet cache, forwarded via `newServer()`), every policy decision that
could have changed the *answer* has already been made and terminated the query, or the query is
genuinely "give me the real answer for this qname" — which is the same real answer for every
policy, since dnsdist's own per-pool cache is what's actually different, not BIND's. This means one
shared BIND instance/cache serves every policy correctly, with no per-client BIND views and no
per-policy BIND configuration needed.

## Cache-sharing semantics

Two `ClientPolicyBinding`s with the *same* `cache_profile_id` (from
`policy_compiler.compile_cache_profile`) are deduplicated onto one shared dnsdist pool + one shared
`PacketCache` — proven safe by construction, since the cache-profile compiler guarantees identical
ids only for genuinely answer-identical policy. Two bindings with *different* `cache_profile_id`s
always get separate pools and separate `PacketCache` objects — proven to never leak (real isolated
tests: `tests/v2/test_policy_runtime_matrix.py`), regardless of query order or cache warm state.

## Proven live (not just unit-tested)

`tests/v2/test_policy_runtime_matrix.py` runs a real isolated dnsdist instance with two conflicting
client policy bindings (distinct real loopback source IPs, e.g. `127.0.0.2` vs `127.0.0.100`),
querying the SAME qname/qtype from both client identities in BOTH orders, with repeated queries to
warm each pool's cache, verifying: SafeSearch on vs off, parental on vs off, malware/security on vs
off, service block on vs off, NXDOMAIN vs REFUSED vs custom-IP response modes (REFUSED verified as
real RCODE 5), distinct upstream profiles, domain-specific routing vs default, and that a warm
cache in one profile's pool never answers a query for the other profile.
