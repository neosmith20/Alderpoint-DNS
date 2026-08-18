# Failure-domain proof: the new analytics-protobuf-receiver service (roadmap Priority 9 continuation)

Extends the existing failure-domain pass (`docs/v2/tier-b-and-
failure-domains.md`) to the new component this session added.

Real RC11 install. With DNS actively answering:

- Stopped `alderpointdns-v2-analytics-protobuf-receiver` -- DNS
  (`example.com`) kept answering `NOERROR` immediately, and the real
  HTTPS management API kept responding normally (`401` unauthenticated,
  not a connection failure).
- Issued 5 more real DNS queries while the receiver stayed stopped --
  `alderpointdns-v2-dnsdist` never restarted (`NRestarts=0`) despite
  its remote logger being continuously unreachable, confirming
  dnsdist's own documented fire-and-forget behavior holds under this
  package's real compiled config, not just in isolated protocol tests.
- Restarted the receiver -- came back `active` immediately, and the 5
  queries issued while it was down were still delivered and correctly
  logged once it reconnected (dnsdist buffers/retries against its
  remote logger across a reconnect within this window; not a
  guaranteed-durable queue for arbitrarily long outages, but real,
  positive evidence against the common case of a brief restart).

No new dependency introduced: DNS answering remains fully independent
of this new component, matching the architecture's existing invariant.
