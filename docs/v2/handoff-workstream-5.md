# Alderpoint DNS V2 — Handoff to Workstream 5

Workstream 4C added real V2 mTLS replication and bounded observational client
discovery on top of the Workstream 4B package baseline. See
`docs/v2/workstream-4c-replication-discovery.md` for protocol, trust, model, and
installed two-node evidence.

## Completed State

- Stable V2 node identity in `control.db`, separate from display name.
- mTLS replication service packaged as `alderpointdns-v2-replication.service`.
- Explicit peer trust/authorization with expected node id and certificate
  fingerprint.
- Versioned bounded JSON replication protocol with replay, stale-generation, and
  deterministic conflict handling.
- Control-state snapshot replication for policy/client/upstream/routing/service
  and notification metadata tables.
- Secret values replicate only over authorized mTLS and are applied to
  `SecretStore`, not control.db.
- Replicated answer-producing state goes through runtime compile/stage/validate/
  promote before success is acknowledged.
- Observed-client aggregate store with retention caps, hostname sanitization,
  stats, and explicit idempotent promotion to managed client.
- Management API exposes node identity, peers, sync/health, observed-client
  listing/detail/forget/settings, and promotion.
- Package version `2.0.0~private3-1` built and installed into two clean Debian 13
  Podman nodes for E2E proof.

## Artifact

- `/tmp/alderpointdns-v2-4c/alderpointdns-v2_2.0.0~private3-1_all.deb`
- Size: `69700460`
- SHA-256: `c869fa9b2615d7adcbdce050513b405b345a075015c5ef4334768573ed8b0f96`

## Known Limits / Next Workstream

- The V2 API is JSON-only; no V2 UI has been added.
- Before any large-scale V2 UI work, read the private internal-only design
  guidance at `docs/v2/internal/ui-design-guidance.md`. Do not redesign the UI
  until a coherent Alderpoint design system is established.
- Discovery has a packaged inbox worker and API injection path; direct dnsdist
  production event emission should be connected when the authoritative V2 DNS
  listener becomes packaged.
- PTR enrichment and ARP/NDP enrichment remain optional future work.
- Bidirectional sync support exists at the trust/protocol level; the 4C installed
  proof exercised node A to node B plus peer-failure recovery.
- Full `tests/v2` in this sandbox still has environment-sensitive failures for
  socket/chown/dnsdist-start tests. Run the full suite in a less restricted CI
  environment before public release gating.
- Public export/release preparation must exclude `docs/v2/internal/` and run the
  generic release hygiene scan against the exported tree with the private scrub
  patterns listed in `docs/v2/internal/ui-design-guidance.md`.
