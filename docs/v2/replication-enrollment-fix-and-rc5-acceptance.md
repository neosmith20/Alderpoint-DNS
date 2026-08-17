# Replication enrollment gap: fix, real defects found along the way, and a real remaining architectural limit (roadmap Priority 12)

## What was fixed (RC4, RC5)

**RC4** (`app/v2/replication_v2.py`, `scripts/v2/alderpointdns_v2_ctl.py`,
`app/v2/webapp.py`; commit `383b1a3`): closed the enrollment gap
documented in `docs/v2/replication-real-two-node-acceptance.md`.
`init-replication-cert` now persists this node's replication CA private
key into the `SecretStore` (new fixed ID
`replication_v2.REPLICATION_CA_KEY_SECRET_ID`), and a real node can now
issue an additional cert signed by its own CA for a *named remote
node*, via either the packaged CLI (`alderpointdns-v2-ctl
issue-peer-cert <remote-node-id>`) or the management API (`POST
/api/replication/issue-peer-cert`). Neither ever returns the CA private
key itself.

**RC5** (commit `b9bbc95`): live two-node acceptance testing of the RC4
fix (using the real CLI, not a test shortcut) immediately found a
second real defect the first fix's own unit tests hadn't caught (they
all connect via literally `"localhost"`, matching every server cert's
hardcoded SAN): `push_to_peer()` failed TLS hostname verification
against any real peer reachable at anything other than the literal
string `"localhost"` -- which is every real cross-host deployment,
since a real appliance cannot know in advance what address a future
peer will dial it on. Fixed by disabling `ctx.check_hostname` in
`client_ssl_context()`: the explicit certificate-fingerprint pinning
`push_to_peer()` already performs right after `connect()`
(`peer.expected_cert_sha256`) is a strictly stronger identity guarantee
than a name inside the cert, so this removes a redundant check without
weakening real security.

## Real live two-node proof (RC5, using only the shipped CLI/API)

Two independently `apt`-installed RC5 containers at real distinct IPs
(`10.88.0.82`/`10.88.0.83`). The full real workflow, no test shortcuts
or direct library calls:

1. `alderpointdns_v2_ctl.py issue-peer-cert <B's node_id> --server-name 10.88.0.83 --out bundle.json` on A.
2. Same command on B, issuing for A's node_id.
3. Each bundle copied (out of band, as a real administrator would) to
   the *other* node and pasted into `PUT /api/replication/peers/{id}`
   through the real HTTPS management API.
4. A real client created on A through A's real HTTPS API.
5. `POST /api/replication/peers/{B}/sync` on A -- real mTLS handshake
   over the real container network to B's real `9443` listener,
   real fingerprint-pinned client cert issued by the real CLI.
6. The client is present in B's real `control.db`.

This is the first time this project has proven replication trust
established between two independent nodes using only shipped,
packaged tooling -- no direct calls into `replication_v2`'s library
functions to fabricate trust material, unlike every prior replication
proof in this project's history including this session's own RC3
acceptance pass.

## Real remaining limitation found while proving this: bidirectional trust needs a schema change, not just enrollment tooling

Attempting the *fully bidirectional* case (both A and B configured to
push to each other, using the natural "give the whole bundle to the
other side, they paste it whole" workflow the CLI's own help text
describes) failed with a real, reproducible `403 peer certificate
fingerprint mismatch` -- not a test artifact, root-caused precisely:

`replication_peers.expected_cert_sha256` is a single field asked to
serve two genuinely different roles depending on which code path reads
it:

- **Outgoing** (`push_to_peer`, when I call the peer): checked against
  the peer's real, fixed **server certificate** -- the one TLS itself
  hands me during the handshake, signed by the peer's own CA at their
  install time. I have no control over what this is; it's dictated by
  their `init-replication-cert` bootstrap.
- **Incoming** (`apply_message`/`_validate_message`, when the peer
  calls me): checked against whatever cert the peer *actually presents
  as its client identity* -- under the new cross-issuance enrollment
  model, that's the **separate cert I issued them** via
  `issue_peer_client_cert`, an entirely different certificate (different
  key, different fingerprint) from their server cert.

These are two different real certificates. A single `expected_cert_
sha256` column cannot correctly pin both at once for a genuinely
bidirectional relationship using cross-issued enrollment certs. The
`direction` column already anticipates this distinction (`push` /
`pull` / `bidirectional`) but nothing in `push_to_peer`/`apply_message`
currently reads or enforces it -- a `bidirectional` peer row is
accepted and stored today even though the current single-fingerprint
schema cannot actually make both directions work simultaneously with
cross-issued certs.

**Worked around for this proof, not fixed as a product change**: set
`direction="push"` and pinned `expected_cert_sha256` to the fingerprint
of the cert A actually presents (rather than A's server cert), matching
a real, common, fully-supported one-directional topology (a primary
pushing to a standby) -- proven working end to end above. Left
unresolved: making `bidirectional` actually work correctly with
cross-issued certs needs either (a) a second pinning column
(`expected_client_cert_sha256` alongside the existing server-facing
`expected_cert_sha256`), or (b) enforcing `direction` so an operator
can't silently configure a `bidirectional` peer that the current schema
can't actually validate correctly in both directions, with a clear
error steering them toward two `push`-direction peer rows instead. Real
product-scope decision for a future session, not attempted here.

## Tests

13 new regression tests this session across `app/v2/replication_v2.py`
(including a real two-node cross-issuance-and-replicate proof with two
separate CAs, and a real hostname-mismatch-then-fixed reproduction),
`app/v2/webapp.py`'s new endpoint, and the actual packaged CLI module
(imported and exercised directly). Full `tests/v2`: 844 passed (1
pre-existing flaky-under-concurrent-load real-mTLS test, confirmed
passing cleanly in isolation, not a regression -- matches prior
sessions' documented flake).

## Artifacts

- RC4: `alderpointdns-v2_2.0.0~rc4-1_all.deb`,
  `sha256:f744781edb367c8d012370a42b150b1713b1c1752fa99bd8d808a645147be900`
  (enrollment CA-key-persistence + issuance fix; superseded by RC5 for
  real cross-host use due to the hostname defect above)
- RC5: `alderpointdns-v2_2.0.0~rc5-1_all.deb`,
  `sha256:56d21f13a42ef9a33159e0c4060c930cabec03d0ec157b7332168d245694f64d`
  (current artifact; both fixes)
