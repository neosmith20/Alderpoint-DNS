# V2 private RC8 — real genuinely bidirectional replication, live proof (roadmap Priority 12)

## Artifact

- Package/version: `alderpointdns-v2` `2.0.0~rc8-1`
- Filename: `alderpointdns-v2_2.0.0~rc8-1_all.deb`
- SHA-256: `31e9f95bb233b07fdcf697af9c28a33bfb1fd5dc9e98fefc93e09173bc26440e`
- Source SHA: commit "Fix real bidirectional-replication-trust schema
  limitation"

## Real live proof: genuinely bidirectional replication, both directions, real shipped tooling only

Two independently `apt`-installed RC8 containers (`10.88.0.88`/
`10.88.0.89`), real bootstrap/login on both, 0 failed units on either.

Full real enrollment workflow, no library shortcuts:

1. `alderpointdns_v2_ctl.py issue-peer-cert` run on **both** nodes
   (each issuing a cert for the other), producing two bundles.
2. Combined fields from **both** bundles into each node's own peer
   record exactly per the CLI's own printed guidance
   (`ca_pem`/`expected_cert_sha256`/`client_cert_pem`/`client_key_pem`
   from the bundle the *other* node issued, plus
   `expected_incoming_cert_sha256` = the fingerprint of the cert *this*
   node itself issued for the other) -- `direction="bidirectional"`.
3. `PUT /api/replication/peers/{id}` on both nodes through the real
   HTTPS management API.
4. A real client created on A, pushed A -> B: `applied: true`.
5. A real client created on B, pushed B -> A: `applied: true`.
6. Both nodes' real `control.db` show **both** clients afterward --
   genuine two-way replication, not just the one-direction case proven
   in earlier RCs.

This is the first time in this project's history that a genuinely
bidirectional replication relationship has been proven working end to
end using only the shipped CLI/API (no direct calls into
`replication_v2`'s library functions to fabricate trust material).
