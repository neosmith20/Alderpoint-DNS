# Real two-node mTLS replication + observational discovery acceptance

Real, disposable, genuinely separate nodes: two independent podman
`--systemd=always` containers on this session's genuine (non-nested) KVM
VM host, each with its own network namespace/IP (`10.88.0.177` /
`10.88.0.178`), each a real `apt-get install` of the current V2 package
(RC36 source, before this session's fixes below), each independently
bootstrapped through the real HTTPS setup/login API.

## mTLS trust/bootstrap

Used only the shipped, packaged enrollment tooling (no direct library
calls to fabricate trust material):

1. `alderpointdns_v2_ctl.py issue-peer-cert <other node's node_id>` run
   on each node, producing a bundle (this node's CA, this node's own
   server-cert fingerprint, a client cert this node's CA issued for the
   *other* node to present, and that cert's own fingerprint).
2. Each bundle copied to the other node (out of band, as a real
   administrator would) and pasted into `PUT
   /api/replication/peers/{id}` on the real HTTPS management API.

## Bidirectional replication -- real defect found and fixed

Configured a genuine `direction="bidirectional"` peer relationship on
both nodes (not two one-way `push` rows) using the two-fingerprint model
(`expected_cert_sha256` for validating the peer's server identity when
*we* call *them*; `expected_incoming_cert_sha256` for validating what
the peer presents when *they* call *us*) that a previous session's
schema fix (pre-RC36) made possible.

**Real defect found**: `alderpointdns_v2_ctl.py issue-peer-cert`'s own
printed operator guidance (the `--out` message) told the *recipient* of
a bundle to use *that bundle's* `issued_cert_sha256` as their own
`expected_incoming_cert_sha256`. That is backwards: the cert described
by that field is the one the recipient will *present outgoing*
(covered already by `client_cert_pem`/`client_key_pem`), not what the
*sender* presents incoming. Confirmed by direct source reading
(`replication_v2._validate_message`'s `expected =
peer.expected_incoming_cert_sha256`) and by
`tests/v2/test_replication_v2.py`'s own already-passing
`test_genuinely_bidirectional_trust_validates_both_directions_independently`,
then reproduced live: following the tool's literal instructions
configures a fingerprint that can never match a real incoming push,
which fails closed with "peer certificate fingerprint mismatch" for
every real cross-node call.

**Fixed**: corrected the printed guidance to say a node's own
`expected_incoming_cert_sha256` must come from *the bundle it issues
itself* (the fingerprint of the cert it handed the peer to present back
to it), not the bundle it receives. New regression test:
`tests/v2/test_ctl_replication_enrollment.py::
test_out_file_guidance_tells_recipient_to_use_their_own_bundle_for_incoming`.

**Real live proof, both directions, using the corrected mapping**:

- A -> B: created a real client on A through A's HTTPS API, `POST
  /api/replication/peers/{B}/sync` on A -- real mTLS handshake over the
  real container network to B's real `9443` listener -- client present
  in B's real `control.db` and served by B's own `/api/clients`.
- B -> A: created a real client on B, `POST
  /api/replication/peers/{A}/sync` on B -- client present in A's
  `control.db`, alongside A's own earlier client (proves B's snapshot
  round-trip did not clobber A's own state).

## Protected secret handling

Created a real notification provider with a real secret value
(`secret_value`) on A through the HTTPS API, synced to B. Confirmed:

- B's `control.db notification_providers` row holds only an opaque
  secret reference id, never the plaintext value.
- B's `/api/notifications` reports `has_secret: true` without exposing
  the value.
- The secret is usable on B (delivered through `SecretStore`, not a raw
  file copy).

## Stale/replay/conflict behavior

Re-ran an identical sync with no intervening changes: `{"applied":
false, "reason": "duplicate_generation"}` -- correctly a no-op, not a
silent re-apply and not an error. (Replay-window and cross-CA
fingerprint-mismatch rejection are already covered by
`test_replication_v2.py`'s existing, passing real-crypto tests --
re-derivable from source, not re-litigated live this pass since nothing
in that path changed.)

## Failure isolation

Stopped A's `alderpointdns-v2-replication` service outright. Real DNS
resolution on A continued working throughout (`dig` against A's live
dnsdist succeeded during the outage). A sync attempt from B correctly
recorded `last_error: "[Errno 111] Connection refused"` on B's own peer
record (visible via `GET /api/replication/peers`) rather than silently
losing the failure -- replication failure does not affect DNS, and the
failure is observable, not swallowed.

## Node restart/recovery

Restarted B's replication service, then the whole B container
(`podman restart`). All core services (`web`, `dnsdist`,
`bind@ctx0`, `replication`) returned to `active` and real DNS
resolution worked again immediately; a subsequent sync succeeded.

## Real observational discovery -- real defect found and fixed

`alderpointdns-v2-dns-observer` (the real discovery ingress on UDP
`1053`) was active from a fresh install onward and its worker/API
pipeline (`/api/discovery/observed-clients`, promote-to-managed,
retention bounds) is real and tested at the unit level -- but a real
UDP query sent to A's real client-facing dnsdist listener (port 53)
from a genuinely distinct source address never appeared in
`/api/discovery/observed-clients`. Root cause, confirmed by reading the
real generated `dnsdist.conf`: the live config generator
(`app/v2/dnsdist_policy_runtime.py`) wires the analytics protobuf
producer (`RemoteLogAction`/`RemoteLogResponseAction` -> port `5391`)
but never wired anything to the discovery ingress -- an exact parallel
to the analytics gap a previous session found and fixed
(`docs/v2/analytics-ingestion-not-wired-to-live-dns.md`), left open for
discovery specifically and already flagged as untested in
`docs/v2/hardware-performance-1g-2g.md` ("the dns-observer ingestion
path specifically, as opposed to dnsdist itself"). Real client
discovery from real DNS-originated traffic did not work end to end in
the shipped package.

**Fixed**: `compile_multi_policy_dnsdist_config` now also emits
`addAction(AllRule(), TeeAction("127.0.0.1:1053", false))` -- dnsdist's
documented fire-and-forget query mirror, which never blocks on or uses
the target's response, so it cannot slow down or affect a real client's
own answer even if `dns-observer` is unreachable or degraded (same
safety property `RemoteLogger` already gives the analytics producer).
New regression coverage:
`tests/v2/test_dnsdist_policy_runtime.py::TestBasicGeneration::
test_discovery_ingress_gets_a_real_copy_of_every_query` (+ a
`discovery_ingress_address=None` disable test).

Real live re-verification after rebuilding with the fix (see this
session's RC bump): a real UDP query from a genuinely distinct source
address through A's real installed dnsdist correctly appeared in
`/api/discovery/observed-clients` with the real source address,
promoted observed -> managed through the real API, and remained bounded
by the existing `max_entries`/`expiry_days` settings (unit-tested,
unchanged this pass). Stopping `alderpointdns-v2-dns-observer` and
`alderpointdns-v2-discovery` outright left real DNS resolution on A
completely unaffected throughout.
