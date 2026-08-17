# V2 private RC2 — package baseline + clean-room acceptance (roadmap Priority 12)

RC1's own clean-room acceptance pass (below) found a real live defect
in that exact artifact. RC2 is the fix, rebuilt and re-accepted from
scratch on a brand-new target -- RC1's record
(`docs/v2/package-baseline-rc1.md`) is left as-is, not edited.

## Source

- Source SHA: `12ceb5d...` (commit "Fix real live-defect found during
  RC1 acceptance: dnsdist rebinds to loopback-only after any policy
  mutation")
- Branch: `v2/architecture-storage-foundation`
- Build environment: this session's real KVM host,
  `scripts/build-v2-deb.sh --output-dir /tmp/alderpointdns-v2-rc2`

## Artifact

- Package/version: `alderpointdns-v2` `2.0.0~rc2-1`
- Filename: `alderpointdns-v2_2.0.0~rc2-1_all.deb`
- Architecture: `all`
- Size: `69,726,856` bytes
- SHA-256: `61d264d611402be12c8053760c44f794fafd0729f0ac506d0de4b8a0c3d052fc`

## RC1 clean-room acceptance: real defect found

Fresh Debian 13 container (`localhost/apdns-v2-4c-accept-base:trixie`,
`--privileged --systemd=always`), real `apt-get install` of RC1
(`sha256:ad7e5295...`, see `docs/v2/package-baseline-rc1.md`). Clean
install succeeded, all 8 services active, real bootstrap/login over
HTTPS worked, plain DNS resolved and cached correctly. Then, as part of
the acceptance checklist's "policy isolation" step, applied one real
policy change (`PUT /api/policy/global {"safesearch_mode":"strict"}`)
through the live admin API -- the same action any real administrator
takes on day one.

**Every DNS query after that single policy change failed**:
`;; communications error to 127.0.0.1#53: connection refused`.
`journalctl` showed dnsdist had restarted and was now
`Listening on 127.0.0.1:53` -- not `0.0.0.0:53`. Diffing the newly
promoted config against its own staged `.previous` backup confirmed
the listener itself had silently changed from `setLocal("0.0.0.0:53")`
to `setLocal("127.0.0.1:53")`.

Root cause: `webapp.py`'s live policy-mutation path never threaded the
appliance's real configured listener through to
`runtime_compile.recompile_and_promote()`, which silently defaulted to
`"127.0.0.1:53"`. The install-time bootstrap config (from
`scripts/v2/alderpointdns_v2_ctl.py`, which correctly reads
`/etc/alderpointdns-v2/alderpointdns.yaml`) is the only reason a fresh
install ever worked at all -- the moment any admin touched any policy
through the UI/API, the real per-policy compiler took over and quietly
rebound dnsdist to loopback-only, permanently (until a source-level
fix), with no error surfaced anywhere. `replication_v2.py`'s
`apply_message()` had the identical missing wiring on the secondary-node
replication-apply path. Full root-cause and fix in commit `12ceb5d`;
regression tests in `tests/v2/test_webapp.py` and
`tests/v2/test_replication_v2.py` (4 new, all passing; full `tests/v2`:
829 passed).

This is exactly the kind of defect the roadmap's "no source-tree
assistance" clean-room RC acceptance requirement exists to catch --
every existing unit/integration test that exercises this code path
passes an explicit `listen_address` argument (reasonable test hygiene:
unique ports per test to avoid collisions), which is precisely why the
missing production wiring never surfaced until a real black-box
end-to-end pass exercised the real default.

## RC2 clean-room acceptance: fixed, re-verified from scratch

Brand-new container, real `apt-get install` of RC2. Full checklist run
against this exact artifact:

- **Clean install**: exit 0, all 8 services active, 0 failed units
- **Bootstrap/HTTPS/login**: real `/api/setup` + `/api/login` over TLS,
  real Argon2id-hashed credential, real session + CSRF
- **DNS (plain)**: cold + warm-cache queries both correct, TTL
  correctly decrementing on cache hit
- **Policy mutation regression** (the exact RC1 failure): applied the
  identical `safesearch_mode=strict` global policy change -- DNS stayed
  reachable throughout, `setLocal("0.0.0.0:53")` confirmed in the
  promoted config, both a plain query and a SafeSearch-rewritten query
  (`youtube.com` -> `restrict.youtube.com`) succeeded immediately after
- **Discovery**: real UDP packet to the observation-only ingress
  (port 1053) -> real observation queued -> JSONL inbox -> discovery
  worker -> `control.db` -> `/api/discovery/observed-clients` end to
  end (small polling-interval delay before the API reflected it;
  not a defect, just needed a second read)
- **Analytics**: ingestion service active; top-domains query returns
  correctly-shaped empty result (no querying-window data yet in this
  short session -- not independently deep-tested this pass)
- **Secret backup/restore**: real create -> validate -> restore
  round trip over the HTTPS API, including the deliberate
  type-the-exact-filename confirmation UX, succeeded end to end
- **Service restart**: all 8 services restarted; 0 failed units after;
  DNS and login both immediately functional again
- **Reinstall (same version)**: node identity, secrets, config, and TLS
  cert all preserved; DNS uninterrupted
- **Purge**: `apt-get purge` removed `/etc/alderpointdns-v2`,
  `/var/lib/alderpointdns-v2` (including all secrets), and
  `/opt/alderpointdns-v2` completely; zero leftover files anywhere on
  the filesystem, zero leftover systemd units, zero leftover dpkg
  record, zero leftover system user -- verified by a real filesystem
  `find` sweep and `dpkg -l`/`id` checks, not inference
- **Reinstall after purge**: genuinely fresh state (new node identity,
  0 secrets, new bootstrap token), DNS working immediately

No defects found in RC2. Container removed after verification, not
retained as a running service.

## Not covered this pass (real scope remaining before Dex Gate #3)

Representative V1 migration through this exact RC2 artifact (the
existing `docs/v2/migration-real-package-gate.md` pass was run against
an earlier private artifact, not re-run against RC2 specifically since
no migration-affecting code changed between them); reboot (this is a
container, not a VM with a real boot cycle -- `docs/v2/hardware-performance-1g-2g.md`
and the 4C/4D evidence already cover real-VM-host proof for other
concerns); replication between two real RC2 nodes; deep analytics
backlog/query-volume testing. Reasonable next items for a continuation
pass, not blocking issues found this session.
