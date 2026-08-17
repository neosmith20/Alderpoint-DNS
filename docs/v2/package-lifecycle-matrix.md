# V2 package lifecycle matrix (roadmap Priority 2)

Real `.deb` install/remove/reinstall/purge/reinstall exercised against
`alderpointdns-v2_2.0.0~private8-1_all.deb` in a fresh
`apdns-v2-4c-accept-base:trixie` container on this session's real KVM
host (`--privileged --systemd=always`).

## Paths exercised this session

1. **Clean install** — postinst completed, all 10 units active (already
   covered repeatedly in prior package-baseline docs; re-confirmed here
   as the lifecycle test's starting state).
2. **Real state created**: inserted a sanitized marker admin
   (`persistmarker`) directly into `control.db`, captured SHA-256 of the
   TLS server cert and replication trust CA as persistence fingerprints.
3. **`apt-get remove`** (not purge): `dpkg -l` shows `rc` (removed,
   config remains) afterward.
   - `control.db` persisted, including the marker admin.
   - TLS cert (`certs/server.crt`) byte-identical (same SHA-256).
   - `alderpointdns-v2` system user/group persisted (correct — only purge
     removes them).
   - `/opt/alderpointdns-v2` correctly had its tracked files/vendor
     runtime removed by dpkg+postrm; two empty leftover directories
     (`app`, `app/v2`) remain — cosmetic (zero bytes, no security/state
     implication), not chased further this session.
4. **Reinstall after remove**: postinst correctly detected existing state
   at every step — `"existing config validated"` (not overwritten),
   `"an admin account already exists; no bootstrap token needed"` (found
   the marker admin), TLS cert reused (`node_identity.created_at` and the
   cert's `valid_until` timestamp both matched the original install's
   timestamp to the second, confirming reuse, not regeneration). Node
   identity UUID confirmed unchanged across remove -> reinstall by
   comparing the printed value against `control.db`'s stored row.
5. **`apt-get remove --purge`**: full wipe confirmed --
   `/var/lib/alderpointdns-v2`, `/etc/alderpointdns-v2`,
   `/var/log/alderpointdns-v2`, `/opt/alderpointdns-v2` (including the
   two leftover empty dirs from step 3) all gone; system user and group
   both removed; `dpkg -l` shows no entry at all. No orphaned secrets,
   private keys, or control state found anywhere.
6. **Reinstall after purge**: genuinely fresh bootstrap confirmed -- new
   node identity UUID, new TLS certificate (different `valid_until`
   timestamp than the pre-purge cert), new bootstrap-setup-token, 0
   admins in the fresh `control.db`. All 8 real systemd units (web,
   dnsdist, replication, analytics, tierb, schedule, discovery,
   dns-observer) reached `active`.

No defects found in any of the six paths above -- remove/purge semantics
match the documented contract in `packaging/v2/postrm`'s own comments
exactly (ordinary remove preserves all user/config state; purge is the
one deliberate full-wipe path), and reinstall correctly detects and
reuses existing state rather than either clobbering it or erroring.

## Not exercised this session (remaining roadmap items)

- Previous private version -> current private version upgrade (would need
  a previous artifact retained/rebuilt at an older commit -- not attempted
  this session).
- Populated V1 -> current V2 (covered separately and thoroughly in
  `docs/v2/migration-real-package-gate.md`, not repeated here).
- Interrupted migration/upgrade (partially covered at the Python-state-
  machine level by `test_migration_durable_state.py`'s crash-restart-at-
  every-stage-boundary test; not re-attempted at the package/process level
  this session).
- Reboot (this session's containers are disposable Podman containers, not
  full VM reboots; not attempted).
- Failed package operation (e.g. a postinst step failing partway) --
  not deliberately injected this session.
- Replication trust / discovery state persistence specifically across
  remove/reinstall (TLS/replication cert files were fingerprinted and
  confirmed unchanged across remove->reinstall as part of the general
  persistence check above, but no replication peer relationship was
  actually established and re-verified end to end).
