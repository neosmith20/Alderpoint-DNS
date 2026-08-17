# V2 private6 — current-HEAD package baseline

Rebuilds the private package to match production code changed at `c7759e1`
(net-probe fix, migration health-check offline degrade). The previously
accepted `private5` artifact predates that commit and should not be treated
as evidence for current HEAD.

## Artifact

- Source SHA: `088162b5bfe8f0f485c61b7e174cd7b238da04f7`
- Package/version: `alderpointdns-v2` `2.0.0~private6-1`
- Filename: `alderpointdns-v2_2.0.0~private6-1_all.deb`
- Size: 69,717,560 bytes
- SHA-256: `72a3ed5d858f5352790e1e973774a7f9f0817b5bb76b176858421e51c2d7b677`

## Clean-install acceptance

Installed into a fresh `localhost/apdns-v2-4c-accept-base:trixie` container
started with `podman run --privileged --systemd=always
-v /sys/fs/cgroup:/sys/fs/cgroup:rw` (the pattern confirmed correct in the
prior session's `ProtectSystem=strict` finding) on this real KVM-VM host
(`systemd-detect-virt` → `kvm`, `--container` → none).

- `apt-get install` of the `.deb`: exit 0, no postinst failure.
- Provisioning: analytics vendor runtime (pyarrow/duckdb healthy,
  degraded=False), `init-state`, node identity, control.db schema 6, secret
  store, TLS bootstrap, dnsdist config + RPZ zone validated and promoted —
  all completed as in prior accepted evidence.
- All 10 V2 systemd units reach `active`/`running`:
  `alderpointdns-v2-web`, `-replication`, `-analytics`, `-tierb`,
  `-schedule`, `-discovery`, `-dns-observer`, `-dnsdist`,
  `-dnsdist-reload.path` (waiting), `-dnsdist-reload.service` (inactive/dead,
  correct idle state for a path-triggered oneshot).
- HTTPS management: `curl -sk https://127.0.0.1:8443/` → `HTTP 200`.
- DNS runtime: raw UDP query to `127.0.0.1:53` (owned by the
  `alderpointdns-v2-dnsdist` unit, not the disabled stock `dnsdist.service`)
  for `example.com A` returned a real answer (`NOERROR`, 2 A records).
- No regression from the migration/net-probe changes observed.

Container removed after verification (not retained as a running service).

This establishes the current package baseline for the remaining V2 roadmap
work (migration matrix, package lifecycle matrix, hardware/performance,
Argon2id, Tier B, failure-domain, adversarial security, CI, RC assembly).
