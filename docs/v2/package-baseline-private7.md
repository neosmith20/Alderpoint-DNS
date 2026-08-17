# V2 private7 — package baseline after real migration gate work

Rebuilt because `app/v2/migration.py`, `app/v2/migration_convert.py`, and
`scripts/v2/alderpointdns_v2_ctl.py` (all package-shipped) changed after
`private6` was built (`promote_to_live`, the `migrate` CLI subcommand, the
encrypted-transport migration warning). `private6` is no longer valid
evidence for current HEAD.

## Artifact

- Source SHA: `c32c935` (this branch, after the migration-gate commit)
- Package/version: `alderpointdns-v2` `2.0.0~private7-1`
- Filename: `alderpointdns-v2_2.0.0~private7-1_all.deb`
- Size: 69,722,200 bytes
- SHA-256: `8d1b1f86e3127a68710f726678c3eb26d23a8da5adad8e7b4fd3ec3e20dbbf8c`

## Acceptance

This artifact is the one used for the real V1->V2 package-level migration
gate documented in `docs/v2/migration-real-package-gate.md` — real
`apt-get install` of both V1 1.1.1-1 and this V2 candidate on the same
host, real `alderpointdns-v2-ctl migrate --promote` run, real service
restart, real DNS query verification. See that document for full results,
including the real defect found (migrated filtering/local-DNS rules are
generated and validated but not actually loaded into the live dnsdist
config by either the migration path or the fresh-install `generate-runtime`
path — a pre-existing runtime-compiler gap, not introduced this session).

Base clean-install acceptance (services/HTTPS/DNS) was already re-verified
for `private6` in `docs/v2/package-baseline-private6.md`; this rebuild
carries no changes to postinst/systemd units/provisioning, only to
`app/v2/migration*.py` and the ctl script, so that evidence still applies
to this artifact's install-time behavior. Not independently re-run.
