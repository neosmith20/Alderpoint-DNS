# V2 private8 — package baseline after RPZ/local-DNS wiring fix

Rebuilt because `app/v2/migration.py`, `migration_convert.py`,
`policy_store.py`, `runtime_compile.py`, and `dnsdist_policy_runtime.py`
(all package-shipped) changed to fix the migrated-filtering/local-DNS
enforcement gap found in `private7`'s real package-level migration test.

## Artifact

- Source SHA: this branch, after the RPZ/local-DNS wiring fix commit
- Package/version: `alderpointdns-v2` `2.0.0~private8-1`
- Filename: `alderpointdns-v2_2.0.0~private8-1_all.deb`
- Size: 69,725,164 bytes
- SHA-256: `5a0224bd86fdedfd82e31b90e7b9dbd785e6344e7e716ad540649a46e4e9bd62`

## Acceptance

Full real package-level migration retest (same procedure as
`private7`'s, see `docs/v2/migration-real-package-gate.md`): real V1
1.1.1-1 install, sanitized seed data, real V2 `private8` install on the
same host, real `alderpointdns-v2-ctl migrate --promote`, real service
restart. All three real DNS checks now pass: migrated local DNS record
resolves, migrated blocked domain returns NXDOMAIN, real upstream
forwarding still works. Full details and exact query results in
`docs/v2/migration-real-package-gate.md`'s "Fixed" section.

Base clean-install acceptance (services/HTTPS) not independently re-run
for this artifact — no changes to postinst/systemd units/provisioning;
`private6`'s evidence still applies to install-time behavior. The
migration retest above additionally exercises normal service start/
restart on this exact artifact.
