# V2 private RC1 — package baseline (roadmap Priority 12)

First private release-candidate build. Source content is identical to
`private12` (no V2 production code changed since that build -- only
V1-only files (`app/backup.py`, `app/upstream_dns.py`, which the V2
package does not ship) and `docs/v2/*.md` changed in between); only the
version string changed, per `scripts/build-v2-deb.sh`'s
`DEB_VERSION="2.0.0~rc1-1"`.

## Source

- Source SHA: `2d434d82df8fc6023da9f860a224558207de14af`
- Branch: `v2/architecture-storage-foundation`
- Build environment: this session's real KVM host (`systemd-detect-virt`
  -> `kvm`), `scripts/build-v2-deb.sh --output-dir /tmp/alderpointdns-v2-rc1`

## Artifact

- Package/version: `alderpointdns-v2` `2.0.0~rc1-1`
- Filename: `alderpointdns-v2_2.0.0~rc1-1_all.deb`
- Architecture: `all`
- Size: `69,726,464` bytes
- SHA-256: `ad7e5295bd52a3200a3677852e41e7c671bb91b94515dddaabf2b85e4055cfa3`

## Acceptance

Clean-install/functional acceptance against this exact artifact tracked
separately in `docs/v2/rc1-clean-install-acceptance.md`.
