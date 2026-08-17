# Private RC export scrub (roadmap Priority 13)

Verifies the eventual public/export surface would contain none of the
listed leak categories. V2 remains fully private this session (no
publish/tag/push performed) -- this is a preemptive check, not a
release action.

## Scope checked

- Every file the real `alderpointdns-v2` `.deb` actually ships:
  `app/v2/`, `vendor/v2-analytics/`, `scripts/v2/alderpointdns_v2_ctl.py`,
  `scripts/provision-v2-analytics-vendor-runtime.sh`, `packaging/v2/*`
  (postinst/preinst/postrm/prerm + systemd units), `LICENSE`/`COPYRIGHT`
  (73 files, per `tar -tf` of the exact same file set `build-v2-deb.sh`
  packages).
- The existing public repo mirror (`/root/alderpointdns-public`) for
  any V2 implementation leakage.

## Checked for, found none

- CC/Dex/Goose or other internal-agent commentary
- Personal/gmail-style email addresses
- Private infrastructure hostnames/IPs (the only non-RFC-reserved/
  well-known-public IPs found are the standard public resolvers this
  code legitimately talks to -- 1.1.1.1, 9.9.9.9, 8.8.8.8, etc. -- and
  `192.0.2.1`, RFC 5737 `TEST-NET-1`, deliberately used as the
  observation-only DNS ingress's synthetic answer)
- Embedded private keys, passwords, API keys, or other credentials
- Obsolete prior product naming (`bindguard`/`proxyv2` -- an unrelated
  private project living alongside this one on this same host --
  do not appear anywhere in shipped V2 code)
- Internal UI design critique (`docs/v2/internal/ui-design-guidance.md`
  is explicitly out of the packaged file set -- `docs/` is never
  tar'd into the `.deb` at all)

## Public repo cross-check

`/root/alderpointdns-public` only contains the three planning documents
that were always meant to be public (`V2_ROADMAP.md` and its two linked
planning docs) -- `V2_ROADMAP.md`'s own header states it was copied
*from* the public repo *into* this private one as reference input, not
the reverse. No V2 implementation code, `docs/v2/*` session notes, or
private fixtures/logs are present in the public mirror.

## Result

Clean. Nothing found requiring redaction before any future export
decision. Historical git commit messages were not audited for old
naming per the roadmap's own explicit instruction that they don't need
rewriting solely for that.
