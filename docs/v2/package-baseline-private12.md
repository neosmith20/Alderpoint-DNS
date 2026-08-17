# V2 private12 — package baseline after adversarial security fixes

Rebuilt because `app/v2/webapp.py` changed (CSRF constant-time comparison
fix, request body size limit). See
`docs/v2/adversarial-security-pass.md` for the full findings writeup.

## Artifact

- Package/version: `alderpointdns-v2` `2.0.0~private12-1`
- Filename: `alderpointdns-v2_2.0.0~private12-1_all.deb`
- SHA-256: `5dc83c855269de8ae2523a2b350fabbf06429a2641e4378595e4376a8d5fb966`

## Acceptance

All live attacks documented in `docs/v2/adversarial-security-pass.md`
were run against this exact artifact: auth bypass, session forgery,
CSRF, six rendered-config-injection payloads, oversized-payload
reflection (found and fixed), path traversal on backup restore, and
replication mTLS (missing cert, wrong CA). No postinst/provisioning
changes since `private11`.
