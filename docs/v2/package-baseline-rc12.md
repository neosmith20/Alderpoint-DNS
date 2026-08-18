# RC12 clean-install acceptance baseline

Real `podman --privileged --systemd=always` container
(`localhost/apdns-v2-4c-accept-base:trixie`), fresh `apt-get install -y`
of `alderpointdns-v2_2.0.0~rc12-1_all.deb`
(sha256 `dc96cec6f5bea7ce5bed6422e8ebf003da9f2a88e4a2a33ec3ef8b8ac2c5d1c0`).

## What RC12 adds over RC11

Only production change since RC11: `remote_node_id` on
`POST /api/replication/issue-peer-cert` is now constrained by
`Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9_-]+$")`
instead of accepting an arbitrary string that gets embedded directly
into a real X.509 certificate CN.

## Live verification

- `apt-get install`: `EXIT:0`.
- `systemctl --failed --no-legend`: zero failed units.
- Real HTTPS bootstrap (`/api/setup`) + login (`/api/login`): both
  `200`.
- Real attack attempt against the new validation, with a real
  authenticated session + CSRF token:
  `POST /api/replication/issue-peer-cert {"remote_node_id":"../../etc/passwd"}`
  -> `HTTP 422`, Pydantic `string_pattern_mismatch` on the pattern
  `^[A-Za-z0-9_-]+$`. Confirms the fix is live in the real installed
  package, not just covered by a unit test.

Container torn down after verification (`podman rm -f apdns-rc12-test`).

## Conclusion

RC12 is a clean, additive hardening fix over RC11 with no regressions
observed in this baseline pass. Continuing directly into the remaining
open roadmap re-verification items (hardware/performance matrix,
Argon2id, Tier B, failure-domain, adversarial security, CI determinism)
against this artifact.
