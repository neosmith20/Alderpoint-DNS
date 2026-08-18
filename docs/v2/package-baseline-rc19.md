# RC19 clean-install acceptance + live verification of the client_name fix

Real `podman --privileged --systemd=always` container, base
`localhost/apdns-v2-4c-accept-base:trixie`, fresh `apt-get install` of
`alderpointdns-v2_2.0.0~rc19-1_all.deb`
(sha256 `aa4307b053b6b05703343df5956d760c5f50e9f97d809e597d8fc76ed3d62241`).

## What RC19 fixes over RC18

`docs/v2/client-name-not-populated-fix.md`: `client_name` was always
blank for every real event with a registered managed client.

## Live verification

- `apt-get install`: `EXIT:0`; `systemctl --failed --no-legend`: zero
  failed units.
- Real HTTPS bootstrap + login, real admin flow: `POST /api/clients`
  (real client "RC19 Test Client"), `POST /api/clients/{id}/identifiers`
  (assigns `127.0.0.1` as its identifier).
- Real `GET /api/analytics/query-log`:
  - A query issued **before** the client was registered:
    `client_name = ""` (correct -- no client matched yet).
  - A query issued **after** registration:
    `client_name = "RC19 Test Client"` -- the real fix, confirmed end
    to end through the real installed package's real HTTPS API.

## Conclusion

All five "policy/client field silently left blank in real analytics
events" defects found this continuation (`cache_profile_id`,
`action`/`block_reason`, `upstream_profile_id`, `client_name`) are now
fixed and individually live-verified against real installed packages.
Container torn down after verification.
