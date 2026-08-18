# RC29 clean-install acceptance + real live confirmation of the control.db/secret-store silent-recreation fix

Real `podman --privileged --systemd=always` container, base
`localhost/apdns-v2-4c-accept-base:trixie`, fresh `apt-get install` of
`alderpointdns-v2_2.0.0~rc29-1_all.deb`
(sha256 `0b0a06427ffec93e9949905467c23cc90d8eaca82c4552f9ceae30bc0038472c`).

## What RC29 adds over RC28

`docs/v2/control-db-silent-recreation-fix.md`: fixes the real defect
found live during RC28's failure-domain/chaos pass -- a missing
`control.db` or secret store was silently, invisibly replaced by an
empty one indistinguishable from a genuine fresh install.

## Real, live verification -- the exact reproduction, repeated against the fix

Fresh RC29 target, real bootstrap + login:

- Real `control.db` moved aside (simulating unavailability) -> real
  `GET /api/setup/status` -> real `500 control_db_missing` with a
  clear message. **No new `control.db` was created** -- confirmed via
  real `ls`, only the real, moved-aside file exists.
- Restored -> real `GET /api/setup/status` -> `{"setup_required":false}`,
  normal operation resumed immediately, no lingering effects.
- Real secrets directory moved aside -> real
  `POST /api/dns-transports/dnscrypt/rotate` -> real
  `500 secret_store_missing` with a clear message. **No new secrets
  directory was created** -- confirmed via real `ls`, only the real,
  moved-aside directory exists.
- Restored -> real `dig @127.0.0.1 cloudflare.com` -> `NOERROR`,
  `alderpointdns-v2-dnsdist` `NRestarts=0`/`active` throughout,
  `systemctl --failed`: zero failed units.

## Conclusion

Both real defects this RC fixes are confirmed resolved against the
exact live reproduction conditions that found them, on the real
installed package -- not just the in-process regression tests.
Container torn down after verification.
