# RC22 clean-install acceptance + live verification of the port-conflict fix and real DoH resolution

Real `podman --privileged --systemd=always` container, base
`localhost/apdns-v2-4c-accept-base:trixie`, fresh `apt-get install` of
`alderpointdns-v2_2.0.0~rc22-1_all.deb`
(sha256 `0ea6679203bb58c5f84ba6bf9e253074cda5ea37c2942e15d4feb3fa52dae140`),
`knot-dnsutils` installed for a real DoH client (`kdig +https`).

## What RC22 fixes over RC21

`docs/v2/dns-transport-port-conflict-fix.md`: a DoT/DoH port
colliding with the management API's own port crash-looped dnsdist and
took down all real DNS answering.

## Live verification

- `apt-get install`: `EXIT:0`; `systemctl --failed --no-legend`: zero
  failed units.
- Real HTTPS bootstrap + login.
- `PUT /api/dns-transports {"doh_enabled":true,"doh_port":8443}` (the
  same port that crash-looped dnsdist on RC21) -> real `400
  port_conflict`, no promotion attempted.
- `PUT /api/dns-transports {"doh_enabled":true,"doh_port":8843,...}`
  (a safe port) -> real `200`, `"promoted":true`.
- `alderpointdns-v2-dnsdist`: `NRestarts=0`, `active` throughout --
  no crash-loop, unlike RC21's reproduction of the original defect.
- Real plain DNS (`dig @127.0.0.1 example.com`): unaffected.
- **Real DoH resolution**: `kdig +https=/dns-query +tls-ca=<real cert>
  @127.0.0.1 -p 8843 example.com A` -> genuine **TLS 1.3 + HTTP/2 POST**
  session, `NOERROR`, both real A records returned, ~42ms.

## Conclusion

Both the port-conflict fix and real DoH resolution are confirmed live
and correct against the real installed package. Container torn down
after verification.
