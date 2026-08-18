# RC25 clean-install acceptance + real, live, end-to-end DNSCrypt resolution

Real `podman --privileged --systemd=always` container, base
`localhost/apdns-v2-4c-accept-base:trixie`, fresh `apt-get install` of
`alderpointdns-v2_2.0.0~rc25-1_all.deb`
(sha256 `01ac3cf18184be38689cb9a85a052b8707b1b6b5992e0ebd936f75b39df09d1d`).

## What RC25 adds over RC24

`docs/v2/dnscrypt-transport-implemented.md`: real DNSCrypt provider-
identity/resolver-certificate provisioning and runtime wiring, closing
the last row of the confirmed mandatory encrypted-transport parity gap.

## Real, live, end-to-end verification

Fresh RC25 target, stock Debian archive `dnsdist 1.9.16` (the
QUIC-lacking build, deliberately *not* upgraded via
`install-enhanced-dnsdist` for this pass -- DNSCrypt needs no QUIC
capability at all, confirmed by design and now by this live result):

- `apt-get install`: `EXIT:0`; `systemctl --failed --no-legend`: zero
  failed units.
- Real HTTPS bootstrap + login.
- Real `POST /api/dns-transports/dnscrypt/rotate {}` -> real `200`,
  a genuine 32-byte-derived fingerprint
  (`DDE5:1912:05F4:4A0D:A1C7:9C32:C5AF:CE22:F556:D7D2:3AA4:8CAC:4370:5A32:242E:F03B`),
  `cert_serial: 1`, `"promoted":true` -- real provider keypair +
  resolver certificate generated via the real dnsdist binary
  (`app/v2/dnscrypt_provisioning.py`) on this genuinely fresh target,
  not carried over from anywhere.
- Real `PUT /api/dns-transports
  {"dnscrypt_enabled":true,"dnscrypt_port":5443,
  "dnscrypt_provider_name":"2.dnscrypt-cert.rc25.local."}` -> real
  `200`, `"promoted":true`.
- Real compiled config confirmed to contain:
  `addDNSCryptBind("0.0.0.0:5443", "2.dnscrypt-cert.rc25.local.",
  "/var/lib/alderpointdns-v2/certs/dnscrypt-resolver.cert",
  "/var/lib/alderpointdns-v2/certs/dnscrypt-resolver.key")` wrapped in
  the real `alderpointdnsv2SafeCapabilityCall` helper.
- Real dnsdist journal: `"Listening on 0.0.0.0:5443 for DNSCrypt"` --
  genuine bind, not a capability-skip message (this stock 1.9.16 build
  genuinely supports DNSCrypt, unlike QUIC).
- **Real `dnscrypt-proxy` (the reference DNSCrypt client) query
  succeeded**: a hand-built `sdns://` stamp encoding the real
  fingerprint/address/provider name returned by the API produced a
  real handshake (`[rc25-resolver] OK (DNSCrypt) - rtt: 0ms`), and a
  real `dig` query through the resulting local `dnscrypt-proxy`
  listener returned the correct, real `NOERROR` answer for
  `cloudflare.com` (`104.16.132.229`/`104.16.133.229`) -- genuine
  end-to-end encrypted resolution through the packaged runtime with
  normal Alderpoint policy/routing active.
- `alderpointdns-v2-dnsdist`: `NRestarts=0`, `active`/`running`
  throughout; real plain DNS (`dig @<container-ip> cloudflare.com`)
  unaffected throughout.

## Conclusion

DNSCrypt is genuinely functional end to end on the real package this
appliance ships, on the stock (non-QUIC) dnsdist build -- no third-party
repository dependency needed for this protocol, unlike DoQ/DoH3. This
completes real, live end-to-end proof for all five mandatory encrypted
transports: DoT, DoH, DoQ, DoH3, and now DNSCrypt. Container torn down
after verification.
