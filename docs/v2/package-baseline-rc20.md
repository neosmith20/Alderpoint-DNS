# RC20 clean-install acceptance + live verification of real DoT resolution

Real `podman --privileged --systemd=always` container, base
`localhost/apdns-v2-4c-accept-base:trixie`, fresh `apt-get install` of
`alderpointdns-v2_2.0.0~rc20-1_all.deb`
(sha256 `5e891e50b7357061c67881559a7848bddd1e7586a854eb7be6082046d9f502d8`),
`knot-dnsutils` installed for a real DoT client (`kdig +tls`).

## What RC20 adds over RC19

`docs/v2/dot-transport-implemented.md`: DNS-over-TLS implemented,
closing part of the confirmed mandatory-parity gap
(`docs/v2/encrypted-transport-parity-gap.md`).

## Live verification

- `apt-get install`: `EXIT:0`; `systemctl --failed --no-legend`: zero
  failed units.
- Real HTTPS bootstrap + login.
- `GET /api/dns-transports`: `dot_cert_provisioned: true` (the
  management TLS cert already exists from install-time bootstrap).
- `PUT /api/dns-transports {"dot_enabled":true,"dot_port":853}` ->
  real recompile+promote, `"promoted":true`; real compiled config
  confirmed to contain `addTLSLocal("0.0.0.0:853", ...)`.
- **Real DoT resolution**: `kdig +tls +tls-ca=<real cert>
  @127.0.0.1 -p 853 example.com A` -> genuine **TLS 1.3** session
  (`ECDHE-X25519`/`ECDSA-SECP256R1-SHA256`/`AES-256-GCM`), `NOERROR`,
  both real A records returned, ~24ms.
- Disabling (`dot_enabled:false`): real recompile, `ss -tlnp` no
  longer shows port 853 bound; plain `dig @127.0.0.1` on port 53
  confirmed unaffected throughout (before, during, and after enabling/
  disabling DoT).

## Conclusion

DoT is a real, working, live-verified feature on this artifact --
the first of five confirmed-missing mandatory-parity encrypted
transports now closed. Container torn down after verification.
