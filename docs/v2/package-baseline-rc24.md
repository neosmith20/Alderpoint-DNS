# RC24 clean-install acceptance + real, live, end-to-end DoQ and DoH3 resolution

Real `podman --privileged --systemd=always` container, base
`localhost/apdns-v2-4c-accept-base:trixie`, fresh `apt-get install` of
`alderpointdns-v2_2.0.0~rc24-1_all.deb`
(sha256 `2bef2e3dedbc368dc7f4acf3abeca6c0085db73977dd504703532c34880503ca`,
before the two live-found-and-fixed defects below;
`e2c578f19508dd7093e0a89f622d77d328bfa0d22326f4a055eb7eeb33b256f8` after).

## What RC24 adds over RC23

`docs/v2/doh3-transport-implemented.md`: DNS-over-HTTP/3 config
generation, and DoQ's real QUIC-capability blocker resolved via V1's
existing opt-in `install-enhanced-dnsdist` mechanism reused verbatim
for V2.

## Real defects found and fixed live during this pass

1. **Missing `gnupg`/`bind9-dnsutils` package dependencies.** V2's own
   `alderpointdns-v2-ctl install-enhanced-dnsdist` (reusing `app/
   dnsdist_upgrade.py`) calls `gpg` (signing-key fingerprint
   verification) and `dig` (post-upgrade baseline resolution check),
   but neither was declared in `scripts/build-v2-deb.sh`'s `Depends:`
   line -- confirmed live: a fresh clean-install container had `curl`
   (transitively pulled in) but not `gpg`, and the command failed
   outright with a fail-closed error and automatic rollback (not a
   silent partial state). Fixed by adding both to `Depends:`, matching
   V1's own `packaging/debian/control`.
2. **V1-hardcoded runtime topology in the reused installer.**
   `install_enhanced_dnsdist()`'s post-upgrade check-config/restart/
   verify steps were hardcoded to V1's own real service name
   (`dnsdist.service`) and config path (`/etc/dnsdist/dnsdist.conf`) --
   confirmed live: restarting the stock `dnsdist` unit on a V2-only
   host (which never generates `/etc/dnsdist/dnsdist.conf`) failed
   outright. Fixed by parameterizing `dnsdist_conf`/
   `service_override_dir`/`cert_dir`/`backup_dir`/
   `dnsdist_service_name`/`required_services`, defaulting to V1's exact
   prior values (V1's own `alderpointdns install-enhanced-dnsdist`
   behavior is unchanged), with V2's CLI passing its own real values
   (`alderpointdns-v2-dnsdist`, `/var/lib/alderpointdns-v2/compiled/
   dnsdist.conf`).
3. **Real restart/verify race condition.** `restart_dnsdist_and_verify_
   services()` only waits for systemd to report the unit "active",
   which happens as soon as the process is exec'd, not once dnsdist has
   actually finished startup (loading backends/ACLs, binding sockets).
   `baseline_dns_test()`'s single immediate `dig` right after observed
   a real, live, reproducible `connection refused` even though the
   exact same query succeeded well under a second later. Fixed with a
   bounded retry loop, matching the shape `restart_dnsdist_and_verify_
   services()` already uses.

All three closed with regression coverage
(`tests/test_dnsdist_upgrade.py`: `BaselineDnsTestTest`,
`RuntimeTopologyParameterizationTest`) and re-verified against a fresh
clean-install target after each fix, not just re-run offline.

## Real, live, end-to-end verification (the actual proof this session was missing)

Fresh RC24 target (post-fix artifact), from a stock clean install:

- `dnsdist --version` before: `dnsdist 1.9.16`, `Enabled features: ...
  dns-over-tls dns-over-https dnscrypt ...` -- **no QUIC**, confirming
  this really is the real stock target, not a pre-warmed host.
- `alderpointdns-v2-ctl install-enhanced-dnsdist` run for real against
  this fresh target (not a host with the repo pre-configured): real
  network resolution of `repo.powerdns.com`, real signing-key download
  + fingerprint verification, real `apt-get install`, real
  `dnsdist --check-config` against V2's actual compiled config, real
  `systemctl restart alderpointdns-v2-dnsdist`, real baseline `dig`
  query succeeding. Report: `dnsdist 1.9.16 -> dnsdist 2.1.1`,
  `dns-over-quic: False -> True`, `dns-over-http3: False -> True`.
- Real admin bootstrap + login, `PUT /api/dns-transports
  {"doq_enabled":true,"doq_port":853,"doh_enabled":true,"doh_port":443,
  "doh3_enabled":true,"doh3_port":8444}` -> real `200`,
  `"promoted":true`.
- Real dnsdist journal: `"Listening on DoQ frontend"
  frontend.address="0.0.0.0:853"` and `"Listening on DoH3 frontend"
  frontend.address="0.0.0.0:8444"` -- genuine binds, not the
  SafeCapabilityCall skip-message path.
- **Real `kdig +quic @<container-ip> -p 853 cloudflare.com A`
  (host-to-container, real network hop) succeeded**: `QUIC session
  (QUICv1)-(TLS1.3)-(ECDHE-X25519)-(ECDSA-SECP256R1-SHA256)-
  (AES-256-GCM)`, real `NOERROR` answer, real A records returned. This
  is the first genuine end-to-end DoQ resolution demonstrated in this
  project (RC23 explicitly could not demonstrate this on the
  QUIC-lacking stock target).
- **Real `curl --http3` DoH3 query (host-to-container) succeeded**:
  real HTTP/3 handshake, `HTTP/3 200`, `content-type:
  application/dns-message`, real DNS answer bytes returned.
- **Real Alt-Svc discovery verified**: a plain DoH request to the same
  appliance returned `alt-svc: h3=":8444"; ma=86400` in the response
  headers, matching the DoH3 listener actually configured.
- `NRestarts=0`, `alderpointdns-v2-dnsdist` `active`/`running`
  throughout; `systemctl --failed`: zero failed units; plain DNS
  (`dig @<container-ip> cloudflare.com`) unaffected throughout.

## Conclusion

DoQ and DoH3 are now genuinely functional end to end on the real
package this appliance ships, not just config-generation-correct --
closing the honest gap RC23 left open. Two real, live-reproduced
defects in the reused installer (missing package deps, V1-hardcoded
runtime topology) and one real race condition were found and fixed
along the way, all with regression coverage. Container torn down after
verification.
