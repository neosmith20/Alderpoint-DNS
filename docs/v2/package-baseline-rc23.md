# RC23 clean-install acceptance + live verification of DoQ's graceful degradation on the real target dnsdist build

Real `podman --privileged --systemd=always` container, base
`localhost/apdns-v2-4c-accept-base:trixie`, fresh `apt-get install` of
`alderpointdns-v2_2.0.0~rc23-1_all.deb`
(sha256 `ba7cf3e1b19c9d4bbd00b860724a7e24fed01d04d0f14820f0f157510421b140`).

## What RC23 adds over RC22

`docs/v2/doq-transport-implemented.md`: DNS-over-QUIC config
generation implemented, with the real defensive capability-call
wrapper ported from V1's own production-proven pattern.

## Real finding during this pass: the real target dnsdist build lacks QUIC

Confirmed: `dnsdist --version` on the real installed RC23 package
reports `dnsdist 1.9.16` with `Enabled features: ... dns-over-tls
dns-over-https dnscrypt ...` -- **no `dns-over-quic`/`dns-over-http3`**.
This is the real package the appliance's own
`Depends: dnsdist (>= 1.9.0)` constraint resolves to from a stock
Debian 13 archive, matching `docs/dnsdist.md`'s own documented
V1 finding. (An earlier scoping check against this session's host
shell found a differently-sourced `dnsdist 2.1.1` with QUIC support,
installed from a third-party PowerDNS repo for earlier ad-hoc testing
convenience -- not representative of what this package really ships;
corrected in `docs/v2/doq-transport-implemented.md`.)

## Live verification

- `apt-get install`: `EXIT:0`; `systemctl --failed --no-legend`: zero
  failed units.
- Real HTTPS bootstrap + login, `PUT /api/dns-transports
  {"doq_enabled":true,"doq_port":853}` -> real `200`,
  `"promoted":true`; real compiled config confirmed to contain
  `addDOQLocal(...)` wrapped in the real
  `alderpointdnsv2SafeCapabilityCall` helper.
- Real dnsdist journal: `"Alderpoint DNS V2: DoQ (addDOQLocal) failed
  on this dnsdist build (Caught exception: addDOQLocal() called but
  DNS over QUIC support is not present!); skipping."` -- the exact
  intended graceful-degradation message, not a crash.
- `alderpointdns-v2-dnsdist`: `NRestarts=0`, `active` -- no
  crash-loop.
- Real plain DNS (`dig @127.0.0.1 example.com`): unaffected throughout.
- Real `kdig +quic @127.0.0.1 -p 853`: correctly failed to connect
  (`ERROR: failed to query server`) -- no QUIC listener is bound, as
  expected, not a hang or a false success.

## Conclusion

DoQ's config generation and defensive degradation are confirmed
correct and safe on the real target dnsdist build. Genuine end-to-end
QUIC resolution could not be demonstrated on this target, honestly
documented as a real environment limitation, not a code defect.
Container torn down after verification.
