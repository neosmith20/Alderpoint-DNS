# Real defect found and fixed: a DoT/DoH port conflict took down all real DNS answering

Found live during RC21 acceptance testing of the new DoH implementation
(`docs/v2/doh-transport-implemented.md`).

## What was found

Enabled DoH via the real `PUT /api/dns-transports` API on a real
installed RC21 package, using `doh_port=8443` -- the same port the
management HTTPS API (`uvicorn`) already binds. The request succeeded
(`200`, `"promoted":true`) because `dnsdist --check-config` only
statically validates the Lua config's syntax; it does not attempt to
actually bind the listed sockets, so a port already held by a
different process is invisible to it.

**Real, live, confirmed consequence:** the moment the promoted config
went live, `alderpointdns-v2-dnsdist` crash-looped trying to bind the
already-occupied port 8443 (`systemctl status` showed a climbing
restart counter), which took down **all real DNS answering** --
`dig @127.0.0.1` returned "connection refused" on port 53, not just a
failure of the misconfigured DoH listener. This directly violates this
architecture's own repeatedly-stated invariant that DNS answering must
never depend on unrelated components, and defeats
`recompile_and_promote()`'s own "a known-good runtime always remains
active on failure" guarantee, since a runtime bind conflict is
invisible to the static validation that guarantee relies on.

## Fix

`app/v2/webapp.py`'s `PUT /api/dns-transports` now validates requested
ports **before** attempting any recompile/promotion:
`_validate_dns_transport_ports` rejects (`400 port_conflict`) any
enabled protocol's port that collides with one of this appliance's own
other fixed, already-bound ports (management API 8443, replication
9443, discovery/dns-observer 1053, analytics receiver 5391, or the
currently configured plain DNS port), and rejects DoT/DoH sharing the
same port when both are enabled. Only checks ports for protocols
actually being enabled -- a leftover/default value for a disabled
protocol never blocks an otherwise-valid update.

## Verification

New tests in `tests/v2/test_webapp.py`'s `TestDnsTransports`:
`test_dot_port_conflicting_with_management_api_rejected`,
`test_doh_port_conflicting_with_replication_service_rejected`,
`test_dot_and_doh_same_port_rejected`,
`test_disabled_protocol_port_conflict_not_checked`.

Full suite: 2100 passed (`tests/`), 908 passed (`tests/v2/`), no
flakes this pass.

## What this does not (yet) cover

This is a fixed, known-ports allowlist, not a real live socket-bind
probe -- an admin-introduced conflict with something *other* than this
appliance's own fixed ports (e.g. a third-party service also bound to
a chosen DoT/DoH port) would still only be caught at runtime. A real
bind-probe (attempt a bind-and-close on the target port before
promoting, or parse `dnsdist --check-config`'s behavior more deeply)
would close that residual gap but was judged unnecessary scope for
this fix -- the confirmed, reproduced failure was specifically a
collision with this appliance's own well-known ports, and that
specific, real, reproduced failure is what's fixed here.
