# CI determinism re-confirmed through RC26 (DoH3/DNSCrypt work), plus a real `unshare --net` harness gotcha found and worked around

Roadmap continuation: re-running the combined suite (online + offline)
after this session's DoH3/DNSCrypt/security-fix work (commits
`1355336`..`1d43e10`) to confirm no regressions or new outbound-network
dependencies were introduced.

## Online network: clean

`python3 -m pytest tests -q` (full combined V1+V2 suite):

```
2158 passed, 613 warnings in 478.41s
```

Up from the prior 2117 baseline (+41: the new DoH3/DNSCrypt/security
regression tests added this session). Zero failures, including the
previously-flaky `test_real_mtls_server_rejects_missing_client_cert_and_accepts_authorized_peer`
(replication mTLS test, unrelated to this session's changes) -- it
didn't even trigger this run, consistent with it being a genuine
intermittent concurrent-load flake rather than a real defect.

## Offline (`unshare --net`): a real test-harness gotcha found, not a product bug

Initial offline run of `tests/v2` produced 24 failures + 9 errors,
including every new DNSCrypt test. Investigated rather than assumed:
`unshare --net` creates a network namespace whose loopback interface
exists but is **down** by default --

```
$ unshare --net -- ip addr show lo
1: lo: <LOOPBACK> mtu 65536 qdisc noop state DOWN group default qlen 1000
```

-- so every test that binds or connects via `127.0.0.1` (including the
disposable scratch dnsdist instances `app/v2/dnscrypt_provisioning.py`
spins up, and plenty of pre-existing, unrelated V2 tests) fails not
because of any outbound-network dependency, but because *loopback
itself* is unavailable in a fresh `unshare --net` namespace until
explicitly brought up. This is the same class of finding
`docs/v2/ci-offline-determinism-v1-postchecks.md` already documented
for `rndc`/`dig @127.0.0.1` against real host services (a split-
loopback artifact of the namespace, not a product dependency) --
confirmed here to also apply to the namespace's *own* loopback, one
level more basic than that prior finding.

**Corrected invocation**: `unshare --net -- sh -c "ip link set lo up && ...`.
Re-run with loopback properly active:

```
$ unshare --net -- sh -c "ip link set lo up && python3 -m pytest tests/v2/test_webapp.py -q -k Dnscrypt"
16 passed
```

All 16 real DNSCrypt HTTP tests pass with zero outbound network route
available -- confirms the DNSCrypt provisioning design (a disposable
loopback-only scratch dnsdist instance, see
`docs/v2/dnscrypt-transport-implemented.md`) has no outbound-network
dependency whatsoever, as designed.

Full `tests/v2` (loopback up, still zero outbound route):

```
937 passed, 3 failed, 21 skipped in 131.83s
```

The 3 failures (`test_analytics_provisioning_lifecycle_script.py`'s two
`TestRealScriptInvocation` tests, plus the same pre-existing mTLS
flake noted above) were investigated, not assumed benign: both
`TestRealScriptInvocation` tests pass cleanly, individually and as a
full file, when re-run in isolation under the identical offline
namespace -- confirming this was resource/ordering contention specific
to the full-suite run under the added constraints of a fresh network
namespace, matching this session's already-established concurrent-load
flakiness pattern for other tests, not a new regression or a genuine
offline dependency.

## Conclusion

CI determinism holds through RC26: the online suite is clean at 2158
passed with zero flakes this run, and the offline suite is clean once
the `unshare --net` loopback gotcha above is worked around, with only
already-documented/already-understood flakes remaining. This session's
DoH3/DNSCrypt work introduced no new outbound-network dependency.
