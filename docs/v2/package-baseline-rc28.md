# RC28 clean-install acceptance + real live confirmation of the login database-lock fix under the exact reproduction conditions

Real `podman --privileged --systemd=always --memory=1g` container, base
`localhost/apdns-v2-4c-accept-base:trixie`, fresh `apt-get install` of
`alderpointdns-v2_2.0.0~rc28-1_all.deb`
(sha256 `4e6271626ee183e29f1d1c486da58b16bd5af4e1e8f88c8f279b880ea5e824ba`).

## What RC28 adds over RC27

`docs/v2/login-database-locked-under-load-fix.md`: fixes the real
`sqlite3.OperationalError: database is locked` -> raw HTTP 500 defect
found live during RC27's hardware/performance matrix pass, under real
combined DNS + analytics + concurrent-login load.

## Real, live verification -- the exact reproduction, repeated against the fix

Fresh RC28 target, 1 GiB memory tier (the same tier the defect was
found on), all real background services active
(analytics/analytics-protobuf-receiver/discovery/dns-observer/
schedule/tierb), real `dnsperf -c 8 -l 15` DNS load running
concurrently with 8 real concurrent `POST /api/login` requests:

```
login 0: HTTP 200 in 6.794s
login 1: HTTP 503 in 0.039s
login 2: HTTP 200 in 7.021s
login 3: HTTP 200 in 6.868s
login 4: HTTP 503 in 0.045s
login 5: HTTP 503 in 0.040s
login 6: HTTP 503 in 0.040s
login 7: HTTP 503 in 0.040s
```

**All 3 logins that passed the Argon2id concurrency limiter now return
real `200`** -- zero `500`s, compared to RC27's identical reproduction
where 2 of 3 returned `500`. The 5 correctly fast-rejected `503`s are
unchanged (the RC13 `HashConcurrencyLimiter` fix, still working as
intended).

DNS itself throughout: `dnsperf` -- `1,141,102` queries sent,
`100.00%` completed, `0` lost, `100.00%` `NOERROR`, `76,069` QPS.
`alderpointdns-v2-dnsdist`: `NRestarts=0`, `active` throughout;
`systemctl --failed`: zero failed units.

## Conclusion

The real defect this RC fixes is confirmed resolved under the exact
live reproduction conditions that found it -- not just the in-process
regression tests. Container torn down after verification.
