# BindGuard

BindGuard is a DNS filtering appliance built from dnsdist, BIND 9, and a local
Python management application.

Current lab endpoints:

- Web setup: `http://127.0.0.1:3000/setup`
- DNS: `127.0.0.1:53`
- DoH: `https://127.0.0.1/dns-query`
- DoT: `127.0.0.1:853`

No default administrator exists. Create the first admin through `/setup`.

Useful commands:

```sh
systemctl status named dnsdist bindguard --no-pager
/opt/bindguard/tests/test_acceptance.sh
/opt/bindguard/scripts/backup.sh
```

See `docs/progress.md`, `docs/issues.md`, and `docs/known-limitations.md` for
verified status.
