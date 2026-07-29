# BindGuard

BindGuard is a DNS filtering appliance built from dnsdist, BIND 9, and a local
Python management application.

Current lab endpoints:

- Web setup: `http://<vm-lan-ip>:3000/setup`
- DNS: `<vm-lan-ip>:53`
- DoH: `https://<vm-lan-ip>/dns-query`
- DoT/DoQ: `<vm-lan-ip>:853`

No default administrator exists. Create the first admin through `/setup`.

Useful commands:

```sh
systemctl status named dnsdist bindguard --no-pager
/opt/bindguard/tests/test_acceptance.sh
/opt/bindguard/scripts/backup.sh
```

See `docs/progress.md`, `docs/issues.md`, and `docs/known-limitations.md` for
verified status.
