# Testing

Run individual suites:

```sh
/opt/bindguard/tests/test_bind_backend.sh
/opt/bindguard/tests/test_dnsdist_frontend.sh
/opt/bindguard/tests/test_blocklist_deploy.sh
/opt/bindguard/tests/test_blocklist_failure_paths.sh
/opt/bindguard/tests/test_analytics.py
/opt/bindguard/tests/test_local_dns.py
/opt/bindguard/tests/test_web_smoke.sh
/opt/bindguard/tests/test_backup_restore.sh
```

The web smoke test also renders DNS Settings with long path/version-like
content and asserts the responsive card/table wrapping rules that prevent
horizontal overflow. It also renders the analytics dashboard and query log with
long domain and IPv6-like values.

The Local DNS suite covers A and AAAA record creation, automatic PTR records,
forward and reverse zone rendering, editing, deletion, disabled records,
duplicate hostname/PTR warnings, invalid host/IP rejection, CNAME conflicts,
multiple reverse zones, serial increments, generated-zone rollback, BIND restart
readiness, analytics client aliases, PTR fallback display, CSV import/export,
and hosts-file preview. The web smoke test renders the Local DNS page with long
domains, IPv6 clients, and upstream-like strings to guard against horizontal
overflow.

The analytics unit suite covers aggregate collection, counter resets, bucketing,
blocked-query detection, ordinary NXDOMAIN handling, protocol classification,
retention cleanup, database-size protection, malformed protobuf input, queue
overflow, privacy modes, and query-log filtering.

Run the combined suite:

```sh
/opt/bindguard/tests/test_acceptance.sh
```

Manual protocol tests:

```sh
dig @127.0.0.1 -p 53 cloudflare.com A
dig @127.0.0.1 -p 53 cloudflare.com A +tcp
kdig +https @127.0.0.1 -p 443 +tls-ca=/etc/bindguard/certs/bindguard-lab.crt +tls-hostname=bindguard.local cloudflare.com A
kdig +tls @127.0.0.1 -p 853 +tls-ca=/etc/bindguard/certs/bindguard-lab.crt +tls-hostname=bindguard.local cloudflare.com A
kdig +quic @127.0.0.1 -p 853 cloudflare.com A
```
