# Testing

Run individual suites:

```sh
/opt/bindguard/tests/test_bind_backend.sh
/opt/bindguard/tests/test_dnsdist_frontend.sh
/opt/bindguard/tests/test_blocklist_deploy.sh
/opt/bindguard/tests/test_blocklist_failure_paths.sh
/opt/bindguard/tests/test_web_smoke.sh
/opt/bindguard/tests/test_backup_restore.sh
```

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
