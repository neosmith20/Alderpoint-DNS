# Troubleshooting

Alderpoint DNS is currently beta software (v0.4.0-beta.5); please include a
sanitized diagnostics bundle when reporting issues (see
`.github/ISSUE_TEMPLATE/bug_report.md`).

Start with:

```sh
systemctl status alderpointdns named dnsdist alderpointdns-analytics
ss -ltnup
dig @127.0.0.1 -p 5353 cloudflare.com A
dig @127.0.0.1 -p 53 cloudflare.com A
/opt/alderpointdns/scripts/alderpointdns-diagnostics --output-dir /tmp
```

Common failures:

- Web app down: DNS should still work. Check `journalctl -u alderpointdns`.
- dnsdist down: frontend DNS and encrypted listeners fail, but BIND backend on
  loopback can still be tested on port `5353`.
- BIND down: DNS resolution fails. Check `named-checkconf -p /etc/bind/named.conf`
  and recent BIND logs.
- Import apply fails: review the preview report and backup created before
  apply.
- Encrypted DNS fails: validate certificate/key match and listener status on
  `/encryption`.
- Cache flush fails: check the `dns_cache_flushes` history and `rndc status`.

Do not expose Alderpoint DNS publicly while troubleshooting. Keep firewall rules
restricted to intended private clients.
