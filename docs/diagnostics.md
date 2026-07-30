# Diagnostics

`alderpointdns-diagnostics` creates a sanitized support bundle:

```sh
sudo /opt/alderpointdns/scripts/alderpointdns-diagnostics --output-dir /tmp
```

The bundle includes:

- Alderpoint DNS version
- OS, kernel, and Python version
- Service status for `alderpointdns`, `named`, `dnsdist`, and
  `alderpointdns-analytics`
- Listener status
- BIND and dnsdist validation output
- SQLite schema object names and `PRAGMA user_version`
- Recent warning/error logs unless `--no-journal` is used
- Network interface summary
- Disk and memory summary
- DNS health-check results through BIND backend and dnsdist frontend
- Configuration file metadata such as path, size, owner UID/GID, and mode

The bundle automatically redacts:

- Passwords
- API keys
- Session secrets
- Enrollment tokens
- Authorization headers
- Private-key PEM blocks
- Sensitive resolver URL query strings
- BIND `key { secret "..."; }` blocks (RNDC/TSIG shared secrets), which
  `named-checkconf -p` would otherwise echo verbatim into the bundle

Private DNS records and detailed query contents are not included by default.
`--include-private-dns` is currently an explicit placeholder that records the
operator's opt-in but still does not export private DNS data; use an encrypted
backup when support truly needs private records.

Redaction can be smoke-tested without creating a bundle:

```sh
/opt/alderpointdns/scripts/alderpointdns-diagnostics --self-test-redaction
```
