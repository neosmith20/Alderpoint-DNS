# Hardening Review

Reviewed areas:

- Authentication: single administrator account, Argon2 password hashing, no
  default credentials.
- Authorization: admin dependency protects every management route; first-run
  setup is only available before an admin exists.
- CSRF: all mutating form routes require a signed-session CSRF token.
- Session cookies: `HttpOnly`, `SameSite=Strict`, and `Secure` when
  `ALDERPOINTDNS_COOKIE_SECURE=1`. Current lab HTTP mode keeps `Secure` off.
- Input validation: DNS records, upstream resolvers, cache settings,
  encryption settings, imports, backup components, and replication enrollment
  all validate before apply.
- File uploads: imports and backups stage uploaded content with size/path
  controls; uploaded certificate keys are validated and never displayed.
- Command execution: privileged operations go through fixed sudoers entries
  without user-controlled command arguments.
- Permissions/ownership: service units use the `alderpointdns` user; generated
  secrets and private keys are mode-restricted.
- Secret storage: local secrets live under `/etc/alderpointdns`; diagnostics and
  default backups redact or exclude them.
- Logging/redaction: diagnostics redacts credentials and excludes private DNS
  data by default.
- DNS recursion ACLs: BIND and dnsdist are restricted to private/loopback
  clients; Alderpoint DNS must not be deployed as a public open resolver.
- Public exposure: encrypted DNS listener wildcard binds require external
  firewall review; public admin UI exposure is unsupported.
- Backup encryption: optional backup password encryption is available for
  off-host archives.
- Replication: enrollment tokens are hashed, one-time, and revocable; runtime
  sync uses mTLS client authentication.

Accepted beta risks:

- Admin UI HTTPS is not implemented natively yet. Use private access or a
  trusted reverse proxy and set `ALDERPOINTDNS_COOKIE_SECURE=1`.
- Signed apt repository publishing is not implemented; beta packages are local
  test artifacts.
- `--include-private-dns` diagnostics remains a placeholder; private DNS data
  should be shared through encrypted backups only.
