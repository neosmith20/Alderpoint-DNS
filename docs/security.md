# Security

This page describes the security controls actually implemented today; see
`docs/hardening-review.md` for accepted risks and `SECURITY.md` for how
to report a vulnerability.

- The web process runs as `alderpointdns`, not root.
- Privileged web operations are restricted by `/etc/sudoers.d/alderpointdns` to
  exact compiler commands.
- The admin UI requires authentication and relies on your network firewall
  (VLAN/segmentation rules) for network reachability.
- Encryption Settings certificate uploads and generation write to
  root:_dnsdist-owned `/etc/alderpointdns/certs` only through the privileged,
  argument-free `alderpointdns_compiler.py encryption-deploy` sudo entry; the
  unprivileged web process only ever stages bytes under
  `/var/lib/alderpointdns/staging`. Private key contents are never rendered back
  to the browser.
- Backup archives exclude TLS/DNSCrypt private keys, the web session-signing
  secret, and dnsdist API/webserver credentials by default; including them
  requires both an explicit checkbox and a separate confirmation checkbox in
  the UI. Password-encrypted archives use `openssl enc -aes-256-cbc -pbkdf2`
  with the password passed via stdin, never a command-line argument (so it
  never appears in process listings). Restore, like create, only runs
  through the privileged, argument-free `backup-{create,restore,preview,
  schedule-deploy}` sudo entries; the web process stages request intent and
  a one-time-use, 0600, deleted-after-read password file, never a live path
  or password as a sudo argument.
- No default administrator exists.
- Passwords are hashed with Argon2, through a single shared implementation
  (`app/auth.py`) used by both the web app and the root-only local recovery
  CLI, so a CLI-issued reset verifies exactly like a web-issued one.
- First-run setup requires a matching password confirmation, both
  client-side and server-side; the entered username is preserved and neither
  password value is ever echoed back after a failed submission.
- Sessions are server-side rows (`sessions` table), not just signed cookie
  contents: the cookie carries only an opaque session id, so a session can be
  individually revoked (logout, a password change revoking every other
  session, or an explicit "revoke all other sessions" action) without
  waiting for cookie expiry.
- Session cookies are signed, `HttpOnly`, and `SameSite=Strict`. Set
  `ALDERPOINTDNS_COOKIE_SECURE=1` in the web service environment when the admin UI
  is served over HTTPS.
- CSRF tokens are required for mutating forms, including first-run setup: an
  anonymous, pre-login session (holding only a CSRF token, never
  authentication state) is established on first page visit so the token
  embedded in the setup/login forms is bound to something persisted
  server-side rather than only ever shown to the browser.
- System > Administration records successful and failed administrative
  security actions (password changes, session revocations, local CLI
  recovery) in an audit log (`admin_audit_log`); passwords and password
  hashes are never written to it.
- A forgotten administrator password can be recovered locally, without any
  network route, via `sudo alderpointdns admin reset-password` (requires
  local root; see `scripts/alderpointdns-admin`). It revokes the
  administrator's existing web sessions and never requires email.
- System > Notifications provider secrets (SMTP passwords, webhook URLs --
  most webhook URLs embed a bearer-equivalent token) are masked, write-only
  fields, never rendered back to the browser after saving. They are
  excluded from backup archives by default, like other credential material,
  and only included when the backup's `private_keys` component is selected.
  Notifications never include raw configuration, passwords, API keys, or DNS
  query contents in their message content.
- dnsdist ACLs allow RFC1918 private networks by default, with an explicit
  environment switch for allow-all mode.
- Encryption Settings can restrict client DNS listeners to a specific IPv4
  and/or IPv6 address. The default wildcard addresses preserve the lab setup
  but should be narrowed or protected by firewall rules before any public or
  multi-tenant deployment.
- BIND listens only on loopback backend ports.
- Local DNS authoritative zones are generated separately from RPZ policy and
  are included only through the managed BIND local-zone include.
- The default Local DNS domain is `home.arpa`; `.local` is rejected because it
  conflicts with multicast DNS.
- AppArmor remains enabled for BIND.
- The analytics collector runs as the restricted `alderpointdns` account and
  listens only on `127.0.0.1:5301`.
- dnsdist's web/API and control sockets remain loopback-only; analytics never
  exposes dnsdist credentials or private TLS keys.
- Detailed query logging can be disabled, client addresses can be anonymized,
  and aggregate-only mode avoids retaining individual query rows.
- Telemetry queues are bounded. If the collector is unavailable or overloaded,
  DNS service continues and telemetry drops are counted separately.

Lab HTTP mode does not mark cookies `Secure`; the environment toggle above is
for HTTPS admin deployments.
