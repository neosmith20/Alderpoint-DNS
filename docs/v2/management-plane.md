# Alderpoint DNS V2 — Management Plane / Native HTTPS (Workstream 4B)

## Architecture

`app/v2/webapp.py`: a real FastAPI application exposing the already-real V2 backend (policy
store/compiler/runtime, analytics, secrets, notifications, migration) as a JSON API. No HTML/UI —
explicitly out of scope for this pass. Runs from installed package paths only
(`/opt/alderpointdns-v2`), served by `uvicorn` with native TLS (`--ssl-certfile`/`--ssl-keyfile`),
packaged as the `alderpointdns-v2-web` systemd unit.

**Never in the DNS hot path.** Every route that changes DNS-affecting state goes through
`app/v2/runtime_compile.py`'s `recompile_and_promote()`, which stages + validates against the real
installed `dnsdist` binary and only promotes on success — the control.db write and the runtime
promotion happen inside one transaction (`_mutate_and_promote` in `webapp.py`): if validation
fails, both the database write and the live runtime roll back together, so control.db and the
compiled runtime can never diverge, and a known-good runtime always stays live.

## HTTPS / TLS lifecycle

- `app/v2/tls_cert.py`: real X.509 via the `cryptography` library (no custom crypto). EC P-256,
  SHA-256, 397-day validity, SAN covering loopback identities. `stage_validate_promote()` never
  touches the live cert/key paths until the replacement pair is confirmed to actually match and be
  time-valid — proven via a real mismatched-key-pair rejection test that leaves the SHA-256 of the
  live certificate byte-for-byte unchanged.
- Bootstrap: `alderpointdns-v2-ctl ensure-tls-cert` (called once at `postinst`, and again as
  `ExecStartPre=` on every service start as a self-heal) is idempotent — generates only if absent
  or invalid, never regenerates a working pair.
- Certificate paths: `/var/lib/alderpointdns-v2/certs/server.crt` (0644),
  `/var/lib/alderpointdns-v2/certs/server.key` (0600), owned `alderpointdns-v2:alderpointdns-v2`.
  Private key material is never logged, never returned by any API response, and never stored in
  control.db.
- **HTTP strategy**: HTTPS-only. There is no separate plaintext listener to redirect from. This is
  the "Preferred" option the spec itself lists, and it sidesteps the redirect-loop/trusted-proxy
  complexity of a dual listener entirely, consistent with V2 not yet having a reverse-proxy story.
- **No HSTS.** Deliberate: the bootstrap certificate is self-signed, and there's no separate HTTP
  listener to redirect from in the first place — an HSTS header sent once and then encountered
  again after a certificate regeneration, appliance reinstall, or browser trust-store reset is
  exactly the "permanently locks an administrator out" failure mode the spec warns against.
  Revisit once a non-self-signed default is the common case.
- **TLS version/ciphers**: uvicorn/Python's `ssl` module defaults (`ssl.PROTOCOL_TLS_SERVER`),
  which on Debian 13's OpenSSL already exclude SSLv3/TLS1.0/1.1 system-wide — no custom cipher
  configuration was added, per "use library/system defaults unless justified." Real proof: `curl`
  against the installed service negotiated TLS 1.3 / `TLS_AES_256_GCM_SHA384`.
- **Trusted proxies**: none configured in this pass — `X-Forwarded-*` headers are never trusted;
  client identity always comes from the real TCP peer.

## Authentication / sessions

Reuses the exact `admins`/`sessions`/`login_attempts` tables control.db's schema already defined
(Workstream 1) and `app/v2/auth_hash.py`'s Argon2id wrapper — no second password database.

- **First-admin bootstrap**: `alderpointdns-v2-ctl init-state` generates a random
  (`secrets.token_urlsafe(32)`) one-time token at `/var/lib/alderpointdns-v2/bootstrap-setup-token`
  (mode 0600), only while no admin account exists, and **never prints the value** to postinst
  output (which can land in a world-readable apt/dpkg log) — only the fact that it was written,
  at a root-only path the operator must read themselves. `POST /api/setup` consumes it with a
  constant-time comparison (`hmac.compare_digest`) and deletes the file on success; a second call
  is rejected once an admin exists (real proof: `409 already_configured`).
- **Login**: real Argon2id verify (`app/v2/auth_hash.py`), bounded by
  `HashConcurrencyLimiter` (§14, prevents memory-exhaustion via concurrent hash floods). A new
  session row is created on every successful login (never reusing a pre-login session — real
  session rotation, proven via a test asserting two logins produce two different CSRF tokens).
- **Rate limiting**: real, persisted (`login_attempts` table, bounded by periodic deletion of old
  rows) — 5 failures per IP per 15-minute window returns `429`, proven with a real repeated-bad-
  login test.
- **Session cookie**: `HttpOnly`, `SameSite=strict`, `Secure` (verified via real `Set-Cookie`
  header inspection over real TLS: `HttpOnly; Max-Age=28800; Path=/; SameSite=strict; Secure`),
  8-hour max age.
- **CSRF**: synchronizer-token pattern (matches the existing, proven V1 `webapp.py` convention) —
  the session's `csrf` value is returned once at login and must be echoed back via the
  `X-CSRF-Token` header on every state-changing request; verified with constant-effort comparison.
  Proven: missing/wrong token → `403`; correct token → success.

## Security headers

`X-Content-Type-Options: nosniff`, `Content-Security-Policy: default-src 'none'; frame-ancestors
'none'`, `Referrer-Policy: no-referrer`, `X-Frame-Options: DENY`, `Cache-Control: no-store` on
every response. No HSTS (see above).

## API surface (this pass)

Real, service-layer-backed (never raw SQL in a route handler) endpoints for: setup/login/logout,
health, networks, global + per-network policy, clients, effective-policy explain
(`policy_service.explain_policy_for_client`, unmodified), upstream profiles, domain routing,
services/blocking rulesets, schedules, analytics (recent log, top domains — via
`AnalyticsService`, unmodified), notifications (via `notification_store` + `SecretStore`,
unmodified), a secrets backup trigger, migration source detection (read-only), system status, and
TLS status/replace.

**Known limitations, stated honestly:**
- `filtering_profile_id` (ordinary allow/block lists) is not yet mapped into the runtime compiler
  — only the three service-blocking-ruleset-shaped fields (`parental_policy_id`,
  `security_policy_id`, `service_blocking_ruleset_id`) and `safesearch_mode` are (see
  `app/v2/runtime_compile.py`'s own docstring for the exact scope statement).
- `safesearch_mode` maps to "all supported providers" when not `"off"` — the policy model has no
  per-provider selection field yet, so `"strict"` and `"moderate"` currently produce the same
  provider set.
- Backup/restore/migration APIs are intentionally thin in this pass: backup covers secrets only
  (not a full control.db snapshot), migration exposes detection only (real preview/run/rollback
  wiring was out of scope for this specific pass, per its own "preview remains read-only, do not
  run migration merely because a page is opened" instruction — nothing here runs a migration).
- No group/tag CRUD endpoints, no RBAC beyond "authenticated admin" (the spec's stated minimum).

## Real defects found and fixed this pass

1. **Exception-handler registration**: an `@app.exception_handler(Exception)` bound to the bare
   `Exception` type is invoked by Starlette's outer `ServerErrorMiddleware`, which re-raises after
   building its response (so an ASGI server can log it) — real HTTP clients see the correct
   response either way, but `TestClient`'s default `raise_server_exceptions=True` surfaced this as
   a test failure. Fixed by registering handlers on the concrete expected types (`ValueError`,
   `RuntimeCompileError`), which are handled by the inner `ExceptionMiddleware` with no re-raise.
2. **`ProtectSystem=strict` vs. `ExecStartPre`**: the web unit's `ExecStartPre` originally called
   the full `init-state` (which also writes `/etc/alderpointdns-v2`), which is outside that unit's
   `ReadWritePaths=` — every single start failed with a real `OSError: [Errno 30] Read-only file
   system`. Fixed by splitting a narrower `ensure-tls-cert` subcommand (touches only `CERTS_DIR`
   under `STATE_DIR`, which is writable) and pointing `ExecStartPre` at that instead.
3. **Provisioned analytics runtime directory mode**: `tempfile.mkdtemp()` creates its staging
   directory `0700`; the old `provision_vendor_runtime()` renamed it directly into place, so the
   promoted `vendor-runtime-v2-analytics/` directory silently inherited owner-only (root)
   permissions — invisible via a root shell (`podman exec` testing), but broke `import
   pyarrow`/`import duckdb` for every real systemd-managed service (which all run as the
   unprivileged `alderpointdns-v2` account) with a `ModuleNotFoundError` indistinguishable from
   "never provisioned." Found via the real analytics-API-over-HTTPS clean-install test returning
   `degraded: true`. Fixed by `chmod 0755` on the staged directory before promotion; added a
   regression test (`test_provisioned_target_directory_is_world_traversable`).
