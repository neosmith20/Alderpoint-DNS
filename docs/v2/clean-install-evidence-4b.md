# Workstream 4B — Clean-Install / End-to-End Evidence

## Artifact identity

- Filename: `alderpointdns-v2_2.0.0~private2-1_all.deb`
- Size: 69,691,952 bytes
- SHA-256: `0a7797aad9b2c6b51079ccd73c24408bef9d8cba16a91826cd482f5b963542e9`
- Built by: `scripts/build-v2-deb.sh` (bumped from `2.0.0~private1-1` since bytes changed —
  Workstream 4A's artifact, SHA-256 `ca030d5...`, is superseded by this one)

## Environment

Brand-new `docker.io/library/debian:trixie` Podman container per test cycle (four separate
containers were built and torn down over the course of this pass, chasing three real defects to
ground — see below); the FINAL clean-install proof below is from the last one, confirmed to start
with `dpkg -s alderpointdns-v2` reporting "not installed" and no `/opt`/`/var/lib` Alderpoint state
present before installation.

## Proof transcript (final, fully-fixed artifact)

1. **Install**: `apt-get install -y /tmp/alderpointdns-v2.deb` — exit 0, all dependencies (now
   including `python3-fastapi`, `python3-itsdangerous`, `python3-pydantic`, `uvicorn`) resolved
   from stock Debian 13.
2. **All four services active**: `alderpointdns-v2-analytics`, `-tierb`, `-schedule`, `-web`.
3. **Real TLS handshake**: `curl -sk -v https://127.0.0.1:8443/api/health` → TLS 1.3 /
   `TLS_AES_256_GCM_SHA384`, `subject: CN=Alderpoint DNS V2 Local (self-signed)`, `HTTP/1.1 200
   OK`. Without `-k`: real rejection (self-signed cert correctly untrusted by curl's default trust
   store).
4. **Setup + login**: real bootstrap token read from `/var/lib/alderpointdns-v2/bootstrap-setup-token`
   (never printed to postinst output), `POST /api/setup` → `201`-shaped success, token file
   deleted; `POST /api/login` → real `Set-Cookie:
   ...; HttpOnly; Max-Age=28800; Path=/; SameSite=strict; Secure`.
5. **Analytics API end-to-end**: `alderpointdns-v2-ctl analytics-worker --once --inject-test-event`
   → real Parquet segment; `GET /api/analytics/recent` and `/api/analytics/top-domains` over real
   HTTPS → real rows, `"degraded":false`.
6. **REQUIRED end-to-end policy proof** (`docs/v2/management-plane.md` §46 equivalent): via real
   HTTPS API calls (login → create service/ruleset → set global `blocking_response_mode=refused` →
   create two networks → set the strict network's policy to
   `service_blocking_ruleset_id=rs-strict, safesearch_mode=strict` — every call returns
   `"runtime":{"promoted":true}`), the real compiled `dnsdist.conf` on disk was validated
   (`dnsdist --check-config` → OK) and then loaded into a genuinely separate, isolated `dnsdist`
   process. Real `dig` queries: strict client (`127.0.0.2`) → `blocked-strict.example` → **RCODE
   REFUSED**; lenient client (`127.0.0.100`) → same domain → **not** refused (real upstream
   NXDOMAIN), including a warm-cache repeat query — no cross-policy leakage in either direction.
7. **Failure isolation**: with all four V2 services stopped/`SIGKILL`ed simultaneously, the
   separately-running isolated `dnsdist` instance (loaded from the same API-promoted config)
   continued answering both `iana.org` (real NOERROR) and the strict-client REFUSED case
   correctly — DNS is provably independent of every management/analytics/worker process.
8. **Real certificate replacement**: generated a second disposable self-signed pair via
   `app.v2.tls_cert.generate_self_signed()`, `POST /api/tls/replace` over real HTTPS (with a valid
   session + CSRF token) → `200`, file on disk changed immediately; `systemctl restart
   alderpointdns-v2-web` → the new certificate (with its distinct SAN) is what curl now receives.
   Mismatched-key-pair replacement attempt → real `400 invalid_certificate`, and the live
   certificate's SHA-256 was verified byte-for-byte unchanged after the rejected attempt.
9. **Reinstall idempotency**: `apt-get install --reinstall` — TLS certificate SHA-256 unchanged,
   admin account preserved (`sqlite3 ... select username from admins` → `admin`), the
   pre-reinstall session cookie remained valid (`GET /api/networks` → `200`), all four services
   still active.
10. **Remove vs purge**: `apt-get remove` preserved the certificate, config, and admin account
    (`select count(*) from admins` → `1`); `apt-get purge` removed `/etc/alderpointdns-v2`,
    `/var/lib/alderpointdns-v2`, and `/opt/alderpointdns-v2` completely (no orphaned directory
    warning — the Workstream 4A `__pycache__` fix still holds).

## Real defects found and fixed during this pass (see docs/v2/management-plane.md for full detail)

1. Exception-handler registration on the bare `Exception` type didn't reach real clients the way
   `TestClient` expected — fixed by registering on the concrete `ValueError`/`RuntimeCompileError`
   types.
2. The web unit's `ExecStartPre` called the full `init-state` (which writes `/etc/alderpointdns-v2`,
   outside that unit's `ReadWritePaths=` under `ProtectSystem=strict`) — every single service start
   failed with a real `OSError: [Errno 30] Read-only file system`. Fixed by adding a narrower
   `ensure-tls-cert` subcommand.
3. The provisioned analytics vendor-runtime directory was silently `0700` (root-only) due to
   `tempfile.mkdtemp()`'s default mode surviving the atomic rename-into-place — invisible when
   testing as root, but broke `import pyarrow`/`import duckdb` for every real systemd-managed
   service (all running as the unprivileged `alderpointdns-v2` account). Found via the real
   analytics-API-over-HTTPS test returning `degraded:true`. Fixed with an explicit `chmod 0755`.

Each defect was found, fixed, and then re-verified end-to-end in a **brand-new** clean container
(not the one that surfaced it) before moving on, per this pass's own "fix it, rebuild, retest in a
new environment" instruction.
