# Adversarial security pass (roadmap Priority 8)

Real installed `alderpointdns-v2` package (private12), real live attacks
against the real HTTPS management API, real mTLS replication listener,
and code review of the DNS/policy rendering path, on this session's real
KVM host.

## Findings fixed

### 1. CSRF token comparison was not constant-time

`app/v2/webapp.py`'s `check_csrf` compared the submitted `X-CSRF-Token`
header to the session's real token with a plain `x_csrf_token !=
admin["csrf"]` -- every other secret-equality check in this codebase
already used `hmac.compare_digest` (e.g. the bootstrap-setup-token check
right next to it), making this the one inconsistent case. Practical
exposure is narrow (an attacker needs an already-valid session cookie to
reach this check at all), but fixed for defense in depth and consistency.
`hmac` promoted to a module-level import (was previously imported
function-locally only where it happened to already be used).

### 2. No request body size limit -- reflected-amplification DoS

Found live: a 5 MB POST body to `/api/local-dns` (valid session + CSRF,
so an authenticated-admin-only exposure, not anonymous) was accepted all
the way through ASGI/Starlette/Pydantic parsing before a field-level
`max_length=255` validator finally rejected it -- and Pydantic's default
validation-error response echoes the full rejected value back verbatim,
producing an almost exact 1:1 reflected response
(`size_download=5000147` bytes for a 5,000,015-byte request). No
legitimate request this API ever needs to accept comes close to this
size (the largest real payload is a TLS certificate+key PEM pair, a few
KB). Fixed: new `_reject_oversized_requests` middleware rejects any
request with a declared `Content-Length` over `MAX_REQUEST_BODY_BYTES`
(1,000,000 bytes) with `413` before any body parsing happens. Documented
limitation, not silently claimed as complete: this checks the declared
`Content-Length` header, not actual bytes read from a chunked-transfer
stream that lies about its length -- full protection against that would
need lower-level ASGI `receive` wrapping, not attempted this session.

Both fixes verified with new regression tests
(`tests/v2/test_webapp.py::TestOversizedRequestRejected`, 2 tests) and
the full existing CSRF/auth suite still passing.

## Findings: none (confirmed correct, not changed)

**Auth bypass**: every protected route returns `401` unauthenticated,
live-verified (`/api/session`, `/api/local-dns`, `/api/system/status`,
`/api/tls/status`, and an unauthenticated mutating `POST
/api/local-dns`).

**CSRF enforcement**: live-verified -- valid session cookie with no CSRF
header -> `403`; valid cookie with a wrong CSRF value -> `403`; only the
correct token succeeds.

**Session cookie forgery/tampering**: a random garbage cookie value, a
one-character-tampered real cookie, and a crafted cookie shaped like a
signed itsdangerous token all correctly return `401`. The session
signing secret is a real 48-byte `secrets.token_urlsafe` value generated
per-install and stored in the secret store -- not derivable or guessable.

**Rendered-config injection via domain names**: live-verified six
payloads against `/api/local-dns`'s `name` field -- a Lua string-breakout
attempt (`evil"});os.execute(...)`), a SQL-injection-shaped string, an
embedded newline, an HTML/script tag, a path-traversal shape, and a
shell-command-substitution shape. All six rejected with `400` by
`app/v2/dns_name_validate.py`'s explicit character-class + label-shape
checks before ever reaching the Lua/zone-file renderer.
`app/v2/dnsdist_gen.py`'s `_lua_string()` helper (which every generated
Lua string literal in this codebase goes through) additionally escapes
backslashes and double quotes as defense in depth even though validated
input should never contain them.

**SQL injection**: grep-reviewed every `execute(f"...")` string-formatted
query in `app/v2/`; the only three (`migration_convert.py`, table-name
interpolation for `PRAGMA table_info`/`SELECT COUNT(*)`) all use table
names drawn exclusively from a hardcoded internal dict, never from
request/user input. `webapp.py` has zero string-formatted SQL --
everything parameterized. `replication_v2.py`'s `_replace_table` builds
`INSERT INTO {table} ({columns})` from a replicated peer's message, but
`table` is checked against a fixed `REPLICATED_TABLES` allowlist and
`columns` must exactly equal the real schema's column list
(`_columns(conn, table)`) before either ever reaches the f-string --
neither is attacker-controllable in practice.

**Command/config injection via subprocess**: grep-verified zero uses of
`shell=True` anywhere in `app/v2/`/`scripts/v2/`; every `subprocess`
call (dnsdist/named-checkzone validation) uses a fixed argv list.

**Path traversal on backup restore**: live-verified five payloads
against `/api/backup/secrets/{name}/restore` (`../../etc/passwd`,
URL-encoded traversal, an absolute path, a Windows-style traversal
shape, and a plain valid-looking name) -- all rejected (`404` for
anything containing a literal `/` that breaks FastAPI's path routing,
`422` for anything failing the name validator).

**Replication mTLS -- missing client cert**: live-verified with real
`openssl s_client` and `curl` against the real `9443` listener -- no
client cert presented -> TLS alert 116 (`certificate required`);
connection never reaches the application layer.

**Replication mTLS -- wrong CA**: live-verified with a freshly-generated
self-signed cert (not signed by the real per-install replication CA).
The initial handshake steps can appear to complete client-side, but
sending real HTTP data over the connection gets TLS alert 48
(`unknown ca`) -- the server's `ssl.CERT_REQUIRED` +
`load_verify_locations(ca_file)` correctly rejects it once actual
application data is attempted. (First test pass with `s_client`'s own
condensed "DONE" output looked ambiguous; retested with a real HTTP
request over the connection to confirm the actual outcome rather than
trusting an ambiguous client-side status line.)

**Replication -- unauthorized valid cert / node identity / replay /
duplicate**: code-reviewed `_validate_message()`
(`app/v2/replication_v2.py`): a cert signed by the real CA but for a
node never explicitly enrolled fails at `peer is None or not
peer.authorized` before any fingerprint check runs; a mismatched
fingerprint against `peer.expected_cert_sha256` is checked explicitly;
a cert whose embedded node id doesn't match the claimed
`sender_node_id` is rejected; messages outside a bounded replay window
or with a previously-seen `message_id` are rejected. Layered correctly;
no gap found.

**XSS**: not independently re-tested live this session (the injection
payloads above cover the domain-name field specifically, at the
DNS-config-rendering layer, not the UI-rendering layer) -- prior session
documentation (`docs/v2/handoff-workstream-6-cc-session.md`'s Workstream
4D security review) already reviewed `app.js`'s `esc()` usage as
consistently applied across all new renderers with no raw
`innerHTML` interpolation of server-controlled strings; not re-verified
independently this session.

## Not covered this session (real scope remaining)

DoH downgrade, ECS boundary isolation, SafeSearch isolation,
cross-policy cache leakage, REFUSED-semantics correctness, backup/restore
content tampering (as opposed to path traversal on the name), Parquet/
aggregate-DB/Tier-B corruption as a security surface specifically (Tier B
corruption was already covered functionally in
`docs/v2/tier-b-and-failure-domains.md`, not from an adversarial-tamper
angle), migration state tampering, secret symlink attacks (the secret
store's own `SecretSymlinkError` defense exists per earlier code review
but wasn't independently re-attacked live this session), and oversized/
malformed replication payloads beyond the size-bound code review above.

## Tests

`tests/v2`: 825 passed (823 + 2 new in
`TestOversizedRequestRejected`). One unrelated flake in
`test_replication_v2.py`'s real mTLS server test under concurrent podman
load during the full-suite run, confirmed passing cleanly in isolation --
matches the exact same test previously documented as flaky under
resource contention in an earlier session, not a regression from this
session's changes.
