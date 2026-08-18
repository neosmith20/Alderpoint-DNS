# Adversarial security pass: DNSCrypt provisioning API (real defect found and fixed)

Roadmap-directed security review of the new attack surface introduced by
`docs/v2/dnscrypt-transport-implemented.md`: the provisioning endpoints
(`POST /api/dns-transports/dnscrypt/rotate`, `PUT /api/dns-transports`),
the secret-handling code path, and the scratch-dnsdist generation
mechanism.

## Real defect found and fixed: failed rotation orphans real private key secrets

**Finding.** `SecretStore.create()` (`app/v2/secret_store.py`) writes
directly to disk and is **not** part of `_mutate_and_promote`'s SQL
transaction. `rotate_dnscrypt`'s `_mutate` closure calls
`secrets_store.create(...)` for the newly-generated provider and/or
resolver private key *before* `_mutate_and_promote` attempts
`recompile_and_promote`. If that later step fails for any reason (a
runtime validation failure, a transient error, anything), the SQL
transaction correctly rolls back `dnscrypt_settings` to its prior state
-- but the secret files already written to disk are never referenced by
anything after the rollback and were never deleted, leaving real
Ed25519/X25519 private key material permanently orphaned in the
protected secret store with no lifecycle: never rotated, never
audited, never cleaned up, accumulating with every failed attempt.

**Live reproduction.** Forced `runtime_compile.recompile_and_promote`
to raise immediately after a real `_mutate` had already generated and
stored real key material via the actual HTTP API:

```
secrets before:                    ['web-session-signing-key']
rotate status:                     500
secrets after failed rotate:       ['9ce588849eca...', 'af63b4ed5de3...', 'web-session-signing-key']
dnscrypt_settings after rollback:  identity_provisioned=False
```

Two real orphaned secrets, containing real generated private key bytes,
confirmed present on disk after the control.db state had correctly
rolled back to "nothing provisioned."

**Fix.** Every secret ID created during a `rotate_dnscrypt` attempt is
now tracked (`holder["new_secret_ids"]`) regardless of outcome. On any
exception from `_mutate_and_promote`, every secret created by *that*
attempt (never a prior successful rotation's secrets) is deleted
before the error propagates to the caller. Verified live: the same
forced-failure reproduction above now leaves the secret store
byte-for-byte identical to its pre-attempt state, and a real successful
rotation immediately afterward still works correctly (proving the
cleanup path didn't damage anything needed for normal operation).

**Regression coverage:**
`tests/v2/test_webapp.py::TestDnscrypt::test_failed_promotion_does_not_orphan_secrets`
-- forces the same failure via the real HTTP API and asserts the
secret store set is unchanged, `identity_provisioned` stays `False`,
and a subsequent real rotation still succeeds correctly.

## Attacks attempted and found NOT exploitable

- **Lua/RCE injection via `dnscrypt_provider_name`**: attempted
  `'"; os.execute("id"); --'` and a payload with an embedded raw
  newline followed by `os.execute(...)`. Neither achieved code
  execution -- `app/v2/dnsdist_gen.py`'s `_lua_string()` escaping
  (backslash-then-quote, applied to every value that reaches
  `addDNSCryptBind`) correctly neutralizes quote-based breakout
  attempts, and dnsdist's own real `--check-config` correctly rejected
  the embedded-newline payload before promotion (the existing
  stage-validate-promote architecture's fail-safe behavior working as
  designed -- the previously-working runtime stayed live, confirmed by
  the `409 runtime_promotion_failed` response).
- **Local secret exposure via the scratch dnsdist's config file**: the
  file that transiently holds the scratch console's plaintext
  encryption key has permissive file-mode bits (`0644`, Python's
  default), but its parent `tempfile.TemporaryDirectory()` is `0700`
  (owner-only) -- confirmed live. On Linux, reaching a file requires
  traverse (execute) permission on every parent directory, so another
  unprivileged local user cannot reach the file regardless of its own
  mode bits. No fix needed; documented here as a verified non-finding.
- **Console-key leakage via CLI arguments/process list**: the scratch
  instance is never started with dnsdist's own `-k KEY` flag (whose
  help text explicitly warns it leaks into shell history and `ps`
  output) -- the key is only ever written into the `0700`-directory
  config file and read via `setKey()`/`-C`, never passed as an
  argument. Confirmed by inspection of every `subprocess`/`Popen` call
  in `app/v2/dnscrypt_provisioning.py`.
- **Secret material in API responses or error messages**: confirmed by
  inspection that no DNSCrypt endpoint response, and no
  `DnsCryptProvisioningError` message (which does include raw dnsdist
  console output for debuggability), ever includes private key bytes
  -- only the public fingerprint, serial, and validity window.

## Hardening applied (defense-in-depth, not exploit-driven)

`dnscrypt_provider_name` previously accepted any string up to 255
characters with no character-set restriction, relying entirely on
dnsdist's own `--check-config` as the only backstop against malformed
input (which worked, per the finding above, but is a downstream safety
net, not a first line of defense for a value with no legitimate reason
to contain control characters, NUL bytes, or backslashes). Now
restricted to `^[A-Za-z0-9._-]+$` -- the real character set a DNS name
(this value's actual purpose) can contain. Verified live: all five
payloads tested above (plus a raw NUL byte and an unescaped backslash)
are now rejected with `422` before ever reaching control.db or the
compiler.
`tests/v2/test_webapp.py::TestDnscrypt::test_malformed_provider_name_rejected_at_the_api_layer`
covers this with the exact payloads used during the live attack pass.

## Not covered by this pass

This was a scoped, targeted review of the new DNSCrypt-specific surface
this continuation added, not a full adversarial sweep of the whole
management API (replication, backup/restore, migration, analytics,
etc. -- those were covered by prior sessions' own security passes, see
`docs/v2/tierb-and-failure-domain-rc13.md` and the RC13 continuation's
adversarial coverage list). A dedicated concurrency/race-condition
stress test (many simultaneous `rotate` calls) and a resource-
exhaustion check (repeated rotate calls spawning many scratch dnsdist
processes) were not performed this pass and remain open.
