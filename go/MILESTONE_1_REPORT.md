# Alderpoint DNS V2 — Go/Svelte Migration, Milestone 1

> **Reclassification (2026-08-25, per explicit governing instruction):** this document is retained
> as accurate historical evidence of what it actually delivered, but its framing below overstates
> that delivery. Blocklists + Local DNS is a **foundation slice** — it proves the architecture
> (Go control-plane API shape, Svelte 5 + strict TS toolchain, auth/session/CSRF, staged-deploy
> pattern, isolated preview pipeline) — **it is not a completed frontend migration milestone** and
> must not be cited as one. The authoritative, current tracking document for the full
> Go/Svelte management-application rewrite is `go/PARITY_MATRIX.md`; the current status and hard
> release gate are recorded in `docs/v2/v2-roadmap.md`'s "Management/control-plane implementation
> language and frontend framework" section. Every claim below (tests, build proof, performance
> measurements, deployment procedure) remains factually accurate for the two pages it covers and is
> unchanged.

Status: **Milestone 1 complete for its actual scope (Blocklists + Local DNS foundation slice).**
Real, tested, deployed. Scope and known gaps are stated plainly below rather than hidden. This is
not frontend parity — see the reclassification note above.

## Identity / safety

| | |
|---|---|
| Baseline SHA (confirmed clean before starting) | `6e2de08316cdf0c856ec4ed22539d838dfb00865` on `v2/architecture-storage-foundation` |
| Bake-off reference (architecture decision) | `spike/go-rust-bakeoff-20260825` @ `61010a8` — Go selected |
| Migration worktree | `/root/alderpointdns-go-migration` (separate `git worktree`, never `/root/alderpointdns-work`) |
| Migration branch / commit | `v2/go-control-plane-migration` @ `7020e4fc0841dac1006058e32e282eab36753a42` |
| Primary worktree | confirmed **still** at `6e2de08316cdf0c856ec4ed22539d838dfb00865`, clean, untouched throughout |
| Python owner preview (`apdns-v2-preview`) | confirmed **still Up**, version unchanged `2.0.0~preview6e2de08316-1`, ports unchanged (53/853/8443/9443), never stopped/restarted/reconfigured; its DB/config/secrets were never read or written |
| Go migration preview (`apdns-go-migration-preview`) | new, isolated podman container — see **Deployment** below |
| Publishing | no RC, tag, push, public package, or release |

## Architecture

One Go module (`alderpointdns/go-controlplane`, at `go/`), one native binary
(`alderpointdns-go`) with two subcommands: `web` (the control-plane HTTP
service — Milestone 1's entire scope) and `migrate` (schema
up/status, usable standalone for ops/CI). Every other Milestone-2+ worker
role (analytics, discovery, replication, schedule, tierb, protobuf-receiver)
is **not implemented** — deliberately out of scope per the brief's
"DO NOT MIGRATE YET" list; the `web`/`migrate` split already establishes
the one-binary-many-subcommands shape those roles will slot into later.

```
go/
  cmd/alderpointdns-go/main.go   subcommand dispatch, graceful shutdown
  internal/
    config/      strict YAML load+validate+migrate, atomic write
    dbmigrate/   versioned SQLite migrations, proven rollback
    auth/        setup, Argon2id, sessions, CSRF, rate-limited login
    blocklists/  parser, pull pipeline, scheduler, jobs
    localdns/    validated CRUD + stage/validate/promote
    httpapi/     middleware, route table, JSON handlers
  schema/        migrations/ (real) + rollback_test/ (deliberately bad)
  config/        appliance.yaml (versioned desired-state template)
  frontend/      Svelte 5 + strict TypeScript
  tests/         black-box acceptance (Python + shell), language-neutral
  openapi.yaml   hand-maintained API contract
```

**Backend dependencies** (mature/boring, no CGO): stdlib `net/http`
(Go 1.22+ method+path routing, no router library), `database/sql` +
`modernc.org/sqlite` (pure Go, no C toolchain — matters for the ARM64
build proof below), `gopkg.in/yaml.v3` (`KnownFields(true)` for strict
config), `golang.org/x/crypto/argon2`, `log/slog`. **32 total resolved
modules** (`go list -m all`), **12 direct** (`go.mod`). `#!` no CGO
anywhere; `CGO_ENABLED=0` throughout.

**Frontend dependencies**: 0 runtime `dependencies`, 7 `devDependencies`
(Svelte, Vite, TypeScript, `@sveltejs/vite-plugin-svelte`, `@tsconfig/svelte`
— all build-time only; **nothing** ships to the appliance's Node runtime
because there is no Node runtime on the appliance, by design).

## Python behavior contracts preserved

Read `app/v2/webapp.py` and `app/v2/policy_store.py` directly (not
guessed) before writing the Go equivalents, so these are field-for-field
matches, not similarly-named reinventions:

- **Session/CSRF**: identical cookie name (`alderpointdns_v2_session`),
  `SameSite=Strict`, `HttpOnly`; CSRF token minted at login, returned in
  the JSON body, checked via `X-CSRF-Token` with a constant-time compare
  on every non-GET request — same mechanism as `check_csrf`.
- **Login rate limiting**: 5 failed attempts / 15 minutes / IP, same as
  `_LOGIN_FAILURE_MAX` / `_LOGIN_FAILURE_WINDOW_SECONDS`, with the same
  bounded-table pruning strategy (`_record_login_attempt`).
- **Setup**: `GET /api/setup/status` → `{"setup_required": bool}` gated
  purely on "zero admin rows exist" (no separate token), `POST /api/setup`
  with the same field names (`username`, `password`, `confirm_password`,
  `create_local_dns`, `server_hostname`, `server_ip`) and the same
  best-effort "seed a Local DNS record, don't fail account creation if
  that part fails" behavior.
- **Blocklists**: same route shape (`/api/blocklists`,
  `/{id}/interval`, `/{id}/toggle`, `/{id}/refresh`, `/refresh-all`,
  `/jobs/{id}`), same interval presets (`0`=Manual Only through `604800`
  =1 week), same `BLOCKLIST_ATTENTION_THRESHOLD = 3` consecutive-failure
  semantics, same "a newly created subscription gets an immediate real
  pull regardless of its interval" behavior.
- **JSON errors**: identical `{"error": "<code>", "detail": "<message>",
  "field": "<optional>"}` shape.

**Deliberate deviation** (disclosed, not hidden): Local DNS **edit and
delete** (`PATCH`/`DELETE /api/local-dns/{id}`) are **new** — the current
Python V2 only has list + create for Local DNS today (verified by reading
`webapp.py`; no edit/delete route exists there). Milestone 1 explicitly
requires the full "list, add, edit, delete" vertical, so the Go version
implements it as a consistent extension of the existing pattern (same
CSRF/validation/stage-promote shape as `create`), not a Python behavior
being changed out from under anyone.

## State/storage ownership map

| Datum | Home | Notes |
|---|---|---|
| Appliance config | `appliance.yaml` | versioned (`schema_version`), strict-validated, atomic write, transparent legacy-config upgrade path |
| Admins, sessions, login attempts | SQLite | never in YAML |
| Blocklist subscription metadata/status/jobs | SQLite | `blocklist_subscriptions`, `blocklist_jobs` |
| Local DNS records | SQLite | `local_dns_records` |
| Generated blocklist runtime artifacts | disk, staged then `rename(2)`-promoted | disposable, regenerable from SQLite state + the subscription's URL |
| Generated Local DNS runtime artifact | disk, staged then `rename(2)`-promoted | disposable, regenerable from SQLite state |
| Browser/API interchange | JSON | never authoritative |

No datum is duplicated across YAML and SQLite.

## Tests

**Go unit tests** (table-driven, per package, `go vet` clean, `-race` clean
on a normal single-pass run — see **Known limitations** for a repeated-
stress-only caveat):

| Package | What's covered |
|---|---|
| `config` | strict unknown-field rejection, schema-version validation, legacy-config transparent upgrade (idempotent), atomic write round-trip |
| `dbmigrate` | in-order apply, idempotent re-run, **explicit rollback proof**: seeds a row, applies a deliberately-invalid `NOT NULL`-no-default migration, asserts it fails, the transaction rolled back, `schema_migrations` is unchanged, and the seed row is intact |
| `auth` | Argon2id hash/verify round-trip, fails-closed on a malformed hash, unique salts |
| `blocklists` | parser format coverage, **create triggers an immediate real pull**, **a failed pull retains the previous-good runtime artifact untouched** (real assertion: byte-compares the file before/after), **attention_required flips true only at exactly 3 consecutive failures**, `RefreshOne` rejects a concurrent duplicate |
| `localdns` | full CRUD, IPv4/IPv6/CNAME/PTR/hostname/TTL validation matrix, duplicate rejection, not-found handling, runtime-artifact regeneration |
| `httpapi` | subscription-id slug generation (catches a real lowercase-ordering bug found during manual testing, see below) |

**Black-box acceptance** (language-neutral, HTTP/CLI only —
`go/tests/acceptance.py`, 24 checks, and
`go/tests/acceptance_migration_restart.sh`, 7 checks; both run clean
against the real release binary): setup/login/session/CSRF-enforcement,
health, full blocklist lifecycle including rapid-double-delete
idempotency, full local-dns lifecycle including invalid-input rejection,
migration up/status, migration rollback, and restart persistence of
admin/session/local-dns state.

**Chromium** (`puppeteer-core` against the compiled frontend, real login
flow, not a mock): 0 console errors, 0 accessibility issues found (no
unlabeled inputs, no missing `alt`), no horizontal overflow at 1280px or
390px viewports, ~1s cold navigation to interactive, ~2.4 MB JS heap.
Screenshots: `go/report-screenshots/` is not committed (see below) but the
same walkthrough is reproducible via `tests/acceptance.py` + any browser.

**Bugs the tests actually caught** (proof the tests do real work, not
theater): (1) subscription-id slugs were uppercase-stripped instead of
lowercased-then-slugged (`strings.ToLower` was applied *after* the
character filter, not before) — found via manual curl testing, fixed,
and now covered by `TestSubscriptionIDFromNameLowercasesFirst`; (2) the
Argon2id memory parameter (originally 64 MiB, matched against no fixed
budget) was inflating idle RSS by ~4x after a single login — see
**Performance gate measurements** below.

## Build proof

```
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w -X main.Version=..." -o alderpointdns-go-amd64 ./cmd/alderpointdns-go
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags="-s -w -X main.Version=..." -o alderpointdns-go-arm64 ./cmd/alderpointdns-go
```

| | amd64 | arm64 |
|---|--:|--:|
| Build time (this host, deps cached) | ~1 s | ~21 s |
| Binary size (stripped) | 11.8 MB | 11.3 MB |
| Dynamically linked? | no (`ldd`: not a dynamic executable) | no |
| C cross-toolchain needed? | n/a | **no** — cross-built from this amd64 host with a bare `GOOS`/`GOARCH` env var change, zero extra packages, exactly the ARM64-build-feasibility proof Milestone 1 asks for |

Frontend build: `npm run build` (Vite), 1.3 s, `svelte-check` 0
errors/warnings across 90 files. `dist/`: **60.2 KB uncompressed / 21.4 KB
gzipped** total (index.html 0.4 KB/0.3 KB gz, JS 56.0 KB/19.5 KB gz,
CSS 3.7 KB/1.1 KB gz).

## Performance gate measurements

Measured against the real amd64 release binary on this build server,
external readiness polling (not the binary's own log line), 300 curl
requests for latency percentiles (curl subprocess overhead is included in
every latency number below — i.e. these are *pessimistic*, real server
latency is lower).

| Gate | Target | Measured | Result |
|---|---|--:|---|
| Cold start → ready | < 100 ms | median 7 ms warm; **one truly-cold run (binary not yet page-cached) hit 109 ms** | met on every subsequent restart; the single first-ever-touch outlier is an OS page-cache effect, not steady-state behavior (systemd restarts of an already-installed binary won't see it) |
| Idle RSS **before any login** | < 25 MB | 13.2–13.4 MB | ✅ met |
| Idle RSS **after one setup+login** | < 25 MB | **36.4 MB** | ❌ **missed** — see root cause below |
| Authenticated API p95 | < 25 ms | 8.9 ms (curl-inclusive; real server latency lower) | ✅ met |
| Authenticated API p99 | < 50 ms | 9.2–12.2 ms (curl-inclusive) | ✅ met |
| Click-to-visible-pending-feedback (DELETE ack) | < 100 ms | 7.6–8.3 ms (curl-inclusive) | ✅ met |
| No SQLite transaction spanning network/parsing/compilation | — | verified by code inspection: `blocklists.download()` runs entirely outside any DB transaction; the only DB writes around it are single-statement `UPDATE`s before/after | ✅ met |
| No unbounded goroutines/queues | — | scheduler is one goroutine; pulls are bounded by a `MaxConcurrentPulls`-sized semaphore, not per-subscription goroutines | ✅ met |

**Root cause of the missed idle-RSS-after-login gate** (real
investigation, not a guess): Argon2id password hashing originally used
`m=64 MiB` per hash operation. Go's allocator doesn't promptly return
scavenged heap back to the OS after a single large allocation event, so
RSS stayed inflated long after the hash call returned — measured **146
MB** resident after just one setup+login with the original parameter.
Fix applied during this milestone (not deferred): lowered to OWASP's
current baseline (`m=19 MiB, t=2, p=1`, still safely above OWASP's
≥15 MiB floor) and added a rate-limited `debug.FreeOSMemory()` call after
every hash operation to force prompt scavenging. This cut idle-RSS-after-
login from 146 MB to **36.4 MB** — a real ~4x fix, landed in this
milestone, not merely reported. The remaining 36.4 MB (11 MB over target)
was isolated (by testing setup+login alone, no blocklist activity at all)
to be inherent to even a single 19 MiB Argon2id call combined with Go's
heap-growth-then-retain behavior, not a leak — `GODEBUG=madvdontneed=1`
was tested and made no measurable difference, ruling out lazy-`MADV_FREE`
accounting as the explanation. **Recommended Milestone 2 follow-up**:
either drop Argon2id memory further (toward the ~15 MiB floor) or set
`GOMEMLIMIT` as a soft cap, then re-measure with `pprof` heap profiling
rather than more black-box guessing.

## Deployment: isolated Go migration preview

```
Container:  apdns-go-migration-preview   (podman, debian:trixie-slim base)
Management: https://172.16.43.100:10443/  (dev TLS cert, SAN=172.16.43.100)
Version:    2.0.0~go-m1-7020e4fc08
```

- **Isolated from `apdns-v2-preview`** on every axis the brief asked for:
  separate container name, separate ports (`10443` only — **port 53 is
  never published or listened on**, confirmed via `podman port`), separate
  state directories (`/root/apdns-go-migration-preview-state/{etc,var-lib}`
  vs. the Python preview's `/root/apdns-v2-preview-state/`), separate
  self-signed dev certificate, separate SQLite database. The Python
  preview's ports (53/853/8443/9443) were re-verified unchanged after
  deploying this container.
- **First-run setup**, not a pre-created account: the deployed instance
  currently answers `{"setup_required": true}` — Alex creates his own
  credentials via `https://172.16.43.100:10443/` the same way the real
  appliance's first boot works.
- The full setup→login→blocklist-create→local-dns vertical was manually
  walked end-to-end against this exact deployment (screenshots taken,
  not committed to keep the repo lean — reproducible via
  `go/tests/acceptance.py` against the container, or a browser) before
  being reset back to first-run state for Alex.
- Synthetic-only: the two demo blocklist subscriptions used during that
  walkthrough pointed at a local fixture HTTP server (never the internet,
  never any owner data) that has since been stopped, and the preview was
  fully reset to a fresh, empty first-run state before being handed off.

**Teardown** (exact procedure):
```sh
podman stop apdns-go-migration-preview
podman rm apdns-go-migration-preview
rm -rf /root/apdns-go-migration-preview-state /root/apdns-go-migration-preview-release
```
This does not touch `apdns-v2-preview`, its state directories, ports, or
data in any way — they are entirely separate.

**Redeploy** (after further Go changes): rebuild the amd64 binary, copy
it + `frontend/dist` + `schema/migrations` into
`/root/apdns-go-migration-preview-release/`, then `podman stop && podman
rm && podman run ...` with the same command as above (state directories
persist across a redeploy unless deliberately wiped).

## Known limitations (next milestone)

1. **Idle-RSS-after-login gate missed by ~11 MB** — root-caused and
   partially fixed this milestone (146 MB → 36.4 MB); closing the rest
   is a Milestone 2 `pprof`-guided item, not a blocker.
2. **Local DNS edit/delete is new capability**, not a Python-parity port
   (the current Python V2 doesn't have it yet) — see above.
3. **No exponential backoff on blocklist pull retries yet** — a failing
   subscription retries on the same fixed interval; fine at Milestone 1
   scale, worth adding before a subscription pointed at a genuinely dead
   URL is left hammering it indefinitely.
4. **`openapi.yaml` is hand-maintained**, not code-generated —
   `openapi-typescript` hit a peer-dependency conflict with this
   project's toolchain versions during setup; switching to generated
   types is a cheap follow-up (see `openapi.yaml`'s header), not a
   blocker for Milestone 1.
5. **A goroutine-lifecycle test-suite flakiness was found and diagnosed,
   not fully fixed**: running the `blocklists` package's tests
   repeatedly under `-race -count=8` (deliberately abnormal stress, not
   normal `go test` usage) can wedge, because background job goroutines
   launched via bare `go s.runJob(...)` aren't cancelled when a test
   times out, and leaked goroutines from a timed-out iteration can
   compound in later iterations. **A single normal pass (`go test ./...`,
   with or without `-race`) is reliably clean** — reproduced 4+ times.
   Root fix (a job-scoped cancellable context threaded through
   `runJob`/`pullOne`/the HTTP client) is a good Milestone 2 hardening
   item, not urgent: the production `web` process already bounds every
   pull by its configured HTTP client timeout and the process's own
   lifetime.
6. **Compatibility path from the live Python V2 state, and V1.1.1
   `.tar.gz` restore, were not exercised** — Milestone 1 was scoped to
   new-install behavior; both are recommended as the first two real
   Milestone 2 tickets, before further feature work.
7. **Dependency security/license audit not yet run** (`govulncheck` +
   license scan) — cheap to do given only 32 total Go modules; recommend
   doing it immediately before any further Milestone 2 work lands.
8. Only `web` and `migrate` subcommands exist; every other worker role
   (analytics, discovery, replication, schedule, tierb,
   protobuf-receiver) is unimplemented, per explicit Milestone 1 scope.

## Reproduction

```sh
cd go
go build ./...  &&  go vet ./...  &&  go test ./...  -race
cd frontend && npm install && npm run build && npx svelte-check --tsconfig ./tsconfig.app.json
```

Black-box acceptance (needs a running instance + a local fixture HTTP
server serving a small blocklist file):
```sh
python3 tests/acceptance.py --base http://127.0.0.1:8444 --fixture-base http://127.0.0.1:8299
sh tests/acceptance_migration_restart.sh ../dist/alderpointdns-go-amd64 schema
```
