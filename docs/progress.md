# Progress

- [x] Baseline inspection captured
- [x] Required project/state/log directory skeleton created
- [x] Local Git repository initialized on `main`
- [x] Baseline and architecture commit (`aaefc75`)
- [x] BIND backend installed, validated, and tested on `127.0.0.1:5353`
- [x] dnsdist plain DNS
- [x] Encrypted DNS where supported by installed package
- [x] Blocklist compiler
- [x] Safe RPZ deployment and rollback
- [x] Web interface
- [x] Authentication
- [x] Aggregate query statistics
- [x] Backup and restore
- [x] Full reboot acceptance
- [x] Per-network policy preparation
- [x] v1 acceptance suite

## Verified BIND milestone

- BIND 9.20.26 installed from Debian security packages.
- UDP and TCP recursion pass on `127.0.0.1:5353`.
- Listener audit confirms BIND has no non-loopback socket and does not occupy 53.
- DNSSEC-valid response has the AD flag.
- DNSSEC-invalid test returns `SERVFAIL`.
- Empty RPZ validates with `named-checkzone`.
- Configuration validates with `named-checkconf`.
- RNDC is restricted to loopback and returns healthy status.
- JSON statistics channel responds only on `127.0.0.1:8053`.
- AppArmor remains enabled with narrow BindGuard path rules.
- Service is enabled and survives a stop/start cycle.
- With BIND stopped, host resolution and an HTTPS download succeeded via
  `/etc/resolv.conf`; BIND was restarted and the complete suite passed again.

## Verified dnsdist milestone

- dnsdist 1.9.15 installed from Debian security packages and enabled.
- Client-facing listeners are lab-safe loopback only until allowed client
  networks are supplied:
  - UDP/TCP DNS on `127.0.0.1:53`
  - DoH on `127.0.0.1:443` path `/dns-query`
  - DoT on `127.0.0.1:853`
- BIND backend health check marks `127.0.0.1:5353` up.
- Access ACL is loopback only.
- Private-resolver dynamic rate limits are configured.
- Packet cache and local dnsdist stats API are configured.
- Temporary self-signed lab certificate validates against its private key.
- DoH and DoT pass with the lab CA explicitly trusted by the test client.
- DoQ and DoH3 are not present in the Debian package build; capability tests
  confirm dnsdist rejects those listeners with explicit unsupported-feature
  errors.
- Backend outage behavior is tested: stopping BIND prevents frontend
  resolution, restarting BIND restores dnsdist service.
- dnsdist restart test passes.
- Integrated BIND and dnsdist automated tests pass.

## Verified filtering milestone

- SQLite state database is initialized at `/var/lib/bindguard/bindguard.db`.
- Seeded public AdGuard DNS filter downloads through the host resolver.
- A 19-source public catalog can be loaded with `seed-public`; sources include
  category assignments and both `adguardteam.github.io` and GitHub raw URLs.
- Download and parse test currently accepts about 160k active domains from one
  realistic public source.
- Plain domains, hosts rules, basic Adblock rules, exceptions, duplicates, IDN
  normalization, invalid rules, and unsupported rules are covered by unit tests.
- Unit tests verify the public catalog size, enabled state, categories, and URL
  host coverage without requiring every large public list to download on every
  routine test run.
- Custom block and custom allow rules deploy successfully.
- Custom allow rules take precedence over downloaded and custom block rules.
- RPZ output validates with `named-checkzone`.
- Complete BIND configuration validates with `named-checkconf`.
- Deployment uses a lock, staging, backup, atomic replacement, `rndc reload`,
  post-deploy ordinary/blocked/allowed DNS tests, and rollback on runtime
  failure.
- Failed source update preserves the previous successful downloaded copy.
- Invalid generated RPZ is rejected before active configuration replacement.
- Forced post-deployment failure rolls back and records `rolled_back`.
- With both BIND and dnsdist stopped, `update-sources` and direct HTTPS download
  still work through the host maintenance resolver; services restart afterward.

## Verified web/auth milestone

- FastAPI/Jinja application runs as dedicated non-root `bindguard` user.
- Administration listener is loopback-only on `127.0.0.1:3000`.
- Initial setup page is reachable and no default administrator exists.
- Passwords are hashed with Argon2.
- Sessions are signed, `HttpOnly`, and `SameSite=Strict`.
- CSRF tokens protect mutating UI actions.
- Login failures are rate-limited by source IP.
- Web pages implemented: dashboard, blocklists, custom rules, DNS settings, and
  system.
- Privileged operations from the web service are limited to exact sudoers
  commands for source update and compiler deployment; no unrestricted shell is
  granted.
- `bindguard.service` is enabled and active.
- Web smoke test passes.

## Verified query statistics milestone

- Dashboard reads aggregate dnsdist statistics from the loopback-only dnsdist
  API.
- Total query count is displayed.
- Blocked query count is displayed from dnsdist rule counters when available.
- Full per-query ingestion is not enabled, avoiding unbounded SQLite growth for
  v1.

## Verified policy-preparation milestone

- SQLite schema includes policy categories for malware, ads and trackers, adult
  content, IoT telemetry, SafeSearch, and custom categories.
- Built-in policy profiles exist for trusted, standard, IoT, and restricted
  networks.
- `profile_categories` stores profile-to-category mappings, with restricted
  enabling all built-in filtering categories.
- `network_policies` can bind CIDRs to policy profiles once real client
  networks are supplied.
- Compiler status output includes policy profiles and network policy rows.
- Unit tests verify the seeded categories, profiles, restricted mapping, and a
  sample CIDR-to-profile binding.

## Verified backup/restore milestone

- Local backup script creates archives under `/var/lib/bindguard/backups`.
- Backup includes `/etc` BindGuard/BIND/dnsdist service configuration, SQLite
  state, downloads, compiled RPZ, and local source tree.
- Restore validates BIND, RPZ, dnsdist, and sudoers before extracting.
- Restore restarts named, dnsdist, and bindguard.
- Backup/restore acceptance test passes and confirms DNS and web services work
  afterward.

## Verified pre-reboot acceptance milestone

- `/opt/bindguard/tests/test_acceptance.sh` runs the BIND backend, dnsdist
  frontend, blocklist deployment, failure-path rollback, web smoke, and
  backup/restore tests.
- The pre-reboot acceptance suite passed on this VM.
- Negative-path stack traces during the suite are expected for invalid RPZ and
  forced rollback tests; both paths were verified as rejected/rolled back.

## Verified post-reboot recovery acceptance milestone

- After the VM reboot, the repository was recovered on `main` at commit
  `f2065b8`; `git status` was clean and `git diff` was empty.
- Live services were verified active and enabled after boot:
  - `bindguard.service` on `127.0.0.1:3000`
  - `dnsdist.service` on loopback DNS, DoH, DoT, stats, and control sockets
  - `named.service` on loopback backend recursion and RNDC
- Listener audit confirmed the DNS and management services remain loopback-only:
  - BIND on `127.0.0.1:5353` and `::1:5353`
  - dnsdist UDP/TCP DNS on `127.0.0.1:53`
  - dnsdist DoH on `127.0.0.1:443`
  - dnsdist DoT on `127.0.0.1:853`
  - dnsdist web stats on `127.0.0.1:8083`
  - dnsdist control console on `127.0.0.1:5199`
  - BindGuard web on `127.0.0.1:3000`
- BIND `rndc status` confirmed the server is up and query logging remains off.
- Installed dnsdist `1.9.15` reports features for DoT and DoH only; DoQ and
  DoH3 remain unsupported by this Debian build.
- `/opt/bindguard/tests/test_dnsdist_frontend.sh` now asserts successful DoH and
  DoT DNS responses, certificate/key match, authenticated-only stats access,
  loopback-only dnsdist DNS/management listeners, dnsdist config validation, and
  configured private-resolver rate limits.
- `/opt/bindguard/tests/test_acceptance.sh` passed after the reboot with the
  strengthened dnsdist checks. The expected invalid-RPZ and forced-rollback
  stack traces still occurred only inside the negative-path tests, and the suite
  completed successfully.
