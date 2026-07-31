# Contributing to Alderpoint DNS

Thanks for your interest in contributing. Alderpoint DNS is beta software
(currently v0.4.0-beta.3), so expect some rough edges in process as well as
in the product — please be patient and open an issue if something here is
unclear or out of date.

## Licensing and contribution policy

Alderpoint DNS is source-available under the [PolyForm Noncommercial
License 1.0.0](LICENSE) — see `README.md`'s License section and
`COMMERCIAL_LICENSING.md` for what that does and does not permit.

- **Bug reports, feature suggestions, logs, testing results, and general
  feedback** may be submitted freely, without any license agreement.
- **Code, documentation, artwork, or any other copyrightable contribution**
  will not be merged until you have explicitly accepted the
  [Contributor License Agreement](CONTRIBUTOR_LICENSE_AGREEMENT.md)
  ("CLA"). Opening a pull request by itself is **not** acceptance of the
  CLA — the specific electronic-signature or other explicit acceptance
  workflow will be established and documented here before public,
  external code contributions are merged. Until then, please raise issues
  and discuss changes rather than opening pull requests with code you
  intend to have merged.
- If your Contribution may be owned in whole or in part by an employer or
  another entity, the CLA requires you to disclose that, and merging may
  require authorization from that employer or entity.
- The project may decline any contribution that cannot be clearly and
  confidently licensed, including where provenance, authorship, or
  third-party rights are unclear.
- Contributions must not include secrets, credentials, private user data,
  copied proprietary code, or other material incompatible with this
  project's license or its contributors' rights (see
  `docs/security.md` for what counts as a secret in this codebase, and
  `THIRD_PARTY_NOTICES.md` for currently tracked third-party components).

## Before you start

- For anything beyond a small fix, please open an issue first to discuss the
  approach. This avoids duplicated work and helps make sure a larger change
  fits the project's direction (see `docs/architecture.md` and
  `docs/known-limitations.md` for what's intentional vs. not-yet-done).
- Security vulnerabilities should **not** be reported as public issues — see
  `SECURITY.md`.

## Development setup

Alderpoint DNS is a Python (FastAPI/Jinja) web application backed by BIND 9
and PowerDNS dnsdist. See `docs/install.md` for the full package list and
directory layout used by the installer; for local development you generally
need the same Python dependencies plus BIND and dnsdist installed, or a VM/
container that matches `docs/supported-systems.md`.

For isolated testing without touching a host system, both installer scripts
support a dry-run mode against an isolated root:

```sh
ALDERPOINTDNS_INSTALL_ROOT=/tmp/alderpointdns-install-root ./scripts/install.sh --dry-run --skip-apt
ALDERPOINTDNS_INSTALL_ROOT=/tmp/alderpointdns-upgrade-root ./scripts/upgrade.sh --dry-run --source /path/to/release --skip-service-restart
```

## Running the test suite

The full Python unit test suite:

```sh
python3 -m unittest discover -s tests -p "test_*.py"
```

Web smoke test (renders key admin pages and checks for layout/overflow
regressions):

```sh
./tests/test_web_smoke.sh
```

Combined acceptance suite (runs the shell-based integration suites together,
including BIND/dnsdist backend and frontend checks, blocklist deploy/failure
paths, encryption layout, and backup/restore):

```sh
./tests/test_acceptance.sh
```

You can also run individual suites directly — see `tests/` for the full list
(for example `tests/test_bind_backend.sh`, `tests/test_dnsdist_frontend.sh`,
`tests/test_custom_rules.py`, `tests/test_importer.py`,
`tests/test_replication.py`, `tests/test_install_upgrade_diagnostics.sh`).
`docs/testing.md` describes what each suite covers in more detail.

Please run the relevant suites locally before opening a pull request. Some
shell-based suites exercise real BIND/dnsdist processes and privileged
deploy paths, so they are best run on a disposable VM or container that
matches the supported systems list, not on a machine you care about.

## Coding conventions

- Python: keep to the style already used in `app/` — plain functions/modules
  rather than heavy frameworks-on-frameworks, explicit validation before any
  privileged or destructive operation, and no user-controlled input
  interpolated directly into generated BIND/dnsdist configuration or Lua
  (see `docs/filtering.md` for the pattern used there).
- Privileged operations must go through the existing narrow sudoers/helper
  pattern (`app/alderpointdns_compiler.py` and the fixed sudo entries in
  `docs/security.md`) rather than introducing new broad `sudo` calls.
- Anything that changes generated DNS configuration should validate before
  activating it (`named-checkconf`/`named-checkzone`/`dnsdist --check-config`)
  and support rollback on failure, consistent with the existing deploy flow.
- Add or update tests alongside behavior changes — new rule forms, import
  sources, or settings should have both parser/unit coverage and, where
  applicable, an acceptance-test path.
- Do not add unverified compatibility, support, or production-readiness
  claims to documentation. If something is partial or not runtime-enforced
  yet, say so explicitly (see `docs/known-limitations.md` for the existing
  tone/pattern).

## Pull requests

- Keep pull requests focused on one change where practical; unrelated
  cleanups make review harder.
- Describe what changed and why, and call out any behavior change that
  affects DNS resolution, filtering precedence, backup/restore, replication,
  or security posture.
- Include or update tests for the change, and note which test suites you
  ran locally.
- Update relevant docs (`docs/`) in the same pull request when behavior,
  configuration, or supported systems change.
- Use the pull request template checklist — see
  `.github/PULL_REQUEST_TEMPLATE.md`.

## Reporting bugs and requesting features

Please use the GitHub issue templates:

- Bug report: `.github/ISSUE_TEMPLATE/bug_report.md`
- Feature request: `.github/ISSUE_TEMPLATE/feature_request.md`

Include your Alderpoint DNS version (`VERSION` file), operating system, and,
for bugs, a sanitized diagnostics bundle when possible
(`scripts/alderpointdns-diagnostics --output-dir /tmp` — see
`docs/troubleshooting.md`).
