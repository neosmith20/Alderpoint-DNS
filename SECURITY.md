# Security Policy

Alderpoint DNS 1.0.0 is our first stable release. It handles DNS
resolution, filtering policy, local credentials, and TLS material for your
network, so we take security reports seriously — but please read the
"Current security posture" section below for the honest current state
before assuming guarantees this document doesn't actually back.

## Supported versions

Only the current 1.0.x line receives security fixes. There is no
long-term support branch for pre-1.0 releases.

| Version | Supported           |
| ------- | -------------------- |
| 1.0.x   | Yes                  |
| < 1.0   | No, please upgrade   |

## Reporting a vulnerability

Please **do not** open a public GitHub issue for a suspected security
vulnerability. Instead:

- Open a [private GitHub Security Advisory](../../security/advisories/new) on
  this repository. This notifies maintainers without disclosing details
  publicly.

Please include, where possible:

- A description of the vulnerability and its potential impact.
- Steps to reproduce, or a proof of concept.
- The affected version (`VERSION` file / `docs/release-notes.md` entry) and
  operating system.
- Which surface is affected, for example: the DNS data path (BIND/dnsdist),
  the web admin UI, Backup & Restore, Network Configuration, Replication,
  Software Updates, import/migration handling, or TLS/key material.

We will acknowledge reports as promptly as we can and work with you on a fix
and coordinated disclosure timeline. Response times are best-effort, not
SLA-backed.

## Current security posture

Alderpoint DNS documents its actual, current security controls (not
aspirational ones) in two places, both re-audited against the shipping
1.0.0 tree:

- `docs/security.md` — the concrete controls in place today: unprivileged
  service accounts, narrowly scoped/argument-free sudoers entries for every
  privileged operation (deployment, Backup & Restore, Network
  Configuration, Software Updates, Replication), Argon2 password hashing,
  signed/`HttpOnly`/`SameSite=Strict` session cookies, CSRF protection on
  every mutating form, backup secret exclusion/optional encryption, mTLS
  for Replication sync, dnsdist/BIND recursion ACL defaults, and more.
- `docs/hardening-review.md` — a reviewed checklist covering
  authentication, authorization, CSRF, input validation, file upload
  handling, command execution, permissions, secret storage,
  logging/redaction, Network Configuration, Software Updates, and DNS
  exposure controls, along with the **accepted risks** the project is
  knowingly shipping with (for example: no native admin UI HTTPS yet, and
  no signed apt repository).

Please read `docs/known-limitations.md` as well — several items there are
security-relevant (for example, the appliance and its listeners are designed
to bind to private/internal interfaces and rely on external firewall/VLAN
rules for network exposure control; Alderpoint DNS must not be deployed as a
public open resolver).

We strongly recommend restricting network reachability of the admin UI and
DNS listeners with your own firewall controls in addition to anything
Alderpoint DNS does internally.

## Software Updates and supply chain

Installing an update always requires an explicit administrator action —
Alderpoint DNS never installs anything unattended. Before any install, the
downloaded (or manually uploaded) `.deb` is verified against its release's
`SHA256SUMS` (or an administrator-supplied checksum for a manual upload),
inspected with `dpkg-deb` (package name, architecture, and version must
match what's expected — no downgrades, no same-version reinstalls), and run
through an `apt-get install` simulation, and a mandatory pre-upgrade backup
is taken first (the install aborts if the backup fails). See
`docs/software-updates.md`. Releases are not currently GPG-signed or served
from a trusted apt repository — see `docs/hardening-review.md`'s accepted
risks.
