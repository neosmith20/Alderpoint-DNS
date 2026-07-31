# Security Policy

Alderpoint DNS is currently in **public beta** (v0.4.0-beta.4). It handles
DNS resolution, filtering policy, local credentials, and TLS material for
your network, so we take security reports seriously even at this stage —
but please read the "Current state" section below before assuming
production-grade guarantees that aren't backed by the current beta.

## Supported versions

Only the current beta line receives security fixes. There is no long-term
support branch yet.

| Version         | Supported          |
| --------------- | ------------------- |
| 0.4.0-beta.4     | Yes                |
| Earlier betas    | No, please upgrade |

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
- Whether the issue affects the DNS data path (BIND/dnsdist), the web admin
  UI, backup/restore, replication, or migration/import handling.

We will acknowledge reports as promptly as we can and work with you on a fix
and coordinated disclosure timeline. Because this is a beta project without a
dedicated security team, response times are best-effort, not SLA-backed.

## Current security posture

Alderpoint DNS documents its actual, current security controls (not
aspirational ones) in two places:

- `docs/security.md` — the concrete controls in place today: unprivileged
  service accounts, narrowly scoped sudoers entries for privileged
  operations, Argon2 password hashing, signed/`HttpOnly`/`SameSite=Strict`
  session cookies, CSRF protection on mutating forms, backup secret
  exclusion/encryption, dnsdist ACL defaults, and more.
- `docs/hardening-review.md` — a reviewed checklist of authentication,
  authorization, CSRF, input validation, file upload handling, command
  execution, permissions, secret storage, logging/redaction, and DNS
  exposure controls, along with the **accepted beta risks** the project is
  knowingly shipping with (for example: no native admin UI HTTPS yet, and no
  signed apt repository yet).

Please read `docs/known-limitations.md` as well — several items there are
security-relevant (for example, the appliance and its listeners are designed
to bind to private/internal interfaces and rely on external firewall/VLAN
rules for network exposure control; Alderpoint DNS must not be deployed as a
public open resolver).

If you are deploying this beta, we strongly recommend restricting network
reachability of the admin UI and DNS listeners with your own firewall
controls in addition to anything Alderpoint DNS does internally.
