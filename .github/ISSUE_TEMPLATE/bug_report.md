---
name: Bug report
about: Report a problem with Alderpoint DNS
title: "[Bug]: "
labels: bug
assignees: ''
---

<!--
Thanks for filing a bug report. Alderpoint DNS is beta software
(v0.4.0-beta.4), so please include as much detail as you can — it helps a
lot with reproducing and triaging issues quickly.

Security vulnerabilities should NOT be reported here — see SECURITY.md for
how to report those privately.
-->

**Alderpoint DNS version** (see the `VERSION` file, or the version shown in
the admin UI):

**Installation method** (fresh install via `scripts/install.sh`, upgrade via
`scripts/upgrade.sh`, `.deb` package, other):

**Operating system and architecture** (e.g. Debian 13 x86_64):

**Hardware/VM details** (vCPU, RAM, disk, virtualization platform if
applicable):

**Network topology** (relevant firewall/VLAN setup, whether the admin UI or
DNS listeners are exposed beyond a private network):

## Expected behavior

<!-- What did you expect to happen? -->

## Actual behavior

<!-- What actually happened? Include exact error messages if any. -->

## Steps to reproduce

1.
2.
3.

## Scope of impact

<!-- Does this affect DNS resolution for clients, only the admin UI, only a
specific feature (filtering, local DNS, backup/restore, migration,
replication, analytics)? -->

**DNS still resolving through the BIND backend?** (yes/no):

**DNS still resolving through the dnsdist frontend?** (yes/no):

## Recent changes before the failure

<!-- Recent config changes, upgrades, imports, restores, etc. -->

## Sanitized diagnostics bundle

<!--
If possible, attach a sanitized diagnostics bundle:
  scripts/alderpointdns-diagnostics --output-dir /tmp
See docs/troubleshooting.md for details. Please double-check the bundle
before attaching it and remove anything you don't want shared publicly.
-->

## Relevant screenshots

<!-- If applicable, add screenshots of the admin UI. -->

## Workaround used

<!-- Any workaround you found, if applicable. -->
