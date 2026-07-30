# Alderpoint DNS Agent Instructions

These instructions are binding for all Alderpoint DNS work in this repository and
on this isolated Alderpoint DNS VM.

## Scope

Alderpoint DNS consists of all application code, databases, documentation, generated
configuration, systemd units, dedicated users, package dependencies, tests,
BIND configuration, dnsdist configuration, TLS certificates, backups, and
project-owned files on this isolated VM.

## Standing Authorization

Within the Alderpoint DNS VM and Alderpoint DNS project, the user has already authorized:

- Reading, creating, editing, moving, and deleting Alderpoint DNS-owned files.
- Installing, upgrading, downgrading, and removing required packages.
- Adding reputable package repositories required by Alderpoint DNS.
- Creating system users, groups, directories, ACLs, capabilities, and narrowly
  scoped sudo rules.
- Starting, stopping, restarting, reloading, enabling, and disabling Alderpoint DNS,
  BIND, dnsdist, and Alderpoint DNS-owned supporting services.
- Rebooting the Alderpoint DNS VM when testing requires it.
- Creating databases and running schema migrations.
- Generating temporary self-signed certificates and local certificate
  authorities.
- Running tests, network captures, diagnostics, benchmarks, and controlled DNS
  traffic.
- Creating backups and rollback points.
- Committing completed work to the local Git repository.
- Using subagents for independent workstreams.
- Making reasonable engineering and UI decisions using safe defaults.

Do not ask the user for permission for any action in that list.

Only ask the user when an action:

- Affects a machine, router, firewall, DNS service, or account outside this VM.
- Requires a credential, private key, public hostname, or external service
  account that is not available.
- Would destroy unrelated user data.
- Would expose Alderpoint DNS publicly or change production network routing.
- Requires a subjective user decision that cannot safely remain configurable.

Missing optional deployment values are not blockers. Add settings,
placeholders, lab values, or disabled states and continue.

Milestones are checkpoints, not stopping points. Do not return control merely
to report progress. Continue until the assigned work is complete or every
remaining task is blocked by a genuine external dependency.

## Required Engineering Behavior

Every configuration-changing operation must use:

1. Staging.
2. Validation.
3. Backup.
4. Atomic activation.
5. Service health verification.
6. Functional DNS testing.
7. Automatic rollback.
8. Recorded deployment result.

Never commit secrets, live private keys, backup archives, database snapshots,
or audit captures.

Plain UDP/TCP DNS on port 53 must remain functional throughout development.

Host maintenance resolution must remain independent of BIND and dnsdist.

DNS must continue operating if the web application, analytics collector,
backup service, or replication service fails.

Update tests and documentation with every user-facing feature.

Run the complete acceptance suite before committing a completed workstream.
