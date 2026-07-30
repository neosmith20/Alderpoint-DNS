# Beta Readiness Checklist

This checklist is for external beta handoff. Passing automated tests is
required but not sufficient for v1.0 readiness.

- [x] Fresh installation path documented and dry-run tested.
- [x] First-run setup has no default administrator.
- [x] Upgrade workflow documented and dry-run tested.
- [x] Backup and restore workflow implemented and acceptance-tested.
- [x] Import and migration supports representative sources with preview.
- [x] Replication enrollment, sync, drift, and revocation tested.
- [x] Service restart test in acceptance.
- [x] Full reboot test after the final beta commit.
- [x] DNS resolution through BIND backend and dnsdist frontend.
- [x] Local DNS and PTR records acceptance-tested.
- [x] Filtering and rollback paths acceptance-tested.
- [x] Upstream resolver changes and analytics tested.
- [x] DoH and DoT upstream configuration tested.
- [x] Client-facing encryption tested where supported by installed dnsdist.
- [x] Resolver failover uses managed dnsdist upstream pool health checks.
- [x] Dashboard analytics panels render real data or clear unavailable states.
- [x] Responsive interface tested by smoke fixtures.
- [x] User permissions use single-admin auth plus CSRF-protected forms.
- [x] Diagnostics bundle generated and redaction-tested.
- [x] Uninstallation behavior documented; normal remove preserves data.
- [x] Recovery after failed deployment covered by rollback-path tests.

Before external beta:

- Run the full acceptance suite.
- Run a controlled full reboot and post-reboot DNS/listener verification.
- Create one fresh test VM and install from a release artifact.
- Attach one sanitized diagnostics bundle to the beta handoff notes.
