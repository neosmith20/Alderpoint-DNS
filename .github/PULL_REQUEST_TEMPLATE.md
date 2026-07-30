## Summary

<!-- What does this change do, and why? -->

## Related issue(s)

<!-- Link any related issues, e.g. Fixes #123 -->

## Type of change

- [ ] Bug fix
- [ ] New feature
- [ ] Documentation only
- [ ] Refactor / cleanup (no behavior change)
- [ ] Test-only change
- [ ] Other (please describe)

## Areas affected

<!-- Check anything this touches -->

- [ ] DNS resolution / BIND backend
- [ ] dnsdist frontend / encrypted resolvers (DoH/DoT/DoQ)
- [ ] Filtering / custom rules / blocklists
- [ ] Local DNS
- [ ] Backup / restore
- [ ] Migration / import (AdGuard Home, Pi-hole, etc.)
- [ ] Replication
- [ ] Analytics
- [ ] Web admin UI
- [ ] Install / upgrade / packaging
- [ ] Security-relevant path (auth, sudoers, secrets, listeners)
- [ ] Documentation

## Testing

<!-- Which test suites did you run locally? See CONTRIBUTING.md. -->

- [ ] `python3 -m unittest discover -s tests -p "test_*.py"`
- [ ] `./tests/test_web_smoke.sh`
- [ ] `./tests/test_acceptance.sh`
- [ ] Other/manual testing (describe below)

<!-- Describe any manual testing steps and results -->

## Documentation

- [ ] Relevant docs under `docs/` were updated in this PR, if behavior,
      configuration, or supported systems changed.
- [ ] No known-limitations or beta-status claims were removed without
      corresponding evidence.

## Checklist

- [ ] I have read `CONTRIBUTING.md`.
- [ ] This PR does not introduce new privileged (`sudo`) command surfaces
      without a narrow, argument-safe allowlist entry.
- [ ] This PR does not interpolate user-controlled input directly into
      generated BIND/dnsdist configuration or Lua.
- [ ] I have not added unverified compatibility, support, or
      production-readiness claims.
