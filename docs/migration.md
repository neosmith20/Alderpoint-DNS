# Migration Guide

BindGuard supports preview-first imports from:

- AdGuard Home YAML or read-only API
- Pi-hole text/list exports
- Generic hosts files
- BIND zone files
- CSV/XLSX
- BindGuard-native JSON

Migration rules:

- Parse first, preview second, apply only selected categories.
- Existing records are not silently overwritten.
- Conflicts, duplicates, skipped entries, unsupported syntax, and warnings are
  shown before apply.
- A backup is taken before apply.
- Unsupported source features are documented rather than fabricated.

Source limitations:

- Pi-hole gravity database internals are not read directly.
- AdGuard domain-specific upstream routing has no BindGuard equivalent yet.
- AdGuard allowlist subscriptions are reported for manual review because
  BindGuard has custom allow rules, not allowlist-subscription objects.
