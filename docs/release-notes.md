# Release Notes

## 0.4.0-beta.1

This is a beta-preparation build, not a v1.0 release.

Highlights:

- Responsive administration sidebar and mobile drawer.
- Managed upstream resolvers for plain DNS, DoT, and DoH.
- Per-upstream resolver analytics from dnsdist backend counters.
- Client-facing encrypted DNS listener controls.
- Expanded import and migration for AdGuard Home, Pi-hole text/list exports,
  BIND zones, hosts files, CSV/XLSX, and BindGuard-native JSON.
- Fresh-install, upgrade, diagnostics, and local test `.deb` tooling.
- BIND cache management with TTL, size, recursive-client, prefetch,
  serve-stale, and flush controls.

Known release caveats:

- Admin UI HTTPS is not implemented yet; use private networks or a trusted
  reverse proxy and enable `BINDGUARD_COOKIE_SECURE=1` when served over HTTPS.
- Pi-hole import targets practical text/list data, not Pi-hole's live gravity
  database internals.
- AdGuard domain-specific upstream routing is reported as unsupported.
- `dpkg-deb` test packages are supported for validation; a signed apt
  repository is not published yet.
