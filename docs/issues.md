# Known issues

- Management UI exposure relies entirely on your network firewall
  (VLAN/segmentation rules). Verify the host is reachable only from the
  intended management network before production use.
- DNS listeners bind to all interfaces. dnsdist allows RFC1918 private
  networks by default; verify your firewall rules before setting
  `ALDERPOINTDNS_DNS_ALLOW_ALL=1` to accept queries from anywhere.
- Web cookies are not marked `Secure` over plain HTTP. Set
  `ALDERPOINTDNS_COOKIE_SECURE=1` once the admin interface is served over
  HTTPS.
- Per-network policy runtime enforcement is not enabled yet; the database and
  compiler-visible profile/category model exist so it can be added without a
  schema rewrite.

See `docs/known-limitations.md` for the broader list and `CHANGELOG.md` for
what has already shipped.
