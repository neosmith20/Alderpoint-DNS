# Known limitations

- Debian dnsdist `1.9.15-0+deb13u1` lacks DNS-over-QUIC and DNS-over-HTTP/3
  support. DoQ and DoH3 are reported as unavailable.
- Admin UI is loopback-only until management CIDR is supplied.
- DNS client ACL is loopback-only until allowed client networks are supplied.
- Temporary self-signed lab certificate is not production trusted.
- Query statistics are aggregate-only; full query history and top-client/domain
  views are future work.
- Per-network policy profiles and SafeSearch enforcement are modeled as future
  work but not fully implemented.
