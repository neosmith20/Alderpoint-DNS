# Configuration

Current lab-safe configuration:

- Admin UI: `127.0.0.1:3000`
- dnsdist DNS: `127.0.0.1:53`
- dnsdist DoH: `127.0.0.1:443/dns-query`
- dnsdist DoT: `127.0.0.1:853`
- BIND backend: `127.0.0.1:5353`
- BIND RPZ: `/var/lib/bindguard/compiled/bind/bindguard.rpz`
- Maintenance DNS: `1.1.1.2`, `1.0.0.2`, `4.2.2.1`, `4.2.2.2`

Final management CIDR, allowed client networks, production hostname, and
production certificate paths remain unset. Until supplied, listeners stay
loopback-only.
