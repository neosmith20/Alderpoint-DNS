# Configuration

Current configuration:

- Admin UI: `0.0.0.0:3000`, authenticated by BindGuard
- dnsdist DNS: `0.0.0.0:53`, `[::]:53`
- dnsdist DoH/DoH3: `0.0.0.0:443`, `[::]:443`, path `/dns-query`
- dnsdist DoT/DoQ: `0.0.0.0:853`, `[::]:853`
- BIND dnsdist backend: `127.0.0.1:5354` with PROXYv2
- BIND recovery/health listener: `127.0.0.1:5353`
- BIND RPZ: `/var/lib/bindguard/compiled/bind/bindguard.rpz`
- Local DNS include: `/var/lib/bindguard/compiled/bind/local-zones.conf`
- Local DNS default domain: `home.arpa`
- Analytics collector: `127.0.0.1:5301`
- Maintenance DNS: `1.1.1.2`, `1.0.0.2`, `4.2.2.1`, `4.2.2.2`

dnsdist accepts RFC1918 private clients by default. Set
`BINDGUARD_DNS_ALLOW_ALL=1` only when pfSense rules are ready to enforce the
intended boundary. The generated self-signed certificate lives at
`/etc/bindguard/certs/bindguard-lab.crt`; replace both cert and key together to
install production TLS material.

Analytics settings are managed from the Statistics page. Detailed query rows
default to seven days of retention; aggregate buckets default to 90 days.
Privacy modes are full, anonymized clients, and aggregate-only. The default
database size limit is 256 MiB; when the database exceeds the configured limit,
BindGuard prunes the oldest detailed query rows and records a local analytics
warning.

Local DNS settings are managed from the Local DNS page. Administrators can
change the internal domain, default TTL, and BindGuard server identity there.
The setup workflow offers to create `bindguard.home.arpa` and the matching PTR
record using the detected server IP, which can be edited later.
