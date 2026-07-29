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
- BIND cache tuning include: `/var/lib/bindguard/compiled/bind/cache-options.conf`
- Managed upstream BIND include:
  `/var/lib/bindguard/compiled/bind/upstream-forwarders.conf`
- Managed upstream dnsdist include:
  `/var/lib/bindguard/compiled/dnsdist/upstream-forwarder.conf`
- Managed upstream loopback listener: `127.0.0.1:5355` (dnsdist upstream pool
  used by BIND when Upstream Resolvers are deployed)
- BIND cache size default: computed from VM memory (an eighth of total RAM,
  bounded to 64-512MB), not BIND's much larger implicit default
- Analytics collector: `127.0.0.1:5301`
- Maintenance DNS: `1.1.1.2`, `1.0.0.2`, `4.2.2.1`, `4.2.2.2`

dnsdist accepts RFC1918 private clients by default. Set
`BINDGUARD_DNS_ALLOW_ALL=1` only when pfSense rules are ready to enforce the
intended boundary. The generated self-signed certificate lives at
`/etc/bindguard/certs/bindguard-lab.crt`; replace both cert and key together to
install production TLS material, or manage this from the Encryption page
(`/encryption`), which also supports a local CA, cert upload, and existing
server-side paths. `dnsdist.conf` reads its certificate paths, DoH path, and
per-protocol ports from `BINDGUARD_TLS_CERT`/`BINDGUARD_TLS_KEY`/
`BINDGUARD_DOH_PATH`/`BINDGUARD_DOH_PORT`/`BINDGUARD_DOH3_PORT`/
`BINDGUARD_DOT_PORT`/`BINDGUARD_DOQ_PORT` environment variables (defaulting
to the original hardcoded lab values), set via the systemd drop-in
`/etc/systemd/system/dnsdist.service.d/bindguard.conf`, which Encryption
Settings deployments regenerate.

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

Upstream DNS resolvers are managed from DNS Settings. On first use, BindGuard
imports the existing BIND `forwarders` values into `upstream_resolvers`.
Subsequent deployments render dnsdist upstream backends for enabled plain DNS,
DoT, and DoH resolvers and point BIND at the local dnsdist upstream listener.
DoH URLs with query strings or fragments are rejected so credentials or tokens
are not stored or exposed in diagnostics.

The analytics collector also polls dnsdist's authenticated local server API and
maps managed upstream backend counters back to `upstream_resolvers.id` through
BindGuard's generated backend names. The Dashboard can therefore rank upstream
resolvers by attempted queries, successful responses, failures, timeouts, and
latency. BindGuard does not add per-query upstream labels unless dnsdist
exposes that exact attribution; current client query rows remain client/domain
analytics, not fabricated resolver traces.
