# Configuration

Some defaults below describe a lab-oriented starting configuration and
should be reviewed before production use (see `docs/known-limitations.md`).

Current configuration:

- Admin UI: `0.0.0.0:3000`, authenticated by Alderpoint DNS
- dnsdist DNS: `0.0.0.0:53`, `[::]:53`
- dnsdist DoH/DoH3: `0.0.0.0:443`, `[::]:443`, path `/dns-query`
- dnsdist DoT/DoQ: `0.0.0.0:853`, `[::]:853`
- BIND dnsdist backend: `127.0.0.1:5354` with PROXYv2
- BIND recovery/health listener: `127.0.0.1:5353`
- BIND RPZ: `/var/lib/alderpointdns/compiled/bind/alderpointdns.rpz`
- Local DNS include: `/var/lib/alderpointdns/compiled/bind/local-zones.conf`
- Local DNS default domain: `home.arpa`
- BIND cache tuning include: `/var/lib/alderpointdns/compiled/bind/cache-options.conf`
- Managed upstream BIND include:
  `/var/lib/alderpointdns/compiled/bind/upstream-forwarders.conf`
- Managed upstream dnsdist include:
  `/var/lib/alderpointdns/compiled/dnsdist/upstream-forwarder.conf`
- Managed upstream loopback listener: `127.0.0.1:5355` (dnsdist upstream pool
  used by BIND when Upstream Resolvers are deployed)
- BIND cache size default: computed from VM memory (an eighth of total RAM,
  bounded to 64-512MB), not BIND's much larger implicit default
- Analytics collector: `127.0.0.1:5301`
- Maintenance DNS: `1.1.1.2`, `1.0.0.2`, `4.2.2.1`, `4.2.2.2`

dnsdist accepts RFC1918 private clients by default. Set
`ALDERPOINTDNS_DNS_ALLOW_ALL=1` only when your firewall rules are ready to
enforce the intended boundary. The generated self-signed certificate lives at
`/etc/alderpointdns/certs/alderpointdns-lab.crt`; replace both cert and key together to
install production TLS material, or manage this from the Encryption page
(`/encryption`), which also supports a local CA, cert upload, and existing
server-side paths. `dnsdist.conf` reads its certificate paths, DoH path, and
per-protocol ports from `ALDERPOINTDNS_TLS_CERT`/`ALDERPOINTDNS_TLS_KEY`/
`ALDERPOINTDNS_DOH_PATH`/`ALDERPOINTDNS_DOH_PORT`/`ALDERPOINTDNS_DOH3_PORT`/
`ALDERPOINTDNS_DOT_PORT`/`ALDERPOINTDNS_DOQ_PORT` environment variables (defaulting
to the original hardcoded lab values), set via the systemd drop-in
`/etc/systemd/system/dnsdist.service.d/alderpointdns.conf`, which Encryption
Settings deployments regenerate.

Analytics settings are managed from the Statistics page. Detailed query rows
default to seven days of retention; aggregate buckets default to 90 days.
Privacy modes are full, anonymized clients, and aggregate-only. The default
database size limit is 256 MiB; when the database exceeds the configured limit,
Alderpoint DNS prunes the oldest detailed query rows and records a local analytics
warning.

Local DNS settings are managed from the Local DNS page. Administrators can
change the internal domain, default TTL, and Alderpoint DNS server identity there.
The setup workflow offers to create `alderpointdns.home.arpa` and the matching PTR
record using the detected server IP, which can be edited later.

Upstream DNS resolvers are managed from DNS Settings. On first use, Alderpoint DNS
imports the existing BIND `forwarders` values into `upstream_resolvers`.
Subsequent deployments render dnsdist upstream backends for enabled plain DNS,
DoT, and DoH resolvers and point BIND at the local dnsdist upstream listener.
For hostname-based DoT/DoH upstreams, `bootstrap_ips` are bootstrap DNS
resolvers used to resolve the configured upstream hostname at deploy time. They
are not treated as the encrypted service endpoint. dnsdist receives the resolved
endpoint IP in `newServer(address=...)`, while `subjectName` and the DoH HTTP
Host remain the configured TLS hostname.
DoH URLs with query strings or fragments are rejected so credentials or tokens
are not stored or exposed in diagnostics.

The analytics collector also polls dnsdist's authenticated local server API and
maps managed upstream backend counters back to `upstream_resolvers.id` through
Alderpoint DNS's generated backend names. The Dashboard can therefore rank upstream
resolvers by attempted queries, successful responses, failures, timeouts, and
latency. Alderpoint DNS does not add per-query upstream labels unless dnsdist
exposes that exact attribution; current client query rows remain client/domain
analytics, not fabricated resolver traces.

## Filter Update Interval

Automatic blocklist (filter) updates are controlled by one global setting on
the Blocklists page (`/blocklists`, Automatic Updates panel). The selectable
values are a fixed server-side allowlist:

| Label | Stored value | Timer interval |
| --- | --- | --- |
| `Disabled — No Updates` | `disabled` | timer stopped and disabled |
| `1 Hour` | `1` | `OnUnitActiveSec=1h` |
| `12 Hours` | `12` | `OnUnitActiveSec=12h` |
| `1 Day` | `24` | `OnUnitActiveSec=24h` |
| `3 Days` | `72` | `OnUnitActiveSec=72h` |
| `1 Week` | `168` | `OnUnitActiveSec=168h` |

Fresh installs default to `1 Day`. An existing setting is never overwritten by
a reinstall, upgrade, or database migration; only a value that is not in the
allowlist (a hand-edited row) is reset to the default. Anything else --
arbitrary numbers, cron expressions, systemd time expressions, unit names,
paths, or shell text -- is rejected with an error and never reaches a unit file
or a `systemctl` argument. The timer expression is always looked up from the
allowlist mapping above, never built from submitted text.

Settings live in the `filter_update_settings` key/value table in
`/var/lib/alderpointdns/alderpointdns.db` (the same shape as `backup_settings`):
`interval_hours`, `last_attempt`, `last_success`, and `last_result` (a
sanitized JSON summary holding the deployment status, active-rule count, and a
short error description with URLs stripped; it never stores query data or
credentials). Because the setting is in the database and the schedule is a
systemd timer, it survives restarts, reboots, and upgrades.

When updates are enabled, the Blocklists panel shows the interval, an
`Enabled` badge, the last automatic attempt, the last successful automatic
update, and the next scheduled update (read unprivileged from
`systemctl show alderpointdns-filter-update.timer
--property=NextElapseUSecRealtime`). When disabled, it shows
`Automatic updates disabled` and no next-run time, and the timer is stopped and
disabled. Manual per-source updates and `Update All Now` keep working in both
states.

Each automatic run executes the ordinary deployment pipeline: only enabled
sources are downloaded, the RPZ is recompiled, validated, activated
atomically, health-checked, and rolled back automatically on failure, and the
result is recorded as a `deployments` row marked `trigger='scheduled'`
(manual deployments leave `trigger` NULL). The pipeline holds an exclusive
lock, so a scheduled run can never overlap a manual deploy or another
scheduled run, and one list failing to download still leaves the other lists
updated with the last valid policy active.

systemd units and privileged commands:

- `/etc/systemd/system/alderpointdns-filter-update.service` -- oneshot,
  `ExecStart=/opt/alderpointdns/app/alderpointdns_compiler.py filter-update-run`.
- `/etc/systemd/system/alderpointdns-filter-update.timer` -- packaged defaults
  `OnBootSec=24h`/`OnUnitActiveSec=24h`, `Persistent=true`.
- `/etc/systemd/system/alderpointdns-filter-update.timer.d/alderpointdns.conf`
  -- runtime drop-in regenerated from the stored setting; removed while
  updates are disabled.
- Sudoers entries in `/etc/sudoers.d/alderpointdns` (exact commands, no
  wildcards): `alderpointdns_compiler.py filter-schedule-deploy` and
  `alderpointdns_compiler.py filter-update-run`. The web app uses
  `filter-schedule-deploy` after Save; the timer itself already runs as root.

Encryption Settings manages client-facing encrypted DNS listeners separately
from upstream resolver encryption. The listener IPv4/IPv6 addresses default to
`0.0.0.0` and `::` to preserve existing lab behavior, but can be changed to
loopback or a specific LAN address before deployment. At least one listen
address is required so ordinary DNS remains reachable. Wildcard listener
addresses still rely on dnsdist ACLs and the host/network firewall for actual
client reachability.
