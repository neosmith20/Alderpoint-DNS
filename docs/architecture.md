# Alderpoint DNS architecture

dnsdist is the sole client-facing DNS frontend. It will terminate plain DNS and
supported encrypted DNS transports, enforce client ACLs and rate limits, and
forward to BIND on `127.0.0.1:5354` with PROXYv2 client address preservation.
The plain `127.0.0.1:5353` BIND listener remains loopback-only for health and
recovery checks.

BIND is a localhost-only validating cache/forwarder. Filtering is compiled into
an RPZ zone. Generated files live under `/var/lib/alderpointdns/compiled` and are
referenced by small package-independent include files.

Local DNS records are authoritative data, not filtering policy. Alderpoint DNS stores
host records and client aliases in SQLite, then generates a dedicated
authoritative forward zone for the configured internal domain, default
`home.arpa`, plus any required IPv4 or IPv6 reverse zones. The generated BIND
include is `/var/lib/alderpointdns/compiled/bind/local-zones.conf`, and zone files
live under `/var/lib/alderpointdns/compiled/bind/local/`. Queries for the internal
zone are answered by BIND locally and are not forwarded to public resolvers.

The Python web application and deployment controller run as a dedicated
unprivileged account. A narrow root-owned helper performs only enumerated
validation, atomic deployment, reload, health-test, and rollback operations.

Alderpoint DNS analytics are native to the appliance. dnsdist emits delayed
protobuf response events to `127.0.0.1:5301`, where
`alderpointdns-analytics.service` receives them with a bounded queue and writes
batched rows to the existing SQLite database. The collector also polls the
loopback-only dnsdist stats API every configured interval for aggregate
latency, cache, drop, and health counters. DNS continues to answer if the
collector is stopped; dnsdist queues only a bounded number of telemetry events
and then drops telemetry rather than blocking query handling.

Blocked-query status is derived by correlating response events with the active
Alderpoint DNS RPZ policy set. Ordinary NXDOMAIN responses are not treated as
blocked unless the queried name also matches the compiled block policy.

Client aliases are presentation-only. They map an IP or CIDR to a friendly
dashboard/query-log label and do not alter DNS answers. When no alias exists,
Alderpoint DNS may use an enabled local PTR record as a cached display fallback.

Management HTTP traffic uses the host resolver from `/etc/resolv.conf`, currently
the explicit maintenance resolvers `1.1.1.2` and `1.0.0.2`. It never uses
`127.0.0.1`, the appliance address, BIND, or dnsdist.

Until the management CIDR and allowed DNS client networks are explicitly known,
all Alderpoint DNS listeners remain limited to loopback.

Policy preparation is represented in SQLite even though v1 runtime enforcement
currently uses the single generated RPZ. The schema includes built-in profiles
for trusted, standard, IoT, and restricted networks; category keys for malware,
ads and trackers, adult content, IoT telemetry, SafeSearch, and custom policy;
and a `network_policies` table that can bind CIDRs to profiles once actual
client networks are supplied.
