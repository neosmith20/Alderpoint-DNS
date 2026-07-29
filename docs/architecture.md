# BindGuard architecture

dnsdist is the sole client-facing DNS frontend. It will terminate plain DNS and
supported encrypted DNS transports, enforce client ACLs and rate limits, and
forward to BIND on `127.0.0.1:5353`.

BIND is a localhost-only validating cache/forwarder. Filtering is compiled into
an RPZ zone. Generated files live under `/var/lib/bindguard/compiled` and are
referenced by small package-independent include files.

The Python web application and deployment controller run as a dedicated
unprivileged account. A narrow root-owned helper performs only enumerated
validation, atomic deployment, reload, health-test, and rollback operations.

Management HTTP traffic uses the host resolver from `/etc/resolv.conf`, currently
the explicit maintenance resolvers `1.1.1.2` and `1.0.0.2`. It never uses
`127.0.0.1`, the appliance address, BIND, or dnsdist.

Until the management CIDR and allowed DNS client networks are explicitly known,
all BindGuard listeners remain limited to loopback.

Policy preparation is represented in SQLite even though v1 runtime enforcement
currently uses the single generated RPZ. The schema includes built-in profiles
for trusted, standard, IoT, and restricted networks; category keys for malware,
ads and trackers, adult content, IoT telemetry, SafeSearch, and custom policy;
and a `network_policies` table that can bind CIDRs to profiles once actual
client networks are supplied.
