# Alderpoint DNS V2 Roadmap

Alderpoint DNS V2 is the planned architectural overhaul that follows the v1.x line through v1.2.1.

The goal is not to clone AdGuard Home internally. It is to preserve the useful DNS-appliance capabilities users expect while making Alderpoint DNS faster, more failure-isolated, more secure, easier to operate, and easier to recover.

## Core direction

- DNS-only appliance. **No DHCP, router, firewall, or NAT functionality.**
- dnsdist + BIND remain the DNS data plane unless benchmarks prove a materially better DNS-only design.
- The host itself must continue to use independent maintenance DNS, so an Alderpoint failure never takes the server's own package/recovery networking down with it.
- Raw query history moves out of the shared control database.
- V2 will benchmark Parquet + Zstandard + DuckDB against dedicated SQLite WAL and compressed JSONL before selecting the analytics storage implementation.
- A small transactional control database remains for bounded relational state such as users, sessions, clients, policies, jobs, audit data, and replication metadata.
- Password storage becomes an explicit Argon2id security contract with unique salts, benchmarked parameters, rehash-on-upgrade, and evaluation of a separately stored root-only pepper.
- Runtime policy is compiled into native dnsdist/BIND structures rather than looked up from a management database per DNS query.
- Native HTTPS administration is mandatory.
- V1 -> V2 migration must be previewable, backed up, validated, recoverable, and boring.

## Mandatory V2 feature gate

V2 will not be published until the agreed DNS feature set is complete, including:

- SafeSearch
- parental and safe-browsing controls
- malware/phishing protection policy
- service blocking with schedules/bedtimes
- detailed per-client settings
- per-client upstream resolvers
- per-client query-log exclusions
- per-client statistics exclusions
- client groups/tags
- DNS-only runtime client discovery
- domain-specific upstream routing
- fallback DNS
- configurable upstream strategies
- configurable blocking response modes
- ECS controls
- native HTTPS administration

Existing Alderpoint capabilities such as filtering, Local DNS, rewrites, encrypted DNS, Clients & Access, cache controls, query log, analytics, backup/restore, replication, migration, notifications, audit logging, and software updates must not regress.

## Delivery target

The current engineering target is **10 focused working days, with a 14-calendar-day target for a private release candidate**, assuming no major dependency or security blocker. That is a planning target, not permission to publish a broken release.

Development is intentionally structured around a small number of consolidated implementation handoffs and three high-value independent review gates to keep engineering-agent usage bounded while another project is also in active development.

## Full planning documents

- [V2 Master Architecture and Delivery Plan](docs/v2-architecture-plan.md)
- [V2 Mandatory Feature / Parity Matrix](docs/v2-adguard-parity-matrix.md)

These documents are intended to remain useful as both a public roadmap and a historical record of why Alderpoint DNS V2 was redesigned.
