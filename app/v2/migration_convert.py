"""V1 -> V2 real migration conversion logic (Workstream 3 final
continuation, Priority 1). Replaces the stub stage functions in
``app/v2/migration.py`` with real conversions, operating only against a
disposable backup copy of the source database -- never the caller's
original source path.

Every function here takes explicit paths/connections and does one bounded
piece of work; ``app/v2/migration.py``'s stage functions call these in
sequence and are the only thing that knows the overall pipeline order.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import sqlite3
from contextlib import closing
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from app.v2 import config as v2config
from app.v2 import control_db
from app.v2 import notification_store as nstore
from app.v2 import policy_store as pstore
from app.v2.local_dns_gen import LocalDnsGenError, LocalDnsRecord
from app.v2.secret_store import SecretStore

# Real schema contract (Gate #2 HIGH finding): every table/column the
# real migration_convert.py functions below actually SELECT from without
# a defensive try/except is REQUIRED -- a source missing any of these
# must be rejected at detection time, before backup/migration proceeds,
# with a diagnostic naming exactly what's missing. This list was built by
# grepping every "SELECT ... FROM <table>" in this module, not guessed;
# it is the real, exhaustive contract, so it stays exhaustive as long as
# new conversion functions update it alongside their own new queries.
REQUIRED_TABLES_AND_COLUMNS: dict[str, frozenset[str]] = {
    "admins": frozenset({"username", "password_hash", "created_at"}),
    "clients": frozenset({"id", "name", "description", "enabled", "created_at", "updated_at"}),
    "client_identifiers": frozenset({"client_id", "kind", "value", "created_at"}),
    "network_policies": frozenset({"cidr", "profile_key", "description", "enabled"}),
    "local_dns_records": frozenset({"fqdn", "record_type", "value", "ttl", "enabled"}),
    "custom_filter_rules": frozenset({"domain", "action", "enabled", "validation_state"}),
    "upstream_resolvers": frozenset(
        {"name", "protocol", "address", "port", "tls_hostname", "doh_path", "position", "enabled"}
    ),
}

# Tables the migration logic already tolerates being entirely absent
# (each read site has its own try/except sqlite3.OperationalError
# fallback) -- documented here explicitly as "supported with a defined
# fallback" rather than left implicit, per §5A's classification
# requirement. A source missing these is still "supported," just with
# reduced fidelity (no analytics-settings-derived config conversion, no
# legacy-history archive registration).
#
# notification_providers real defect found live during package-level
# migration acceptance testing: this table is lazily created by V1's own
# app/notifications.py init_db(), only ever called from the
# alderpointdns-notify.timer's periodic check -- NOT part of V1's base
# schema created at install time. A real, never-yet-fired-its-first-
# timer-tick V1 install (a perfectly ordinary, freshly installed
# appliance) genuinely lacks this table, and migration must not hard-
# fail a real, valid, otherwise-fully-migratable V1 source over a table
# it was previously misclassified as REQUIRED -- there's simply nothing
# to migrate in that case, same as any other optional/empty table below.
OPTIONAL_TABLES_AND_COLUMNS: dict[str, frozenset[str]] = {
    "analytics_settings": frozenset({"key", "value"}),
    "query_events": frozenset({"ts"}),
    "notification_providers": frozenset({"kind", "name", "enabled", "config_json", "secret"}),
}


class MigrationConvertError(RuntimeError):
    pass


class UnsupportedSourceSchemaError(MigrationConvertError):
    """Raised specifically for a schema-contract failure (missing
    required table/column) -- distinguished from a generic
    MigrationConvertError (e.g. file-not-found, corrupt file) so a caller
    can tell "wrong/incomplete version" apart from "not a database at
    all."""


# --------------------------------------------------------------------------
# 1. Source discovery
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class SourceInfo:
    db_path: Path
    detected_version: str
    table_count: int
    classification: str  # "supported_complete" | "supported_with_optional_gaps"
    missing_optional: tuple[str, ...] = ()


def _real_columns(conn: sqlite3.Connection, table: str) -> set[str]:
    return {row[1] for row in conn.execute(f"PRAGMA table_info({table})").fetchall()}


def resolve_source_db_path(source_path: Path) -> Path:
    """Explicit source-root/source-database contract (real defect closed:
    RC42's UI supplied V1's real installed database FILE,
    ``/var/lib/alderpointdns/alderpointdns.db``, but this function
    unconditionally treated its argument as a DIRECTORY and appended
    ``alderpointdns.db`` again -- looking for the non-existent
    ``.../alderpointdns.db/alderpointdns.db`` and failing with
    ``unsupported_source`` on a completely real, present V1 install).

    ``source_path`` may be either:
    - a direct path to the source database FILE itself (a real V1
      install's ``alderpointdns.db``, or a restored copy of one), or
    - a source ROOT directory that CONTAINS ``alderpointdns.db``.

    Both are validated explicitly and unambiguously here, once, so every
    caller (API, CLI, tests) gets the same resolution instead of each
    guessing independently.
    """
    source_path = Path(source_path)
    if source_path.is_file():
        return source_path
    if source_path.is_dir():
        candidate = source_path / "alderpointdns.db"
        if candidate.is_file():
            return candidate
        raise MigrationConvertError(
            f"source root {source_path} does not contain alderpointdns.db"
        )
    raise MigrationConvertError(
        f"source path not found: {source_path} (expected either the source "
        "database file itself, e.g. /var/lib/alderpointdns/alderpointdns.db, "
        "or a directory containing it)"
    )


def detect_source(source_root: Path) -> SourceInfo:
    """Real, exhaustive pre-flight schema validation (§5A-5B): every table
    and column the real migration conversion functions actually read is
    checked here, BEFORE backup/migration proceeds -- a source missing
    ``client_identifiers`` is now rejected right here, with every missing
    table/column named explicitly, not just the first one encountered.

    Never opens the source for writing.
    """
    db_path = resolve_source_db_path(Path(source_root))
    try:
        uri = f"file:{db_path}?mode=ro"
        conn = sqlite3.connect(uri, uri=True)
    except sqlite3.Error as exc:
        raise MigrationConvertError(f"cannot open source database read-only: {exc}") from exc
    try:
        try:
            tables = {
                r[0]
                for r in conn.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                ).fetchall()
            }
        except sqlite3.DatabaseError as exc:
            raise MigrationConvertError(f"source is not a valid SQLite database: {exc}") from exc

        problems: list[str] = []
        for table, required_cols in REQUIRED_TABLES_AND_COLUMNS.items():
            if table not in tables:
                problems.append(f"missing required table: {table}")
                continue
            actual_cols = _real_columns(conn, table)
            missing_cols = required_cols - actual_cols
            if missing_cols:
                problems.append(
                    f"table {table!r} is missing required column(s): {sorted(missing_cols)}"
                )
        if problems:
            raise UnsupportedSourceSchemaError(
                "source database schema is unsupported/incomplete for migration:\n  "
                + "\n  ".join(problems)
            )

        missing_optional = []
        for table, required_cols in OPTIONAL_TABLES_AND_COLUMNS.items():
            if table not in tables:
                missing_optional.append(table)
                continue
            actual_cols = _real_columns(conn, table)
            if required_cols - actual_cols:
                missing_optional.append(table)

        classification = "supported_with_optional_gaps" if missing_optional else "supported_complete"
        return SourceInfo(
            db_path=db_path, detected_version="v1.x", table_count=len(tables),
            classification=classification, missing_optional=tuple(missing_optional),
        )
    finally:
        conn.close()


# --------------------------------------------------------------------------
# 2/3. Mandatory backup + restore-test
# --------------------------------------------------------------------------


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _table_row_counts(db_path: Path) -> dict[str, int]:
    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    try:
        tables = [
            r[0]
            for r in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
            ).fetchall()
        ]
        return {t: conn.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0] for t in tables}
    finally:
        conn.close()


def create_backup(source_db_path: Path, staging_dir: Path) -> dict:
    """Consistent snapshot via SQLite's own backup API (not a raw file
    copy, which would risk capturing an inconsistent mid-write WAL state)
    -- ``sqlite3.Connection.backup()`` produces a transactionally
    consistent copy even against a live, actively-written database.
    """
    staging_dir.mkdir(parents=True, exist_ok=True)
    backup_path = staging_dir / "pre-migration-backup.db"

    src = sqlite3.connect(f"file:{source_db_path}?mode=ro", uri=True)
    try:
        dst = sqlite3.connect(str(backup_path))
        try:
            src.backup(dst)
        finally:
            dst.close()
    finally:
        src.close()

    checksum = _sha256_file(backup_path)
    counts = _table_row_counts(backup_path)
    manifest = {
        "source_path": str(source_db_path),
        "backup_path": str(backup_path),
        "sha256": checksum,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "table_row_counts": counts,
        "size_bytes": backup_path.stat().st_size,
    }
    manifest_path = staging_dir / "pre-migration-backup.manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True))
    return manifest


def verify_backup(manifest: dict) -> None:
    """Re-checksum + integrity-check + row-count cross-check. Migration
    MUST NOT proceed past this gate unless this raises nothing.
    """
    backup_path = Path(manifest["backup_path"])
    if not backup_path.exists():
        raise MigrationConvertError(f"backup file missing: {backup_path}")
    actual_checksum = _sha256_file(backup_path)
    if actual_checksum != manifest["sha256"]:
        raise MigrationConvertError(
            f"backup checksum mismatch: expected {manifest['sha256']}, got {actual_checksum} "
            "-- backup is corrupt or was tampered with"
        )
    conn = sqlite3.connect(f"file:{backup_path}?mode=ro", uri=True)
    try:
        integrity = conn.execute("PRAGMA integrity_check").fetchone()[0]
        if integrity != "ok":
            raise MigrationConvertError(f"backup failed integrity_check: {integrity}")
    finally:
        conn.close()
    actual_counts = _table_row_counts(backup_path)
    expected_counts = manifest["table_row_counts"]
    if actual_counts != expected_counts:
        raise MigrationConvertError(
            f"backup row counts changed since creation: expected {expected_counts}, "
            f"got {actual_counts}"
        )


def restore_test(manifest: dict, restore_dir: Path) -> dict:
    """Proves the backup can actually reconstruct usable source state, not
    merely that its checksum matches. Copies the backup to a disposable
    location, opens it, and confirms representative tables/rows are
    readable -- this is what a real disaster-recovery restore would need
    to succeed at.
    """
    import shutil

    restore_dir.mkdir(parents=True, exist_ok=True)
    restored_path = restore_dir / "restored-for-test.db"
    shutil.copy2(manifest["backup_path"], restored_path)

    conn = sqlite3.connect(f"file:{restored_path}?mode=ro", uri=True)
    try:
        admin_count = conn.execute("SELECT COUNT(*) FROM admins").fetchone()[0]
        client_count = conn.execute("SELECT COUNT(*) FROM clients").fetchone()[0]
    except sqlite3.Error as exc:
        raise MigrationConvertError(f"restored backup is not queryable: {exc}") from exc
    finally:
        conn.close()
    return {"restored_path": str(restored_path), "admin_count": admin_count, "client_count": client_count}


# --------------------------------------------------------------------------
# 4. Migration preview (read-only)
# --------------------------------------------------------------------------


def build_preview(backup_db_path: Path) -> dict:
    conn = sqlite3.connect(f"file:{backup_db_path}?mode=ro", uri=True)
    warnings: list[str] = []
    try:
        def _count(table: str) -> int:
            try:
                return conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
            except sqlite3.OperationalError:
                return 0

        secret_count = _count("notification_providers")
        query_history_count = _count("query_events")
        if _count("policy_profiles") > 1:
            warnings.append(
                "source has multiple named policy profiles; V1's profile/category concept "
                "has no direct V2 equivalent yet -- network policies are migrated as V2 "
                "network scopes with default-policy layers, and profile-specific filtering "
                "behavior is NOT automatically reconstructed (see migrate_policies warnings)"
            )

        enabled_transports = _enabled_inbound_encrypted_transports(conn)
        if enabled_transports:
            warnings.append(
                "source has inbound encrypted DNS transport(s) enabled for clients "
                f"({', '.join(enabled_transports)}) via V1 encryption_settings -- V2's "
                "runtime generator does not emit inbound DoT/DoH/DoH3/DoQ/DNSCrypt "
                "listeners yet (plain UDP/TCP:53 only), so this configuration has NO "
                "migration path and will NOT be present after migration; clients using "
                "encrypted DNS to this appliance will need plain DNS or manual "
                "reconfiguration post-migration"
            )

        report = {
            "source_version": "v1.x",
            "target_schema": "v2 (control.db schema v2/v3/v4, config schema "
            f"{v2config.CONFIG_SCHEMA_VERSION})",
            "object_counts": {
                "admins": _count("admins"),
                "clients": _count("clients"),
                "client_identifiers": _count("client_identifiers"),
                "access_rules": _count("access_rules"),
                "local_dns_records": _count("local_dns_records"),
                # custom_rules (bare "domain"/"action"/"enabled" columns)
                # is dead V1 schema: no current V1 code path (webapp.py's
                # real /rules feature, custom_rules.py's add_rule/
                # add_rules_bulk, the importer) ever writes to it -- every
                # real custom filter rule a real V1 admin has ever created
                # lives in custom_filter_rules instead (found live during
                # RC2 migration acceptance testing: a real V1 install with
                # 20 real rules created through the real add_rule() API
                # previewed and migrated as 0 rules with the old query).
                "custom_rules_block": conn.execute(
                    "SELECT COUNT(*) FROM custom_filter_rules WHERE action='block' AND enabled=1 AND validation_state='valid'"
                ).fetchone()[0] if _count("custom_filter_rules") else 0,
                "custom_rules_allow": conn.execute(
                    "SELECT COUNT(*) FROM custom_filter_rules WHERE action='allow' AND enabled=1 AND validation_state='valid'"
                ).fetchone()[0] if _count("custom_filter_rules") else 0,
                "notification_providers": secret_count,
                "upstream_resolvers": _count("upstream_resolvers"),
                "network_policies": _count("network_policies"),
            },
            "secret_count_no_values": secret_count,
            "query_history_treatment": (
                f"{query_history_count} raw query_events rows will be registered as a "
                "bounded read-only legacy archive, NOT copied into control.db or bulk-"
                "converted as part of this migration"
            ),
            "statistics_treatment": "aggregate rebuild strategy recorded, not auto-run",
            "encryption_settings": {
                "inbound_transports_enabled_in_source": enabled_transports,
                "migrated": False,
            },
            "warnings": warnings,
        }
        return report
    finally:
        conn.close()


# V1's app/encryption.py flag names -> the client-facing label used in
# warnings/docs. Table is key/value (`encryption_settings`), so any subset
# may be present or absent; a missing key is treated as "unknown, not
# confirmed disabled" (V1 defaults doh_enabled/dot_enabled to "1" --
# app/encryption.py's _DEFAULTS -- so most real installs have at least one
# of these on).
_INBOUND_ENCRYPTED_TRANSPORT_FLAGS: tuple[tuple[str, str], ...] = (
    ("doh_enabled", "DoH"),
    ("dot_enabled", "DoT"),
    ("doh3_enabled", "DoH3"),
    ("doq_enabled", "DoQ"),
    ("dnscrypt_enabled", "DNSCrypt"),
)


def _enabled_inbound_encrypted_transports(conn: sqlite3.Connection) -> list[str]:
    try:
        kv = dict(conn.execute("SELECT key, value FROM encryption_settings").fetchall())
    except sqlite3.OperationalError:
        return []  # table absent entirely -- nothing to report
    return [
        label
        for flag_key, label in _INBOUND_ENCRYPTED_TRANSPORT_FLAGS
        if kv.get(flag_key) in ("1", "true", "True")
    ]


# --------------------------------------------------------------------------
# 5. Desired YAML conversion
# --------------------------------------------------------------------------


def convert_config(backup_db_path: Path) -> v2config.AlderpointV2Config:
    conn = sqlite3.connect(f"file:{backup_db_path}?mode=ro", uri=True)
    try:
        analytics_kv = dict(conn.execute("SELECT key, value FROM analytics_settings").fetchall())
    except sqlite3.OperationalError:
        analytics_kv = {}
    finally:
        conn.close()

    retention_days = int(analytics_kv.get("retention_days", "30"))
    cfg = v2config.AlderpointV2Config(
        listeners=[v2config.Listener(protocol="udp", address="0.0.0.0", port=53)],
        analytics=v2config.AnalyticsPolicy(
            enabled=True, retention_value=retention_days, retention_unit="days"
        ),
    )
    errors = cfg.validate()
    if errors:
        raise MigrationConvertError(f"converted config failed validation: {errors}")
    return cfg


# --------------------------------------------------------------------------
# 6. control.db initialization
# --------------------------------------------------------------------------


def initialize_target_control_db(target_control_db: Path) -> None:
    pstore.ensure_schema(target_control_db)
    nstore.ensure_schema(target_control_db)


# --------------------------------------------------------------------------
# 7. Admin/auth metadata
# --------------------------------------------------------------------------


def migrate_admins(backup_db_path: Path, target_control_db: Path) -> dict:
    """Argon2id hashes are reused as-is (no plaintext ever handled) --
    real V1 data confirms admin password hashes are already
    ``$argon2id$...``, which is directly compatible with V2's own hashing
    library. Any hash NOT in a recognized safe format is flagged for a
    forced re-authentication/rehash on first V2 login rather than migrated
    blindly -- never silently trusted.
    """
    src = sqlite3.connect(f"file:{backup_db_path}?mode=ro", uri=True)
    migrated = 0
    needs_rehash: list[str] = []
    try:
        rows = src.execute("SELECT username, password_hash, created_at FROM admins").fetchall()
    finally:
        src.close()

    with control_db.connect(target_control_db) as conn:
        for username, password_hash, created_at in rows:
            if not password_hash.startswith("$argon2id$"):
                needs_rehash.append(username)
                continue
            conn.execute(
                "INSERT OR IGNORE INTO admins (username, password_hash, created_at) "
                "VALUES (?, ?, ?)",
                (username, password_hash, created_at),
            )
            migrated += 1
    return {"migrated": migrated, "needs_rehash": needs_rehash}


# --------------------------------------------------------------------------
# 8. Clients & access
# --------------------------------------------------------------------------


def _validate_identifier(kind: str, value: str) -> bool:
    try:
        if kind in ("ipv4", "ipv6"):
            ipaddress.ip_address(value)
        elif kind in ("ipv4_cidr", "ipv6_cidr"):
            ipaddress.ip_network(value, strict=False)
        elif kind == "clientid":
            if not value.strip():
                return False
        else:
            return False
        return True
    except ValueError:
        return False


def migrate_clients(backup_db_path: Path, target_control_db: Path) -> dict:
    """Idempotent by construction (§21/§22 "idempotent stage replay", "no
    duplicate converted objects" on retry): clears any clients this
    migration previously wrote into the target before re-inserting from
    the source. This is safe specifically because ``target_control_db``
    is disposable staging output owned entirely by this migration run
    (nothing else writes to it concurrently) -- clearing and rebuilding
    from the same read-only source on every stage attempt is simpler and
    more robust than trying to detect exactly how far a prior partial
    attempt got. A version of this function without the clear step was a
    real gap found during this session's own review: a crash mid-stage
    (not just between stages, which the durable-state tests already
    covered) followed by a stage retry would have inserted every client a
    second time, since plain ``INSERT`` has no uniqueness guard on name.
    """
    src = sqlite3.connect(f"file:{backup_db_path}?mode=ro", uri=True)
    warnings: list[str] = []
    clients_migrated = 0
    identifiers_migrated = 0
    identifiers_skipped = 0
    try:
        clients = src.execute(
            "SELECT id, name, description, enabled, created_at, updated_at FROM clients"
        ).fetchall()
        identifiers = src.execute(
            "SELECT client_id, kind, value, created_at FROM client_identifiers"
        ).fetchall()
    finally:
        src.close()

    with control_db.connect(target_control_db) as conn:
        # Cascades to client_identifiers via ON DELETE CASCADE.
        conn.execute("DELETE FROM clients")
        id_map: dict[int, int] = {}
        for old_id, name, description, enabled, created_at, updated_at in clients:
            cur = conn.execute(
                "INSERT INTO clients (name, description, enabled, created_at, updated_at) "
                "VALUES (?, ?, ?, ?, ?)",
                (name, description, enabled, created_at, updated_at),
            )
            id_map[old_id] = cur.lastrowid
            clients_migrated += 1

        for old_client_id, kind, value, created_at in identifiers:
            if not _validate_identifier(kind, value):
                warnings.append(f"skipped invalid client identifier ({kind}={value!r})")
                identifiers_skipped += 1
                continue
            new_client_id = id_map.get(old_client_id)
            if new_client_id is None:
                identifiers_skipped += 1
                continue
            try:
                conn.execute(
                    "INSERT INTO client_identifiers (client_id, kind, value, created_at) "
                    "VALUES (?, ?, ?, ?)",
                    (new_client_id, kind, value, created_at),
                )
                identifiers_migrated += 1
            except sqlite3.IntegrityError:
                warnings.append(f"skipped duplicate client identifier ({kind}={value!r})")
                identifiers_skipped += 1

    return {
        "clients_migrated": clients_migrated,
        "identifiers_migrated": identifiers_migrated,
        "identifiers_skipped": identifiers_skipped,
        "warnings": warnings,
    }


# --------------------------------------------------------------------------
# 9/10. Policy conversion + Local DNS
# --------------------------------------------------------------------------


def migrate_policies(backup_db_path: Path, target_control_db: Path) -> dict:
    """V1's ``network_policies`` (CIDR -> named profile_key) becomes V2
    network scopes; each gets a V2 default policy layer (sane defaults,
    per §9's explicit instruction to inherit defaults rather than
    fabricate behavior when V1 lacks a direct concept) since V1's
    profile_key/policy_profiles system has no per-profile filtering
    behavior of its own in this schema (that lives in the separate,
    global-only ``custom_filter_rules`` table, migrated in ``migrate_filtering``)
    -- this semantic simplification is explicitly surfaced as a preview
    warning, not silently applied.
    """
    src = sqlite3.connect(f"file:{backup_db_path}?mode=ro", uri=True)
    warnings: list[str] = []
    networks_migrated = 0
    try:
        rows = src.execute(
            "SELECT cidr, profile_key, description, enabled FROM network_policies"
        ).fetchall()
    finally:
        src.close()

    with control_db.connect(target_control_db) as conn:
        # Idempotent retry (§21/§22), same reasoning as migrate_clients.
        conn.execute("DELETE FROM policy_networks")
        for i, (cidr, profile_key, description, enabled) in enumerate(rows):
            if not enabled:
                warnings.append(f"skipped disabled network policy {cidr!r}")
                continue
            network_id = f"migrated-net-{i}"
            try:
                pstore.create_network(conn, network_id, cidr)
                networks_migrated += 1
                warnings.append(
                    f"network {cidr!r} (V1 profile {profile_key!r}) migrated with V2 "
                    "default policy layer -- V1 profile-specific behavior was not "
                    "reconstructed automatically"
                )
            except (pstore.PolicyStoreError,) as exc:
                warnings.append(f"skipped network policy {cidr!r}: {exc}")

    return {"networks_migrated": networks_migrated, "warnings": warnings}


def migrate_local_dns(backup_db_path: Path) -> tuple[list[LocalDnsRecord], list[str]]:
    src = sqlite3.connect(f"file:{backup_db_path}?mode=ro", uri=True)
    warnings: list[str] = []
    records: list[LocalDnsRecord] = []
    try:
        rows = src.execute(
            "SELECT fqdn, record_type, value, ttl, enabled FROM local_dns_records"
        ).fetchall()
    finally:
        src.close()

    for fqdn, record_type, value, ttl, enabled in rows:
        if not enabled:
            continue
        try:
            records.append(LocalDnsRecord(fqdn=fqdn, record_type=record_type, value=value, ttl=ttl))
        except LocalDnsGenError as exc:
            warnings.append(f"skipped invalid local DNS record {fqdn!r}/{record_type!r}: {exc}")
    return records, warnings


# --------------------------------------------------------------------------
# 12. Filtering / allow / block
# --------------------------------------------------------------------------


def migrate_filtering(backup_db_path: Path) -> dict:
    """Reads V1's real custom-filter-rule table. custom_filter_rules, not
    the bare custom_rules table this used to (incorrectly) read from --
    custom_rules has matching-looking domain/action/enabled columns but
    is dead schema no current V1 code path ever writes to; every real V1
    admin's real custom rules (via the actual /rules UI, custom_rules.py's
    add_rule()/add_rules_bulk(), or the importer) live in
    custom_filter_rules instead. Found live during RC2 migration
    acceptance testing: a real V1 install with 20 real rules migrated as
    zero with the old query, silently.

    Only 'block'/'allow' domain rules the V1 app itself currently
    considers active and valid are migrated -- rewrite/regex/comment/
    unsupported rule_types have no V2 equivalent in this simple
    domain-list migration and are surfaced as a count in warnings rather
    than silently dropped.
    """
    src = sqlite3.connect(f"file:{backup_db_path}?mode=ro", uri=True)
    try:
        rows = src.execute(
            "SELECT domain, action FROM custom_filter_rules "
            "WHERE enabled = 1 AND validation_state = 'valid' AND action IN ('block', 'allow') "
            "AND domain IS NOT NULL"
        ).fetchall()
        skipped = src.execute(
            "SELECT COUNT(*) FROM custom_filter_rules "
            "WHERE enabled = 1 AND validation_state = 'valid' AND action NOT IN ('block', 'allow')"
        ).fetchone()[0]
    finally:
        src.close()
    blocked = sorted({d for d, a in rows if a == "block"})
    allowed = sorted({d for d, a in rows if a == "allow"})
    warnings: list[str] = []
    if skipped:
        warnings.append(
            f"{skipped} enabled custom filter rule(s) use a rewrite/regex rule type with no V2 "
            "migration path yet and were not migrated (only plain block/allow domain rules are)"
        )
    return {"blocked_domains": blocked, "allowed_domains": allowed, "warnings": warnings}


def migrate_filtering_to_control_db(blocked_domains: list[str], target_control_db: Path) -> dict:
    """Makes migrated V1 block-list domains actually enforced by the real
    compiled runtime, not just present in a staged report.

    V2's real per-effective-policy compiler (``app/v2/runtime_compile.py``
    -> ``app/v2/dnsdist_policy_runtime.py``) enforces domains reachable
    through the ``service_blocking_ruleset`` mechanism (parental/security/
    service rulesets plus ``filtering_profile_id``, all sharing
    ``policy_store.create_service_ruleset``) -- there is still no separate
    "plain ad-hoc block list" storage/CRUD surface distinct from that
    mechanism. Rather than inventing a new storage mechanism under
    migration, this reuses the existing, already-wired ruleset mechanism:
    every migrated blocked domain becomes one
    ``service_definitions`` row (exact match) inside one synthetic service
    named ``migrated-v1-custom-blocklist``, grouped into one ruleset
    (``migrated-v1-custom-blocklist``) that the global policy layer's
    ``service_blocking_ruleset_id`` is pointed at -- so it compiles into a
    real terminal block rule for every network, the same as any
    admin-configured parental/security ruleset would.

    V1's "allow" domains (``migrate_filtering``'s ``allowed_domains``) are
    intentionally NOT written anywhere here: they exist in V1 to override
    entries in V1's much larger default aggregator blocklist (the
    ``sources``-derived list, tracked separately and never migrated at
    all -- see ``docs/v2/migration-real-package-gate.md``), so with no
    migrated default blocklist for them to override, they have nothing to
    do post-migration. ``app/v2/dnsdist_policy_runtime.py``'s
    ``ClientPolicyBinding.allowed_domains`` field exists for a future
    per-binding allow-list but nothing populates it from control.db
    anywhere in the codebase today (fresh-install or migrated) -- out of
    scope for this fix, which is about making migrated block rules
    enforced, not building a new allow-list feature.
    """
    if not blocked_domains:
        return {"ruleset_created": False, "domains_migrated": 0}

    with control_db.connect(target_control_db) as conn:
        # Idempotent retry (§21/§22): same pattern as migrate_upstreams --
        # delete-then-recreate rather than erroring on a second attempt.
        conn.execute(
            "DELETE FROM service_blocking_ruleset_members WHERE ruleset_row_id IN "
            "(SELECT id FROM service_blocking_rulesets WHERE ruleset_id = 'migrated-v1-custom-blocklist')"
        )
        conn.execute(
            "DELETE FROM service_blocking_rulesets WHERE ruleset_id = 'migrated-v1-custom-blocklist'"
        )
        conn.execute(
            "DELETE FROM service_domains WHERE service_row_id IN "
            "(SELECT id FROM service_definitions WHERE service_id = 'migrated-v1-custom-blocklist')"
        )
        conn.execute(
            "DELETE FROM service_definitions WHERE service_id = 'migrated-v1-custom-blocklist'"
        )
        pstore.create_service(
            conn, "migrated-v1-custom-blocklist", "Migrated V1 Custom Block List",
            domains=[("exact", d) for d in blocked_domains], category="migrated",
        )
        pstore.create_service_ruleset(
            conn, "migrated-v1-custom-blocklist", ["migrated-v1-custom-blocklist"]
        )
        from dataclasses import replace as _dc_replace

        global_layer = pstore.load_policy_layer(conn, "global", "singleton")
        pstore.save_policy_layer(
            conn, "global", "singleton",
            _dc_replace(global_layer, service_blocking_ruleset_id="migrated-v1-custom-blocklist"),
        )
    return {"ruleset_created": True, "domains_migrated": len(blocked_domains)}


def migrate_local_dns_to_control_db(records: "list[LocalDnsRecord]", target_control_db: Path) -> dict:
    """Writes migrated local DNS records into control.db's shared
    ``local_dns_records`` table (``policy_store.upsert_local_dns_record``)
    so the real runtime compiler actually answers for them (see
    ``app/v2/dnsdist_policy_runtime.py``'s local-DNS compilation) --
    previously these only ever reached the standalone, not-live-wired
    zone-file generator (``app/v2/local_dns_gen.py``).
    """
    with control_db.connect(target_control_db) as conn:
        for record in records:
            pstore.upsert_local_dns_record(
                conn, record.fqdn, record.record_type, record.value, record.ttl,
            )
    return {"records_migrated": len(records)}


# --------------------------------------------------------------------------
# 13. Upstream configuration
# --------------------------------------------------------------------------


def migrate_upstreams(backup_db_path: Path, target_control_db: Path) -> dict:
    """Real doh_path column from V1's schema is carried through (Gate #2
    Blocker 1). If a DoH-transport source resolver has no tls_hostname
    (V1's schema allows an empty string there), the profile is NOT
    migrated with a silently-downgraded plain/unverified transport --
    it's skipped entirely with an explicit warning naming the resolver,
    so an operator must deliberately reconfigure it post-migration rather
    than unknowingly end up sending DNS queries in the clear (or to an
    unverified TLS peer) where they previously expected DoH.
    """
    src = sqlite3.connect(f"file:{backup_db_path}?mode=ro", uri=True)
    try:
        rows = src.execute(
            "SELECT name, protocol, address, port, tls_hostname, doh_path, position "
            "FROM upstream_resolvers WHERE enabled = 1 ORDER BY position ASC"
        ).fetchall()
    finally:
        src.close()

    if not rows:
        return {"migrated": 0, "warnings": ["no enabled upstream resolvers found in source"]}

    warnings: list[str] = []
    transport = rows[0][1]
    endpoints = []
    for name, protocol, address, port, tls_hostname, doh_path, position in rows:
        if protocol != transport:
            warnings.append(
                f"resolver {name!r} has protocol {protocol!r} differing from the profile's "
                f"transport {transport!r} -- mixed-transport profiles are not supported, skipped"
            )
            continue
        if transport == "doh" and not tls_hostname:
            warnings.append(
                f"resolver {name!r} is configured for DoH but has no TLS hostname in the "
                "source -- refusing to migrate it as an unverified/downgraded transport; "
                "reconfigure this upstream manually after migration"
            )
            continue
        endpoints.append(
            pstore.UpstreamEndpointRecord(
                address=f"{address}:{port}",
                tls_hostname=tls_hostname or None,
                priority=position,
                weight=1,
                secret_ref=None,
                doh_path=(doh_path or None) if transport == "doh" else None,
            )
        )

    if not endpoints:
        return {"migrated": 0, "warnings": warnings + ["no migratable upstream endpoints after validation"]}

    with control_db.connect(target_control_db) as conn:
        # Idempotent retry (§21/§22): create_upstream_profile() would
        # otherwise raise a duplicate-id conflict on a second attempt.
        conn.execute(
            "DELETE FROM upstream_profiles WHERE upstream_profile_id = 'migrated-default'"
        )
        pstore.create_upstream_profile(
            conn, "migrated-default", "Migrated Default Upstreams",
            transport=transport, endpoints=endpoints, strategy="ordered",
        )
        # Creating the profile row alone is not enough -- the real runtime
        # compiler (app/v2/runtime_compile.py's build_bindings()) only
        # ever uses an upstream profile a policy layer actually points at
        # (policy.upstream_profile_id); without this, every migrated
        # binding silently falls back to the hardcoded default resolvers
        # (1.1.1.1/9.9.9.9 plain) instead of the migrated upstream. Set on
        # the global layer specifically (not a network layer) so it's the
        # effective default for every binding unless a network overrides
        # it later -- merge onto whatever global layer already exists
        # rather than clobbering other fields an operator may have set.
        from dataclasses import replace as _dc_replace

        global_layer = pstore.load_policy_layer(conn, "global", "singleton")
        pstore.save_policy_layer(
            conn, "global", "singleton",
            _dc_replace(global_layer, upstream_profile_id="migrated-default"),
        )
    return {"migrated": len(endpoints), "warnings": warnings}


# --------------------------------------------------------------------------
# 15. Notification providers -> secret store
# --------------------------------------------------------------------------


def migrate_notifications(
    backup_db_path: Path, target_control_db: Path, secret_store: SecretStore
) -> dict:
    src = sqlite3.connect(f"file:{backup_db_path}?mode=ro", uri=True)
    try:
        try:
            rows = src.execute(
                "SELECT kind, name, enabled, config_json, secret FROM notification_providers"
            ).fetchall()
        except sqlite3.OperationalError:
            # Real defect found live during package-level migration
            # acceptance testing: this table is lazily created by V1's
            # own notify-check timer, not part of its base schema -- a
            # real, freshly installed V1 source genuinely may not have
            # it yet, same as OPTIONAL_TABLES_AND_COLUMNS's other
            # entries. Nothing to migrate, not an error.
            rows = []
    finally:
        src.close()

    migrated = 0
    kind_map = {"webhook": "webhook", "email": "email_smtp", "pushover": "pushover", "slack": "slack"}
    with control_db.connect(target_control_db) as conn:
        # Idempotent retry (§21/§22): provider ids are deterministic
        # (migrated-{kind}-{i}), so a retry would otherwise hit a
        # duplicate-id conflict and fail the whole stage rather than
        # complete. delete_provider() also removes the referenced secret,
        # so a retry never leaves an orphaned secret file behind either.
        for existing in nstore.list_providers(conn):
            if existing.provider_id.startswith("migrated-"):
                nstore.delete_provider(conn, secret_store, existing.provider_id)
        for i, (kind, name, enabled, config_json, secret) in enumerate(rows):
            v2_kind = kind_map.get(kind, "webhook")
            try:
                endpoint = json.loads(config_json).get("url", "")
            except (json.JSONDecodeError, AttributeError):
                endpoint = ""
            nstore.create_provider(
                conn, secret_store, f"migrated-{kind}-{i}", v2_kind, name, endpoint,
                secret_value=secret if secret else None,
            )
            migrated += 1
    return {"migrated": migrated}


# --------------------------------------------------------------------------
# 16/17. Legacy query history + aggregate strategy
# --------------------------------------------------------------------------


def register_legacy_analytics_archive(backup_db_path: Path, target_root: Path) -> dict:
    """V1 raw query history becomes a bounded read-only legacy archive by
    default -- this function registers WHERE it lives and basic bounds,
    it never copies raw rows into control.db or the V2 aggregate store.
    """
    src = sqlite3.connect(f"file:{backup_db_path}?mode=ro", uri=True)
    try:
        try:
            row_count, min_ts, max_ts = src.execute(
                "SELECT COUNT(*), MIN(ts), MAX(ts) FROM query_events"
            ).fetchone()
        except sqlite3.OperationalError:
            row_count, min_ts, max_ts = 0, None, None
    finally:
        src.close()

    manifest = {
        "legacy_archive_path": str(backup_db_path),
        "row_count": row_count,
        "time_range": [min_ts, max_ts],
        "read_only": True,
        "aggregate_rebuild_strategy": (
            "not run automatically as part of migration; a future explicit conversion "
            "job may rebuild V2 aggregate rollups from this archive's raw rows if the "
            "operator requests it -- no data is lost, no bulk conversion is on the "
            "critical migration path"
        ),
    }
    target_root.mkdir(parents=True, exist_ok=True)
    (target_root / "legacy-analytics-archive.manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True)
    )
    return manifest
