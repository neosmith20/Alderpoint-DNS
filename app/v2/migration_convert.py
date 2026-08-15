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

SUPPORTED_SOURCE_TABLES = ("admins", "clients")


class MigrationConvertError(RuntimeError):
    pass


# --------------------------------------------------------------------------
# 1. Source discovery
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class SourceInfo:
    db_path: Path
    detected_version: str
    table_count: int


def detect_source(source_root: Path) -> SourceInfo:
    """Real detection: the source db file must exist, open read-only
    without error, and contain the tables this migrator knows how to read.
    Never opens the source for writing.
    """
    db_path = Path(source_root) / "alderpointdns.db"
    if not db_path.exists():
        raise MigrationConvertError(f"source database not found at {db_path}")
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
        missing = [t for t in SUPPORTED_SOURCE_TABLES if t not in tables]
        if missing:
            raise MigrationConvertError(
                f"source database is missing required table(s) {missing} -- "
                "not a supported Alderpoint DNS v1 database"
            )
        return SourceInfo(db_path=db_path, detected_version="v1.x", table_count=len(tables))
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
                "custom_rules_block": conn.execute(
                    "SELECT COUNT(*) FROM custom_rules WHERE action='block'"
                ).fetchone()[0] if _count("custom_rules") else 0,
                "custom_rules_allow": conn.execute(
                    "SELECT COUNT(*) FROM custom_rules WHERE action='allow'"
                ).fetchone()[0] if _count("custom_rules") else 0,
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
            "warnings": warnings,
        }
        return report
    finally:
        conn.close()


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
    global-only ``custom_rules`` table, migrated in ``migrate_filtering``)
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
    src = sqlite3.connect(f"file:{backup_db_path}?mode=ro", uri=True)
    try:
        rows = src.execute(
            "SELECT domain, action FROM custom_rules WHERE enabled = 1"
        ).fetchall()
    finally:
        src.close()
    blocked = sorted({d for d, a in rows if a == "block"})
    allowed = sorted({d for d, a in rows if a == "allow"})
    return {"blocked_domains": blocked, "allowed_domains": allowed}


# --------------------------------------------------------------------------
# 13. Upstream configuration
# --------------------------------------------------------------------------


def migrate_upstreams(backup_db_path: Path, target_control_db: Path) -> dict:
    src = sqlite3.connect(f"file:{backup_db_path}?mode=ro", uri=True)
    try:
        rows = src.execute(
            "SELECT name, protocol, address, port, tls_hostname, position "
            "FROM upstream_resolvers WHERE enabled = 1 ORDER BY position ASC"
        ).fetchall()
    finally:
        src.close()

    if not rows:
        return {"migrated": 0, "warnings": ["no enabled upstream resolvers found in source"]}

    endpoints = []
    for i, (name, protocol, address, port, tls_hostname, position) in enumerate(rows):
        endpoints.append(
            pstore.UpstreamEndpointRecord(
                address=f"{address}:{port}",
                tls_hostname=tls_hostname or None,
                priority=position,
                weight=1,
                secret_ref=None,
            )
        )
    with control_db.connect(target_control_db) as conn:
        # Idempotent retry (§21/§22): create_upstream_profile() would
        # otherwise raise a duplicate-id conflict on a second attempt.
        conn.execute(
            "DELETE FROM upstream_profiles WHERE upstream_profile_id = 'migrated-default'"
        )
        pstore.create_upstream_profile(
            conn, "migrated-default", "Migrated Default Upstreams",
            transport=rows[0][1], endpoints=endpoints, strategy="ordered",
        )
    return {"migrated": len(rows), "warnings": []}


# --------------------------------------------------------------------------
# 15. Notification providers -> secret store
# --------------------------------------------------------------------------


def migrate_notifications(
    backup_db_path: Path, target_control_db: Path, secret_store: SecretStore
) -> dict:
    src = sqlite3.connect(f"file:{backup_db_path}?mode=ro", uri=True)
    try:
        rows = src.execute(
            "SELECT kind, name, enabled, config_json, secret FROM notification_providers"
        ).fetchall()
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
