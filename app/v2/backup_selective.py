"""Versioned selective appliance backup preview/restore helpers.

This module is intentionally category-oriented. A backup can be valid as an
archive while still not being acceptable to restore wholesale; operators need
to see portable content, pick categories, and have the backend enforce that
choice against a staged copy before live promotion.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import sqlite3
import tarfile
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from app.v2 import backup_restore
from app.v2 import control_db
from app.v2 import migration_convert as mconv
from app.v2 import notification_store as nstore
from app.v2 import policy_store as pstore
from app.v2.parquet_writer import ParquetSegmentWriter
from app.v2.secret_store import SecretStore

INVENTORY_SCHEMA_VERSION = 1
SUPPORTED_CONFLICT_POLICIES = {"merge", "replace"}

CATEGORY_ORDER = (
    "system_configuration",
    "administrator_accounts",
    "clients_identifiers",
    "upstreams",
    "blocklist_subscriptions",
    "custom_block_rules",
    "custom_allow_rules",
    "filtering_schedules",
    "local_dns",
    "notifications",
    "analytics_history",
    "runtime_files",
    "tls_private_keys",
)

CATEGORY_LABELS = {
    "system_configuration": "System configuration",
    "administrator_accounts": "Administrator accounts",
    "clients_identifiers": "Clients and identifiers",
    "upstreams": "Upstreams",
    "blocklist_subscriptions": "Blocklist subscriptions",
    "custom_block_rules": "Custom block rules",
    "custom_allow_rules": "Custom allow rules",
    "filtering_schedules": "Filtering schedules",
    "local_dns": "Local DNS zones and records",
    "notifications": "Notifications",
    "analytics_history": "Analytics/query history",
    "runtime_files": "Generated/runtime host files",
    "tls_private_keys": "TLS keys and certificates",
}

SENSITIVE_CATEGORIES = {"administrator_accounts", "tls_private_keys"}
DEFAULT_RECOMMENDED = {
    "clients_identifiers",
    "upstreams",
    "blocklist_subscriptions",
    "custom_block_rules",
    "local_dns",
    "notifications",
}


class SelectiveRestoreError(RuntimeError):
    pass


@dataclass(frozen=True)
class SelectedStage:
    staged: backup_restore.StagedRestore
    inventory: dict[str, Any]
    analytics_stage_dir: Path | None = None


def file_digest(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _row_count(conn: sqlite3.Connection, table: str, where: str = "", params: tuple = ()) -> int:
    try:
        suffix = f" WHERE {where}" if where else ""
        return int(conn.execute(f"SELECT COUNT(*) FROM {table}{suffix}", params).fetchone()[0])
    except sqlite3.OperationalError:
        return 0


def _sample(conn: sqlite3.Connection, sql: str, params: tuple = (), limit: int = 5) -> list[str]:
    try:
        return [str(r[0]) for r in conn.execute(sql, params).fetchmany(limit)]
    except sqlite3.OperationalError:
        return []


def _category(
    category_id: str,
    *,
    found: int = 0,
    restorable: int | None = None,
    skipped: int = 0,
    supported: bool = True,
    selected_by_default: bool | None = None,
    warning: str = "",
    unsupported_reason: str = "",
    transform: str = "",
    samples: list[str] | None = None,
    conflicts: int = 0,
) -> dict[str, Any]:
    if restorable is None:
        restorable = found if supported else 0
    if selected_by_default is None:
        selected_by_default = supported and category_id in DEFAULT_RECOMMENDED and restorable > 0
    if category_id in SENSITIVE_CATEGORIES:
        selected_by_default = False
    return {
        "id": category_id,
        "label": CATEGORY_LABELS[category_id],
        "found_count": found,
        "restorable_count": restorable,
        "skipped_count": skipped,
        "conflict_count": conflicts,
        "supported": supported and restorable > 0,
        "selected_by_default": selected_by_default,
        "sensitive": category_id in SENSITIVE_CATEGORIES,
        "warning": warning,
        "unsupported_reason": unsupported_reason,
        "transform": transform,
        "samples": samples or [],
    }


def _v1_db_from_archive(backup_path: Path, staging_dir: Path) -> tuple[Path, dict]:
    manifest = backup_restore.validate_legacy_v1_backup(backup_path)
    extract_dir = staging_dir / "v1-source"
    extract_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    db_path = extract_dir / "alderpointdns.db"
    with tarfile.open(backup_path, mode="r:gz") as tar:
        member = tar.getmember(backup_restore.LEGACY_V1_DB_ARCHIVE_RELPATH)
        fh = tar.extractfile(member)
        if fh is None:
            raise SelectiveRestoreError("V1 backup database entry is unreadable")
        with open(db_path, "wb") as out:
            shutil.copyfileobj(fh, out, length=1024 * 1024)
    os.chmod(db_path, 0o600)
    return db_path, {
        "format": manifest.backup_format,
        "source_version": manifest.source_version,
        "created_at": manifest.created_at,
        "source_node_id": manifest.source_node_id,
        "key_mode": manifest.key_mode,
    }


def _build_v1_inventory(db_path: Path, live_control_db: Path) -> list[dict[str, Any]]:
    src = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    try:
        with control_db.connect(live_control_db, create_if_missing=False) as live:
            pstore.ensure_blocklist_subscription_schema(live)
            nstore.ensure_schema(live_control_db)
            block_rules = _row_count(src, "custom_filter_rules", "enabled=1 AND validation_state='valid' AND action='block'")
            allow_rules = _row_count(src, "custom_filter_rules", "enabled=1 AND validation_state='valid' AND action='allow'")
            q_count = _row_count(src, "query_events")
            try:
                q_min, q_max = src.execute("SELECT MIN(ts), MAX(ts) FROM query_events").fetchone()
            except sqlite3.OperationalError:
                q_min, q_max = None, None
            return [
            _category(
                "system_configuration",
                found=_row_count(src, "analytics_settings") + _row_count(src, "dns_cache_settings"),
                restorable=_row_count(src, "analytics_settings"),
                warning="Portable analytics retention settings can be translated; raw host/runtime files are regenerated by V2.",
                transform="V1 settings are translated into V2 config defaults where a portable V2 equivalent exists.",
            ),
            _category(
                "administrator_accounts",
                found=_row_count(src, "admins"),
                samples=_sample(src, "SELECT username FROM admins ORDER BY username"),
                warning="Selecting this may add administrator password hashes from the backup. It is never selected automatically.",
                conflicts=_row_count(live, "admins"),
            ),
            _category(
                "clients_identifiers",
                found=_row_count(src, "clients"),
                restorable=_row_count(src, "clients"),
                samples=_sample(src, "SELECT name FROM clients ORDER BY name"),
                conflicts=_row_count(live, "clients"),
                transform="Clients and valid IP/CIDR/ClientID identifiers are converted into V2 client records.",
            ),
            _category(
                "upstreams",
                found=_row_count(src, "upstream_resolvers"),
                restorable=_row_count(src, "upstream_resolvers", "enabled=1"),
                samples=_sample(src, "SELECT name || ' (' || protocol || ')' FROM upstream_resolvers ORDER BY position"),
                conflicts=_row_count(live, "upstream_profiles"),
                transform="Enabled V1 resolvers are converted into a V2 upstream profile and selected on the global policy.",
            ),
            _category(
                "blocklist_subscriptions",
                found=_row_count(src, "sources"),
                samples=_sample(src, "SELECT name FROM sources ORDER BY name"),
                conflicts=len(pstore.list_blocklist_subscriptions(live)),
                transform="V1 source definitions are translated to V2 blocklist subscriptions. Downloaded cache files are not copied; subscriptions refresh again after restore.",
            ),
            _category(
                "custom_block_rules",
                found=block_rules,
                samples=_sample(src, "SELECT domain FROM custom_filter_rules WHERE enabled=1 AND validation_state='valid' AND action='block' ORDER BY domain"),
                transform="Valid enabled V1 block rules are converted into a V2 service-blocking ruleset.",
            ),
            _category(
                "custom_allow_rules",
                found=allow_rules,
                supported=False,
                unsupported_reason="V2 does not yet have a category-level allow-rule destination equivalent to V1's default blocklist override semantics.",
                samples=_sample(src, "SELECT domain FROM custom_filter_rules WHERE enabled=1 AND validation_state='valid' AND action='allow' ORDER BY domain"),
            ),
            _category(
                "filtering_schedules",
                found=_row_count(src, "filter_schedule_settings"),
                supported=False,
                unsupported_reason="V1 filter-update timer settings do not map to the current V2 blocklist refresh scheduler yet.",
            ),
            _category(
                "local_dns",
                found=_row_count(src, "local_dns_records"),
                samples=_sample(src, "SELECT fqdn || ' ' || record_type || ' ' || value FROM local_dns_records WHERE enabled=1 ORDER BY fqdn"),
                conflicts=_row_count(live, "local_dns_records"),
                transform="Enabled V1 Local DNS records are validated and inserted through the V2 Local DNS store. Raw BIND zone files are not copied.",
            ),
            _category(
                "notifications",
                found=_row_count(src, "notification_providers"),
                samples=_sample(src, "SELECT name FROM notification_providers ORDER BY name"),
                conflicts=len(nstore.list_providers(live)),
                transform="Provider metadata is migrated into V2 and secrets are imported into the staged V2 secret store.",
            ),
            _category(
                "analytics_history",
                found=q_count,
                samples=[f"time range {q_min} to {q_max}"] if q_count and q_min is not None else [],
                selected_by_default=False,
                warning="Historical rows are converted into V2 raw analytics segments. Large histories may take time.",
                transform="V1 query_events rows are normalized into V2 Parquet query history.",
            ),
            _category(
                "runtime_files",
                found=0,
                supported=False,
                unsupported_reason="Generated BIND, dnsdist, systemd, sudoers, and downloaded cache files are host/runtime artifacts. V2 regenerates runtime from selected portable state.",
            ),
            _category(
                "tls_private_keys",
                found=0,
                supported=False,
                unsupported_reason="V1 private key files are not imported by selective restore; V2 management/DNSCrypt identity remains unchanged.",
            ),
            ]
    finally:
        src.close()


def build_inventory(
    backup_path: Path,
    *,
    key: bytes,
    live_control_db: Path,
    passphrase: str | None = None,
) -> dict[str, Any]:
    digest = file_digest(backup_path)
    size = backup_path.stat().st_size
    if backup_path.name.endswith(".tar.gz"):
        with tempfile.TemporaryDirectory(prefix="apdns-v1-preview-") as td:
            db_path, meta = _v1_db_from_archive(backup_path, Path(td))
            categories = _build_v1_inventory(db_path, live_control_db)
    else:
        manifest = backup_restore.validate_appliance_backup(backup_path, key, passphrase=passphrase)
        meta = {
            "format": manifest.backup_format,
            "source_version": manifest.source_version,
            "created_at": manifest.created_at,
            "source_node_id": manifest.source_node_id,
            "key_mode": manifest.key_mode,
        }
        with tempfile.TemporaryDirectory(prefix="apdns-v2-preview-") as td:
            staged = backup_restore.stage_appliance_restore(backup_path, key, Path(td) / "stage", passphrase=passphrase)
            db_path = staged.staging_dir / backup_restore.CONTROL_DB_NAME
            categories = _build_v2_inventory(db_path, live_control_db)
    supported = [c["id"] for c in categories if c["supported"]]
    recommended = [c["id"] for c in categories if c["selected_by_default"]]
    return {
        "schema_version": INVENTORY_SCHEMA_VERSION,
        "backup_name": backup_path.name,
        "archive_digest": digest,
        "metadata": {
            "original_filename": backup_path.name,
            "detected_format": meta["format"],
            "source_alderpoint_version": meta["source_version"],
            "created_at": meta["created_at"],
            "source_node_id": meta.get("source_node_id"),
            "archive_size_bytes": size,
            "key_mode": meta["key_mode"],
            "encrypted": meta["key_mode"] in ("local", "passphrase"),
            "validation": "valid",
        },
        "supported_category_ids": supported,
        "recommended_category_ids": recommended,
        "categories": categories,
        "conflict_policies": sorted(SUPPORTED_CONFLICT_POLICIES),
        "default_conflict_policy": "merge",
    }


def _build_v2_inventory(db_path: Path, live_control_db: Path) -> list[dict[str, Any]]:
    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    try:
        with control_db.connect(live_control_db, create_if_missing=False) as live:
            pstore.ensure_blocklist_subscription_schema(live)
            nstore.ensure_schema(live_control_db)
            return [
            _category("system_configuration", found=1, restorable=1, warning="Only portable V2 control-state settings are restored; runtime files are regenerated."),
            _category("administrator_accounts", found=_row_count(conn, "admins"), samples=_sample(conn, "SELECT username FROM admins ORDER BY username"), conflicts=_row_count(live, "admins")),
            _category("clients_identifiers", found=_row_count(conn, "clients"), samples=_sample(conn, "SELECT name FROM clients ORDER BY name"), conflicts=_row_count(live, "clients")),
            _category("upstreams", found=_row_count(conn, "upstream_profiles"), samples=_sample(conn, "SELECT name FROM upstream_profiles ORDER BY name"), conflicts=_row_count(live, "upstream_profiles")),
            _category("blocklist_subscriptions", found=_row_count(conn, "blocklist_subscriptions"), samples=_sample(conn, "SELECT name FROM blocklist_subscriptions ORDER BY name"), conflicts=_row_count(live, "blocklist_subscriptions")),
            _category("custom_block_rules", found=_row_count(conn, "service_definitions"), transform="Selected V2 service definitions/rulesets are restored from the native backup."),
            _category("custom_allow_rules", found=0, supported=False, unsupported_reason="No native V2 allow-rule table is currently present in the backup schema."),
            _category("filtering_schedules", found=_row_count(conn, "schedules"), supported=_row_count(conn, "schedules") > 0),
            _category("local_dns", found=_row_count(conn, "local_dns_records"), samples=_sample(conn, "SELECT name || ' ' || record_type || ' ' || value FROM local_dns_records ORDER BY name"), conflicts=_row_count(live, "local_dns_records")),
            _category("notifications", found=_row_count(conn, "notification_providers"), samples=_sample(conn, "SELECT name FROM notification_providers ORDER BY name"), conflicts=_row_count(live, "notification_providers")),
            _category("analytics_history", found=0, supported=False, unsupported_reason="Native V2 appliance backups intentionally exclude raw query history."),
            _category("runtime_files", found=0, supported=False, unsupported_reason="Runtime files are regenerated from restored V2 control state."),
            _category("tls_private_keys", found=0, supported=False, unsupported_reason="TLS/private-key restore remains all-or-nothing in the native backup and is not selectable yet."),
            ]
    finally:
        conn.close()


def _copy_live_db(live_control_db: Path, dest: Path) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    src = sqlite3.connect(f"file:{live_control_db}?mode=ro", uri=True)
    try:
        out = sqlite3.connect(str(dest))
        try:
            src.backup(out)
        finally:
            out.close()
    finally:
        src.close()


def _clear_tables(conn: sqlite3.Connection, tables: list[str]) -> None:
    for table in tables:
        try:
            conn.execute(f"DELETE FROM {table}")
        except sqlite3.OperationalError:
            pass


def _copy_table_from_backup(conn: sqlite3.Connection, table: str) -> None:
    cols = [r[1] for r in conn.execute(f"PRAGMA backup.table_info({table})").fetchall()]
    if not cols:
        return
    quoted = ", ".join(cols)
    conn.execute(f"DELETE FROM main.{table}")
    conn.execute(f"INSERT INTO main.{table} ({quoted}) SELECT {quoted} FROM backup.{table}")


def _restore_v1_blocklist_subscriptions(source_db: Path, target_db: Path, policy: str) -> int:
    src = sqlite3.connect(f"file:{source_db}?mode=ro", uri=True)
    try:
        try:
            rows = src.execute("SELECT name, url, enabled, category FROM sources ORDER BY id").fetchall()
        except sqlite3.OperationalError:
            rows = []
    finally:
        src.close()
    with control_db.connect(target_db) as conn:
        pstore.ensure_blocklist_subscription_schema(conn)
        if policy == "replace":
            for sub in pstore.list_blocklist_subscriptions(conn):
                pstore.delete_blocklist_subscription(conn, sub["subscription_id"])
        for name, url, enabled, category in rows:
            sub_id = _slug(str(name) or str(url))
            base = sub_id
            suffix = 2
            while pstore.get_blocklist_subscription(conn, sub_id):
                if policy == "merge":
                    existing = pstore.get_blocklist_subscription(conn, sub_id)
                    if existing and existing["url"] == url:
                        pstore.set_blocklist_subscription_enabled(conn, sub_id, bool(enabled))
                        break
                sub_id = f"{base}-{suffix}"
                suffix += 1
            else:
                pstore.create_blocklist_subscription(conn, sub_id, str(name), str(url), str(category or ""))
                pstore.set_blocklist_subscription_enabled(conn, sub_id, bool(enabled))
    return len(rows)


def _slug(text: str) -> str:
    import re

    out = re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")
    return out[:64] or "restored"


def _import_v1_analytics(source_db: Path, dest_root: Path) -> dict[str, Any]:
    src = sqlite3.connect(f"file:{source_db}?mode=ro", uri=True)
    src.row_factory = sqlite3.Row
    try:
        try:
            columns = {r[1] for r in src.execute("PRAGMA table_info(query_events)").fetchall()}
            rows = src.execute("SELECT * FROM query_events ORDER BY ts").fetchall()
        except sqlite3.OperationalError:
            columns = set()
            rows = []
    finally:
        src.close()
    writer = ParquetSegmentWriter(dest_root, max_rows_per_segment=50_000)
    records = []
    for i, row in enumerate(rows, 1):
        records.append({
            "id": i,
            "ts": float(row["ts"] if "ts" in columns else 0.0),
            "client": (row["client"] if "client" in columns else "") or "",
            "client_name": "",
            "domain": (row["domain"] if "domain" in columns else "") or "",
            "qtype": (row["qtype"] if "qtype" in columns else "A") or "A",
            "protocol": (row["protocol"] if "protocol" in columns else "udp") or "udp",
            "rcode": (row["rcode"] if "rcode" in columns else "NOERROR") or "NOERROR",
            "latency_ms": float((row["latency_ms"] if "latency_ms" in columns else 0.0) or 0.0),
            "blocked": bool((row["blocked"] if "blocked" in columns else 0) or 0),
            "block_reason": ((row["block_source"] if "block_source" in columns else "") or (row["block_category"] if "block_category" in columns else "")) or "",
            "upstream": "",
            "cache_status": "miss",
            "cache_profile_id": "",
        })
    writer.ingest(records)
    writer.flush()
    if writer.stats.flush_failures or writer.stats.dependency_unavailable:
        raise SelectiveRestoreError(f"analytics import failed: {writer.stats.last_error}")
    return {"rows_imported": len(rows), "segments_written": writer.stats.segments_written}


def stage_selected_restore(
    backup_path: Path,
    *,
    key: bytes,
    live_control_db: Path,
    live_secrets_dir: Path,
    staging_dir: Path,
    selected_categories: list[str],
    archive_digest: str,
    conflict_policy: str = "merge",
    passphrase: str | None = None,
) -> SelectedStage:
    if conflict_policy not in SUPPORTED_CONFLICT_POLICIES:
        raise SelectiveRestoreError(f"unsupported conflict policy: {conflict_policy}")
    if file_digest(backup_path) != archive_digest:
        raise SelectiveRestoreError("backup archive changed after preview; preview it again before restoring")
    inventory = build_inventory(backup_path, key=key, live_control_db=live_control_db, passphrase=passphrase)
    supported = set(inventory["supported_category_ids"])
    selected = set(selected_categories)
    unsupported = sorted(selected - supported)
    if unsupported:
        raise SelectiveRestoreError(f"selected unsupported category/categories: {', '.join(unsupported)}")
    if not selected:
        raise SelectiveRestoreError("select at least one supported category to restore")

    if staging_dir.exists():
        shutil.rmtree(staging_dir)
    staging_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    work_db = staging_dir / backup_restore.CONTROL_DB_NAME
    _copy_live_db(live_control_db, work_db)
    staged_secrets_dir = staging_dir / "secrets-stage"
    shutil.copytree(live_secrets_dir, staged_secrets_dir, dirs_exist_ok=True)
    analytics_stage = None

    if backup_path.name.endswith(".tar.gz"):
        source_db, _ = _v1_db_from_archive(backup_path, staging_dir / "source")
        if "system_configuration" in selected:
            cfg = mconv.convert_config(source_db)
            # Stored in report only for now; V2 live config file remains under explicit configuration UI control.
            (staging_dir / "converted-config.json").write_text(json.dumps(cfg.__dict__, default=str, indent=2))
        if "administrator_accounts" in selected:
            mconv.migrate_admins(source_db, work_db)
        if "clients_identifiers" in selected:
            mconv.migrate_clients(source_db, work_db)
        if "upstreams" in selected:
            mconv.migrate_upstreams(source_db, work_db)
        if "blocklist_subscriptions" in selected:
            _restore_v1_blocklist_subscriptions(source_db, work_db, conflict_policy)
        filtering = mconv.migrate_filtering(source_db)
        if "custom_block_rules" in selected:
            mconv.migrate_filtering_to_control_db(filtering["blocked_domains"], work_db)
        if "local_dns" in selected:
            records, _warnings = mconv.migrate_local_dns(source_db)
            mconv.migrate_local_dns_to_control_db(records, work_db)
        if "notifications" in selected:
            mconv.migrate_notifications(source_db, work_db, SecretStore(staged_secrets_dir))
        if "analytics_history" in selected:
            analytics_stage = staging_dir / "analytics-parquet"
            _import_v1_analytics(source_db, analytics_stage)
    else:
        full_stage = backup_restore.stage_appliance_restore(backup_path, key, staging_dir / "full", passphrase=passphrase)
        backup_db = full_stage.staging_dir / backup_restore.CONTROL_DB_NAME
        conn = sqlite3.connect(str(work_db))
        try:
            conn.execute(f"ATTACH DATABASE ? AS backup", (str(backup_db),))
            category_tables = {
                "administrator_accounts": ["admins"],
                "clients_identifiers": ["clients", "client_identifiers"],
                "upstreams": ["upstream_profiles", "upstream_endpoints", "domain_routes"],
                "blocklist_subscriptions": ["blocklist_subscriptions"],
                "custom_block_rules": ["service_definitions", "service_domains", "service_blocking_rulesets", "service_blocking_ruleset_members"],
                "filtering_schedules": ["schedules"],
                "local_dns": ["local_dns_records"],
                "notifications": ["notification_providers"],
            }
            for cat, tables in category_tables.items():
                if cat in selected:
                    for table in tables:
                        _copy_table_from_backup(conn, table)
            conn.commit()
        finally:
            conn.close()
        if "notifications" in selected and (full_stage.staging_dir / backup_restore.SECRETS_NAME).exists():
            payload = json.loads((full_stage.staging_dir / backup_restore.SECRETS_NAME).read_text())
            SecretStore(staged_secrets_dir).import_all(payload, overwrite=True)

    secrets_payload = json.dumps(SecretStore(staged_secrets_dir).export_all()).encode("utf-8")
    secrets_path = staging_dir / backup_restore.SECRETS_NAME
    secrets_path.write_bytes(secrets_payload)
    manifest = backup_restore.ApplianceManifest(
        format_version=backup_restore.BACKUP_FORMAT_VERSION,
        created_at=inventory["metadata"]["created_at"] or "",
        source_version=inventory["metadata"]["source_alderpoint_version"] or "unknown",
        control_db_schema_version=backup_restore._control_db_schema_version(work_db),
        contents=["control_db", "secrets"],
        secret_count=len(json.loads(secrets_payload.decode("utf-8"))),
        cert_files=[],
        raw_query_history_included=False,
        product=backup_restore.PRODUCT_ID,
        key_mode="selected",
        backup_format=inventory["metadata"]["detected_format"],
        migration_preview=inventory,
    )
    return SelectedStage(
        staged=backup_restore.StagedRestore(staging_dir=staging_dir, manifest=manifest),
        inventory=inventory,
        analytics_stage_dir=analytics_stage,
    )


def promote_selected_analytics(stage_dir: Path | None, live_root: Path) -> dict[str, Any]:
    if stage_dir is None or not stage_dir.exists():
        return {"analytics_promoted": False, "segments": 0}
    count = len(list(stage_dir.rglob("*.parquet")))
    for src in stage_dir.rglob("*.parquet"):
        rel = src.relative_to(stage_dir)
        dest = live_root / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        final = dest
        if final.exists():
            final = dest.with_name(f"{dest.stem}-restore-{file_digest(src)[:8]}{dest.suffix}")
        shutil.copy2(src, final)
    return {"analytics_promoted": True, "segments": count}
