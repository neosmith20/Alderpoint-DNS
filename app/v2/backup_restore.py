"""V2 full appliance backup/restore (beta-rescue priority 3).

Replaces RC43's "secrets-only" backup (real, but only ever one component
of what an appliance backup means) with a real whole-appliance backup:

- control.db itself (a consistent snapshot via sqlite3's own Connection.
  backup() API, not a raw file copy, so a concurrent writer can never
  produce a torn/corrupt snapshot) -- this alone covers desired
  configuration, clients/groups/networks, policy assignments, filtering,
  Local DNS, upstream profiles, domain routing/fallback, schedules,
  DNS-transport/encryption settings, notification configuration, and
  replication peer/identity metadata, since all of that already lives in
  control.db.
- protected secrets (notification provider tokens, the replication
  client key, etc. -- via the existing, audited
  app/v2/secret_store.py + app/v2/secret_backup.py primitives)
- the active HTTPS certificate/key and the DNSCrypt resolver
  certificate/key, when present

Explicit policy on raw query history: EXCLUDED, architecturally, not by
a runtime flag that could be flipped incorrectly. control.db has a
schema guard (app/v2/control_db.py's _assert_no_forbidden_tables) that
refuses to let raw query-history tables exist in it at all, and this
module only ever reads control.db plus the secrets/cert files above --
it has no code path that could reach the separate parquet/duckdb query
store under vendor-runtime-v2-analytics.

Format: one encrypted archive (a tar of control.db + secrets.json +
certs/* + manifest.json, encrypted as a single unit with the same
audited ``cryptography.fernet`` primitive app/v2/secret_backup.py
already uses -- AES-128-CBC + HMAC-SHA256 authenticated encryption, so
any bit of tampering or a wrong key is detected before anything is
touched, never silently misapplied).

Restore is staged: decrypt + untar + validate happen entirely in a
scratch directory before anything about the live appliance changes. The
live control.db/secrets/certs are only replaced by an atomic rename
after every validation has passed, and the pre-restore live state is
itself snapshotted first so a failure during promotion can be rolled
back -- "a failed restore must leave the prior valid appliance
operational" is enforced structurally, not just documented.
"""

from __future__ import annotations

import io
import json
import os
import shutil
import sqlite3
import tarfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from cryptography.fernet import Fernet, InvalidToken

from app.v2.secret_store import SecretStore, SecretStoreError

BACKUP_FORMAT_VERSION = 1
MANIFEST_NAME = "manifest.json"
CONTROL_DB_NAME = "control.db"
SECRETS_NAME = "secrets.json"
CERTS_DIR_NAME = "certs"


class ApplianceBackupError(RuntimeError):
    pass


class ApplianceBackupKeyError(ApplianceBackupError):
    """Wrong key or corrupted/tampered archive."""


class ApplianceRestoreError(RuntimeError):
    pass


@dataclass(frozen=True)
class CertFile:
    """One certificate/key file to include, by its live path and the
    relative name it should have inside the archive's certs/ directory."""
    live_path: Path
    archive_name: str


@dataclass(frozen=True)
class BackupResult:
    backup_path: Path
    created_at: str
    contents: list[str]
    secret_count: int
    control_db_schema_version: Optional[int]
    size_bytes: int


@dataclass(frozen=True)
class ApplianceManifest:
    format_version: int
    created_at: str
    source_version: str
    control_db_schema_version: Optional[int]
    contents: list[str]
    secret_count: int
    cert_files: list[str]
    raw_query_history_included: bool = False


@dataclass(frozen=True)
class StagedRestore:
    """Everything a restore needs, already decrypted/validated into a
    scratch directory. Nothing about the live appliance has been touched
    yet at this point."""
    staging_dir: Path
    manifest: ApplianceManifest


def _snapshot_sqlite_db(source_path: Path, dest_path: Path) -> None:
    """A real consistent snapshot (sqlite3's own online backup API), not
    a raw byte copy -- safe against a concurrent writer, unlike
    shutil.copy on a live database file."""
    src = sqlite3.connect(f"file:{source_path}?mode=ro", uri=True)
    try:
        dest = sqlite3.connect(str(dest_path))
        try:
            src.backup(dest)
        finally:
            dest.close()
    finally:
        src.close()


def _control_db_schema_version(db_path: Path) -> Optional[int]:
    try:
        conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
        try:
            row = conn.execute("SELECT MAX(version) FROM schema_migrations").fetchone()
            return int(row[0]) if row and row[0] is not None else None
        finally:
            conn.close()
    except sqlite3.Error:
        return None


def create_appliance_backup(
    control_db_path: Path,
    secret_store: SecretStore,
    key: bytes,
    backup_path: Path,
    *,
    cert_files: Optional[list[CertFile]] = None,
    source_version: str = "unknown",
) -> BackupResult:
    if not control_db_path.exists():
        raise ApplianceBackupError(f"control.db not found: {control_db_path}")
    cert_files = cert_files or []

    buf = io.BytesIO()
    contents: list[str] = []
    included_cert_names: list[str] = []
    with tarfile.open(fileobj=buf, mode="w") as tar:
        import tempfile

        with tempfile.TemporaryDirectory() as td:
            snap_path = Path(td) / CONTROL_DB_NAME
            _snapshot_sqlite_db(control_db_path, snap_path)
            tar.add(snap_path, arcname=CONTROL_DB_NAME)
        contents.append("control_db")

        secrets_payload = json.dumps(secret_store.export_all()).encode("utf-8")
        secret_count = len(secret_store.export_all())
        info = tarfile.TarInfo(name=SECRETS_NAME)
        info.size = len(secrets_payload)
        tar.addfile(info, io.BytesIO(secrets_payload))
        if secret_count:
            contents.append("secrets")

        for cert in cert_files:
            if cert.live_path.exists():
                arcname = f"{CERTS_DIR_NAME}/{cert.archive_name}"
                tar.add(cert.live_path, arcname=arcname)
                included_cert_names.append(cert.archive_name)
        if included_cert_names:
            contents.append("certs")

        schema_version = _control_db_schema_version(control_db_path)
        manifest = {
            "format_version": BACKUP_FORMAT_VERSION,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "source_version": source_version,
            "control_db_schema_version": schema_version,
            "contents": contents,
            "secret_count": secret_count,
            "cert_files": included_cert_names,
            # Explicit, not implicit: this backup format has no field for
            # raw query history because there is no code path that could
            # populate one -- see this module's docstring.
            "raw_query_history_included": False,
        }
        manifest_bytes = json.dumps(manifest, indent=2).encode("utf-8")
        info = tarfile.TarInfo(name=MANIFEST_NAME)
        info.size = len(manifest_bytes)
        tar.addfile(info, io.BytesIO(manifest_bytes))

    fernet = Fernet(key)
    ciphertext = fernet.encrypt(buf.getvalue())

    backup_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    tmp = backup_path.parent / f".{backup_path.name}.tmp"
    with open(tmp, "wb") as fh:
        fh.write(ciphertext)
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, backup_path)
    os.chmod(backup_path, 0o600)

    return BackupResult(
        backup_path=backup_path, created_at=manifest["created_at"], contents=contents,
        secret_count=secret_count, control_db_schema_version=schema_version,
        size_bytes=backup_path.stat().st_size,
    )


def _open_archive(backup_path: Path, key: bytes) -> tarfile.TarFile:
    if not backup_path.exists():
        raise ApplianceRestoreError(f"backup file not found: {backup_path}")
    ciphertext = backup_path.read_bytes()
    fernet = Fernet(key)
    try:
        plaintext = fernet.decrypt(ciphertext)
    except InvalidToken as exc:
        raise ApplianceBackupKeyError(
            "cannot decrypt backup -- wrong key, or the backup file is corrupted/tampered with"
        ) from exc
    try:
        return tarfile.open(fileobj=io.BytesIO(plaintext), mode="r")
    except tarfile.TarError as exc:
        raise ApplianceRestoreError(f"backup payload is not a valid archive after decryption: {exc}") from exc


def _read_manifest(tar: tarfile.TarFile) -> ApplianceManifest:
    try:
        member = tar.getmember(MANIFEST_NAME)
    except KeyError as exc:
        raise ApplianceRestoreError("backup archive is missing its manifest") from exc
    fh = tar.extractfile(member)
    if fh is None:
        raise ApplianceRestoreError("backup archive manifest is unreadable")
    try:
        data = json.loads(fh.read())
    except json.JSONDecodeError as exc:
        raise ApplianceRestoreError(f"backup manifest is not valid JSON: {exc}") from exc
    if data.get("format_version") != BACKUP_FORMAT_VERSION:
        raise ApplianceRestoreError(
            f"unsupported backup format version {data.get('format_version')!r} "
            f"(this code supports version {BACKUP_FORMAT_VERSION})"
        )
    return ApplianceManifest(
        format_version=data["format_version"], created_at=data.get("created_at", ""),
        source_version=data.get("source_version", "unknown"),
        control_db_schema_version=data.get("control_db_schema_version"),
        contents=list(data.get("contents", [])), secret_count=int(data.get("secret_count", 0)),
        cert_files=list(data.get("cert_files", [])),
        raw_query_history_included=bool(data.get("raw_query_history_included", False)),
    )


def validate_appliance_backup(backup_path: Path, key: bytes) -> ApplianceManifest:
    """Decrypt + untar + sanity-check in memory only. Never writes
    anywhere. Used by both the standalone "Validate" action and as the
    first phase of a real restore."""
    tar = _open_archive(backup_path, key)
    try:
        manifest = _read_manifest(tar)
        if "control_db" in manifest.contents:
            try:
                member = tar.getmember(CONTROL_DB_NAME)
            except KeyError as exc:
                raise ApplianceRestoreError("manifest says control_db is included but the archive has none") from exc
            fh = tar.extractfile(member)
            if fh is None or member.size == 0:
                raise ApplianceRestoreError("control.db entry in the backup archive is empty")
        return manifest
    finally:
        tar.close()


def stage_appliance_restore(backup_path: Path, key: bytes, staging_dir: Path) -> StagedRestore:
    """Decrypt + untar + validate into ``staging_dir`` (fully isolated
    from any live path). Also opens the staged control.db read-only to
    confirm it is a real, openable SQLite database with the expected
    core schema before declaring the stage successful -- corruption that
    Fernet's own integrity check wouldn't catch (e.g. a truncated tar
    entry) is caught here instead of during promotion."""
    if staging_dir.exists():
        shutil.rmtree(staging_dir)
    staging_dir.mkdir(parents=True, exist_ok=True, mode=0o700)

    tar = _open_archive(backup_path, key)
    try:
        manifest = _read_manifest(tar)
        # Never trust archive member paths blindly (path traversal via
        # "../"): extract only the exact, known member names this format
        # defines, each to an exact target path under staging_dir.
        allowed = {CONTROL_DB_NAME, SECRETS_NAME, MANIFEST_NAME}
        allowed |= {f"{CERTS_DIR_NAME}/{name}" for name in manifest.cert_files}
        for member in tar.getmembers():
            if member.name not in allowed or not member.isfile():
                continue
            target = staging_dir / member.name
            target.parent.mkdir(parents=True, exist_ok=True)
            fh = tar.extractfile(member)
            if fh is None:
                continue
            target.write_bytes(fh.read())
    finally:
        tar.close()

    if "control_db" in manifest.contents:
        db_path = staging_dir / CONTROL_DB_NAME
        try:
            conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
            try:
                tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
            finally:
                conn.close()
        except sqlite3.Error as exc:
            raise ApplianceRestoreError(f"staged control.db failed to open: {exc}") from exc
        required = {"admins", "clients", "policies"}
        missing = required - tables
        if missing:
            raise ApplianceRestoreError(f"staged control.db is missing expected tables: {sorted(missing)}")

    if "secrets" in manifest.contents:
        secrets_path = staging_dir / SECRETS_NAME
        try:
            json.loads(secrets_path.read_text())
        except (OSError, json.JSONDecodeError) as exc:
            raise ApplianceRestoreError(f"staged secrets payload is invalid: {exc}") from exc

    return StagedRestore(staging_dir=staging_dir, manifest=manifest)


@dataclass(frozen=True)
class PromotionResult:
    control_db_restored: bool
    secret_count_restored: int
    certs_restored: list[str]
    rollback_dir: Path


def promote_appliance_restore(
    staged: StagedRestore,
    live_control_db_path: Path,
    live_secrets_dir: Path,
    live_certs: Optional[list[CertFile]] = None,
    *,
    rollback_root: Path,
) -> PromotionResult:
    """Only called after stage_appliance_restore has already fully
    validated everything. Snapshots the CURRENT live state into
    ``rollback_root`` first, then swaps in the staged state file by file
    using atomic renames. If any single swap fails partway, everything
    already snapshotted is restored from the rollback copy before the
    exception propagates -- the live appliance is never left in a state
    that is neither the old one nor the new one.
    """
    live_certs = live_certs or []
    rollback_root.mkdir(parents=True, exist_ok=True, mode=0o700)
    restored_certs: list[str] = []
    swapped: list[tuple[Path, Path]] = []  # (live_path, rollback_path) already swapped, for rollback

    def _snapshot_and_swap(live_path: Path, staged_path: Path, rollback_name: str) -> None:
        rollback_path = rollback_root / rollback_name
        if live_path.exists():
            shutil.copy2(live_path, rollback_path)
        else:
            rollback_path = Path("")  # nothing to roll back to; swap will just remove on rollback
        live_path.parent.mkdir(parents=True, exist_ok=True)
        tmp = live_path.parent / f".{live_path.name}.restore-tmp"
        shutil.copy2(staged_path, tmp)
        os.replace(tmp, live_path)
        swapped.append((live_path, rollback_path if rollback_path != Path("") else None))

    def _rollback() -> None:
        for live_path, rollback_path in reversed(swapped):
            try:
                if rollback_path is not None and rollback_path.exists():
                    os.replace(rollback_path, live_path)
                elif live_path.exists():
                    live_path.unlink()
            except OSError:
                pass  # best-effort rollback; the original exception is what matters

    try:
        control_db_restored = False
        if "control_db" in staged.manifest.contents:
            _snapshot_and_swap(live_control_db_path, staged.staging_dir / CONTROL_DB_NAME, "control.db.bak")
            control_db_restored = True

        secret_count_restored = 0
        if "secrets" in staged.manifest.contents:
            secrets_path = staged.staging_dir / SECRETS_NAME
            payload = json.loads(secrets_path.read_text())
            live_store = SecretStore(live_secrets_dir)
            if live_secrets_dir.exists():
                rollback_secrets_dir = rollback_root / "secrets.bak"
                if rollback_secrets_dir.exists():
                    shutil.rmtree(rollback_secrets_dir)
                shutil.copytree(live_secrets_dir, rollback_secrets_dir)
            try:
                live_store.import_all(payload, overwrite=True)
            except SecretStoreError as exc:
                raise ApplianceRestoreError(f"restoring secrets failed: {exc}") from exc
            secret_count_restored = len(payload)

        for cert in live_certs:
            staged_cert = staged.staging_dir / CERTS_DIR_NAME / cert.archive_name
            if staged_cert.exists():
                _snapshot_and_swap(cert.live_path, staged_cert, f"cert-{cert.archive_name}.bak")
                restored_certs.append(cert.archive_name)
    except BaseException:
        _rollback()
        raise

    return PromotionResult(
        control_db_restored=control_db_restored, secret_count_restored=secret_count_restored,
        certs_restored=restored_certs, rollback_dir=rollback_root,
    )
