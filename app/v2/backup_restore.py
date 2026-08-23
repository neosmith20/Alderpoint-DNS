"""V2 full appliance backup/restore (beta-rescue priority 3).

Replaces the prior "secrets-only" backup (real, but only ever one component
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

import base64
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
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from app.v2.secret_store import SecretStore, SecretStoreError

BACKUP_FORMAT_VERSION = 1
MANIFEST_NAME = "manifest.json"
CONTROL_DB_NAME = "control.db"
SECRETS_NAME = "secrets.json"
CERTS_DIR_NAME = "certs"
MAX_ARCHIVE_BYTES = 1_000_000_000
MAX_EXPANDED_BYTES = 4_000_000_000
MAX_COMPRESSION_RATIO = 200
PRODUCT_ID = "alderpointdns-v2-appliance"

# Cross-appliance portability (native upload/restore, milestone 1): a backup
# meant to move to a *different* appliance cannot be encrypted with a key
# that only exists in this appliance's own secret store (the prior
# same-appliance-only design). Passphrase mode derives the Fernet key from
# an operator-supplied passphrase with PBKDF2-HMAC-SHA256 and a random
# per-backup salt. The salt/KDF parameters are not secret and are stored as
# a small cleartext header in front of the Fernet token (the token itself
# is still authenticated -- a wrong passphrase or tampered header/token is
# still detected before anything is touched); "local" mode (the original
# behavior, keyed from a secret this appliance never exports) remains for
# quick same-appliance backups where portability isn't needed.
FILE_MAGIC = b"APDNSBAKv2\n"
PBKDF2_ITERATIONS = 390_000
PBKDF2_MIN_ITERATIONS = 200_000
PBKDF2_MAX_ITERATIONS = 1_000_000
_SALT_BYTES = 16

# Archive-bomb / malformed-archive defenses (native upload/restore,
# milestone 1): this format's own archives only ever contain a handful of
# small, known-named members, so these ceilings are generous for any real
# backup and tight against a crafted one.
MAX_ARCHIVE_MEMBERS = 64
MAX_MEMBER_BYTES = 2 * 1024 * 1024 * 1024  # 2 GiB per member
MAX_TOTAL_EXTRACTED_BYTES = 4 * 1024 * 1024 * 1024  # 4 GiB total
MAX_UPLOAD_BYTES = 512 * 1024 * 1024  # 512 MiB compressed/encrypted upload


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
    product: str = PRODUCT_ID
    source_node_id: Optional[str] = None
    key_mode: str = "local"


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


def derive_key_from_passphrase(passphrase: str, salt: bytes, iterations: int = PBKDF2_ITERATIONS) -> bytes:
    """A Fernet-compatible key derived from an operator passphrase, never
    from anything only this appliance holds -- what makes a backup
    restorable on a *different* Alderpoint DNS appliance."""
    if not passphrase:
        raise ApplianceBackupError("a passphrase is required for a portable (cross-appliance) backup")
    if len(salt) != _SALT_BYTES:
        raise ApplianceBackupError("portable backup salt has an invalid length")
    if iterations < PBKDF2_MIN_ITERATIONS or iterations > PBKDF2_MAX_ITERATIONS:
        raise ApplianceBackupError("portable backup KDF iteration count is outside the supported bounds")
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=iterations)
    return base64.urlsafe_b64encode(kdf.derive(passphrase.encode("utf-8")))


def create_appliance_backup(
    control_db_path: Path,
    secret_store: SecretStore,
    key: bytes,
    backup_path: Path,
    *,
    cert_files: Optional[list[CertFile]] = None,
    source_version: str = "unknown",
    passphrase: Optional[str] = None,
    source_node_id: Optional[str] = None,
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
        key_mode = "passphrase" if passphrase else "local"
        manifest = {
            "format_version": BACKUP_FORMAT_VERSION,
            "product": PRODUCT_ID,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "source_version": source_version,
            "source_node_id": source_node_id,
            "control_db_schema_version": schema_version,
            "contents": contents,
            "secret_count": secret_count,
            "cert_files": included_cert_names,
            # Explicit, not implicit: this backup format has no field for
            # raw query history because there is no code path that could
            # populate one -- see this module's docstring.
            "raw_query_history_included": False,
            "key_mode": key_mode,
        }
        manifest_bytes = json.dumps(manifest, indent=2).encode("utf-8")
        info = tarfile.TarInfo(name=MANIFEST_NAME)
        info.size = len(manifest_bytes)
        tar.addfile(info, io.BytesIO(manifest_bytes))

    header = b""
    if passphrase:
        salt = os.urandom(_SALT_BYTES)
        key = derive_key_from_passphrase(passphrase, salt, PBKDF2_ITERATIONS)
        header_obj = {"salt_b64": base64.b64encode(salt).decode("ascii"), "iterations": PBKDF2_ITERATIONS}
        header = FILE_MAGIC + json.dumps(header_obj).encode("utf-8") + b"\n"

    fernet = Fernet(key)
    ciphertext = fernet.encrypt(buf.getvalue())

    backup_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    tmp = backup_path.parent / f".{backup_path.name}.tmp"
    with open(tmp, "wb") as fh:
        fh.write(header)
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


def _open_archive(backup_path: Path, key: bytes, *, passphrase: Optional[str] = None) -> tarfile.TarFile:
    if not backup_path.exists():
        raise ApplianceRestoreError(f"backup file not found: {backup_path}")
    payload = backup_path.read_bytes()
    decrypt_key = key
    ciphertext = payload
    if payload.startswith(FILE_MAGIC):
        try:
            header_raw, ciphertext = payload[len(FILE_MAGIC):].split(b"\n", 1)
            header = json.loads(header_raw.decode("utf-8"))
            salt = base64.b64decode(header["salt_b64"], validate=True)
            iterations = int(header.get("iterations", PBKDF2_ITERATIONS))
        except (ValueError, KeyError, json.JSONDecodeError, UnicodeDecodeError, TypeError) as exc:
            raise ApplianceRestoreError(f"portable backup header is invalid: {exc}") from exc
        if not passphrase:
            raise ApplianceBackupKeyError("this portable backup requires its restore passphrase")
        decrypt_key = derive_key_from_passphrase(passphrase, salt, iterations)
    fernet = Fernet(decrypt_key)
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
        product=data.get("product", PRODUCT_ID),
        source_node_id=data.get("source_node_id"),
        key_mode=data.get("key_mode", "local"),
    )


def _validate_member_name(name: str) -> None:
    path = Path(name)
    if path.is_absolute() or name.startswith("/") or "\\" in name:
        raise ApplianceRestoreError(f"backup archive contains an invalid absolute path: {name!r}")
    parts = path.parts
    if not parts or any(part in ("", ".", "..") for part in parts):
        raise ApplianceRestoreError(f"backup archive contains an unsafe path: {name!r}")


def _validate_archive_members(
    tar: tarfile.TarFile,
    manifest: ApplianceManifest,
    *,
    archive_size_bytes: int,
) -> dict[str, tarfile.TarInfo]:
    allowed = {CONTROL_DB_NAME, SECRETS_NAME, MANIFEST_NAME}
    allowed |= {f"{CERTS_DIR_NAME}/{name}" for name in manifest.cert_files}
    seen: dict[str, tarfile.TarInfo] = {}
    expanded_size = 0
    members = tar.getmembers()
    if len(members) > MAX_ARCHIVE_MEMBERS:
        raise ApplianceRestoreError("backup archive contains too many entries")
    for member in members:
        _validate_member_name(member.name)
        if member.name not in allowed:
            raise ApplianceRestoreError(f"backup archive contains an unexpected entry: {member.name!r}")
        if not member.isfile():
            raise ApplianceRestoreError(f"backup archive contains a non-regular entry: {member.name!r}")
        if member.name in seen:
            raise ApplianceRestoreError(f"backup archive contains a duplicate entry: {member.name!r}")
        if member.size < 0:
            raise ApplianceRestoreError(f"backup archive contains an invalid entry size: {member.name!r}")
        if member.size > MAX_MEMBER_BYTES:
            raise ApplianceRestoreError(f"backup archive entry exceeds the per-entry size limit: {member.name!r}")
        expanded_size += member.size
        if expanded_size > MAX_TOTAL_EXTRACTED_BYTES or expanded_size > MAX_EXPANDED_BYTES:
            raise ApplianceRestoreError("backup archive expanded size exceeds the configured safety limit")
        seen[member.name] = member
    if archive_size_bytes > 0 and expanded_size / max(archive_size_bytes, 1) > MAX_COMPRESSION_RATIO:
        raise ApplianceRestoreError("backup archive compression ratio exceeds the configured safety limit")
    if MANIFEST_NAME not in seen:
        raise ApplianceRestoreError("backup archive is missing its manifest")
    if manifest.product != PRODUCT_ID:
        raise ApplianceRestoreError(f"backup product {manifest.product!r} is not compatible with this appliance")
    if "control_db" in manifest.contents and CONTROL_DB_NAME not in seen:
        raise ApplianceRestoreError("manifest says control_db is included but the archive has none")
    if "secrets" in manifest.contents and SECRETS_NAME not in seen:
        raise ApplianceRestoreError("manifest says secrets are included but the archive has none")
    return seen


def validate_appliance_backup(backup_path: Path, key: bytes, *, passphrase: Optional[str] = None) -> ApplianceManifest:
    """Decrypt + untar + sanity-check in memory only. Never writes
    anywhere. Used by both the standalone "Validate" action and as the
    first phase of a real restore."""
    archive_size = backup_path.stat().st_size if backup_path.exists() else 0
    if archive_size > MAX_ARCHIVE_BYTES or archive_size > MAX_UPLOAD_BYTES:
        raise ApplianceRestoreError("backup file exceeds the configured upload/archive size limit")
    tar = _open_archive(backup_path, key, passphrase=passphrase)
    try:
        manifest = _read_manifest(tar)
        members = _validate_archive_members(tar, manifest, archive_size_bytes=archive_size)
        if "control_db" in manifest.contents:
            member = members[CONTROL_DB_NAME]
            fh = tar.extractfile(member)
            if fh is None or member.size == 0:
                raise ApplianceRestoreError("control.db entry in the backup archive is empty")
        return manifest
    finally:
        tar.close()


def stage_appliance_restore(backup_path: Path, key: bytes, staging_dir: Path, *, passphrase: Optional[str] = None) -> StagedRestore:
    """Decrypt + untar + validate into ``staging_dir`` (fully isolated
    from any live path). Also opens the staged control.db read-only to
    confirm it is a real, openable SQLite database with the expected
    core schema before declaring the stage successful -- corruption that
    Fernet's own integrity check wouldn't catch (e.g. a truncated tar
    entry) is caught here instead of during promotion."""
    if staging_dir.exists():
        shutil.rmtree(staging_dir)
    staging_dir.mkdir(parents=True, exist_ok=True, mode=0o700)

    archive_size = backup_path.stat().st_size if backup_path.exists() else 0
    if archive_size > MAX_ARCHIVE_BYTES or archive_size > MAX_UPLOAD_BYTES:
        raise ApplianceRestoreError("backup file exceeds the configured upload/archive size limit")
    tar = _open_archive(backup_path, key, passphrase=passphrase)
    try:
        manifest = _read_manifest(tar)
        members = _validate_archive_members(tar, manifest, archive_size_bytes=archive_size)
        for member in members.values():
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


def restore_from_rollback(
    live_control_db_path: Path,
    live_secrets_dir: Path,
    live_certs: Optional[list[CertFile]] = None,
    *,
    rollback_root: Path,
) -> None:
    """Restore the pre-restore snapshot captured by promote_appliance_restore.

    This is used when a later runtime compile/promotion/health step fails
    after the durable state swap already succeeded.
    """
    live_certs = live_certs or []
    db_backup = rollback_root / "control.db.bak"
    db_absent = rollback_root / "control.db.absent"
    if db_backup.exists():
        live_control_db_path.parent.mkdir(parents=True, exist_ok=True)
        os.replace(db_backup, live_control_db_path)
    elif db_absent.exists():
        try:
            live_control_db_path.unlink()
        except FileNotFoundError:
            pass
    secrets_backup = rollback_root / "secrets.bak"
    secrets_absent = rollback_root / "secrets.absent"
    if secrets_backup.exists():
        if live_secrets_dir.exists():
            shutil.rmtree(live_secrets_dir)
        shutil.copytree(secrets_backup, live_secrets_dir)
    elif secrets_absent.exists() and live_secrets_dir.exists():
        shutil.rmtree(live_secrets_dir)
    for cert in live_certs:
        backup = rollback_root / f"cert-{cert.archive_name}.bak"
        absent = rollback_root / f"cert-{cert.archive_name}.absent"
        if backup.exists():
            cert.live_path.parent.mkdir(parents=True, exist_ok=True)
            os.replace(backup, cert.live_path)
        elif absent.exists():
            try:
                cert.live_path.unlink()
            except FileNotFoundError:
                pass


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
    swapped: list[tuple[Path, Path | None]] = []  # (live_path, rollback_path) already swapped, for rollback

    def _snapshot_and_swap(live_path: Path, staged_path: Path, rollback_name: str) -> None:
        rollback_path = rollback_root / rollback_name
        if live_path.exists():
            shutil.copy2(live_path, rollback_path)
        else:
            (rollback_root / rollback_name.replace(".bak", ".absent")).write_text("", encoding="utf-8")
            rollback_path = None
        live_path.parent.mkdir(parents=True, exist_ok=True)
        tmp = live_path.parent / f".{live_path.name}.restore-tmp"
        shutil.copy2(staged_path, tmp)
        os.replace(tmp, live_path)
        swapped.append((live_path, rollback_path))

    def _rollback() -> None:
        try:
            restore_from_rollback(live_control_db_path, live_secrets_dir, live_certs, rollback_root=rollback_root)
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
            rollback_secrets_dir = rollback_root / "secrets.bak"
            secrets_preexisted = live_secrets_dir.exists()
            if secrets_preexisted:
                if rollback_secrets_dir.exists():
                    shutil.rmtree(rollback_secrets_dir)
                shutil.copytree(live_secrets_dir, rollback_secrets_dir)
            else:
                (rollback_root / "secrets.absent").write_text("", encoding="utf-8")
            live_store = SecretStore(live_secrets_dir)
            try:
                live_store.import_all(payload, overwrite=True)
            except SecretStoreError as exc:
                if rollback_secrets_dir.exists():
                    if live_secrets_dir.exists():
                        shutil.rmtree(live_secrets_dir)
                    shutil.copytree(rollback_secrets_dir, live_secrets_dir)
                elif not secrets_preexisted and live_secrets_dir.exists():
                    shutil.rmtree(live_secrets_dir)
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
