"""V2 protected secret-store backup/restore (Workstream 3 final
continuation, Priority 2, §22-23).

Uses ``cryptography.fernet.Fernet`` (AES-128-CBC + HMAC-SHA256,
authenticated encryption) -- an existing, audited, already-installed
dependency (``cryptography`` 43.0.0) -- rather than inventing home-grown
cryptography, per the brief's explicit instruction. Every backup is
encrypted at rest and integrity-protected: a wrong key or any bit of
tampering with the ciphertext raises during decrypt, it never silently
produces garbage plaintext.

Key management is intentionally out of this module's scope: callers
supply the Fernet key (32 url-safe base64-encoded bytes,
``Fernet.generate_key()``); where that key itself is stored/protected
(e.g. under the same root-only filesystem contract as
``app/v2/secret_store.py``, or a future dedicated key-management
integration) is a deployment decision, not something this module decides.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from cryptography.fernet import Fernet, InvalidToken

from app.v2.secret_store import SecretStore, SecretStoreError

BACKUP_FORMAT_VERSION = 1


class SecretBackupError(RuntimeError):
    pass


class SecretBackupKeyError(SecretBackupError):
    """Wrong key or corrupted/tampered ciphertext -- distinguished from
    other backup errors so a caller can specifically prompt for "check
    your key" rather than a generic failure message."""


@dataclass(frozen=True)
class BackupResult:
    backup_path: Path
    secret_count: int
    created_at: str


def _atomic_write_bytes(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    tmp = path.parent / f".{path.name}.tmp"
    with open(tmp, "wb") as fh:
        fh.write(data)
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, path)
    dir_fd = os.open(str(path.parent), os.O_RDONLY)
    try:
        os.fsync(dir_fd)
    finally:
        os.close(dir_fd)
    os.chmod(path, 0o600)


def create_encrypted_backup(store: SecretStore, backup_path: Path, key: bytes) -> BackupResult:
    """Exports every secret (plaintext, in memory only -- see
    ``SecretStore.export_all``'s own warning) and immediately encrypts it
    before it ever touches disk. The backup file itself carries the
    format version and secret count in its (encrypted) payload, plus its
    own checksum implicitly via Fernet's built-in HMAC -- there is no
    separate "ordinary" export path this function could accidentally fall
    back to on error; encryption happens before the first byte is written.
    """
    plaintext_secrets = store.export_all()
    payload = {
        "format_version": BACKUP_FORMAT_VERSION,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "secrets": plaintext_secrets,
    }
    fernet = Fernet(key)
    ciphertext = fernet.encrypt(json.dumps(payload).encode("utf-8"))
    _atomic_write_bytes(backup_path, ciphertext)
    return BackupResult(
        backup_path=backup_path, secret_count=len(plaintext_secrets), created_at=payload["created_at"]
    )


def restore_encrypted_backup(
    backup_path: Path, key: bytes, target_store: SecretStore, *, overwrite: bool = False
) -> int:
    """Restores into ``target_store`` -- a caller-supplied store, which may
    be (and in the intended use case, for a real disaster-recovery
    restore, IS) a completely separate ``SecretStore`` instance/directory
    from wherever the backup was created, per §23's explicit requirement.

    Atomicity: decryption + JSON parsing + format validation all happen
    in memory before ``SecretStore.import_all`` is called at all -- so a
    wrong key, corrupted ciphertext, or malformed payload never reaches
    the store and never leaves a partial restore behind.
    ``SecretStore.import_all`` itself is now also two-phase (see the fix
    in ``app/v2/secret_store.py``), so even a batch that fails an
    id/conflict check partway through the *decrypted* dict still leaves
    no partial write.
    """
    if not backup_path.exists():
        raise SecretBackupError(f"backup file not found: {backup_path}")
    ciphertext = backup_path.read_bytes()

    fernet = Fernet(key)
    try:
        plaintext = fernet.decrypt(ciphertext)
    except InvalidToken as exc:
        raise SecretBackupKeyError(
            "cannot decrypt backup -- wrong key, or the backup file is corrupted/tampered with"
        ) from exc

    try:
        payload = json.loads(plaintext)
    except json.JSONDecodeError as exc:
        raise SecretBackupError(f"backup payload is not valid JSON after decryption: {exc}") from exc

    if not isinstance(payload, dict) or "secrets" not in payload or "format_version" not in payload:
        raise SecretBackupError("backup payload is missing required fields")
    if payload["format_version"] != BACKUP_FORMAT_VERSION:
        raise SecretBackupError(
            f"unsupported backup format version {payload['format_version']!r} "
            f"(this code supports version {BACKUP_FORMAT_VERSION})"
        )

    try:
        target_store.import_all(payload["secrets"], overwrite=overwrite)
    except SecretStoreError as exc:
        raise SecretBackupError(f"restore rejected by secret store: {exc}") from exc

    return len(payload["secrets"])
