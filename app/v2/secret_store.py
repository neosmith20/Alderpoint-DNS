"""V2 protected secret storage foundation (Workstream 2, §11).

Frozen architecture (``docs/v2/architecture-map.md`` "Notification secret
architecture"): ``control.db`` holds provider metadata plus a **secret
reference/key identifier only**; the actual secret value lives here, in a
dedicated root-controlled store, keyed by that reference. Primary initial
use case is notification-provider credentials
(``notification_providers.secret`` in the v1 schema, see
``docs/v2/storage-audit.md``), but nothing here is notification-specific —
this is a general small secret-value store.

Design choice: one file per secret, named by a validated stable ID, stored
under a directory locked to ``0700`` (owner-only — even group-read is
refused, unlike the config file's ``0640``, because this directory holds
plaintext secret material, not operator-facing configuration). This is
deliberately *not* a general-purpose vault (encryption-at-rest,
transit-sealing, HSM integration, dynamic leases) — Workstream 2's brief is
explicit that a smaller robust design is preferred over inventing a large
one prematurely. Encryption-at-rest, if adopted, is a Workstream 3+ layer on
top of this file-per-secret shape, not a redesign of it.

Explicitly NOT implemented here: an Argon2id pepper file. The pepper
decision remains DEFERRED (see ``docs/v2/architecture-map.md``); this module
is generic and could technically hold one, but nothing in this repository
calls it that way, and no pepper file is created by any code here.
"""

from __future__ import annotations

import errno
import os
import re
import tempfile
import uuid
from dataclasses import dataclass
from pathlib import Path

_ID_PATTERN = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
_STORE_DIR_MODE = 0o700
_SECRET_FILE_MODE = 0o600


class SecretStoreError(RuntimeError):
    """Base error for this module."""


class InvalidSecretIdError(SecretStoreError):
    """Raised when a secret ID fails the allowlist pattern — this is the
    path-traversal defense: an ID like ``../../etc/passwd`` or containing a
    ``/`` never reaches ``Path`` construction at all."""


class SecretNotFoundError(SecretStoreError):
    pass


class SecretSymlinkError(SecretStoreError):
    """A secret file path was found to be a symlink — refused, same policy
    as app/v2/config.py's load_file/atomic_write."""


@dataclass(frozen=True)
class SecretMetadata:
    """Everything about a secret EXCEPT its value — safe to log, return over
    an API, or include in a listing. Never carries the plaintext."""

    secret_id: str
    created_at: str


def _validate_id(secret_id: str) -> None:
    if not _ID_PATTERN.match(secret_id):
        raise InvalidSecretIdError(
            f"invalid secret id {secret_id!r}: must match {_ID_PATTERN.pattern}"
        )


def new_secret_id() -> str:
    """Generate a fresh, collision-resistant, filesystem-safe ID."""
    return uuid.uuid4().hex


class SecretStore:
    """Root-controlled directory of individually-stored secret values.

    ``root`` should be a dedicated path (e.g.
    ``/var/lib/alderpointdns/secrets`` — exact production path not yet
    pinned, this workstream only fixes the shape). This class never opens
    any path outside ``root`` — every operation validates the secret ID
    against the allowlist pattern before building a filesystem path from it,
    so a malicious or malformed ID cannot escape the store directory.
    """

    def __init__(self, root: str | os.PathLike):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        os.chmod(self.root, _STORE_DIR_MODE)

    def _path_for(self, secret_id: str) -> Path:
        _validate_id(secret_id)
        return self.root / secret_id

    def create(self, value: str, *, secret_id: str | None = None) -> str:
        """Store a new secret value, returning its stable ID (generated if
        not supplied). Refuses to overwrite an existing secret — use
        ``update`` for that, so a caller can't accidentally clobber a
        different secret by ID collision."""
        secret_id = new_secret_id() if secret_id is None else secret_id
        path = self._path_for(secret_id)
        if path.exists() or path.is_symlink():
            raise SecretStoreError(f"secret id {secret_id!r} already exists")
        self._atomic_write(path, value)
        return secret_id

    def get(self, secret_id: str) -> str:
        path = self._path_for(secret_id)
        if path.is_symlink():
            raise SecretSymlinkError(f"refusing to read {path}: path is a symlink")
        flags = os.O_RDONLY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            fd = os.open(str(path), flags)
        except OSError as exc:
            if exc.errno == errno.ENOENT:
                raise SecretNotFoundError(secret_id) from exc
            if hasattr(os, "O_NOFOLLOW") and exc.errno == errno.ELOOP:
                raise SecretSymlinkError(
                    f"refusing to read {path}: became a symlink between check and open"
                ) from exc
            raise
        with os.fdopen(fd, "r", encoding="utf-8") as fh:
            return fh.read()

    def update(self, secret_id: str, value: str) -> None:
        path = self._path_for(secret_id)
        if not path.exists():
            raise SecretNotFoundError(secret_id)
        if path.is_symlink():
            raise SecretSymlinkError(f"refusing to write {path}: path is a symlink")
        self._atomic_write(path, value)

    def delete(self, secret_id: str) -> None:
        path = self._path_for(secret_id)
        if path.is_symlink():
            raise SecretSymlinkError(f"refusing to delete {path}: path is a symlink")
        try:
            path.unlink()
        except FileNotFoundError as exc:
            raise SecretNotFoundError(secret_id) from exc

    def list_ids(self) -> list[str]:
        """Metadata-only listing — IDs, never values. Safe to expose over an
        admin API or log."""
        return sorted(
            p.name for p in self.root.iterdir()
            if p.is_file() and _ID_PATTERN.match(p.name)
        )

    def exists(self, secret_id: str) -> bool:
        try:
            path = self._path_for(secret_id)
        except InvalidSecretIdError:
            return False
        return path.exists() and not path.is_symlink()

    def _atomic_write(self, path: Path, value: str) -> None:
        fd, tmp_name = tempfile.mkstemp(
            prefix=f".{path.name}.", suffix=".tmp", dir=str(self.root)
        )
        try:
            os.chmod(tmp_name, _SECRET_FILE_MODE)
            with os.fdopen(fd, "w", encoding="utf-8") as tmp:
                tmp.write(value)
                tmp.flush()
                os.fsync(tmp.fileno())
            os.replace(tmp_name, path)
        except BaseException:
            try:
                os.unlink(tmp_name)
            except FileNotFoundError:
                pass
            raise
        dir_fd = os.open(str(self.root), os.O_RDONLY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)

    # --- backup/restore/replication hooks (designed, not wired to a real
    # backup pipeline in this workstream — see docs/v2/architecture-map.md
    # "Notification secret architecture" for the future requirements list
    # this satisfies the shape of) -----------------------------------------

    def export_all(self) -> dict[str, str]:
        """Returns every secret ID -> plaintext value. Deliberately named
        loudly (not just ``export``) as a reminder this returns plaintext —
        callers building the actual backup pipeline are responsible for
        encrypting the result before it touches disk/network, never calling
        this and writing the return value directly to an ordinary backup
        archive. This is the hook a protected/encrypted secret-backup path
        (Workstream 2+ deliverable, see architecture-map.md) is expected to
        call; it is not itself that protected path.
        """
        return {secret_id: self.get(secret_id) for secret_id in self.list_ids()}

    def import_all(self, secrets: dict[str, str], *, overwrite: bool = False) -> None:
        """Restore-to-new-appliance hook: bulk-load secret_id -> value pairs
        (e.g. from a decrypted backup). ``overwrite=False`` (default) refuses
        to clobber an existing secret with the same ID, matching ``create``'s
        no-silent-overwrite policy; pass ``overwrite=True`` for an explicit
        full restore onto a fresh store.

        Validated in two passes so a bad entry never leaves a partial
        restore behind: every id/conflict check runs first (no I/O), and
        only if the whole batch passes does any file actually get written.
        A previous version wrote entries one at a time as it iterated,
        which meant an invalid id or an unexpected conflict partway
        through the dict left earlier secrets already committed to disk --
        a real partial-restore bug, fixed here.
        """
        for secret_id in secrets:
            _validate_id(secret_id)
            if self.exists(secret_id) and not overwrite:
                raise SecretStoreError(
                    f"secret id {secret_id!r} already exists (pass overwrite=True to replace)"
                )
        for secret_id, value in secrets.items():
            if self.exists(secret_id):
                self.update(secret_id, value)
            else:
                self.create(value, secret_id=secret_id)
