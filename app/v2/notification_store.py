"""V2 notification-provider CRUD, secret-store-backed (Workstream 3
continuation, §17).

Split matches the brief exactly: control.db holds provider metadata plus a
*reference* to a secret; the actual credential/token/webhook-secret value
lives only in ``app/v2/secret_store.py``. This module is the CRUD surface
tying the two together, with tests proving (by direct SQLite inspection,
not just by not-calling-the-wrong-function) that no plaintext credential
ever reaches control.db, and a redaction helper for anything that might
otherwise end up in a log line.
"""

from __future__ import annotations

import sqlite3
from contextlib import closing
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from app.v2 import control_db
from app.v2.secret_store import SecretNotFoundError, SecretStore, new_secret_id

NOTIFICATION_SCHEMA_VERSION = 3

_MIGRATION_V3: list[str] = [
    """
    CREATE TABLE IF NOT EXISTS notification_providers (
        id INTEGER PRIMARY KEY,
        provider_id TEXT NOT NULL UNIQUE,
        kind TEXT NOT NULL CHECK(kind IN ('webhook','email_smtp','pushover','slack')),
        display_name TEXT NOT NULL,
        endpoint TEXT NOT NULL DEFAULT '',
        secret_ref TEXT,
        enabled INTEGER NOT NULL DEFAULT 1,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
    )
    """,
]


class NotificationStoreError(ValueError):
    pass


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def ensure_schema(path: str | Path) -> None:
    control_db.initialize(path)
    with control_db.connect(path) as conn:
        present = conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='notification_providers'"
        ).fetchone() is not None
    if not present:
        control_db.apply_migration_in_transaction(
            path, _MIGRATION_V3, NOTIFICATION_SCHEMA_VERSION
        )


@dataclass(frozen=True)
class NotificationProviderMetadata:
    """Never carries the secret value -- only its reference id."""

    provider_id: str
    kind: str
    display_name: str
    endpoint: str
    secret_ref: Optional[str]
    enabled: bool

    def redacted(self) -> dict:
        """Safe-to-log representation: secret_ref itself is an opaque
        random id (see secret_store.new_secret_id), not a credential, but
        is still masked here so a log line never even hints at whether a
        secret is configured beyond a boolean -- matching the "logs
        contain no secret" requirement conservatively."""
        d = {
            "provider_id": self.provider_id,
            "kind": self.kind,
            "display_name": self.display_name,
            "endpoint": self.endpoint,
            "has_secret": self.secret_ref is not None,
            "enabled": self.enabled,
        }
        return d


def create_provider(
    conn: sqlite3.Connection,
    secrets: SecretStore,
    provider_id: str,
    kind: str,
    display_name: str,
    endpoint: str,
    secret_value: Optional[str] = None,
) -> NotificationProviderMetadata:
    if kind not in ("webhook", "email_smtp", "pushover", "slack"):
        raise NotificationStoreError(f"invalid provider kind: {kind!r}")
    secret_ref = None
    if secret_value is not None:
        secret_ref = new_secret_id()
        secrets.create(secret_value, secret_id=secret_ref)
    try:
        now = _now()
        conn.execute(
            "INSERT INTO notification_providers "
            "(provider_id, kind, display_name, endpoint, secret_ref, enabled, created_at, updated_at) "
            "VALUES (?, ?, ?, ?, ?, 1, ?, ?)",
            (provider_id, kind, display_name, endpoint, secret_ref, now, now),
        )
    except sqlite3.IntegrityError as exc:
        if secret_ref is not None:
            secrets.delete(secret_ref)  # don't orphan a secret on a failed insert
        raise NotificationStoreError(f"duplicate provider_id: {exc}") from exc
    return NotificationProviderMetadata(provider_id, kind, display_name, endpoint, secret_ref, True)


def _row_to_metadata(row) -> NotificationProviderMetadata:
    provider_id, kind, display_name, endpoint, secret_ref, enabled = row
    return NotificationProviderMetadata(
        provider_id, kind, display_name, endpoint, secret_ref, bool(enabled)
    )


def get_provider(conn: sqlite3.Connection, provider_id: str) -> Optional[NotificationProviderMetadata]:
    row = conn.execute(
        "SELECT provider_id, kind, display_name, endpoint, secret_ref, enabled "
        "FROM notification_providers WHERE provider_id = ?",
        (provider_id,),
    ).fetchone()
    return _row_to_metadata(row) if row is not None else None


def list_providers(conn: sqlite3.Connection) -> list[NotificationProviderMetadata]:
    rows = conn.execute(
        "SELECT provider_id, kind, display_name, endpoint, secret_ref, enabled "
        "FROM notification_providers ORDER BY provider_id"
    ).fetchall()
    return [_row_to_metadata(r) for r in rows]


def update_provider_secret(
    conn: sqlite3.Connection, secrets: SecretStore, provider_id: str, new_secret_value: str
) -> NotificationProviderMetadata:
    """Rotates the secret: writes a new secret_store entry, only then
    repoints control.db's reference, only then deletes the old secret --
    so a crash between steps never leaves the provider referencing a
    secret_ref that doesn't exist."""
    existing = get_provider(conn, provider_id)
    if existing is None:
        raise NotificationStoreError(f"unknown provider_id: {provider_id!r}")
    new_ref = new_secret_id()
    secrets.create(new_secret_value, secret_id=new_ref)
    conn.execute(
        "UPDATE notification_providers SET secret_ref = ?, updated_at = ? WHERE provider_id = ?",
        (new_ref, _now(), provider_id),
    )
    if existing.secret_ref is not None:
        with_ = existing.secret_ref
        if secrets.exists(with_):
            secrets.delete(with_)
    return get_provider(conn, provider_id)


def delete_provider(conn: sqlite3.Connection, secrets: SecretStore, provider_id: str) -> None:
    existing = get_provider(conn, provider_id)
    if existing is None:
        raise NotificationStoreError(f"unknown provider_id: {provider_id!r}")
    conn.execute("DELETE FROM notification_providers WHERE provider_id = ?", (provider_id,))
    if existing.secret_ref is not None and secrets.exists(existing.secret_ref):
        secrets.delete(existing.secret_ref)


def resolve_secret(secrets: SecretStore, metadata: NotificationProviderMetadata) -> str:
    """Only place a caller (e.g. an actual notification-send code path)
    should ever obtain the plaintext value -- explicit, not implicit via
    any metadata accessor."""
    if metadata.secret_ref is None:
        raise NotificationStoreError(
            f"provider {metadata.provider_id!r} has no configured secret"
        )
    try:
        return secrets.get(metadata.secret_ref)
    except SecretNotFoundError as exc:
        raise NotificationStoreError(
            f"provider {metadata.provider_id!r} references a missing secret "
            f"{metadata.secret_ref!r} -- configuration is inconsistent, re-enter the credential"
        ) from exc
