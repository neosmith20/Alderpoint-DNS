"""V2 secret replication (Workstream 3 final continuation, Priority 2,
§24).

Provides the maximum safe functional layer buildable this session:
authenticated+encrypted envelope construction, generation-based conflict
resolution, and atomic local application -- proven against isolated
primary/secondary ``SecretStore`` fixtures. Reuses
``app/v2/secret_backup.py``'s Fernet-based encryption (same "no home-grown
cryptography" constraint) rather than a separate scheme.

**What this module deliberately does NOT do, and why (a genuine, stated
blocker, not a silent gap):** it does not open a network connection or
speak the existing V1 replication protocol's mTLS transport
(``app/replication.py``/``app/encryption.py``'s local-CA-issued
certificates). That transport is a substantial existing subsystem built
around V1's `replication_replicas`/`replication_generations` control
tables and a specific HTTP(S) API surface; correctly integrating a V2
secret channel into it -- reusing its cert issuance, its enrollment flow,
its retry/backoff behavior -- is real additional work distinct from "can
this module encrypt/version/apply a secret payload correctly," which is
what's proven here. The envelope/conflict/application logic below is
exactly what a real transport would carry; only the wire transport itself
is not built this session.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

from cryptography.fernet import Fernet, InvalidToken

from app.v2.secret_store import SecretStore, SecretStoreError

REPLICATION_FORMAT_VERSION = 1


class SecretReplicationError(RuntimeError):
    pass


class SecretReplicationAuthError(SecretReplicationError):
    """Wrong/missing key material, or a tampered envelope -- authentication
    failure, distinguished from an ordinary conflict/version mismatch."""


@dataclass(frozen=True)
class ApplyResult:
    applied: bool
    reason: str
    secret_count: int = 0


def build_envelope(store: SecretStore, key: bytes, node_id: str, generation: int) -> bytes:
    """Authenticated, encrypted, versioned. ``generation`` must be a
    monotonically increasing integer the caller tracks per-node (e.g. a
    counter bumped on every local secret-store mutation) -- this module
    doesn't invent one, since generation semantics are a replication-
    system-wide concern the existing V1 replication tables
    (``replication_generations``) already model.
    """
    if not node_id:
        raise SecretReplicationError("node_id must not be empty")
    payload = {
        "format_version": REPLICATION_FORMAT_VERSION,
        "node_id": node_id,
        "generation": generation,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "secrets": store.export_all(),
    }
    fernet = Fernet(key)
    return fernet.encrypt(json.dumps(payload).encode("utf-8"))


def apply_envelope(
    envelope: bytes,
    key: bytes,
    target_store: SecretStore,
    known_generations: dict[str, int],
) -> ApplyResult:
    """Applies an envelope built by ``build_envelope`` to
    ``target_store``, iff its generation is strictly newer than the
    highest generation previously seen from that ``node_id`` (per
    ``known_generations``, a caller-owned dict this function reads but
    does not persist -- durable generation tracking is the caller's
    responsibility, matching the existing replication tables' design).
    A stale/duplicate envelope is not an error -- it's a normal, expected
    outcome of at-least-once delivery -- so it returns
    ``applied=False, reason="stale_generation"`` rather than raising.

    Never logs a secret value: this function's own body never formats a
    plaintext secret into any string that isn't the in-memory dict handed
    to ``SecretStore.import_all`` (which itself writes to per-secret files
    under a 0700/0600 permission contract, not to any log stream).
    """
    fernet = Fernet(key)
    try:
        plaintext = fernet.decrypt(envelope)
    except InvalidToken as exc:
        raise SecretReplicationAuthError(
            "cannot decrypt replication envelope -- wrong key or tampered/corrupted envelope"
        ) from exc

    try:
        payload = json.loads(plaintext)
    except json.JSONDecodeError as exc:
        raise SecretReplicationError(f"envelope payload is not valid JSON: {exc}") from exc

    for field_name in ("format_version", "node_id", "generation", "secrets"):
        if field_name not in payload:
            raise SecretReplicationError(f"envelope missing required field: {field_name!r}")
    if payload["format_version"] != REPLICATION_FORMAT_VERSION:
        raise SecretReplicationError(
            f"unsupported replication format version {payload['format_version']!r}"
        )

    node_id = payload["node_id"]
    generation = payload["generation"]
    last_known = known_generations.get(node_id, -1)
    if generation <= last_known:
        return ApplyResult(applied=False, reason="stale_generation")

    try:
        target_store.import_all(payload["secrets"], overwrite=True)
    except SecretStoreError as exc:
        raise SecretReplicationError(f"replication apply rejected by secret store: {exc}") from exc

    known_generations[node_id] = generation
    return ApplyResult(applied=True, reason="applied", secret_count=len(payload["secrets"]))
