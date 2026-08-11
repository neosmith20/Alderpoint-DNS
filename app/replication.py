#!/usr/bin/env python3
"""Alderpoint DNS-native one-way primary-to-replica configuration replication.

A `primary` Alderpoint DNS node compiles its filtering/Local DNS/policy state into
numbered, hashed "generations" every time it successfully deploys. A
`replica` node enrolls once (a short-lived, single-use, hashed token bound to
a specific replica identity), is issued a client certificate signed by the
primary's own local CA (reusing `app.encryption.ensure_local_ca()` rather
than building a second CA), and from then on authenticates to the primary
using mutual TLS only -- there is no password or SSH key anywhere in this
flow. The replica polls (does not accept a push connection) for the latest
generation, verifies the payload hash, stages the data, applies it into its
own local tables, and reuses the *existing* `alderpointdns_compiler.py deploy`
pipeline (via the same enumerated, argument-free sudo path every other
Alderpoint DNS feature uses) to regenerate and atomically activate BIND/dnsdist
configuration -- this module never reimplements zone/RPZ generation.

Replication failure (primary down, replica down, revoked cert, corrupted
generation) must never interrupt DNS service on either node: a replica that
cannot reach its primary simply keeps serving whatever it last applied.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import http.client
import http.server
import json
import secrets
import shutil
import sqlite3
import ssl
import subprocess
import tempfile
import threading
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from app import encryption
from app.db_retry import DatabaseBusyError, retry_on_locked


DB_PATH = Path("/var/lib/alderpointdns/alderpointdns.db")
BACKUP_DIR = Path("/var/lib/alderpointdns/backups")
STAGING_DIR = Path("/var/lib/alderpointdns/staging")
REPL_DIR = Path("/var/lib/alderpointdns/replication")
SERVER_CERT_PATH = REPL_DIR / "replication-server.crt"
SERVER_KEY_PATH = REPL_DIR / "replication-server.key"

# Bumped whenever the shape of the replicated payload changes in a way that
# an older replica could misinterpret. A replica refuses a generation whose
# schema_version is newer than its own rather than risk corrupting itself.
SCHEMA_VERSION = 1

ENROLLMENT_TTL_MINUTES = 15
# How long an enrollment may sit "reserved" (staged for the privileged
# sudo step) before it's treated as orphaned and released back to a plain
# unreserved pending token. Generous versus real cert-issuance latency
# (well under a second), tiny versus ENROLLMENT_TTL_MINUTES -- long enough
# that a normal in-flight request is never released out from under it,
# short enough that a crashed/killed request never locks out a retry for
# more than a few tens of seconds.
RESERVATION_TTL_SECONDS = 45
DEFAULT_LISTEN_PORT = 8843
DEFAULT_POLL_INTERVAL_SECONDS = 60
MAX_BACKOFF_SECONDS = 300

ROLES = {"standalone", "primary", "replica"}


class ReplicationError(ValueError):
    pass


def now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()


def connect(db_path: Path | None = None) -> sqlite3.Connection:
    path = db_path or DB_PATH
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path, timeout=5.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout=5000")
    return conn


def run(command: list[str], check: bool = True, input: str | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, text=True, input=input, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=check)


# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------

def _ensure_column(conn: sqlite3.Connection, table: str, column: str, definition: str) -> None:
    columns = {row["name"] for row in conn.execute(f"PRAGMA table_info({table})")}
    if column not in columns:
        conn.execute(f'ALTER TABLE {table} ADD COLUMN "{column}" {definition}')


def init_db(conn: sqlite3.Connection | None = None) -> None:
    close = conn is None
    db = conn or connect()
    try:
        if close:
            db.execute("PRAGMA journal_mode=WAL")
        db.executescript(
            """
            CREATE TABLE IF NOT EXISTS replication_settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS replication_enrollments (
                id INTEGER PRIMARY KEY,
                node_id TEXT NOT NULL UNIQUE,
                node_name TEXT NOT NULL,
                token_hash TEXT NOT NULL,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','consumed','revoked','expired')),
                consumed_at TEXT
            );
            CREATE TABLE IF NOT EXISTS replication_replicas (
                id INTEGER PRIMARY KEY,
                node_id TEXT NOT NULL UNIQUE,
                display_name TEXT NOT NULL,
                cert_fingerprint TEXT NOT NULL,
                cert_serial TEXT NOT NULL DEFAULT '',
                enrolled_at TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active','paused','revoked')),
                last_generation_acked INTEGER NOT NULL DEFAULT 0,
                last_ack_hash TEXT NOT NULL DEFAULT '',
                last_seen_at TEXT,
                last_result TEXT NOT NULL DEFAULT ''
            );
            CREATE TABLE IF NOT EXISTS replication_generations (
                id INTEGER PRIMARY KEY,
                generation_number INTEGER NOT NULL UNIQUE,
                created_at TEXT NOT NULL,
                source_node_id TEXT NOT NULL,
                schema_version INTEGER NOT NULL,
                sections TEXT NOT NULL,
                content_hash TEXT NOT NULL,
                payload TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS replication_sync_history (
                id INTEGER PRIMARY KEY,
                attempted_at TEXT NOT NULL,
                generation_number INTEGER,
                result TEXT NOT NULL,
                message TEXT NOT NULL DEFAULT ''
            );
            """
        )
        # A NULL-able marker rather than a new 'reserved' status value, so
        # this migrates additively without touching the existing status
        # CHECK constraint (which SQLite cannot ALTER in place without a
        # full table rebuild): a row is "reserved" precisely when
        # status='pending' AND reserved_at IS NOT NULL.
        _ensure_column(db, "replication_enrollments", "reserved_at", "TEXT")
        if close:
            db.commit()
    finally:
        if close:
            db.close()


DEFAULTS = {
    "role": "standalone",
    "listen_host": "0.0.0.0",
    "listen_port": str(DEFAULT_LISTEN_PORT),
    "poll_interval_seconds": str(DEFAULT_POLL_INTERVAL_SECONDS),
    "primary_address": "",
    "paused": "0",
    "include_encryption_settings": "0",
    "include_certificates": "0",
    "last_applied_generation": "0",
    "last_applied_hash": "",
    "last_sync_status": "",
    "last_sync_at": "",
    "drift_detected": "0",
    "drift_checked_at": "",
}


def node_id(conn: sqlite3.Connection | None = None) -> str:
    """This node's own stable identity. Generated once and persisted -- never
    derived from hostname, which is explicitly excluded from the replicated
    payload and must not double as node identity either."""
    close = conn is None
    db = conn or connect()
    try:
        init_db(db)
        row = db.execute("SELECT value FROM replication_settings WHERE key='node_id'").fetchone()
        if row:
            return row["value"]
        value = str(uuid.uuid4())
        db.execute("INSERT INTO replication_settings(key, value) VALUES ('node_id', ?)", (value,))
        db.commit()
        return value
    finally:
        if close:
            db.close()


def settings(conn: sqlite3.Connection | None = None) -> dict[str, str]:
    close = conn is None
    db = conn or connect()
    try:
        init_db(db)
        node_id(db)
        for key, value in DEFAULTS.items():
            db.execute("INSERT OR IGNORE INTO replication_settings(key, value) VALUES (?, ?)", (key, value))
        db.commit()
        return {row["key"]: row["value"] for row in db.execute("SELECT key, value FROM replication_settings")}
    finally:
        if close:
            db.close()


def update_settings(values: dict[str, Any], conn: sqlite3.Connection | None = None) -> None:
    close = conn is None
    db = conn or connect()
    try:
        init_db(db)
        for key, value in values.items():
            db.execute(
                "INSERT INTO replication_settings(key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (key, str(value)),
            )
        if close:
            db.commit()
    finally:
        if close:
            db.close()


def set_role(role: str, conn: sqlite3.Connection | None = None) -> None:
    if role not in ROLES:
        raise ReplicationError(f"unknown role {role!r}")
    update_settings({"role": role}, conn)


# ---------------------------------------------------------------------------
# Certificates (reuses app.encryption's local CA rather than a second one)
# ---------------------------------------------------------------------------

def _fingerprint(cert_pem: bytes) -> str:
    STAGING_DIR.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=str(STAGING_DIR)) as tmp:
        cert_path = Path(tmp) / "cert.pem"
        cert_path.write_bytes(cert_pem)
        out = run(["openssl", "x509", "-in", str(cert_path), "-noout", "-fingerprint", "-sha256"], check=False).stdout
    return out.split("=", 1)[-1].strip().replace(":", "").lower()


def _serial_of(cert_pem: bytes) -> str:
    STAGING_DIR.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=str(STAGING_DIR)) as tmp:
        cert_path = Path(tmp) / "cert.pem"
        cert_path.write_bytes(cert_pem)
        out = run(["openssl", "x509", "-in", str(cert_path), "-noout", "-serial"], check=False).stdout
    return out.split("=", 1)[-1].strip()


def _issue_cert(cn: str, ext_lines: list[str], days: int, is_server: bool) -> tuple[bytes, bytes]:
    """Sign a CSR with Alderpoint DNS's local CA (app.encryption.ensure_local_ca).
    Mirrors app.encryption.issue_from_local_ca's exact openssl invocation
    pattern but writes to caller-chosen in-memory PEM bytes instead of the
    fixed Encryption Settings server-cert path, and supports client-auth
    extended key usage for replica identities."""
    encryption.ensure_local_ca()
    STAGING_DIR.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=str(STAGING_DIR)) as tmp:
        tmp_path = Path(tmp)
        key_out = tmp_path / "leaf.key"
        csr_out = tmp_path / "leaf.csr"
        cert_out = tmp_path / "leaf.crt"
        ext_file = tmp_path / "leaf.ext"
        ext_file.write_text("\n".join(ext_lines) + "\n")
        run(["openssl", "genrsa", "-out", str(key_out), "2048"])
        run(["openssl", "req", "-new", "-key", str(key_out), "-subj", f"/CN={cn}", "-out", str(csr_out)])
        run(
            [
                "openssl", "x509", "-req", "-in", str(csr_out),
                "-CA", str(encryption.CA_CERT_PATH), "-CAkey", str(encryption.CA_KEY_PATH),
                "-CAcreateserial", "-CAserial", str(encryption.CA_SERIAL_PATH),
                "-days", str(days), "-sha256", "-extfile", str(ext_file),
                "-out", str(cert_out),
            ]
        )
        return cert_out.read_bytes(), key_out.read_bytes()


def issue_client_cert(replica_node_id: str, days: int = 825) -> dict[str, Any]:
    """Issue a client certificate identifying one replica. Only the CN
    (a stable node id, not a DNS name) matters for a client cert -- there is
    no SAN to check the way there is for a server cert."""
    cert_pem, key_pem = _issue_cert(
        replica_node_id,
        ["extendedKeyUsage=clientAuth", "keyUsage=digitalSignature"],
        days,
        is_server=False,
    )
    return {
        "cert_pem": cert_pem.decode(),
        "key_pem": key_pem.decode(),
        "fingerprint": _fingerprint(cert_pem),
        "serial": _serial_of(cert_pem),
    }


def ensure_server_cert() -> tuple[Path, Path]:
    """Server certificate for the primary's mTLS replication listener.

    Design choice (documented per the task): the replication endpoint always
    uses a certificate issued by Alderpoint DNS's own local CA, regardless of the
    Encryption Settings cert_mode (self-signed/local-CA/uploaded/existing-
    path) configured for DoH/DoT/etc. Replication's trust root must be the
    same CA that signs replica client certs, so mixing in an uploaded/
    external server cert here would add complexity without any real security
    benefit -- replicas only ever need to trust Alderpoint DNS's own CA.
    """
    if SERVER_CERT_PATH.exists() and SERVER_KEY_PATH.exists():
        return SERVER_CERT_PATH, SERVER_KEY_PATH
    ip = encryption.detect_server_ip()
    sans = ["DNS:alderpointdns-primary", "IP:127.0.0.1"]
    if ip and ip != "127.0.0.1":
        sans.append(f"IP:{ip}")
    cert_pem, key_pem = _issue_cert(
        "alderpointdns-replication-primary",
        [f"subjectAltName={','.join(dict.fromkeys(sans))}", "extendedKeyUsage=serverAuth", "keyUsage=digitalSignature,keyEncipherment"],
        3650,
        is_server=True,
    )
    REPL_DIR.mkdir(parents=True, exist_ok=True)
    SERVER_CERT_PATH.write_bytes(cert_pem)
    SERVER_CERT_PATH.chmod(0o644)
    SERVER_KEY_PATH.write_bytes(key_pem)
    SERVER_KEY_PATH.chmod(0o644)
    try:
        shutil.chown(SERVER_KEY_PATH, user="alderpointdns", group="alderpointdns")
        shutil.chown(SERVER_CERT_PATH, user="alderpointdns", group="alderpointdns")
    except (LookupError, PermissionError):
        pass
    return SERVER_CERT_PATH, SERVER_KEY_PATH


# ---------------------------------------------------------------------------
# Enrollment (primary side)
# ---------------------------------------------------------------------------

def _hash_token(raw: str) -> str:
    return hashlib.sha256(raw.encode()).hexdigest()


def generate_enrollment_token(node_name: str, conn: sqlite3.Connection | None = None) -> dict[str, Any]:
    """Create a one-time, single-use, short-lived enrollment token bound to
    a specific intended replica identity. The raw token is returned exactly
    once and never stored -- only its hash is persisted."""
    name = (node_name or "").strip()
    if not name:
        raise ReplicationError("node_name is required")
    close = conn is None
    db = conn or connect()
    try:
        init_db(db)
        raw_token = secrets.token_urlsafe(32)
        new_node_id = str(uuid.uuid4())
        created = now()
        expires = (dt.datetime.now(dt.timezone.utc) + dt.timedelta(minutes=ENROLLMENT_TTL_MINUTES)).replace(microsecond=0).isoformat()
        db.execute(
            "INSERT INTO replication_enrollments(node_id, node_name, token_hash, created_at, expires_at, status) VALUES (?, ?, ?, ?, ?, 'pending')",
            (new_node_id, name, _hash_token(raw_token), created, expires),
        )
        if close:
            db.commit()
        return {"token": raw_token, "node_id": new_node_id, "node_name": name, "expires_at": expires}
    finally:
        if close:
            db.close()


def revoke_enrollment(enrollment_id: int, conn: sqlite3.Connection | None = None) -> None:
    close = conn is None
    db = conn or connect()
    try:
        init_db(db)
        db.execute("UPDATE replication_enrollments SET status='revoked' WHERE id=? AND status='pending'", (enrollment_id,))
        if close:
            db.commit()
    finally:
        if close:
            db.close()


def list_enrollments(conn: sqlite3.Connection | None = None) -> list[dict[str, Any]]:
    close = conn is None
    db = conn or connect()
    try:
        init_db(db)
        _expire_stale_enrollments(db)
        rows = [dict(r) for r in db.execute("SELECT * FROM replication_enrollments ORDER BY id DESC")]
        if close:
            db.commit()
        return rows
    finally:
        if close:
            db.close()


def _expire_stale_enrollments(db: sqlite3.Connection) -> None:
    db.execute("UPDATE replication_enrollments SET status='expired' WHERE status='pending' AND expires_at < ?", (now(),))
    # Recovers an orphaned reservation -- one whose unprivileged requester
    # crashed, was killed, or otherwise never reached its own release path
    # -- so a single interrupted request can never make a token permanently
    # unusable. Real requests finish (consume or release) in well under a
    # second; only a genuinely abandoned reservation is ever this old.
    stale_before = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(seconds=RESERVATION_TTL_SECONDS)).replace(microsecond=0).isoformat()
    db.execute(
        "UPDATE replication_enrollments SET reserved_at=NULL WHERE status='pending' AND reserved_at IS NOT NULL AND reserved_at < ?",
        (stale_before,),
    )


def consume_enrollment(raw_token: str, cert_days: int = 825, conn: sqlite3.Connection | None = None) -> dict[str, Any]:
    """Primary-side: verify a presented enrollment token (hash compare, not
    expired, not consumed) then, and only then, issue a client certificate
    and record the replica. No partial state changes happen on rejection."""
    close = conn is None
    db = conn or connect()
    try:
        init_db(db)
        _expire_stale_enrollments(db)
        token_hash = _hash_token(raw_token)
        row = db.execute(
            "SELECT * FROM replication_enrollments WHERE token_hash=? AND status='pending' AND expires_at >= ?",
            (token_hash, now()),
        ).fetchone()
        if row is None:
            raise ReplicationError("enrollment token is invalid, expired, or already used")
        return _finish_enrollment(db, row, cert_days)
    except Exception:
        db.rollback()
        raise
    finally:
        if close:
            db.close()


# /etc/alderpointdns/certs is root:_dnsdist 0751 -- traversable so the
# unprivileged alderpointdns web process (which is what runs the primary's
# HTTP replication listener, see
# start_primary_listener/ensure_primary_listener_running) can read the
# public cert material, but it still cannot write the CA material
# consume_enrollment() needs. So, exactly like every other Alderpoint DNS
# feature that needs a privileged filesystem write, the listener only
# validates the token itself (a plain SQLite write, no privilege required)
# and hands the *hash* of the now-reserved token to the privileged
# alderpointdns_compiler.py replication-consume-enrollment sudo entry over
# its stdin (never argv, so it never appears in `ps`) to actually read and
# process. Unlike dns_cache's request_flush/process_pending_flush or
# backup's request_backup/process_pending_request -- where a periodic
# consumer processes whatever is queued and doesn't need to trace a result
# back to one specific caller -- this HTTP handler must reply to the exact
# replica that asked with the exact certificate material for the exact
# token it presented. Passing the reservation's own token_hash directly
# into the subprocess is what makes that correct: an id-less shared file
# would let two concurrent /replication/enroll requests race on which
# subprocess consumes which reservation and each replica could be handed
# back the wrong certificate. See request_enrollment_consumption(),
# release_enrollment_reservation(), and process_pending_enrollment_consumption()
# for the three-step reserve / run-privileged-step / consume-or-release
# lifecycle this implements.


def request_enrollment_consumption(raw_token: str, conn: sqlite3.Connection | None = None) -> dict[str, Any]:
    """Unprivileged-safe: atomically reserves the token (a short write
    transaction, committed before returning) and hands back its hash for
    the caller to pass to the privileged step over stdin. Never touches
    certificate material.

    The reservation UPDATE's WHERE clause (status='pending' AND
    reserved_at IS NULL) is the sole source of concurrency safety here:
    SQLite serializes writers, so if two requests present the same token
    at once, at most one UPDATE can match a row still eligible for
    reservation -- the other necessarily affects zero rows and raises,
    rather than both proceeding to spend a real privileged cert-issuance
    step on the same token. Replays of an already-consumed token or a
    token some other reservation is currently holding fail exactly the
    same way, with exactly the same error message, deliberately not
    distinguishing "which" invalid state applies -- a rejected caller
    learns only that this token cannot be used right now."""
    close = conn is None
    db = conn or connect()
    try:
        init_db(db)
        _expire_stale_enrollments(db)
        # Committed on its own, independent of whatever happens below: this
        # sweep's effect (expiring dead tokens, releasing orphaned
        # reservations) is beneficial regardless of whether *this* caller's
        # own token turns out to be valid, and must not be undone by a
        # rollback triggered by this request's own rejection.
        db.commit()
        token_hash = _hash_token(raw_token)
        reserved_at = now()
        cursor = retry_on_locked(
            lambda: db.execute(
                """
                UPDATE replication_enrollments
                SET reserved_at=?
                WHERE token_hash=? AND status='pending' AND reserved_at IS NULL AND expires_at >= ?
                """,
                (reserved_at, token_hash, now()),
            )
        )
        if cursor.rowcount != 1:
            raise ReplicationError("enrollment token is invalid, expired, or already used")
        row = db.execute(
            "SELECT node_id, node_name FROM replication_enrollments WHERE token_hash=?",
            (token_hash,),
        ).fetchone()
        # Committed immediately (not left to the caller) so this short
        # reservation transaction's writer lock is released right away --
        # the caller is about to invoke a blocking sudo subprocess with no
        # database transaction of its own open at all.
        db.commit()
        return {"node_id": row["node_id"], "node_name": row["node_name"], "token_hash": token_hash}
    finally:
        if close:
            db.close()


def release_enrollment_reservation(token_hash: str, conn: sqlite3.Connection | None = None) -> None:
    """Reverts a reservation made by request_enrollment_consumption() back
    to a plain, unreserved pending token. Call this whenever the privileged
    step did not demonstrably succeed (it raised, exited nonzero, or its
    output could not be parsed) so a single failed attempt never leaves an
    otherwise-valid token stuck and unusable -- the replica can simply
    retry with the same token. A no-op if the token was already consumed
    (status is no longer 'pending') or already released."""
    close = conn is None
    db = conn or connect()
    try:
        init_db(db)
        retry_on_locked(
            lambda: db.execute(
                "UPDATE replication_enrollments SET reserved_at=NULL WHERE token_hash=? AND status='pending'",
                (token_hash,),
            )
        )
        # Committed immediately for the same reason as the reservation
        # itself: this may run on a long-lived per-request connection, and
        # the release must take effect (and drop the writer lock) right
        # away rather than whenever that connection eventually closes.
        db.commit()
    finally:
        if close:
            db.close()


def process_pending_enrollment_consumption(token_hash: str, cert_days: int = 825, conn: sqlite3.Connection | None = None) -> dict[str, Any]:
    """Executed by the privileged compiler process, given the reservation's
    token_hash (read from stdin by the CLI entry point -- never an argv
    value, and never a shared file another concurrent invocation could
    clobber or race on). Finishes the specific reservation identified by
    that hash: issues the client certificate, then completes the state
    transition to 'consumed' in one short transaction. Raises rather than
    silently doing nothing if the reservation can't be found, since a
    caller always has a specific token_hash it expects to be reservable."""
    if not token_hash:
        raise ReplicationError("no enrollment reservation token provided")
    close = conn is None
    db = conn or connect()
    try:
        init_db(db)
        row = db.execute(
            "SELECT * FROM replication_enrollments WHERE token_hash=? AND status='pending' AND reserved_at IS NOT NULL",
            (token_hash,),
        ).fetchone()
        if row is None:
            raise ReplicationError("enrollment reservation is invalid, expired, or already completed")
        return _finish_enrollment(db, row, cert_days)
    except Exception:
        db.rollback()
        raise
    finally:
        if close:
            db.close()


def _finish_enrollment(db: sqlite3.Connection, row: sqlite3.Row, cert_days: int) -> dict[str, Any]:
    issued = issue_client_cert(row["node_id"], days=cert_days)
    ts = now()
    db.execute(
        """
        INSERT INTO replication_replicas(node_id, display_name, cert_fingerprint, cert_serial, enrolled_at, status)
        VALUES (?, ?, ?, ?, ?, 'active')
        ON CONFLICT(node_id) DO UPDATE SET
          cert_fingerprint=excluded.cert_fingerprint, cert_serial=excluded.cert_serial,
          enrolled_at=excluded.enrolled_at, status='active'
        """,
        (row["node_id"], row["node_name"], issued["fingerprint"], issued["serial"], ts),
    )
    db.execute("UPDATE replication_enrollments SET status='consumed', consumed_at=? WHERE id=?", (ts, row["id"]))
    db.commit()
    ensure_server_cert()
    return {
        "node_id": row["node_id"],
        "node_name": row["node_name"],
        "ca_cert_pem": encryption.CA_CERT_PATH.read_text(),
        "client_cert_pem": issued["cert_pem"],
        "client_key_pem": issued["key_pem"],
    }


def list_replicas(conn: sqlite3.Connection | None = None) -> list[dict[str, Any]]:
    close = conn is None
    db = conn or connect()
    try:
        init_db(db)
        rows = [dict(r) for r in db.execute("SELECT * FROM replication_replicas ORDER BY id DESC")]
        return rows
    finally:
        if close:
            db.close()


def set_replica_status(replica_id: int, status: str, conn: sqlite3.Connection | None = None) -> None:
    if status not in {"active", "paused", "revoked"}:
        raise ReplicationError(f"unknown replica status {status!r}")
    close = conn is None
    db = conn or connect()
    try:
        init_db(db)
        db.execute("UPDATE replication_replicas SET status=? WHERE id=?", (status, replica_id))
        if close:
            db.commit()
    finally:
        if close:
            db.close()


def _replica_by_fingerprint(db: sqlite3.Connection, fingerprint: str) -> sqlite3.Row | None:
    return db.execute("SELECT * FROM replication_replicas WHERE cert_fingerprint=?", (fingerprint,)).fetchone()


# ---------------------------------------------------------------------------
# Replicable payload: strict allowlist, with an explicit denylist enforced
# even if an allowlisted table later grows a new column.
# ---------------------------------------------------------------------------

# table -> tuple of columns to select. Only these exact columns are ever
# read; a new column added to one of these tables later is NOT replicated
# unless someone deliberately adds it here.
REPLICABLE_TABLES: dict[str, tuple[str, ...]] = {
    "sources": ("name", "url", "enabled", "category"),
    "custom_rules": ("domain", "action", "enabled", "comment", "created_at"),
    "custom_filter_rules": (
        "rule_text", "normalized", "rule_type", "action", "domain", "match_subdomains",
        "pattern", "rewrite_address", "address_family", "qtype_restriction", "priority",
        "enabled", "validation_state", "unsupported_reason", "source_system", "comment",
        "created_at", "updated_at",
    ),
    "categories": ("key", "name", "description"),
    "policy_profiles": ("key", "name", "description", "is_custom"),
    "profile_categories": ("profile_key", "category_key", "enabled"),
    "network_policies": ("cidr", "profile_key", "description", "enabled"),
    "local_dns_records": ("name", "fqdn", "record_type", "value", "ttl", "comment", "enabled", "auto_ptr", "created_at", "updated_at"),
    "client_aliases": ("cidr", "display_name", "description", "created_at", "updated_at"),
}
# local_dns_settings and dns_cache_settings are key/value tables; only these
# specific keys are replicable. server_hostname/server_ip are node identity
# and listen-address data and are explicitly never replicated.
REPLICABLE_LOCAL_DNS_SETTING_KEYS = ("internal_domain", "default_ttl")
REPLICABLE_CACHE_SETTING_KEYS = (
    "max_cache_size_mb", "min_cache_ttl", "max_cache_ttl", "min_ncache_ttl", "max_ncache_ttl",
    "prefetch_enabled", "prefetch_trigger", "prefetch_eligible",
    "serve_stale_enabled", "max_stale_ttl", "stale_answer_client_timeout",
)
REPLICABLE_ENCRYPTION_SETTING_KEYS = (
    "doh_enabled", "doh3_enabled", "dot_enabled", "doq_enabled", "dnscrypt_enabled",
    "doh_path", "doh_port", "doh3_port", "dot_port", "doq_port", "dnscrypt_port",
)

# Explicit denylist -- defense in depth. Even though build_payload() only
# ever touches REPLICABLE_TABLES above, this set is checked positively by
# tests and by build_payload() itself, so adding a table to
# REPLICABLE_TABLES by mistake in the future cannot silently start shipping
# query logs, analytics, credentials, or node identity to every replica.
NEVER_REPLICATED_TABLES = {
    "query_events", "analytics_events", "analytics_aggregate_buckets", "analytics_counter_state",
    "admins", "login_attempts", "deployments", "local_dns_deployments", "dns_cache_deployments",
    "dns_cache_flushes", "encryption_deployments", "import_jobs",
    "replication_settings", "replication_enrollments", "replication_replicas",
    "replication_generations", "replication_sync_history",
    # Managed upstream DNS resolvers are appliance-local by design: dns1 and
    # dns2 can (and, in the incident this denylist entry documents, did)
    # legitimately need different upstream resolvers, and each appliance's
    # own app.upstream_dns.deploy_upstreams() already keeps its own
    # upstream_resolvers rows and its own live dnsdist config reconciled.
    # Replicating this table would let a primary silently override a
    # replica's independently-managed upstream resolvers -- explicitly
    # listed here (not just "not in REPLICABLE_TABLES") so this stays true
    # even if someone adds it to REPLICABLE_TABLES by mistake later.
    "upstream_resolvers", "upstream_deployments",
}


def _table_exists(db: sqlite3.Connection, table: str) -> bool:
    return db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,)).fetchone() is not None


def build_payload(conn: sqlite3.Connection, include_encryption_settings: bool = False, include_certificates: bool = False) -> dict[str, Any]:
    """Read-only serialization of the replicable subset of live tables.
    Never writes anything; never SELECT *s a whole table -- every column
    read is named explicitly against the REPLICABLE_* allowlists above."""
    sections: dict[str, Any] = {}
    for table, columns in REPLICABLE_TABLES.items():
        if table in NEVER_REPLICATED_TABLES:  # pragma: no cover - defensive, should never trip
            continue
        if not _table_exists(conn, table):
            continue
        col_sql = ", ".join(columns)
        rows = [dict(r) for r in conn.execute(f"SELECT {col_sql} FROM {table}")]
        sections[table] = rows

    if _table_exists(conn, "local_dns_settings"):
        placeholders = ",".join("?" * len(REPLICABLE_LOCAL_DNS_SETTING_KEYS))
        rows = conn.execute(
            f"SELECT key, value FROM local_dns_settings WHERE key IN ({placeholders})",
            REPLICABLE_LOCAL_DNS_SETTING_KEYS,
        )
        sections["local_dns_settings"] = {r["key"]: r["value"] for r in rows}

    if _table_exists(conn, "dns_cache_settings"):
        placeholders = ",".join("?" * len(REPLICABLE_CACHE_SETTING_KEYS))
        rows = conn.execute(
            f"SELECT key, value FROM dns_cache_settings WHERE key IN ({placeholders})",
            REPLICABLE_CACHE_SETTING_KEYS,
        )
        sections["dns_cache_settings"] = {r["key"]: r["value"] for r in rows}

    if include_encryption_settings and _table_exists(conn, "encryption_settings"):
        placeholders = ",".join("?" * len(REPLICABLE_ENCRYPTION_SETTING_KEYS))
        rows = conn.execute(
            f"SELECT key, value FROM encryption_settings WHERE key IN ({placeholders})",
            REPLICABLE_ENCRYPTION_SETTING_KEYS,
        )
        sections["encryption_settings"] = {r["key"]: r["value"] for r in rows}

    if include_certificates:
        # Public CA certificate only. Private key bytes are never included
        # in a replicated payload, with or without this flag -- there is no
        # code path in this module that ever puts key material into
        # build_payload()'s output.
        if encryption.CA_CERT_PATH.exists():
            sections["ca_certificate_pem"] = encryption.CA_CERT_PATH.read_text()

    return sections


def canonical_json(data: Any) -> str:
    return json.dumps(data, sort_keys=True, separators=(",", ":"))


def content_hash(sections: dict[str, Any]) -> str:
    return hashlib.sha256(canonical_json(sections).encode()).hexdigest()


# ---------------------------------------------------------------------------
# Generations (primary side)
# ---------------------------------------------------------------------------

def create_generation(conn: sqlite3.Connection | None = None, include_encryption_settings: bool | None = None, include_certificates: bool | None = None) -> dict[str, Any]:
    close = conn is None
    db = conn or connect()
    try:
        init_db(db)
        cfg = settings(db)
        inc_enc = cfg.get("include_encryption_settings") == "1" if include_encryption_settings is None else include_encryption_settings
        inc_cert = cfg.get("include_certificates") == "1" if include_certificates is None else include_certificates
        sections = build_payload(db, inc_enc, inc_cert)
        digest = content_hash(sections)
        row = db.execute("SELECT MAX(generation_number) AS n FROM replication_generations").fetchone()
        next_number = (row["n"] or 0) + 1
        created = now()
        db.execute(
            """
            INSERT INTO replication_generations(generation_number, created_at, source_node_id, schema_version, sections, content_hash, payload)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (next_number, created, node_id(db), SCHEMA_VERSION, canonical_json(list(sections.keys())), digest, canonical_json(sections)),
        )
        if close:
            db.commit()
        return {
            "generation_number": next_number,
            "created_at": created,
            "source_node_id": node_id(db),
            "schema_version": SCHEMA_VERSION,
            "content_hash": digest,
            "sections": sections,
        }
    finally:
        if close:
            db.close()


def latest_generation(conn: sqlite3.Connection | None = None) -> dict[str, Any] | None:
    close = conn is None
    db = conn or connect()
    try:
        init_db(db)
        row = db.execute("SELECT * FROM replication_generations ORDER BY generation_number DESC LIMIT 1").fetchone()
        if row is None:
            return None
        return {
            "generation_number": row["generation_number"],
            "created_at": row["created_at"],
            "source_node_id": row["source_node_id"],
            "schema_version": row["schema_version"],
            "content_hash": row["content_hash"],
            "sections": json.loads(row["payload"]),
        }
    finally:
        if close:
            db.close()


def on_deploy_success(conn: sqlite3.Connection | None = None) -> dict[str, Any] | None:
    """Called at the end of a successful alderpointdns_compiler.py deploy(). A
    no-op unless this node's role is 'primary'. Deliberately never allowed
    to raise into the caller -- a replication bug must never fail an
    otherwise-successful DNS deployment."""
    close = conn is None
    db = conn or connect()
    try:
        init_db(db)
        cfg = settings(db)
        if cfg.get("role") != "primary":
            return None
        return create_generation(db)
    except Exception:
        return None
    finally:
        if close:
            db.close()


# ---------------------------------------------------------------------------
# mTLS transport
# ---------------------------------------------------------------------------

def build_server_ssl_context(server_cert: Path, server_key: Path, ca_cert: Path) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile=str(server_cert), keyfile=str(server_key))
    ctx.load_verify_locations(cafile=str(ca_cert))
    # CERT_OPTIONAL, not CERT_REQUIRED: /replication/enroll is called before
    # a replica has any client certificate at all (that is the point of
    # enrollment). Any client cert that IS presented must still chain to our
    # CA -- OpenSSL enforces that unconditionally once load_verify_locations
    # is set, regardless of OPTIONAL vs REQUIRED. Endpoints that need an
    # authenticated replica check for a peer cert themselves.
    ctx.verify_mode = ssl.CERT_OPTIONAL
    return ctx


def build_client_ssl_context(ca_cert: Path, client_cert: Path | None = None, client_key: Path | None = None) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.load_verify_locations(cafile=str(ca_cert))
    # Lab-mode simplification, documented: the primary's reachable address is
    # admin-configured (often a bare IP on this isolated VM) and may not
    # match a cert SAN, so hostname checking is disabled while CA-chain
    # verification (the actual trust boundary here) stays mandatory. A
    # production deployment reachable by stable DNS name should re-enable
    # check_hostname once SANs are guaranteed to match.
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_REQUIRED
    if client_cert and client_key:
        ctx.load_cert_chain(certfile=str(client_cert), keyfile=str(client_key))
    return ctx


@dataclass
class ServerContext:
    db_path: Path
    ca_cert: Path
    server_cert: Path
    server_key: Path


def _make_handler(ctx: ServerContext) -> type[http.server.BaseHTTPRequestHandler]:
    class Handler(http.server.BaseHTTPRequestHandler):
        server_version = "AlderpointDNSReplication/1"
        protocol_version = "HTTP/1.1"

        def log_message(self, fmt: str, *args: Any) -> None:  # noqa: A003 - stdlib signature
            pass

        def _body(self) -> dict[str, Any]:
            length = int(self.headers.get("Content-Length", "0") or "0")
            raw = self.rfile.read(length) if length else b""
            return json.loads(raw.decode()) if raw else {}

        def _reply(self, status: int, payload: dict[str, Any]) -> None:
            body = json.dumps(payload).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _peer_fingerprint(self) -> str | None:
            try:
                der = self.connection.getpeercert(binary_form=True)  # type: ignore[attr-defined]
            except (AttributeError, ValueError):
                return None
            if not der:
                return None
            return hashlib.sha256(der).hexdigest()

        def _authenticated_replica(self, db: sqlite3.Connection) -> sqlite3.Row:
            fingerprint = self._peer_fingerprint()
            if not fingerprint:
                raise PermissionError("client certificate required")
            row = _replica_by_fingerprint(db, fingerprint)
            if row is None:
                raise PermissionError("unrecognized client certificate")
            if row["status"] != "active":
                raise PermissionError(f"replica is {row['status']}")
            return row

        def do_POST(self) -> None:  # noqa: N802 - stdlib signature
            db = connect(ctx.db_path)
            try:
                if self.path == "/replication/enroll":
                    return self._handle_enroll(db)
                if self.path == "/replication/ack":
                    return self._handle_ack(db)
                self._reply(404, {"error": "not found"})
            except PermissionError as exc:
                self._reply(403, {"error": str(exc)})
            except ReplicationError as exc:
                self._reply(400, {"error": str(exc)})
            except DatabaseBusyError:
                self._reply(503, {"error": "the database is temporarily busy, please try again"})
            except Exception as exc:  # pragma: no cover - defensive
                self._reply(500, {"error": str(exc)})
            finally:
                db.close()

        def do_GET(self) -> None:  # noqa: N802 - stdlib signature
            db = connect(ctx.db_path)
            try:
                if self.path.startswith("/replication/generations/latest"):
                    return self._handle_latest(db)
                self._reply(404, {"error": "not found"})
            except PermissionError as exc:
                self._reply(403, {"error": str(exc)})
            except Exception as exc:  # pragma: no cover - defensive
                self._reply(500, {"error": str(exc)})
            finally:
                db.close()

        def _handle_enroll(self, db: sqlite3.Connection) -> None:
            body = self._body()
            token = str(body.get("token", ""))
            if not token:
                raise ReplicationError("token is required")
            # This listener runs as the unprivileged alderpointdns user and
            # cannot write /etc/alderpointdns/certs itself. request_enrollment_
            # consumption() atomically reserves the token in a short,
            # already-committed transaction -- no database write transaction
            # is open here, or anywhere else in this method, while the
            # blocking privileged sudo call below does the real CA-signing
            # work. If that privileged step doesn't demonstrably succeed,
            # the reservation is released so the token remains usable for a
            # retry rather than being stuck forever.
            reservation = request_enrollment_consumption(token, conn=db)
            try:
                proc = run(
                    ["sudo", "/opt/alderpointdns/app/alderpointdns_compiler.py", "replication-consume-enrollment"],
                    check=False,
                    input=reservation["token_hash"],
                )
                if proc.returncode != 0:
                    raise ReplicationError(f"enrollment could not be completed: {proc.stdout[-500:]}")
                result = json.loads(proc.stdout)
            except Exception:
                release_enrollment_reservation(reservation["token_hash"], conn=db)
                raise
            self._reply(200, result)

        def _handle_latest(self, db: sqlite3.Connection) -> None:
            replica = self._authenticated_replica(db)
            gen = latest_generation(db)
            db.execute("UPDATE replication_replicas SET last_seen_at=? WHERE id=?", (now(), replica["id"]))
            db.commit()
            if gen is None:
                self._reply(200, {"generation": None})
                return
            self._reply(200, {"generation": gen})

        def _handle_ack(self, db: sqlite3.Connection) -> None:
            replica = self._authenticated_replica(db)
            body = self._body()
            gen_number = int(body.get("generation_number", 0))
            gen_hash = str(body.get("content_hash", ""))
            result = str(body.get("result", "unknown"))
            message = str(body.get("message", ""))
            fields = {"last_seen_at": now(), "last_result": f"{result}: {message}"[:500]}
            if result == "success":
                fields["last_generation_acked"] = gen_number
                fields["last_ack_hash"] = gen_hash
            assignments = ", ".join(f"{k}=:{k}" for k in fields)
            fields["id"] = replica["id"]
            db.execute(f"UPDATE replication_replicas SET {assignments} WHERE id=:id", fields)
            db.commit()
            self._reply(200, {"ok": True})

    return Handler


@dataclass
class RunningServer:
    httpd: http.server.ThreadingHTTPServer
    thread: threading.Thread

    def stop(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(timeout=5)


def start_primary_listener(host: str, port: int, ctx: ServerContext) -> RunningServer:
    handler_cls = _make_handler(ctx)
    httpd = http.server.ThreadingHTTPServer((host, port), handler_cls)
    tls_ctx = build_server_ssl_context(ctx.server_cert, ctx.server_key, ctx.ca_cert)
    httpd.socket = tls_ctx.wrap_socket(httpd.socket, server_side=True)
    thread = threading.Thread(target=httpd.serve_forever, kwargs={"poll_interval": 0.2}, daemon=True)
    thread.start()
    return RunningServer(httpd, thread)


_PRIMARY_LISTENER: RunningServer | None = None
_PRIMARY_LOCK = threading.Lock()


def ensure_primary_listener_running() -> bool:
    """Idempotently (re)start the singleton in-process primary listener
    using this module's default DB_PATH and issued server cert. Returns
    True if a listener is running after the call."""
    global _PRIMARY_LISTENER
    with _PRIMARY_LOCK:
        if _PRIMARY_LISTENER is not None:
            return True
        cfg = settings()
        if cfg.get("role") != "primary":
            return False
        if not (SERVER_CERT_PATH.exists() and SERVER_KEY_PATH.exists() and encryption.CA_CERT_PATH.exists()):
            return False
        ctx = ServerContext(DB_PATH, encryption.CA_CERT_PATH, SERVER_CERT_PATH, SERVER_KEY_PATH)
        try:
            _PRIMARY_LISTENER = start_primary_listener(cfg.get("listen_host", "0.0.0.0"), int(cfg.get("listen_port", DEFAULT_LISTEN_PORT)), ctx)
        except OSError:
            return False
        return True


def stop_primary_listener() -> None:
    global _PRIMARY_LISTENER
    with _PRIMARY_LOCK:
        if _PRIMARY_LISTENER is not None:
            _PRIMARY_LISTENER.stop()
            _PRIMARY_LISTENER = None


# ---------------------------------------------------------------------------
# Replica-side HTTP client
# ---------------------------------------------------------------------------

def _https_request(host: str, port: int, method: str, path: str, ssl_ctx: ssl.SSLContext, body: dict[str, Any] | None = None, timeout: float = 10) -> tuple[int, dict[str, Any]]:
    conn = http.client.HTTPSConnection(host, port, timeout=timeout, context=ssl_ctx)
    try:
        payload = json.dumps(body or {}).encode()
        conn.request(method, path, body=payload, headers={"Content-Type": "application/json", "Content-Length": str(len(payload))})
        resp = conn.getresponse()
        raw = resp.read()
        data = json.loads(raw.decode()) if raw else {}
        return resp.status, data
    finally:
        conn.close()


def enroll_with_primary(primary_host: str, primary_port: int, token: str, ca_cert_for_bootstrap: Path | None = None) -> dict[str, Any]:
    """Replica side of the manual-token enrollment path. `ca_cert_for_bootstrap`
    is optional trust-on-first-use: if not supplied, the connection to fetch
    the CA verifies nothing yet (this single bootstrap call is inherently a
    trust-on-first-use step, same as any enrollment token flow) -- once this
    call returns the CA certificate, every subsequent call is fully verified
    against it."""
    if ca_cert_for_bootstrap and ca_cert_for_bootstrap.exists():
        ctx = build_client_ssl_context(ca_cert_for_bootstrap)
    else:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    status, data = _https_request(primary_host, primary_port, "POST", "/replication/enroll", ctx, {"token": token})
    if status != 200:
        raise ReplicationError(data.get("error", f"enrollment failed with HTTP {status}"))
    return data


@dataclass
class ReplicaContext:
    db_path: Path
    primary_host: str
    primary_port: int
    ca_cert: Path
    client_cert: Path
    client_key: Path
    deploy_fn: Callable[[], tuple[bool, str]] | None = None


def _default_deploy_fn() -> tuple[bool, str]:
    proc = subprocess.run(
        ["sudo", "/opt/alderpointdns/app/alderpointdns_compiler.py", "deploy", "--no-download"],
        text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
    )
    return proc.returncode == 0, proc.stdout[-4000:]


def fetch_latest_generation(rc: ReplicaContext) -> dict[str, Any] | None:
    ctx = build_client_ssl_context(rc.ca_cert, rc.client_cert, rc.client_key)
    status, data = _https_request(rc.primary_host, rc.primary_port, "GET", "/replication/generations/latest", ctx)
    if status != 200:
        raise ReplicationError(data.get("error", f"fetch failed with HTTP {status}"))
    return data.get("generation")


def ack_generation(rc: ReplicaContext, generation_number: int, content_hash_value: str, result: str, message: str = "") -> None:
    ctx = build_client_ssl_context(rc.ca_cert, rc.client_cert, rc.client_key)
    _https_request(
        rc.primary_host, rc.primary_port, "POST", "/replication/ack", ctx,
        {"generation_number": generation_number, "content_hash": content_hash_value, "result": result, "message": message},
    )


# ---------------------------------------------------------------------------
# Replica apply pipeline
# ---------------------------------------------------------------------------

def _snapshot_replicable_tables(db: sqlite3.Connection) -> dict[str, Any]:
    snapshot: dict[str, Any] = {}
    for table, columns in REPLICABLE_TABLES.items():
        if not _table_exists(db, table):
            continue
        col_sql = ", ".join(columns)
        snapshot[table] = [dict(r) for r in db.execute(f"SELECT {col_sql} FROM {table}")]
    if _table_exists(db, "local_dns_settings"):
        placeholders = ",".join("?" * len(REPLICABLE_LOCAL_DNS_SETTING_KEYS))
        snapshot["local_dns_settings"] = {
            r["key"]: r["value"] for r in db.execute(f"SELECT key, value FROM local_dns_settings WHERE key IN ({placeholders})", REPLICABLE_LOCAL_DNS_SETTING_KEYS)
        }
    if _table_exists(db, "dns_cache_settings"):
        placeholders = ",".join("?" * len(REPLICABLE_CACHE_SETTING_KEYS))
        snapshot["dns_cache_settings"] = {
            r["key"]: r["value"] for r in db.execute(f"SELECT key, value FROM dns_cache_settings WHERE key IN ({placeholders})", REPLICABLE_CACHE_SETTING_KEYS)
        }
    if _table_exists(db, "encryption_settings"):
        placeholders = ",".join("?" * len(REPLICABLE_ENCRYPTION_SETTING_KEYS))
        snapshot["encryption_settings"] = {
            r["key"]: r["value"] for r in db.execute(f"SELECT key, value FROM encryption_settings WHERE key IN ({placeholders})", REPLICABLE_ENCRYPTION_SETTING_KEYS)
        }
    return snapshot


def _replace_settings_subset(db: sqlite3.Connection, table: str, allowed_keys: tuple[str, ...], values: dict[str, Any]) -> None:
    if not _table_exists(db, table):
        return
    placeholders = ",".join("?" * len(allowed_keys))
    db.execute(f"DELETE FROM {table} WHERE key IN ({placeholders})", allowed_keys)
    db.executemany(
        f"INSERT INTO {table}(key, value) VALUES (?, ?)",
        [(key, str(value)) for key, value in values.items() if key in allowed_keys],
    )


def _restore_snapshot(db: sqlite3.Connection, snapshot: dict[str, Any]) -> None:
    for table, columns in REPLICABLE_TABLES.items():
        if table not in snapshot or not _table_exists(db, table):
            continue
        db.execute(f"DELETE FROM {table}")
        rows = snapshot[table]
        if rows:
            cols = list(rows[0].keys())
            placeholders = ", ".join("?" * len(cols))
            db.executemany(
                f"INSERT INTO {table}({', '.join(cols)}) VALUES ({placeholders})",
                [tuple(row[c] for c in cols) for row in rows],
            )
    _replace_settings_subset(db, "local_dns_settings", REPLICABLE_LOCAL_DNS_SETTING_KEYS, snapshot.get("local_dns_settings", {}))
    _replace_settings_subset(db, "dns_cache_settings", REPLICABLE_CACHE_SETTING_KEYS, snapshot.get("dns_cache_settings", {}))
    _replace_settings_subset(db, "encryption_settings", REPLICABLE_ENCRYPTION_SETTING_KEYS, snapshot.get("encryption_settings", {}))
    db.commit()


def _apply_sections(db: sqlite3.Connection, sections: dict[str, Any]) -> None:
    """Overwrite a replica's own replicated tables with the generation's
    content. v1 design choice (documented): these tables are treated as
    fully primary-owned on a replica once replication is enabled -- each
    successful sync fully replaces them rather than diffing/merging, which
    keeps the apply/rollback logic simple and unambiguous. A future version
    could track row provenance to allow replica-local additions alongside
    replicated rows."""
    for table, columns in REPLICABLE_TABLES.items():
        if table not in sections or not _table_exists(db, table):
            continue
        db.execute(f"DELETE FROM {table}")
        rows = sections[table]
        if rows:
            cols = list(columns)
            placeholders = ", ".join("?" * len(cols))
            db.executemany(
                f"INSERT INTO {table}({', '.join(cols)}) VALUES ({placeholders})",
                [tuple(row[c] for c in cols) for row in rows],
            )
    _replace_settings_subset(db, "local_dns_settings", REPLICABLE_LOCAL_DNS_SETTING_KEYS, sections.get("local_dns_settings", {}))
    _replace_settings_subset(db, "dns_cache_settings", REPLICABLE_CACHE_SETTING_KEYS, sections.get("dns_cache_settings", {}))
    _replace_settings_subset(db, "encryption_settings", REPLICABLE_ENCRYPTION_SETTING_KEYS, sections.get("encryption_settings", {}))
    db.commit()


def replica_sync_once(rc: ReplicaContext, force: bool = False) -> dict[str, Any]:
    """The full replica apply pipeline. Never raises for ordinary sync
    failures (network down, primary unreachable, hash mismatch, deploy
    failure, revoked cert) -- every failure is caught, recorded to
    replication_sync_history, and returned as a result dict, so a caller
    running this on a schedule can never have it crash the polling loop or
    (transitively) any DNS-serving process."""
    db = connect(rc.db_path)
    result: dict[str, Any] = {"attempted_at": now(), "result": "error", "message": "", "generation_number": None}
    try:
        init_db(db)
        cfg = settings(db)
        if cfg.get("paused") == "1" and not force:
            result.update(result="skipped", message="replication is paused")
            return result

        # 1. Fetch latest generation over mTLS.
        try:
            generation = fetch_latest_generation(rc)
        except Exception as exc:
            # Primary unavailable: this is not an error state for DNS. The
            # replica simply keeps serving whatever it last applied.
            result.update(result="unreachable", message=str(exc))
            return result

        if generation is None:
            result.update(result="no_generation", message="primary has not published a generation yet")
            return result

        gen_number = int(generation["generation_number"])
        gen_hash = generation["content_hash"]
        result["generation_number"] = gen_number

        if not force and gen_number <= int(cfg.get("last_applied_generation", "0")):
            result.update(result="up_to_date", message=f"already at generation {cfg.get('last_applied_generation')}")
            return result

        if int(generation.get("schema_version", SCHEMA_VERSION)) > SCHEMA_VERSION:
            result.update(result="failed", message=f"generation requires schema version {generation['schema_version']}, this replica only supports {SCHEMA_VERSION}")
            return result

        # 2. Authenticate (mTLS already did this) and verify hash.
        sections = generation["sections"]
        if content_hash(sections) != gen_hash:
            result.update(result="failed", message="payload content hash did not match the generation's declared hash")
            try:
                ack_generation(rc, gen_number, gen_hash, "failed", result["message"])
            except Exception:
                pass
            return result

        # 3. Save previous state.
        snapshot = _snapshot_replicable_tables(db)

        # 4-5. Stage + apply into live tables.
        try:
            _apply_sections(db, sections)
        except Exception as exc:
            db.rollback()
            result.update(result="failed", message=f"failed to apply staged data: {exc}")
            try:
                ack_generation(rc, gen_number, gen_hash, "failed", result["message"])
            except Exception:
                pass
            return result

        # 6-9. Reuse the existing compiler's staged/validate/atomic/rollback/
        # health-check/functional-test deploy pipeline -- never reimplemented
        # here.
        deploy_fn = rc.deploy_fn or _default_deploy_fn
        ok, deploy_output = deploy_fn()
        if not ok:
            # 11. Roll back the SQLite changes too; the compiler's own deploy()
            # already rolled its own BIND/dnsdist state back to the previous
            # good config.
            _restore_snapshot(db, snapshot)
            result.update(result="failed", message=f"deploy failed, rolled back: {deploy_output[-500:]}")
            try:
                ack_generation(rc, gen_number, gen_hash, "failed", result["message"])
            except Exception:
                pass
            return result

        # 10. Acknowledge success.
        update_settings({"last_applied_generation": gen_number, "last_applied_hash": gen_hash, "last_sync_status": "success", "last_sync_at": now(), "drift_detected": "0"}, db)
        db.commit()
        try:
            ack_generation(rc, gen_number, gen_hash, "success", "applied")
        except Exception:
            pass
        result.update(result="success", message=f"applied generation {gen_number}")
        return result
    except Exception as exc:  # pragma: no cover - defensive catch-all
        result.update(result="error", message=str(exc))
        return result
    finally:
        try:
            db.execute(
                "INSERT INTO replication_sync_history(attempted_at, generation_number, result, message) VALUES (?, ?, ?, ?)",
                (result["attempted_at"], result["generation_number"], result["result"], result["message"]),
            )
            update_settings({"last_sync_status": result["result"], "last_sync_at": now()}, db)
            db.commit()
        except Exception:
            pass
        db.close()


def check_drift(rc: ReplicaContext) -> dict[str, Any]:
    """Recompute this replica's own live-table hash and compare it against
    the hash it last successfully applied. Used for scheduled reconciliation
    and surfaced as a clear 'drifted' status -- catches manual edits made
    directly on the replica outside of replication."""
    db = connect(rc.db_path)
    try:
        init_db(db)
        cfg = settings(db)
        expected = cfg.get("last_applied_hash", "")
        local_sections = build_payload(db)
        local_hash = content_hash(local_sections)
        drifted = bool(expected) and local_hash != expected
        update_settings({"drift_detected": "1" if drifted else "0", "drift_checked_at": now()}, db)
        db.commit()
        return {"drifted": drifted, "local_hash": local_hash, "expected_hash": expected}
    finally:
        db.close()


def sync_history(conn: sqlite3.Connection | None = None, limit: int = 20) -> list[dict[str, Any]]:
    close = conn is None
    db = conn or connect()
    try:
        init_db(db)
        return [dict(r) for r in db.execute("SELECT * FROM replication_sync_history ORDER BY id DESC LIMIT ?", (limit,))]
    finally:
        if close:
            db.close()


# ---------------------------------------------------------------------------
# Background poll loop (replica side)
# ---------------------------------------------------------------------------

class ReplicaPoller:
    """Periodic polling with a fixed short retry interval on success and
    capped exponential backoff on failure (documented choice: a fixed
    interval alone would hammer an unreachable primary; unbounded backoff
    could leave a recovered primary undetected for too long)."""

    def __init__(self, rc: ReplicaContext, interval_seconds: int = DEFAULT_POLL_INTERVAL_SECONDS) -> None:
        self.rc = rc
        self.base_interval = interval_seconds
        self._stop = threading.Event()
        self._wake = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        self._wake.set()
        if self._thread:
            self._thread.join(timeout=5)

    def sync_now(self) -> dict[str, Any]:
        self._wake.set()
        return replica_sync_once(self.rc, force=True)

    def _loop(self) -> None:
        backoff = self.base_interval
        while not self._stop.is_set():
            try:
                result = replica_sync_once(self.rc)
                backoff = self.base_interval if result["result"] in {"success", "up_to_date", "skipped", "no_generation"} else min(backoff * 2, MAX_BACKOFF_SECONDS)
            except Exception:
                backoff = min(backoff * 2, MAX_BACKOFF_SECONDS)
            self._wake.wait(timeout=backoff)
            self._wake.clear()


_REPLICA_POLLER: ReplicaPoller | None = None
_REPLICA_LOCK = threading.Lock()


def ensure_replica_poller_running() -> bool:
    global _REPLICA_POLLER
    with _REPLICA_LOCK:
        cfg = settings()
        if cfg.get("role") != "replica":
            return False
        client_cert = REPL_DIR / "client.crt"
        client_key = REPL_DIR / "client.key"
        ca_cert = REPL_DIR / "ca.crt"
        if not (client_cert.exists() and client_key.exists() and ca_cert.exists()):
            return False
        primary_address = cfg.get("primary_address", "")
        if not primary_address:
            return False
        host, _, port_str = primary_address.partition(":")
        port = int(port_str) if port_str else DEFAULT_LISTEN_PORT
        rc = ReplicaContext(DB_PATH, host, port, ca_cert, client_cert, client_key)
        if _REPLICA_POLLER is None:
            _REPLICA_POLLER = ReplicaPoller(rc, int(cfg.get("poll_interval_seconds", DEFAULT_POLL_INTERVAL_SECONDS)))
            _REPLICA_POLLER.start()
        return True


def _build_replica_context() -> ReplicaContext | None:
    cfg = settings()
    if cfg.get("role") != "replica":
        return None
    client_cert, client_key, ca_cert = REPL_DIR / "client.crt", REPL_DIR / "client.key", REPL_DIR / "ca.crt"
    if not (client_cert.exists() and client_key.exists() and ca_cert.exists()):
        return None
    primary_address = cfg.get("primary_address", "")
    if not primary_address:
        return None
    host, _, port_str = primary_address.partition(":")
    port = int(port_str) if port_str else DEFAULT_LISTEN_PORT
    return ReplicaContext(DB_PATH, host, port, ca_cert, client_cert, client_key)


def trigger_sync_now() -> dict[str, Any]:
    """Web-triggered manual "Sync Now", independent of the background
    poller's own schedule."""
    rc = _build_replica_context()
    if rc is None:
        raise ReplicationError("this node is not an enrolled replica")
    if _REPLICA_POLLER is not None:
        return _REPLICA_POLLER.sync_now()
    return replica_sync_once(rc, force=True)


def trigger_drift_check() -> dict[str, Any]:
    rc = _build_replica_context()
    if rc is None:
        raise ReplicationError("this node is not an enrolled replica")
    return check_drift(rc)


def stop_replica_poller() -> None:
    global _REPLICA_POLLER
    with _REPLICA_LOCK:
        if _REPLICA_POLLER is not None:
            _REPLICA_POLLER.stop()
            _REPLICA_POLLER = None


def autostart() -> None:
    """Called once at web-app startup so a service restart re-establishes
    whichever role was previously configured, without any admin action."""
    try:
        cfg = settings()
        if cfg.get("role") == "primary":
            ensure_primary_listener_running()
        elif cfg.get("role") == "replica":
            ensure_replica_poller_running()
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Replica-side enrollment bootstrap (stores issued material for the poller)
# ---------------------------------------------------------------------------

def store_enrollment_material(primary_address: str, enrolled: dict[str, Any]) -> None:
    """Persist what enroll_with_primary() returned so the replica's own
    poller can use it. `enrolled` is the dict returned by
    consume_enrollment() on the primary (relayed back to this replica over
    the token-authenticated HTTPS call)."""
    REPL_DIR.mkdir(parents=True, exist_ok=True)
    (REPL_DIR / "ca.crt").write_text(enrolled["ca_cert_pem"])
    (REPL_DIR / "client.crt").write_text(enrolled["client_cert_pem"])
    client_key_path = REPL_DIR / "client.key"
    client_key_path.write_text(enrolled["client_key_pem"])
    client_key_path.chmod(0o600)
    update_settings(
        {
            "role": "replica",
            "primary_address": primary_address,
            "last_applied_generation": "0",
            "last_applied_hash": "",
        }
    )
