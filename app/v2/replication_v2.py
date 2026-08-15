"""V2 mTLS replication protocol and bounded state application."""

from __future__ import annotations

import hashlib
import http.client
import http.server
import ipaddress
import json
import os
import ssl
import threading
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from app.v2 import control_db, node_identity, notification_store, policy_store, runtime_compile
from app.v2.secret_store import SecretStore

REPLICATION_SCHEMA_VERSION = 6
PROTOCOL_VERSION = 1
MAX_BODY_BYTES = 1_000_000
MAX_OBJECTS = 2000
MAX_SECRET_BYTES = 64 * 1024
REPLAY_WINDOW_SECONDS = 10 * 60
MAX_SEEN_MESSAGES = 4096

REPLICATED_TABLES = (
    "clients",
    "client_identifiers",
    "client_groups",
    "client_group_members",
    "policy_layers",
    "policy_networks",
    "policy_groups",
    "policy_client_group_membership",
    "policy_schedules",
    "policy_schedule_windows",
    "upstream_profiles",
    "upstream_endpoints",
    "domain_routing_rules",
    "service_definitions",
    "service_domains",
    "service_blocking_rulesets",
    "service_blocking_ruleset_members",
    "notification_providers",
)

_MIGRATION: list[str] = [
    """
    CREATE TABLE IF NOT EXISTS replication_peers (
        peer_node_id TEXT PRIMARY KEY,
        display_name TEXT NOT NULL DEFAULT '',
        url TEXT NOT NULL,
        ca_pem TEXT NOT NULL,
        expected_cert_sha256 TEXT NOT NULL,
        client_cert_pem TEXT NOT NULL DEFAULT '',
        client_key_pem TEXT NOT NULL DEFAULT '',
        authorized INTEGER NOT NULL DEFAULT 0,
        direction TEXT NOT NULL DEFAULT 'bidirectional'
            CHECK(direction IN ('push','pull','bidirectional')),
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        last_seen_at TEXT,
        last_attempt_at TEXT,
        last_success_at TEXT,
        last_error TEXT NOT NULL DEFAULT '',
        local_generation INTEGER NOT NULL DEFAULT 0,
        remote_known_generation INTEGER NOT NULL DEFAULT 0
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS replication_seen_messages (
        peer_node_id TEXT NOT NULL,
        message_id TEXT NOT NULL,
        seen_at TEXT NOT NULL,
        PRIMARY KEY(peer_node_id, message_id)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS replication_generations_v2 (
        source_node_id TEXT PRIMARY KEY,
        generation INTEGER NOT NULL,
        content_hash TEXT NOT NULL,
        updated_at TEXT NOT NULL
    )
    """,
]


class ReplicationError(RuntimeError):
    pass


class ReplicationAuthError(ReplicationError):
    pass


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _table_exists(conn, table: str) -> bool:
    return conn.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,)).fetchone() is not None


def ensure_schema(path: str | Path) -> None:
    control_db.initialize(path)
    policy_store.ensure_schema(path)
    notification_store.ensure_schema(path)
    node_identity.ensure_schema(path)
    with control_db.connect(path) as conn:
        present = _table_exists(conn, "replication_peers")
    if not present:
        control_db.apply_migration_in_transaction(path, _MIGRATION, REPLICATION_SCHEMA_VERSION)


def cert_fingerprint_sha256(pem: str | bytes) -> str:
    data = pem.encode("utf-8") if isinstance(pem, str) else pem
    cert = x509.load_pem_x509_certificate(data)
    return cert.fingerprint(hashes.SHA256()).hex()


def cert_node_id(pem: str | bytes) -> str:
    data = pem.encode("utf-8") if isinstance(pem, str) else pem
    cert = x509.load_pem_x509_certificate(data)
    attrs = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    return attrs[0].value if attrs else ""


def generate_private_ca(common_name: str) -> tuple[str, str]:
    from datetime import timedelta

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc) - timedelta(minutes=1))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(True, False, False, False, False, True, True, False, False), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .sign(key, hashes.SHA256())
    )
    return (
        cert.public_bytes(serialization.Encoding.PEM).decode("ascii"),
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        ).decode("ascii"),
    )


def issue_node_cert(ca_pem: str, ca_key_pem: str, node_id: str, *, server_name: str = "localhost") -> tuple[str, str]:
    from datetime import timedelta

    ca = x509.load_pem_x509_certificate(ca_pem.encode("utf-8"))
    ca_key = serialization.load_pem_private_key(ca_key_pem.encode("utf-8"), password=None)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, node_id)])
    try:
        san_name = x509.IPAddress(ipaddress.ip_address(server_name))
    except ValueError:
        san_name = x509.DNSName(server_name)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc) - timedelta(minutes=1))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=825))
        .add_extension(x509.SubjectAlternativeName([san_name]), critical=False)
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.CLIENT_AUTH]),
            critical=False,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
        .sign(ca_key, hashes.SHA256())
    )
    return (
        cert.public_bytes(serialization.Encoding.PEM).decode("ascii"),
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        ).decode("ascii"),
    )


@dataclass(frozen=True)
class Peer:
    peer_node_id: str
    display_name: str
    url: str
    ca_pem: str
    expected_cert_sha256: str
    client_cert_pem: str
    client_key_pem: str
    authorized: bool
    direction: str
    last_attempt_at: str | None
    last_success_at: str | None
    last_error: str
    local_generation: int
    remote_known_generation: int

    def public_dict(self) -> dict:
        return {
            "peer_node_id": self.peer_node_id,
            "display_name": self.display_name,
            "url": self.url,
            "expected_cert_sha256": self.expected_cert_sha256,
            "authorized": self.authorized,
            "direction": self.direction,
            "last_attempt_at": self.last_attempt_at,
            "last_success_at": self.last_success_at,
            "last_error": self.last_error,
            "local_generation": self.local_generation,
            "remote_known_generation": self.remote_known_generation,
            "lag": max(0, self.local_generation - self.remote_known_generation),
        }


def upsert_peer(
    conn,
    *,
    peer_node_id: str,
    display_name: str,
    url: str,
    ca_pem: str,
    expected_cert_sha256: str,
    client_cert_pem: str = "",
    client_key_pem: str = "",
    authorized: bool = True,
    direction: str = "bidirectional",
) -> None:
    if not peer_node_id or len(peer_node_id) > 128:
        raise ValueError("invalid peer_node_id")
    if direction not in ("push", "pull", "bidirectional"):
        raise ValueError("invalid direction")
    if not url.startswith("https://"):
        raise ValueError("replication peer url must be https://")
    if expected_cert_sha256 and len(expected_cert_sha256) != 64:
        raise ValueError("expected_cert_sha256 must be a SHA-256 hex fingerprint")
    now = _now()
    conn.execute(
        """
        INSERT INTO replication_peers(
            peer_node_id, display_name, url, ca_pem, expected_cert_sha256,
            client_cert_pem, client_key_pem, authorized, direction, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(peer_node_id) DO UPDATE SET
            display_name=excluded.display_name,
            url=excluded.url,
            ca_pem=excluded.ca_pem,
            expected_cert_sha256=excluded.expected_cert_sha256,
            client_cert_pem=excluded.client_cert_pem,
            client_key_pem=excluded.client_key_pem,
            authorized=excluded.authorized,
            direction=excluded.direction,
            updated_at=excluded.updated_at
        """,
        (
            peer_node_id,
            display_name[:128],
            url,
            ca_pem,
            expected_cert_sha256.lower(),
            client_cert_pem,
            client_key_pem,
            1 if authorized else 0,
            direction,
            now,
            now,
        ),
    )


def list_peers(conn) -> list[Peer]:
    rows = conn.execute(
        """
        SELECT peer_node_id, display_name, url, ca_pem, expected_cert_sha256,
               client_cert_pem, client_key_pem, authorized, direction,
               last_attempt_at, last_success_at, last_error,
               local_generation, remote_known_generation
        FROM replication_peers ORDER BY peer_node_id
        """
    ).fetchall()
    return [Peer(r[0], r[1], r[2], r[3], r[4], r[5], r[6], bool(r[7]), r[8], r[9], r[10], r[11], r[12], r[13]) for r in rows]


def get_peer(conn, peer_node_id: str) -> Peer | None:
    return next((p for p in list_peers(conn) if p.peer_node_id == peer_node_id), None)


def remove_peer(conn, peer_node_id: str) -> None:
    conn.execute("DELETE FROM replication_peers WHERE peer_node_id=?", (peer_node_id,))
    conn.execute("DELETE FROM replication_seen_messages WHERE peer_node_id=?", (peer_node_id,))


def _columns(conn, table: str) -> list[str]:
    return [r[1] for r in conn.execute(f"PRAGMA table_info({table})").fetchall()]


def export_control_snapshot(conn) -> dict[str, Any]:
    objects = []
    for table in REPLICATED_TABLES:
        if not _table_exists(conn, table):
            continue
        cols = _columns(conn, table)
        rows = conn.execute(f"SELECT {', '.join(cols)} FROM {table}").fetchall()
        objects.append({"table": table, "columns": cols, "rows": [list(r) for r in rows]})
    if sum(len(o["rows"]) for o in objects) > MAX_OBJECTS:
        raise ReplicationError("replication snapshot exceeds object count bound")
    return {"tables": objects}


def export_secret_snapshot(secrets: SecretStore) -> dict[str, str]:
    exported = secrets.export_all()
    for sid, value in exported.items():
        if len(value.encode("utf-8")) > MAX_SECRET_BYTES:
            raise ReplicationError(f"secret {sid!r} exceeds replication size bound")
    return exported


def current_generation(conn) -> tuple[int, str]:
    snapshot = json.dumps(export_control_snapshot(conn), sort_keys=True, separators=(",", ":"))
    digest = hashlib.sha256(snapshot.encode("utf-8")).hexdigest()
    row = conn.execute(
        "SELECT generation, content_hash FROM replication_generations_v2 WHERE source_node_id='local'"
    ).fetchone()
    if row is None:
        conn.execute(
            "INSERT INTO replication_generations_v2(source_node_id, generation, content_hash, updated_at) VALUES ('local', 1, ?, ?)",
            (digest, _now()),
        )
        return 1, digest
    gen, old = row
    if old != digest:
        gen += 1
        conn.execute(
            "UPDATE replication_generations_v2 SET generation=?, content_hash=?, updated_at=? WHERE source_node_id='local'",
            (gen, digest, _now()),
        )
    return gen, digest


def build_message(conn, secrets: SecretStore, *, sender_node_id: str | None = None, message_id: str | None = None) -> dict:
    identity = node_identity.get_or_create(conn)
    sender = sender_node_id or identity.node_id
    generation, content_hash = current_generation(conn)
    return {
        "protocol_version": PROTOCOL_VERSION,
        "message_id": message_id or str(uuid.uuid4()),
        "sender_node_id": sender,
        "category": "snapshot",
        "operation": "upsert",
        "generation": generation,
        "content_hash": content_hash,
        "created_at": _now(),
        "payload": {
            "control": export_control_snapshot(conn),
            "secrets": export_secret_snapshot(secrets),
        },
    }


def _validate_message(conn, message: dict, *, peer_cert_pem: str | None = None) -> Peer:
    raw_size = len(json.dumps(message, separators=(",", ":")).encode("utf-8"))
    if raw_size > MAX_BODY_BYTES:
        raise ReplicationError("replication message exceeds size bound")
    if message.get("protocol_version") != PROTOCOL_VERSION:
        raise ReplicationError("unsupported replication protocol version")
    if message.get("category") != "snapshot" or message.get("operation") != "upsert":
        raise ReplicationError("unsupported replication category or operation")
    sender = message.get("sender_node_id")
    if not isinstance(sender, str) or not sender:
        raise ReplicationError("sender_node_id is required")
    peer = get_peer(conn, sender)
    if peer is None or not peer.authorized:
        raise ReplicationAuthError("peer is not explicitly authorized")
    if peer_cert_pem:
        actual_fp = cert_fingerprint_sha256(peer_cert_pem)
        actual_node = cert_node_id(peer_cert_pem)
        if peer.expected_cert_sha256 and actual_fp.lower() != peer.expected_cert_sha256.lower():
            raise ReplicationAuthError("peer certificate fingerprint mismatch")
        if actual_node and actual_node != sender:
            raise ReplicationAuthError("peer certificate node identity mismatch")
    try:
        created = datetime.fromisoformat(message["created_at"])
    except Exception as exc:
        raise ReplicationError("invalid created_at timestamp") from exc
    if abs(time.time() - created.timestamp()) > REPLAY_WINDOW_SECONDS:
        raise ReplicationAuthError("replication message outside replay window")
    msg_id = message.get("message_id")
    if not isinstance(msg_id, str) or len(msg_id) > 128:
        raise ReplicationError("invalid message_id")
    if conn.execute(
        "SELECT 1 FROM replication_seen_messages WHERE peer_node_id=? AND message_id=?", (sender, msg_id)
    ).fetchone():
        raise ReplicationAuthError("duplicate replication message")
    return peer


def _replace_table(conn, table: str, columns: list[str], rows: Iterable[list[Any]]) -> None:
    expected = _columns(conn, table)
    if columns != expected:
        raise ReplicationError(f"schema mismatch for replicated table {table}")
    row_list = list(rows)
    if len(row_list) > MAX_OBJECTS:
        raise ReplicationError(f"too many rows for replicated table {table}")
    conn.execute(f"DELETE FROM {table}")
    if not row_list:
        return
    placeholders = ", ".join("?" for _ in columns)
    conn.executemany(
        f"INSERT INTO {table} ({', '.join(columns)}) VALUES ({placeholders})",
        row_list,
    )


def apply_message(
    conn,
    secrets: SecretStore,
    message: dict,
    *,
    peer_cert_pem: str | None = None,
    staging_dir: Path | None = None,
    live_dnsdist_conf_path: Path | None = None,
) -> dict:
    peer = _validate_message(conn, message, peer_cert_pem=peer_cert_pem)
    sender = message["sender_node_id"]
    generation = int(message["generation"])
    last = conn.execute("SELECT generation FROM replication_generations_v2 WHERE source_node_id=?", (sender,)).fetchone()
    if last is not None:
        last_generation = int(last[0])
        last_hash = conn.execute(
            "SELECT content_hash FROM replication_generations_v2 WHERE source_node_id=?", (sender,)
        ).fetchone()[0]
        if generation < last_generation:
            _record_seen(conn, sender, message["message_id"])
            return {"applied": False, "reason": "stale_generation", "generation": generation}
        if generation == last_generation:
            _record_seen(conn, sender, message["message_id"])
            if str(message.get("content_hash", "")) == str(last_hash):
                return {"applied": False, "reason": "duplicate_generation", "generation": generation}
            conn.execute(
                "UPDATE replication_peers SET last_error=? WHERE peer_node_id=?",
                ("conflict: equal generation with different content hash", sender),
            )
            raise ReplicationError("conflict: equal generation with different content hash")
    payload = message.get("payload")
    if not isinstance(payload, dict):
        raise ReplicationError("payload must be an object")
    tables = payload.get("control", {}).get("tables")
    if not isinstance(tables, list):
        raise ReplicationError("control payload missing tables")
    secret_payload = payload.get("secrets", {})
    if not isinstance(secret_payload, dict):
        raise ReplicationError("secrets payload must be an object")
    for secret_id, value in secret_payload.items():
        if not isinstance(secret_id, str) or not isinstance(value, str):
            raise ReplicationError("invalid secret payload")
        if len(value.encode("utf-8")) > MAX_SECRET_BYTES:
            raise ReplicationError("secret payload exceeds bound")
    conn.execute("BEGIN IMMEDIATE")
    try:
        for obj in tables:
            table = obj.get("table")
            if table not in REPLICATED_TABLES:
                raise ReplicationError(f"unauthorized replicated table: {table!r}")
            _replace_table(conn, table, obj.get("columns"), obj.get("rows"))
        old_secrets = secrets.export_all()
        secrets.import_all(secret_payload, overwrite=True)
        if staging_dir is not None and live_dnsdist_conf_path is not None:
            try:
                runtime_compile.recompile_and_promote(conn, staging_dir, live_dnsdist_conf_path)
            except BaseException:
                secrets.import_all(old_secrets, overwrite=True)
                raise
        conn.execute(
            "INSERT INTO replication_generations_v2(source_node_id, generation, content_hash, updated_at) VALUES (?, ?, ?, ?) "
            "ON CONFLICT(source_node_id) DO UPDATE SET generation=excluded.generation, content_hash=excluded.content_hash, updated_at=excluded.updated_at",
            (sender, generation, message.get("content_hash", ""), _now()),
        )
        _record_seen(conn, sender, message["message_id"])
        conn.execute(
            "UPDATE replication_peers SET last_seen_at=?, last_success_at=?, last_error='', remote_known_generation=? WHERE peer_node_id=?",
            (_now(), _now(), generation, sender),
        )
        conn.execute("COMMIT")
        return {"applied": True, "reason": "applied", "generation": generation, "peer": peer.peer_node_id}
    except BaseException:
        conn.execute("ROLLBACK")
        try:
            if "old_secrets" in locals():
                secrets.import_all(old_secrets, overwrite=True)
        except Exception:
            pass
        raise


def _record_seen(conn, peer_node_id: str, message_id: str) -> None:
    conn.execute(
        "INSERT OR IGNORE INTO replication_seen_messages(peer_node_id, message_id, seen_at) VALUES (?, ?, ?)",
        (peer_node_id, message_id, _now()),
    )
    rows = conn.execute(
        "SELECT message_id FROM replication_seen_messages WHERE peer_node_id=? ORDER BY seen_at DESC LIMIT -1 OFFSET ?",
        (peer_node_id, MAX_SEEN_MESSAGES),
    ).fetchall()
    for (old_id,) in rows:
        conn.execute("DELETE FROM replication_seen_messages WHERE peer_node_id=? AND message_id=?", (peer_node_id, old_id))


def _write_temp_file(root: Path, name: str, data: str, mode: int = 0o600) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    path = root / name
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(data)
    return path


def client_ssl_context(peer: Peer, temp_root: Path) -> ssl.SSLContext:
    if not peer.client_cert_pem or not peer.client_key_pem:
        raise ReplicationAuthError("client certificate/key are required")
    ca = _write_temp_file(temp_root, f"{peer.peer_node_id}.ca.pem", peer.ca_pem)
    cert = _write_temp_file(temp_root, f"{peer.peer_node_id}.client.crt", peer.client_cert_pem)
    key = _write_temp_file(temp_root, f"{peer.peer_node_id}.client.key", peer.client_key_pem)
    ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=str(ca))
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.check_hostname = True
    ctx.load_cert_chain(str(cert), str(key))
    return ctx


def push_to_peer(conn, secrets: SecretStore, peer_node_id: str, temp_root: Path) -> dict:
    peer = get_peer(conn, peer_node_id)
    if peer is None:
        raise ReplicationError("unknown peer")
    message = build_message(conn, secrets)
    body = json.dumps(message).encode("utf-8")
    if len(body) > MAX_BODY_BYTES:
        raise ReplicationError("replication request exceeds body bound")
    from urllib.parse import urlparse

    parsed = urlparse(peer.url)
    ctx = client_ssl_context(peer, temp_root)
    conn.execute("UPDATE replication_peers SET last_attempt_at=?, last_error='' WHERE peer_node_id=?", (_now(), peer_node_id))
    try:
        client = http.client.HTTPSConnection(parsed.hostname, parsed.port or 443, context=ctx, timeout=10)
        client.request("POST", parsed.path or "/replication/v1/apply", body=body, headers={"Content-Type": "application/json"})
        resp = client.getresponse()
        response_body = resp.read(MAX_BODY_BYTES)
        if resp.status >= 300:
            raise ReplicationError(f"peer returned HTTP {resp.status}: {response_body[:200]!r}")
        result = json.loads(response_body.decode("utf-8"))
        conn.execute(
            "UPDATE replication_peers SET last_success_at=?, last_error='', remote_known_generation=? WHERE peer_node_id=?",
            (_now(), message["generation"], peer_node_id),
        )
        return result
    except Exception as exc:
        conn.execute(
            "UPDATE replication_peers SET last_error=? WHERE peer_node_id=?",
            (str(exc)[:512], peer_node_id),
        )
        raise


class ReplicationHandler(http.server.BaseHTTPRequestHandler):
    control_db_path: Path
    secrets_dir: Path
    staging_dir: Path
    live_dnsdist_conf_path: Path

    def log_message(self, fmt, *args):  # avoid logging request bodies/secrets
        return

    def do_GET(self):
        if self.path != "/replication/v1/health":
            self.send_error(404)
            return
        self._json(200, {"status": "ok", "protocol_version": PROTOCOL_VERSION})

    def do_POST(self):
        if self.path != "/replication/v1/apply":
            self.send_error(404)
            return
        cert = self.connection.getpeercert(binary_form=True)
        if not cert:
            self._json(403, {"error": "client_certificate_required"})
            return
        peer_pem = ssl.DER_cert_to_PEM_cert(cert)
        length = int(self.headers.get("content-length", "0"))
        if length <= 0 or length > MAX_BODY_BYTES:
            self._json(413, {"error": "payload_too_large"})
            return
        try:
            message = json.loads(self.rfile.read(length))
            with control_db.connect(self.control_db_path) as db:
                result = apply_message(
                    db,
                    SecretStore(self.secrets_dir),
                    message,
                    peer_cert_pem=peer_pem,
                    staging_dir=self.staging_dir,
                    live_dnsdist_conf_path=self.live_dnsdist_conf_path,
                )
            self._json(200, result)
        except ReplicationAuthError as exc:
            self._json(403, {"error": "replication_auth_failed", "detail": str(exc)})
        except Exception as exc:
            self._json(400, {"error": "replication_failed", "detail": str(exc)})

    def _json(self, status: int, body: dict) -> None:
        raw = json.dumps(body).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)


def serve(
    *,
    bind: tuple[str, int],
    server_cert: Path,
    server_key: Path,
    ca_file: Path,
    control_db_path: Path,
    secrets_dir: Path,
    staging_dir: Path,
    live_dnsdist_conf_path: Path,
) -> http.server.ThreadingHTTPServer:
    handler = type("BoundReplicationHandler", (ReplicationHandler,), {})
    handler.control_db_path = control_db_path
    handler.secrets_dir = secrets_dir
    handler.staging_dir = staging_dir
    handler.live_dnsdist_conf_path = live_dnsdist_conf_path
    httpd = http.server.ThreadingHTTPServer(bind, handler)
    ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(str(server_cert), str(server_key))
    ctx.load_verify_locations(str(ca_file))
    ctx.verify_mode = ssl.CERT_REQUIRED
    httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
    return httpd


def serve_forever_in_thread(**kwargs) -> tuple[http.server.ThreadingHTTPServer, threading.Thread]:
    httpd = serve(**kwargs)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    return httpd, thread
