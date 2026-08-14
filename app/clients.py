#!/usr/bin/env python3
"""Clients & Access: persistent named clients, strong ClientIDs, IPv4/IPv6
identification, and DNS access policy (allow/deny) enforced at dnsdist.

Design notes (see docs/clients-and-access.md for the operator-facing
version):

- A "client" is a stable, named record that owns one or more
  "identifiers" (exact IPv4/IPv6 address, IPv4/IPv6 CIDR, or a strong
  ClientID for encrypted-DNS transports). Multiple identifiers on one
  client are how a household device with several interfaces/protocols is
  represented without creating duplicate client rows.

- ClientIDs are identifiers, not authentication: high entropy makes them
  very hard to guess, but knowing one is enough to present it -- there is
  no signature or proof-of-possession involved. See CLIENTID_MIN_HEX_LEN
  and validate_clientid() below.

- Access policy is: explicit DENY beats explicit ALLOW beats the default
  policy. Rules can reference a raw IPv4/IPv6/CIDR/ClientID value directly,
  or a persistent client (which expands to that client's identifiers, and
  only applies while the client is enabled).

- Enforcement lives in dnsdist (deploy_access_layer() below), compiled to
  native NetmaskGroupRule (IP/CIDR) and SNIRule/HTTPPathRule (ClientID on
  DoT/DoQ and DoH respectively) objects at deploy time -- never a per-query
  Python/SQLite lookup. See ClientID Transport support notes below.
"""

from __future__ import annotations

import base64
import ipaddress
import os
import shutil
import sqlite3
import subprocess
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Literal

DB_PATH = Path("/var/lib/alderpointdns/alderpointdns.db")
COMPILED_DNSDIST_DIR = Path("/var/lib/alderpointdns/compiled/dnsdist")
BACKUP_DIR = Path("/var/lib/alderpointdns/backups")
STAGING_DIR = Path("/var/lib/alderpointdns/staging")
DNSDIST_CONF = Path("/etc/dnsdist/dnsdist.conf")
DNSDIST_PACKAGING_CONF = Path(__file__).resolve().parent.parent / "packaging" / "dnsdist.conf"

ACCESS_LUA_NAME = "access-policy.conf"
DATA_ALLOW_V4 = "access-allow-v4.txt"
DATA_ALLOW_V6 = "access-allow-v6.txt"
DATA_DENY_V4 = "access-deny-v4.txt"
DATA_DENY_V6 = "access-deny-v6.txt"
DATA_ALLOW_SNI = "access-allow-sni.txt"
DATA_DENY_SNI = "access-deny-sni.txt"
DATA_ALLOW_PATH = "access-allow-path.txt"
DATA_DENY_PATH = "access-deny-path.txt"
DATA_DOH_CLIENTID_PATHS = "access-doh-clientid-paths.txt"

# Alderpoint's own convention for a DNS-hostname-label carrying a ClientID
# on DoT/DoQ (SNI-based transports). Not an AdGuard Home compatibility
# claim -- documented in docs/clients-and-access.md.
CLIENTID_SNI_SUFFIX = "clientid.alderpointdns.local"

# Minimum/allowed ClientID strengths. 128-bit (32 hex) is deliberately
# never accepted -- see CLIENTID_MIN_HEX_LEN below and docs/clients-and-access.md.
CLIENTID_ALLOWED_HEX_LENGTHS = (48, 64)  # 192-bit, 256-bit
CLIENTID_MIN_HEX_LEN = 48
CLIENTID_MAX_HEX_LEN = 64
DNS_LABEL_MAX_LEN = 63

IdentifierKind = Literal["ipv4", "ipv4_cidr", "ipv6", "ipv6_cidr", "clientid"]
RuleKind = Literal["ipv4", "ipv4_cidr", "ipv6", "ipv6_cidr", "clientid", "client"]
Action = Literal["allow", "deny"]


class ClientsError(ValueError):
    """Base error for validation/state problems raised to callers (webapp
    turns these into 400s with the message shown to the admin)."""


class ClientIDError(ClientsError):
    pass


class AccessPolicyError(ClientsError):
    pass


def now() -> str:
    import datetime as dt

    return dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def connect() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, timeout=10.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout=10000")
    return conn


def run(command: list[str], check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, capture_output=True, text=True, check=check, timeout=30)


# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------

def init_db(conn: sqlite3.Connection | None = None) -> None:
    owns_conn = conn is None
    db = conn or connect()
    try:
        db.executescript(
            """
            CREATE TABLE IF NOT EXISTS clients (
                id INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                description TEXT NOT NULL DEFAULT '',
                enabled INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS client_identifiers (
                id INTEGER PRIMARY KEY,
                client_id INTEGER NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
                kind TEXT NOT NULL CHECK(kind IN ('ipv4','ipv4_cidr','ipv6','ipv6_cidr','clientid')),
                value TEXT NOT NULL,
                created_at TEXT NOT NULL,
                UNIQUE(kind, value)
            );
            CREATE INDEX IF NOT EXISTS idx_client_identifiers_client ON client_identifiers(client_id);
            CREATE TABLE IF NOT EXISTS access_settings (
                id INTEGER PRIMARY KEY CHECK(id = 1),
                default_policy TEXT NOT NULL DEFAULT 'allow' CHECK(default_policy IN ('allow','deny')),
                updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS access_rules (
                id INTEGER PRIMARY KEY,
                action TEXT NOT NULL CHECK(action IN ('allow','deny')),
                kind TEXT NOT NULL CHECK(kind IN ('ipv4','ipv4_cidr','ipv6','ipv6_cidr','clientid','client')),
                value TEXT,
                client_id INTEGER REFERENCES clients(id) ON DELETE CASCADE,
                created_at TEXT NOT NULL,
                UNIQUE(action, kind, value, client_id)
            );
            CREATE INDEX IF NOT EXISTS idx_access_rules_client ON access_rules(client_id);
            """
        )
        db.execute(
            "INSERT OR IGNORE INTO access_settings(id, default_policy, updated_at) VALUES (1, 'allow', ?)",
            (now(),),
        )
        db.commit()
        _migrate_client_aliases(db)
    finally:
        if owns_conn:
            db.close()


def _migrate_client_aliases(db: sqlite3.Connection) -> int:
    """Idempotently copy legacy client_aliases rows into the new client
    model. client_aliases itself is left intact (Local DNS and existing
    import/replication/backup code still reads it for display purposes) --
    this is a one-way, additive, repeat-safe copy, not a table rename.
    Safe under repeated startup: a given (kind, value) identifier is only
    ever migrated into a client once, thanks to client_identifiers'
    UNIQUE(kind, value) constraint below."""
    has_table = db.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name='client_aliases'"
    ).fetchone()
    if not has_table:
        return 0
    migrated = 0
    for row in db.execute("SELECT cidr, display_name, description, created_at, updated_at FROM client_aliases"):
        try:
            kind, value = normalize_identifier(row["cidr"])
        except ClientsError:
            continue
        already = db.execute(
            "SELECT 1 FROM client_identifiers WHERE kind=? AND value=?", (kind, value)
        ).fetchone()
        if already:
            continue
        ts_created = row["created_at"] or now()
        ts_updated = row["updated_at"] or ts_created
        cur = db.execute(
            "INSERT INTO clients(name, description, enabled, created_at, updated_at) VALUES (?, ?, 1, ?, ?)",
            (row["display_name"] or value, row["description"] or "", ts_created, ts_updated),
        )
        db.execute(
            "INSERT INTO client_identifiers(client_id, kind, value, created_at) VALUES (?, ?, ?, ?)",
            (cur.lastrowid, kind, value, ts_created),
        )
        migrated += 1
    if migrated:
        db.commit()
    return migrated


# ---------------------------------------------------------------------------
# Identifier normalization
# ---------------------------------------------------------------------------

def normalize_identifier(raw: str) -> tuple[IdentifierKind, str]:
    """Validates and canonicalizes a raw identifier string. Returns
    (kind, canonical_value). Raises ClientsError on anything malformed.
    ClientIDs are recognized by looking hexadecimal and being 48/64 chars;
    everything else is parsed as an IP address or network."""
    text = raw.strip()
    if not text:
        raise ClientsError("identifier is required")
    if len(text) <= CLIENTID_MAX_HEX_LEN and all(c in "0123456789abcdefABCDEF" for c in text) and "/" not in text and "." not in text and ":" not in text:
        return "clientid", validate_clientid(text)
    try:
        if "/" in text:
            network = ipaddress.ip_network(text, strict=False)
            kind: IdentifierKind = "ipv4_cidr" if network.version == 4 else "ipv6_cidr"
            return kind, str(network)
        address = ipaddress.ip_address(text)
        kind = "ipv4" if address.version == 4 else "ipv6"
        return kind, str(address)
    except ValueError as exc:
        raise ClientsError(f"'{raw}' is not a valid IPv4/IPv6 address, CIDR, or ClientID: {exc}") from None


def identifier_network(kind: IdentifierKind, value: str) -> ipaddress.IPv4Network | ipaddress.IPv6Network | None:
    if kind in ("ipv4", "ipv4_cidr", "ipv6", "ipv6_cidr"):
        return ipaddress.ip_network(value, strict=False)
    return None


def _legacy_alias_cidr(kind: str, value: str) -> str | None:
    if kind not in ("ipv4", "ipv4_cidr", "ipv6", "ipv6_cidr"):
        return None
    try:
        return str(ipaddress.ip_network(value, strict=False))
    except ValueError:
        return None


def _delete_legacy_aliases_for_identifiers(db: sqlite3.Connection, identifiers: Iterable[sqlite3.Row | dict[str, Any]]) -> int:
    """Retire legacy client_aliases rows for normalized identifiers an
    administrator deliberately deleted. client_aliases was the migration
    source for v1.0.2-era display aliases; once that alias has become a
    normalized persistent client/identifier, keeping it after the
    normalized object is deleted makes init_db() recreate a zombie client.
    Only matching legacy rows are removed; unrelated aliases remain intact
    and still migrate normally."""
    has_table = db.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name='client_aliases'"
    ).fetchone()
    if not has_table:
        return 0
    removed = 0
    seen: set[str] = set()
    for identifier in identifiers:
        cidr = _legacy_alias_cidr(identifier["kind"], identifier["value"])
        if not cidr or cidr in seen:
            continue
        seen.add(cidr)
        removed += db.execute("DELETE FROM client_aliases WHERE cidr=?", (cidr,)).rowcount
    return removed


# ---------------------------------------------------------------------------
# ClientID: generation, validation, DNS-safe encoding
# ---------------------------------------------------------------------------

def generate_clientid(bits: int) -> str:
    """Cryptographically secure ClientID generation. Uses secrets.token_hex,
    which is documented to be suitable for security-sensitive use (backed by
    os.urandom). Never uses random, uuid, timestamps, counters, or hashes of
    predictable state."""
    import secrets

    if bits == 192:
        return secrets.token_hex(24)  # 24 bytes = 48 hex chars
    if bits == 256:
        return secrets.token_hex(32)  # 32 bytes = 64 hex chars
    raise ClientIDError("ClientID strength must be 192 or 256 bits")


def validate_clientid(raw: str) -> str:
    """Validates and normalizes a ClientID to canonical lowercase hex.
    Rejects anything under the 192-bit (48 hex) minimum, anything over the
    256-bit (64 hex) maximum, non-hex content, and odd lengths in between
    that aren't exactly 48 or 64. Never truncates or otherwise weakens a
    supplied value -- an out-of-policy value is rejected outright."""
    text = raw.strip().lower()
    if not text:
        raise ClientIDError("ClientID is required")
    if any(c not in "0123456789abcdef" for c in text):
        raise ClientIDError("ClientID must be hexadecimal (0-9, a-f)")
    if len(text) < CLIENTID_MIN_HEX_LEN:
        raise ClientIDError(
            f"ClientID is only {len(text)} hex characters; Alderpoint requires at least "
            f"{CLIENTID_MIN_HEX_LEN} (192-bit). Shorter/weaker ClientIDs (including 32-hex/128-bit) "
            "are not accepted."
        )
    if len(text) not in CLIENTID_ALLOWED_HEX_LENGTHS:
        if len(text) > CLIENTID_MAX_HEX_LEN:
            raise ClientIDError(f"ClientID is {len(text)} hex characters, longer than the supported 256-bit (64 hex) maximum")
        raise ClientIDError(
            f"ClientID must be exactly 48 hex characters (192-bit) or 64 hex characters (256-bit); got {len(text)}"
        )
    return text


def clientid_strength_bits(canonical_hex: str) -> int:
    return {48: 192, 64: 256}[len(canonical_hex)]


def clientid_dns_label(canonical_hex: str) -> str:
    """The DNS-label-safe representation of a ClientID, for hostname-based
    transports (DoT/DoQ SNI). A 192-bit (48 hex) ID already fits a single
    63-character DNS label as plain hex, so it is used as-is. A 256-bit
    (64 hex) ID does not fit as hex, so it is re-encoded, losslessly and
    deterministically, as lowercase RFC 4648 Base32 without padding (32
    random bytes -> 52 base32 characters, safely under the 63-char limit).
    Both representations round-trip to the exact same underlying bytes --
    see clientid_from_dns_label()."""
    if len(canonical_hex) <= DNS_LABEL_MAX_LEN:
        return canonical_hex
    raw = bytes.fromhex(canonical_hex)
    return base64.b32encode(raw).decode("ascii").rstrip("=").lower()


def clientid_from_dns_label(label: str) -> str:
    """Inverse of clientid_dns_label(): recovers the canonical lowercase hex
    ClientID from either representation. Used by tests to prove the mapping
    is lossless/reversible, and available for any future need to resolve a
    label back to its canonical form."""
    text = label.strip().lower()
    if text and all(c in "0123456789abcdef" for c in text) and len(text) in CLIENTID_ALLOWED_HEX_LENGTHS:
        return text
    padded = text.upper() + "=" * ((-len(text)) % 8)
    try:
        raw = base64.b32decode(padded)
    except Exception as exc:  # noqa: BLE001 - surfaced as a validation error
        raise ClientIDError(f"'{label}' is not a valid ClientID or DNS-safe label: {exc}") from None
    return raw.hex()


def clientid_doh_path(base_path: str, canonical_hex: str) -> str:
    """The DoH URL path carrying a ClientID: HTTP paths have no 63-character
    label limit, so the full canonical hex (48 or 64 chars) is always used
    -- no re-encoding needed here, unlike the DNS-label case."""
    return base_path.rstrip("/") + "/" + canonical_hex


def clientid_sni_hostname(canonical_hex: str) -> str:
    return clientid_dns_label(canonical_hex) + "." + CLIENTID_SNI_SUFFIX


# ---------------------------------------------------------------------------
# Persistent clients CRUD
# ---------------------------------------------------------------------------

def list_clients(conn: sqlite3.Connection | None = None) -> list[dict[str, Any]]:
    owns = conn is None
    db = conn or connect()
    try:
        init_db(db)
        clients = [dict(row) for row in db.execute("SELECT * FROM clients ORDER BY name COLLATE NOCASE")]
        for client in clients:
            client["identifiers"] = [
                dict(row)
                for row in db.execute(
                    "SELECT * FROM client_identifiers WHERE client_id=? ORDER BY kind, value", (client["id"],)
                )
            ]
        return clients
    finally:
        if owns:
            db.close()


def get_client(client_id: int, conn: sqlite3.Connection | None = None) -> dict[str, Any] | None:
    owns = conn is None
    db = conn or connect()
    try:
        init_db(db)
        row = db.execute("SELECT * FROM clients WHERE id=?", (client_id,)).fetchone()
        if not row:
            return None
        client = dict(row)
        client["identifiers"] = [
            dict(r) for r in db.execute("SELECT * FROM client_identifiers WHERE client_id=? ORDER BY kind, value", (client_id,))
        ]
        return client
    finally:
        if owns:
            db.close()


def create_client(name: str, description: str = "", identifiers: Iterable[str] = (), enabled: bool = True) -> int:
    name = name.strip()
    if not name:
        raise ClientsError("client name is required")
    if len(name) > 200:
        raise ClientsError("client name is too long (200 characters max)")
    if len(description) > 2000:
        raise ClientsError("description is too long (2000 characters max)")
    normalized = [normalize_identifier(v) for v in identifiers]
    ts = now()
    with connect() as db:
        init_db(db)
        with db:
            cur = db.execute(
                "INSERT INTO clients(name, description, enabled, created_at, updated_at) VALUES (?, ?, ?, ?, ?)",
                (name, description, 1 if enabled else 0, ts, ts),
            )
            client_id = cur.lastrowid
            for kind, value in normalized:
                _insert_identifier(db, client_id, kind, value, ts)
        return client_id


def update_client(client_id: int, name: str, description: str, enabled: bool) -> None:
    name = name.strip()
    if not name:
        raise ClientsError("client name is required")
    if len(name) > 200:
        raise ClientsError("client name is too long (200 characters max)")
    if len(description) > 2000:
        raise ClientsError("description is too long (2000 characters max)")
    ts = now()
    with connect() as db:
        init_db(db)
        with db:
            cur = db.execute(
                "UPDATE clients SET name=?, description=?, enabled=?, updated_at=? WHERE id=?",
                (name, description, 1 if enabled else 0, ts, client_id),
            )
            if cur.rowcount == 0:
                raise ClientsError("client not found")


def set_client_enabled(client_id: int, enabled: bool) -> None:
    with connect() as db:
        init_db(db)
        with db:
            cur = db.execute(
                "UPDATE clients SET enabled=?, updated_at=? WHERE id=?", (1 if enabled else 0, now(), client_id)
            )
            if cur.rowcount == 0:
                raise ClientsError("client not found")


def delete_client(client_id: int) -> None:
    """Deletes a client and cascades to its identifiers and any access
    rules that reference it directly. The schema declares ON DELETE
    CASCADE, but nothing in this codebase turns on
    `PRAGMA foreign_keys=ON` (SQLite defaults it off), so cascade is
    performed explicitly here rather than relying on a constraint that
    would silently not fire."""
    with connect() as db:
        init_db(db)
        with db:
            identifiers = db.execute("SELECT kind, value FROM client_identifiers WHERE client_id=?", (client_id,)).fetchall()
            _delete_legacy_aliases_for_identifiers(db, identifiers)
            db.execute("DELETE FROM access_rules WHERE kind='client' AND client_id=?", (client_id,))
            db.execute("DELETE FROM client_identifiers WHERE client_id=?", (client_id,))
            cur = db.execute("DELETE FROM clients WHERE id=?", (client_id,))
            if cur.rowcount == 0:
                raise ClientsError("client not found")


def _insert_identifier(db: sqlite3.Connection, client_id: int, kind: str, value: str, ts: str) -> int:
    existing = db.execute("SELECT client_id FROM client_identifiers WHERE kind=? AND value=?", (kind, value)).fetchone()
    if existing:
        raise ClientsError(f"identifier '{value}' is already assigned to another client")
    cur = db.execute(
        "INSERT INTO client_identifiers(client_id, kind, value, created_at) VALUES (?, ?, ?, ?)",
        (client_id, kind, value, ts),
    )
    return cur.lastrowid


def add_identifier(client_id: int, raw_value: str) -> int:
    kind, value = normalize_identifier(raw_value)
    ts = now()
    with connect() as db:
        init_db(db)
        with db:
            if not db.execute("SELECT 1 FROM clients WHERE id=?", (client_id,)).fetchone():
                raise ClientsError("client not found")
            identifier_id = _insert_identifier(db, client_id, kind, value, ts)
            db.execute("UPDATE clients SET updated_at=? WHERE id=?", (ts, client_id))
        return identifier_id


def remove_identifier(identifier_id: int) -> None:
    with connect() as db:
        init_db(db)
        with db:
            row = db.execute("SELECT client_id, kind, value FROM client_identifiers WHERE id=?", (identifier_id,)).fetchone()
            if not row:
                raise ClientsError("identifier not found")
            _delete_legacy_aliases_for_identifiers(db, [row])
            db.execute("DELETE FROM client_identifiers WHERE id=?", (identifier_id,))
            db.execute("UPDATE clients SET updated_at=? WHERE id=?", (now(), row["client_id"]))


# ---------------------------------------------------------------------------
# Access policy CRUD
# ---------------------------------------------------------------------------

def get_default_policy(conn: sqlite3.Connection | None = None) -> str:
    owns = conn is None
    db = conn or connect()
    try:
        init_db(db)
        row = db.execute("SELECT default_policy FROM access_settings WHERE id=1").fetchone()
        return row["default_policy"] if row else "allow"
    finally:
        if owns:
            db.close()


def set_default_policy(policy: str) -> None:
    if policy not in ("allow", "deny"):
        raise AccessPolicyError("default policy must be 'allow' or 'deny'")
    with connect() as db:
        init_db(db)
        with db:
            db.execute("UPDATE access_settings SET default_policy=?, updated_at=? WHERE id=1", (policy, now()))


def list_access_rules(conn: sqlite3.Connection | None = None) -> list[dict[str, Any]]:
    owns = conn is None
    db = conn or connect()
    try:
        init_db(db)
        rows = db.execute(
            """
            SELECT access_rules.*, clients.name AS client_name, clients.enabled AS client_enabled
            FROM access_rules LEFT JOIN clients ON clients.id = access_rules.client_id
            ORDER BY access_rules.action, access_rules.kind, access_rules.value
            """
        ).fetchall()
        return [dict(row) for row in rows]
    finally:
        if owns:
            db.close()


def add_access_rule(action: str, kind: str, value: str | None = None, client_id: int | None = None) -> int:
    if action not in ("allow", "deny"):
        raise AccessPolicyError("action must be 'allow' or 'deny'")
    ts = now()
    with connect() as db:
        init_db(db)
        with db:
            if kind == "client":
                if not client_id:
                    raise AccessPolicyError("a persistent client must be selected for a 'client' rule")
                if not db.execute("SELECT 1 FROM clients WHERE id=?", (client_id,)).fetchone():
                    raise ClientsError("client not found")
                stored_value = None
            elif kind == "clientid":
                stored_value = validate_clientid(value or "")
            elif kind in ("ipv4", "ipv4_cidr", "ipv6", "ipv6_cidr"):
                actual_kind, stored_value = normalize_identifier(value or "")
                if actual_kind != kind:
                    kind = actual_kind
            else:
                raise AccessPolicyError(f"unsupported rule kind '{kind}'")
            existing = db.execute(
                "SELECT id FROM access_rules WHERE action=? AND kind=? AND value IS ? AND client_id IS ?",
                (action, kind, stored_value, client_id if kind == "client" else None),
            ).fetchone()
            if existing:
                raise AccessPolicyError("this rule already exists")
            cur = db.execute(
                "INSERT INTO access_rules(action, kind, value, client_id, created_at) VALUES (?, ?, ?, ?, ?)",
                (action, kind, stored_value, client_id if kind == "client" else None, ts),
            )
            return cur.lastrowid


def remove_access_rule(rule_id: int) -> None:
    with connect() as db:
        init_db(db)
        with db:
            cur = db.execute("DELETE FROM access_rules WHERE id=?", (rule_id,))
            if cur.rowcount == 0:
                raise AccessPolicyError("rule not found")


# ---------------------------------------------------------------------------
# Policy evaluation (shared by the web "effective access" preview, tests,
# and as the source of truth the dnsdist compiler below renders from)
# ---------------------------------------------------------------------------

@dataclass
class AccessDecision:
    allowed: bool
    reason: str


def _rule_matches_ip(kind: str, value: str, address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    if kind in ("ipv4", "ipv6"):
        try:
            return ipaddress.ip_address(value) == address
        except ValueError:
            return False
    if kind in ("ipv4_cidr", "ipv6_cidr"):
        try:
            return address in ipaddress.ip_network(value, strict=False)
        except ValueError:
            return False
    return False


def _expand_rules(rules: list[dict[str, Any]], clients_by_id: dict[int, dict[str, Any]]) -> list[dict[str, Any]]:
    """Expands 'client' rules into one effective (action, kind, value) entry
    per identifier of that client, skipped entirely while the client is
    disabled."""
    expanded: list[dict[str, Any]] = []
    for rule in rules:
        if rule["kind"] == "client":
            client = clients_by_id.get(rule["client_id"])
            if not client or not client["enabled"]:
                continue
            for identifier in client["identifiers"]:
                expanded.append({
                    "action": rule["action"],
                    "kind": identifier["kind"],
                    "value": identifier["value"],
                    "source": f"client:{client['name']}",
                })
        else:
            expanded.append({**rule, "source": f"rule:{rule['kind']}"})
    return expanded


def evaluate_access(
    remote_ip: str | None,
    clientid: str | None,
    rules: list[dict[str, Any]],
    clients_by_id: dict[int, dict[str, Any]],
    default_policy: str,
) -> AccessDecision:
    """Deny beats allow beats default. See docs/clients-and-access.md for
    the full precedence table this implements identically to the compiled
    dnsdist rules in render_access_data()."""
    expanded = _expand_rules(rules, clients_by_id)
    address = None
    if remote_ip:
        try:
            address = ipaddress.ip_address(remote_ip)
        except ValueError:
            address = None
    deny_matches = []
    allow_matches = []
    for rule in expanded:
        matched = False
        if rule["kind"] == "clientid":
            matched = bool(clientid) and rule["value"] == clientid
        elif address is not None:
            matched = _rule_matches_ip(rule["kind"], rule["value"], address)
        if matched:
            (deny_matches if rule["action"] == "deny" else allow_matches).append(rule)
    if deny_matches:
        m = deny_matches[0]
        return AccessDecision(False, f"denied by {m['source']} ({m['kind']}={m['value']})")
    if allow_matches:
        m = allow_matches[0]
        return AccessDecision(True, f"allowed by {m['source']} ({m['kind']}={m['value']})")
    return AccessDecision(default_policy == "allow", f"default policy ({default_policy})")


def resolve_client_name(raw_client: str, conn: sqlite3.Connection | None = None) -> str | None:
    """Most-specific-network resolution of a raw client address to a
    persistent client's display name, for analytics labeling. Callers MUST
    NOT call this on a value that analytics privacy settings have already
    anonymized/truncated (that would defeat the privacy mode by re-deriving
    an identity from data that was deliberately made less specific) -- see
    app/analytics.py's clients_data(), which only calls this when
    privacy_mode == 'full'. Falls back to the legacy client_aliases-backed
    local_dns.alias_for_client() (and its own PTR fallback) so aliases that
    predate/bypass the new model still resolve."""
    try:
        address = ipaddress.ip_address(raw_client)
    except ValueError:
        return None
    owns = conn is None
    db = conn or connect()
    try:
        init_db(db)
        best: tuple[int, str] | None = None
        rows = db.execute(
            """
            SELECT client_identifiers.kind, client_identifiers.value, clients.name
            FROM client_identifiers JOIN clients ON clients.id = client_identifiers.client_id
            WHERE clients.enabled = 1 AND client_identifiers.kind IN ('ipv4','ipv4_cidr','ipv6','ipv6_cidr')
            """
        ).fetchall()
        for row in rows:
            try:
                net = ipaddress.ip_network(row["value"], strict=False)
            except ValueError:
                continue
            if address in net and (best is None or net.prefixlen > best[0]):
                best = (net.prefixlen, row["name"])
        if best:
            return best[1]
    finally:
        if owns:
            db.close()
    try:
        from app import local_dns

        return local_dns.alias_for_client(raw_client)
    except Exception:  # noqa: BLE001 - analytics labeling must never break on a lookup error
        return None


def effective_access_for_client(client: dict[str, Any], rules: list[dict[str, Any]], clients_by_id: dict[int, dict[str, Any]], default_policy: str) -> list[dict[str, Any]]:
    """Per-identifier effective access for a persistent client, so the UI
    can show mixed-identifier clients honestly instead of one misleading
    summary line."""
    results = []
    for identifier in client["identifiers"]:
        ip = identifier["value"] if identifier["kind"] in ("ipv4", "ipv6") else None
        cid = identifier["value"] if identifier["kind"] == "clientid" else None
        if identifier["kind"] in ("ipv4_cidr", "ipv6_cidr"):
            # Represent the network's first usable/representative host for
            # a CIDR identifier so evaluate_access has a concrete address.
            net = ipaddress.ip_network(identifier["value"], strict=False)
            ip = str(net.network_address)
        if not client["enabled"]:
            decision = AccessDecision(False, "client disabled")
        else:
            decision = evaluate_access(ip, cid, rules, clients_by_id, default_policy)
        results.append({"identifier": identifier, "decision": decision})
    return results


# ---------------------------------------------------------------------------
# dnsdist compiled enforcement layer
# ---------------------------------------------------------------------------

def access_lua_path() -> Path:
    return COMPILED_DNSDIST_DIR / ACCESS_LUA_NAME


def _check_line_safe(entry: str) -> str:
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in entry):
        raise AccessPolicyError("refusing to write a data-file entry containing control characters")
    return entry


def render_doh_clientid_paths(conn: sqlite3.Connection) -> str:
    """dnsdist's DoH frontend only routes requests whose path is in the
    fixed list passed to addDOHLocal() at startup -- a request to any other
    path (including a ClientID-suffixed one HTTPPathRule would otherwise
    match) is rejected by dnsdist's own HTTP layer with a 404 before any
    Lua rule ever sees it. So every configured ClientID's DoH path must be
    registered on the frontend itself, not just matched by our access
    rules -- this covers every clientid identifier that exists on any
    client, regardless of whether an access rule currently references it,
    since the alternative is a DoH connection presenting a perfectly valid
    ClientID getting a bare 404 instead of being served (under whatever
    the default policy says) at all. Read by packaging/dnsdist.conf's DoH
    block at dnsdist startup -- changing the set of ClientIDs therefore
    requires the dnsdist restart deploy_access_layer() already performs."""
    from app import encryption

    doh_path = encryption.settings(conn).get("doh_path", "/dns-query") or "/dns-query"
    values = {row["value"] for row in conn.execute("SELECT DISTINCT value FROM client_identifiers WHERE kind='clientid'")}
    # A ClientID can also appear directly in an access rule without ever
    # being attached to a persistent client (add_access_rule("deny",
    # "clientid", ...) with no client_id) -- those need routing too.
    values.update(row["value"] for row in conn.execute("SELECT DISTINCT value FROM access_rules WHERE kind='clientid' AND value IS NOT NULL"))
    paths = sorted({clientid_doh_path(doh_path, v) for v in values})
    return "\n".join(_check_line_safe(p) for p in paths) + ("\n" if paths else "")


def render_access_data(rules: list[dict[str, Any]], clients_by_id: dict[int, dict[str, Any]], default_policy: str, doh_base_path: str = "/dns-query") -> dict[str, str]:
    """Plain, line-oriented data files consumed by the static Lua loader
    below -- exactly the same 'never interpolate user text into Lua'
    pattern app/custom_rules.py uses. Every value here has already been
    through normalize_identifier()/validate_clientid(), so it is guaranteed
    to be a canonical IP/CIDR/hex string with no Lua-meaningful characters."""
    expanded = _expand_rules(rules, clients_by_id)
    allow_v4, allow_v6, deny_v4, deny_v6 = [], [], [], []
    allow_sni, deny_sni, allow_path, deny_path = [], [], [], []
    for rule in expanded:
        kind, value, action = rule["kind"], rule["value"], rule["action"]
        if kind == "ipv4":
            (allow_v4 if action == "allow" else deny_v4).append(value + "/32")
        elif kind == "ipv4_cidr":
            (allow_v4 if action == "allow" else deny_v4).append(value)
        elif kind == "ipv6":
            (allow_v6 if action == "allow" else deny_v6).append(value + "/128")
        elif kind == "ipv6_cidr":
            (allow_v6 if action == "allow" else deny_v6).append(value)
        elif kind == "clientid":
            sni = clientid_sni_hostname(value)
            path = clientid_doh_path(doh_base_path, value)
            (allow_sni if action == "allow" else deny_sni).append(sni)
            (allow_path if action == "allow" else deny_path).append(path)

    def text(entries: list[str]) -> str:
        return "\n".join(_check_line_safe(e) for e in entries) + ("\n" if entries else "")

    return {
        DATA_ALLOW_V4: text(sorted(set(allow_v4))),
        DATA_ALLOW_V6: text(sorted(set(allow_v6))),
        DATA_DENY_V4: text(sorted(set(deny_v4))),
        DATA_DENY_V6: text(sorted(set(deny_v6))),
        DATA_ALLOW_SNI: text(sorted(set(allow_sni))),
        DATA_DENY_SNI: text(sorted(set(deny_sni))),
        DATA_ALLOW_PATH: text(sorted(set(allow_path))),
        DATA_DENY_PATH: text(sorted(set(deny_path))),
        "access-default-policy.txt": default_policy + "\n",
    }


def render_access_lua(data_dir: Path) -> str:
    """Static Lua include, compiled once per deploy from the data files
    above -- never per query. Deny is evaluated first and always wins
    (RCodeAction REFUSED, a terminal action). Loopback/::1 are always
    exempt from the default-deny gate (undeniable by the *default* policy
    only -- an explicit deny rule against loopback, unusual as that would
    be, still applies first) so Alderpoint's own health checks/acceptance
    tests never get locked out by a Default Deny policy. When the default
    policy is 'allow', no gate is added at all: that is exactly the
    pre-existing behavior (everything not explicitly denied falls through
    to the normal catch-all bind-pool action), so Default Allow costs
    nothing extra on the hot path."""
    return f"""-- Managed by Alderpoint DNS Clients & Access. Do not edit by hand.
-- Static loader: user-controlled values live only in the data files below
-- (one entry per line); no user text is ever interpolated into Lua code.
local alderpointdnsAccessDataDir = "{data_dir}"

local function alderpointdnsAccessLines(name)
  local entries = {{}}
  local handle = io.open(alderpointdnsAccessDataDir .. "/" .. name, "r")
  if handle then
    for line in handle:lines() do
      if line ~= "" then
        table.insert(entries, line)
      end
    end
    handle:close()
  end
  return entries
end

local function alderpointdnsNMG(name)
  local entries = alderpointdnsAccessLines(name)
  if #entries == 0 then
    return nil
  end
  local nmg = newNMG()
  for _, entry in ipairs(entries) do
    nmg:addMask(entry)
  end
  return nmg
end

local alderpointdnsDenyV4 = alderpointdnsNMG("{DATA_DENY_V4}")
local alderpointdnsDenyV6 = alderpointdnsNMG("{DATA_DENY_V6}")
if alderpointdnsDenyV4 then
  addAction(NetmaskGroupRule(alderpointdnsDenyV4), RCodeAction(DNSRCode.REFUSED))
end
if alderpointdnsDenyV6 then
  addAction(NetmaskGroupRule(alderpointdnsDenyV6), RCodeAction(DNSRCode.REFUSED))
end
for _, sni in ipairs(alderpointdnsAccessLines("{DATA_DENY_SNI}")) do
  addAction(SNIRule(sni), RCodeAction(DNSRCode.REFUSED))
end
for _, path in ipairs(alderpointdnsAccessLines("{DATA_DENY_PATH}")) do
  addAction(HTTPPathRule(path), RCodeAction(DNSRCode.REFUSED))
end

local alderpointdnsDefaultPolicy = "allow"
local alderpointdnsPolicyFile = io.open(alderpointdnsAccessDataDir .. "/access-default-policy.txt", "r")
if alderpointdnsPolicyFile then
  local line = alderpointdnsPolicyFile:read("*l")
  alderpointdnsPolicyFile:close()
  if line then
    alderpointdnsDefaultPolicy = line
  end
end

if alderpointdnsDefaultPolicy == "deny" then
  -- Loopback is always exempt from the *default*-deny gate (documented in
  -- docs/clients-and-access.md) so Alderpoint's own internal health
  -- checks/acceptance tests never get locked out. An explicit deny rule
  -- above already ran and would have REFUSED loopback first if an admin
  -- deliberately added one.
  local alderpointdnsAllowV4 = alderpointdnsNMG("{DATA_ALLOW_V4}") or newNMG()
  alderpointdnsAllowV4:addMask("127.0.0.1/32")
  local alderpointdnsAllowV6 = alderpointdnsNMG("{DATA_ALLOW_V6}") or newNMG()
  alderpointdnsAllowV6:addMask("::1/128")
  local alderpointdnsGateParts = {{
    NetmaskGroupRule(alderpointdnsAllowV4),
    NetmaskGroupRule(alderpointdnsAllowV6)
  }}
  for _, sni in ipairs(alderpointdnsAccessLines("{DATA_ALLOW_SNI}")) do
    table.insert(alderpointdnsGateParts, SNIRule(sni))
  end
  for _, path in ipairs(alderpointdnsAccessLines("{DATA_ALLOW_PATH}")) do
    table.insert(alderpointdnsGateParts, HTTPPathRule(path))
  end
  addAction(NotRule(OrRule(alderpointdnsGateParts)), RCodeAction(DNSRCode.REFUSED))
end
"""


DOH_ALTSVC_MARKER_BEGIN = "-- ALDERPOINT-DNS-MANAGED-BLOCK: doh-altsvc BEGIN"
DOH_ALTSVC_MARKER_END = "-- ALDERPOINT-DNS-MANAGED-BLOCK: doh-altsvc END"
_DOH_CLIENTID_PATHS_SENTINEL = "access-doh-clientid-paths.txt"


def ensure_doh_clientid_paths_migration() -> bool:
    """Idempotently syncs the doh-altsvc managed block's DoH listener setup
    to the version that reads ClientID paths dynamically (see
    render_doh_clientid_paths()) into an existing dnsdist.conf that
    predates it -- a straight block replace (begin/end markers to
    begin/end markers) from the current packaging template, the same
    granularity app/encryption.py's own doh-altsvc migration uses. A
    no-op once already applied (checked via the sentinel string that only
    appears in the new block shape) or if the file doesn't have the
    doh-altsvc block at all yet (that migration owns creating it first)."""
    if not DNSDIST_CONF.exists():
        return False
    current = DNSDIST_CONF.read_text()
    if DOH_ALTSVC_MARKER_BEGIN not in current or DOH_ALTSVC_MARKER_END not in current:
        return False
    if _DOH_CLIENTID_PATHS_SENTINEL in current:
        return False
    template = DNSDIST_PACKAGING_CONF.read_text()
    if DOH_ALTSVC_MARKER_BEGIN not in template or DOH_ALTSVC_MARKER_END not in template:
        return False

    def _extract_block(text: str) -> str | None:
        start = text.find(DOH_ALTSVC_MARKER_BEGIN)
        end = text.find(DOH_ALTSVC_MARKER_END)
        if start == -1 or end == -1 or end < start:
            return None
        return text[start : end + len(DOH_ALTSVC_MARKER_END)]

    old_block = _extract_block(current)
    new_block = _extract_block(template)
    if not old_block or not new_block:
        return False
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    shutil.copy2(DNSDIST_CONF, BACKUP_DIR / f"dnsdist.conf.pre-doh-clientid-paths.{int(time.time())}")
    DNSDIST_CONF.write_text(current.replace(old_block, new_block, 1))
    return True


def ensure_dnsdist_access_include() -> bool:
    """Idempotently insert the guarded access-policy dofile include into an
    existing dnsdist.conf that lacks it, immediately after the
    NOTIFY/UPDATE/AXFR/IXFR REFUSED block and before upstream routing /
    custom rules / the default bind-pool action, so DENY takes effect
    before any other processing. Mirrors
    custom_rules.ensure_dnsdist_custom_include() exactly. Returns True when
    a change was made."""
    lua_path = access_lua_path()
    current = DNSDIST_CONF.read_text() if DNSDIST_CONF.exists() else DNSDIST_PACKAGING_CONF.read_text()
    if str(lua_path) in current:
        return False
    marker = 'addAction(AllRule(), PoolAction("alderpointdns_bind"))'
    if marker not in current:
        raise AccessPolicyError("dnsdist.conf is missing the default bind-pool action marker")
    include_block = (
        f'local alderpointdnsAccessConfig = "{lua_path}"\n'
        'local alderpointdnsAccessFile = io.open(alderpointdnsAccessConfig, "r")\n'
        'if alderpointdnsAccessFile then\n'
        '  alderpointdnsAccessFile:close()\n'
        '  dofile(alderpointdnsAccessConfig)\n'
        'end\n'
    )
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    if DNSDIST_CONF.exists():
        shutil.copy2(DNSDIST_CONF, BACKUP_DIR / f"dnsdist.conf.pre-access-policy.{int(time.time())}")
    DNSDIST_CONF.write_text(current.replace(marker, include_block + "\n" + marker, 1))
    return True


def _restore_backups(backups: list[tuple[Path, Path | None]]) -> None:
    for path, backup in backups:
        try:
            if backup and backup.exists():
                shutil.copy2(backup, path)
            elif path.exists():
                path.unlink()
        except OSError:
            continue


def deploy_access_layer(conn: sqlite3.Connection | None = None) -> dict[str, Any]:
    """Stage, validate, atomically install, and (only when content actually
    changed) restart dnsdist for the access-policy layer. On any failure,
    restores its own previously-installed files and restarts dnsdist before
    re-raising -- the active (last-known-good) configuration is never
    replaced by a config that failed validation. Mirrors
    app/custom_rules.py's deploy_dnsdist_layer() exactly."""
    from app import encryption

    owns = conn is None
    db = conn or connect()
    try:
        init_db(db)
        rules = list_access_rules(db)
        clients_by_id = {c["id"]: c for c in list_clients(db)}
        default_policy = get_default_policy(db)
        doh_path = encryption.settings(db).get("doh_path", "/dns-query") or "/dns-query"
        doh_clientid_paths = render_doh_clientid_paths(db)
    finally:
        if owns:
            db.close()

    data_files = render_access_data(rules, clients_by_id, default_policy, doh_path)
    data_files[DATA_DOH_CLIENTID_PATHS] = doh_clientid_paths
    final_lua = render_access_lua(COMPILED_DNSDIST_DIR)
    targets: dict[Path, str] = {access_lua_path(): final_lua}
    for name, text in data_files.items():
        targets[COMPILED_DNSDIST_DIR / name] = text
    changed = any(not path.exists() or path.read_text() != text for path, text in targets.items())
    info: dict[str, Any] = {"changed": changed, "backups": [], "default_policy": default_policy, "rule_count": len(rules)}
    if not changed:
        return info
    STAGING_DIR.mkdir(parents=True, exist_ok=True)
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    stage = Path(tempfile.mkdtemp(prefix="alderpointdns-access-policy-", dir=str(STAGING_DIR)))
    backups: list[tuple[Path, Path | None]] = []
    try:
        ensure_dnsdist_access_include()
        staged_lua = stage / ACCESS_LUA_NAME
        staged_lua.write_text(render_access_lua(stage))
        for name, text in data_files.items():
            (stage / name).write_text(text)
        if DNSDIST_CONF.exists():
            composite = stage / "dnsdist-composite-check.conf"
            composite.write_text(DNSDIST_CONF.read_text().replace(str(access_lua_path()), str(staged_lua)))
            run(["dnsdist", "--check-config", "-C", str(composite)])
        COMPILED_DNSDIST_DIR.mkdir(parents=True, exist_ok=True)
        for path, text in targets.items():
            backup = BACKUP_DIR / f"{path.name}.last-good.{int(time.time())}" if path.exists() else None
            if backup:
                shutil.copy2(path, backup)
            backups.append((path, backup))
            staged_final = stage / f"final-{path.name}"
            staged_final.write_text(text)
            os.replace(staged_final, path)
        info["backups"] = backups
        run(["systemctl", "restart", "dnsdist"])
    except Exception:
        _restore_backups(backups)
        if backups:
            run(["systemctl", "restart", "dnsdist"], check=False)
        raise
    finally:
        shutil.rmtree(stage, ignore_errors=True)
    return info


def ensure_access_data_files(conn: sqlite3.Connection | None = None) -> bool:
    """Writes the current access-policy Lua/data files to disk (from
    whatever is in the database right now) without restarting dnsdist --
    used by dnsdist_conf_migrate() so an upgraded install has the files the
    dofile include expects to find, without a second dnsdist restart in
    the same upgrade (upgrade.sh already restarts dnsdist once, after
    migrate() runs). On a fresh/untouched install this is default policy
    'allow' with zero rules, which renders to empty data files and an
    effectively inert Lua include -- no behavior change until an admin
    configures something. Returns True if any file was created/changed."""
    from app import encryption

    owns = conn is None
    db = conn or connect()
    try:
        init_db(db)
        rules = list_access_rules(db)
        clients_by_id = {c["id"]: c for c in list_clients(db)}
        default_policy = get_default_policy(db)
        doh_path = encryption.settings(db).get("doh_path", "/dns-query") or "/dns-query"
        doh_clientid_paths = render_doh_clientid_paths(db)
    finally:
        if owns:
            db.close()
    data_files = render_access_data(rules, clients_by_id, default_policy, doh_path)
    data_files[DATA_DOH_CLIENTID_PATHS] = doh_clientid_paths
    targets = {access_lua_path(): render_access_lua(COMPILED_DNSDIST_DIR)}
    for name, text in data_files.items():
        targets[COMPILED_DNSDIST_DIR / name] = text
    changed = any(not path.exists() or path.read_text() != text for path, text in targets.items())
    if changed:
        COMPILED_DNSDIST_DIR.mkdir(parents=True, exist_ok=True)
        for path, text in targets.items():
            path.write_text(text)
    return changed


def rollback_access_layer(info: dict[str, Any]) -> None:
    if not info.get("changed") or not info.get("backups"):
        return
    _restore_backups(info["backups"])
    run(["systemctl", "restart", "dnsdist"], check=False)
