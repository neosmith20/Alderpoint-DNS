#!/usr/bin/env python3
"""Alderpoint DNS Encryption Settings: DoH/DoH3/DoT/DoQ/DNSCrypt, TLS certificates,
and Apple mobile configuration profiles.

Plain UDP/TCP DNS on port 53 is never controlled from here — it is always on,
per Alderpoint DNS's binding engineering requirements. This module only manages
the encrypted-DNS listeners dnsdist terminates and the certificate material
they use.
"""

from __future__ import annotations

import datetime as dt
import ipaddress
import os
import plistlib
import re
import shutil
import socket
import sqlite3
import subprocess
import tempfile
import time
import uuid
from pathlib import Path
from typing import Any


DB_PATH = Path("/var/lib/alderpointdns/alderpointdns.db")
BACKUP_DIR = Path("/var/lib/alderpointdns/backups")
STAGING_DIR = Path("/var/lib/alderpointdns/staging")
CERT_DIR = Path("/etc/alderpointdns/certs")
CERT_PATH_DEFAULT = CERT_DIR / "alderpointdns-lab.crt"
KEY_PATH_DEFAULT = CERT_DIR / "alderpointdns-lab.key"
CA_CERT_PATH = CERT_DIR / "alderpointdns-ca.crt"
CA_KEY_PATH = CERT_DIR / "alderpointdns-ca.key"
CA_SERIAL_PATH = CERT_DIR / "alderpointdns-ca.srl"
UPLOADED_CERT_PATH = CERT_DIR / "alderpointdns-uploaded.crt"
UPLOADED_KEY_PATH = CERT_DIR / "alderpointdns-uploaded.key"
# Written by the unprivileged web process (staging is alderpointdns-writable);
# consumed and cleared by the privileged deploy step, since /etc/alderpointdns/certs
# is root:_dnsdist owned and not writable by the web app directly.
PENDING_UPLOAD_CERT = STAGING_DIR / "pending-cert-upload.crt"
PENDING_UPLOAD_KEY = STAGING_DIR / "pending-cert-upload.key"
DNSCRYPT_PROVIDER_PUBLIC = CERT_DIR / "dnscrypt-provider.public"
DNSCRYPT_PROVIDER_PRIVATE = CERT_DIR / "dnscrypt-provider.private"
DNSCRYPT_CERT = CERT_DIR / "dnscrypt-resolver.cert"
DNSCRYPT_KEY = CERT_DIR / "dnscrypt-resolver.key"

DNSDIST_CONF = Path("/etc/dnsdist/dnsdist.conf")
DNSDIST_ENV_OVERRIDE = Path("/etc/systemd/system/dnsdist.service.d/alderpointdns.conf")

MIGRATION_MARKER = "-- Encryption Settings (managed by app/encryption.py)"

DEFAULTS = {
    "server_hostname": "alderpointdns.local",
    "bootstrap_ip": "",
    "listen_ipv4": "0.0.0.0",
    "listen_ipv6": "::",
    "doh_enabled": "1",
    "doh3_enabled": "1",
    "dot_enabled": "1",
    "doq_enabled": "1",
    "dnscrypt_enabled": "0",
    "doh_path": "/dns-query",
    "doh_port": "443",
    "doh3_port": "443",
    "dot_port": "853",
    "doq_port": "853",
    "dnscrypt_port": "5443",
    "dnscrypt_provider": "2.dnscrypt-cert.alderpointdns.local",
    "cert_mode": "self_signed",
    "cert_path": str(CERT_PATH_DEFAULT),
    "key_path": str(KEY_PATH_DEFAULT),
    "pending_cert_action": "none",
    "dnscrypt_cert_serial": "0",
}

HOSTNAME_RE = re.compile(r"^(?=.{1,253}$)([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$")


class EncryptionError(ValueError):
    pass


def now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()


def connect() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def run(command: list[str], check: bool = True, env: dict[str, str] | None = None, input_text: str | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=check, env=env, input=input_text)


def detect_server_ip() -> str:
    try:
        proc = run(["hostname", "-I"], check=False)
        for token in proc.stdout.split():
            try:
                ip = ipaddress.ip_address(token)
            except ValueError:
                continue
            if ip.version == 4:
                return str(ip)
    except Exception:
        pass
    return "127.0.0.1"


def init_db(conn: sqlite3.Connection | None = None) -> None:
    close = conn is None
    db = conn or connect()
    try:
        if close:
            db.execute("PRAGMA journal_mode=WAL")
        db.executescript(
            """
            CREATE TABLE IF NOT EXISTS encryption_settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS encryption_deployments (
                id INTEGER PRIMARY KEY,
                started_at TEXT NOT NULL,
                finished_at TEXT,
                status TEXT NOT NULL,
                message TEXT NOT NULL DEFAULT '',
                protocol_tests TEXT NOT NULL DEFAULT ''
            );
            """
        )
        defaults = dict(DEFAULTS)
        defaults["bootstrap_ip"] = detect_server_ip()
        db.executemany(
            "INSERT OR IGNORE INTO encryption_settings(key, value) VALUES (?, ?)",
            list(defaults.items()),
        )
        if close:
            db.commit()
    finally:
        if close:
            db.close()


def settings(conn: sqlite3.Connection | None = None) -> dict[str, str]:
    init_db(conn)
    close = conn is None
    db = conn or connect()
    try:
        return {row["key"]: row["value"] for row in db.execute("SELECT key, value FROM encryption_settings")}
    finally:
        if close:
            db.close()


def _bool(value: Any) -> str:
    return "1" if str(value) in {"1", "true", "on", "yes"} else "0"


def _port(name: str, value: Any) -> str:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        raise EncryptionError(f"{name} must be an integer port") from None
    if not (1 <= parsed <= 65535):
        raise EncryptionError(f"{name} must be between 1 and 65535")
    return str(parsed)


def validate_settings(values: dict[str, Any]) -> dict[str, str]:
    out: dict[str, str] = {}
    hostname = str(values.get("server_hostname", "")).strip().lower().rstrip(".")
    if not hostname or not HOSTNAME_RE.match(hostname):
        raise EncryptionError("server_hostname must be a valid hostname")
    out["server_hostname"] = hostname
    bootstrap_ip = str(values.get("bootstrap_ip", "")).strip()
    if bootstrap_ip:
        try:
            out["bootstrap_ip"] = str(ipaddress.ip_address(bootstrap_ip))
        except ValueError:
            raise EncryptionError("bootstrap_ip must be a valid IP address") from None
    else:
        out["bootstrap_ip"] = detect_server_ip()
    listen_ipv4 = str(values.get("listen_ipv4", DEFAULTS["listen_ipv4"])).strip()
    listen_ipv6 = str(values.get("listen_ipv6", DEFAULTS["listen_ipv6"])).strip()
    if listen_ipv4:
        try:
            ip = ipaddress.ip_address(listen_ipv4)
            if ip.version != 4:
                raise ValueError
            out["listen_ipv4"] = str(ip)
        except ValueError:
            raise EncryptionError("listen_ipv4 must be blank or a valid IPv4 address") from None
    else:
        out["listen_ipv4"] = ""
    if listen_ipv6:
        try:
            ip = ipaddress.ip_address(listen_ipv6.strip("[]"))
            if ip.version != 6:
                raise ValueError
            out["listen_ipv6"] = str(ip)
        except ValueError:
            raise EncryptionError("listen_ipv6 must be blank or a valid IPv6 address") from None
    else:
        out["listen_ipv6"] = ""
    if not out["listen_ipv4"] and not out["listen_ipv6"]:
        raise EncryptionError("at least one DNS listen address must be configured")
    for flag in ("doh_enabled", "doh3_enabled", "dot_enabled", "doq_enabled", "dnscrypt_enabled"):
        out[flag] = _bool(values.get(flag, "0"))
    doh_path = str(values.get("doh_path", "/dns-query")).strip() or "/dns-query"
    if not doh_path.startswith("/"):
        doh_path = "/" + doh_path
    out["doh_path"] = doh_path
    out["doh_port"] = _port("doh_port", values.get("doh_port", 443))
    out["doh3_port"] = _port("doh3_port", values.get("doh3_port", 443))
    out["dot_port"] = _port("dot_port", values.get("dot_port", 853))
    out["doq_port"] = _port("doq_port", values.get("doq_port", 853))
    out["dnscrypt_port"] = _port("dnscrypt_port", values.get("dnscrypt_port", 5443))
    provider = str(values.get("dnscrypt_provider", DEFAULTS["dnscrypt_provider"])).strip().rstrip(".") or DEFAULTS["dnscrypt_provider"]
    out["dnscrypt_provider"] = provider
    cert_mode = str(values.get("cert_mode", "self_signed")).strip()
    if cert_mode not in {"self_signed", "local_ca", "uploaded", "existing_path"}:
        raise EncryptionError(f"unknown cert_mode {cert_mode!r}")
    out["cert_mode"] = cert_mode
    if cert_mode == "existing_path":
        cert_path = str(values.get("cert_path", "")).strip()
        key_path = str(values.get("key_path", "")).strip()
        if not cert_path or not key_path:
            raise EncryptionError("existing_path mode requires both cert_path and key_path")
        out["cert_path"] = cert_path
        out["key_path"] = key_path
    else:
        out["cert_path"] = values.get("cert_path") or DEFAULTS["cert_path"]
        out["key_path"] = values.get("key_path") or DEFAULTS["key_path"]
    return out


def update_settings(values: dict[str, Any]) -> None:
    validated = validate_settings(values)
    with connect() as conn:
        init_db(conn)
        for key, value in validated.items():
            conn.execute(
                "INSERT INTO encryption_settings(key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (key, value),
            )


# ---------------------------------------------------------------------------
# Certificate management
# ---------------------------------------------------------------------------

def _write_owned(path: Path, content: bytes, mode: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_bytes(content)
    tmp.chmod(mode)
    os.replace(tmp, path)
    try:
        shutil.chown(path, user="root", group="_dnsdist")
    except (LookupError, PermissionError, OSError):
        pass


def generate_self_signed(hostname: str, extra_sans: list[str] | None = None, days: int = 825) -> None:
    sans = [f"DNS:{hostname}"]
    for name in extra_sans or []:
        sans.append(f"IP:{name}" if _looks_like_ip(name) else f"DNS:{name}")
    san_arg = ",".join(dict.fromkeys(sans))
    with tempfile.TemporaryDirectory(dir=str(STAGING_DIR)) as tmp:
        tmp_path = Path(tmp)
        key_out = tmp_path / "server.key"
        cert_out = tmp_path / "server.crt"
        run([
            "openssl", "req", "-x509", "-newkey", "rsa:3072", "-sha256", "-days", str(days), "-nodes",
            "-subj", f"/CN={hostname}",
            "-addext", f"subjectAltName={san_arg}",
            "-keyout", str(key_out),
            "-out", str(cert_out),
        ])
        _write_owned(CERT_PATH_DEFAULT, cert_out.read_bytes(), 0o644)
        _write_owned(KEY_PATH_DEFAULT, key_out.read_bytes(), 0o640)


def _looks_like_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def ensure_local_ca() -> None:
    if CA_CERT_PATH.exists() and CA_KEY_PATH.exists():
        return
    with tempfile.TemporaryDirectory(dir=str(STAGING_DIR)) as tmp:
        tmp_path = Path(tmp)
        key_out = tmp_path / "ca.key"
        cert_out = tmp_path / "ca.crt"
        run([
            "openssl", "req", "-x509", "-newkey", "rsa:4096", "-sha256", "-days", "3650", "-nodes",
            "-subj", "/CN=Alderpoint DNS Local CA",
            "-addext", "basicConstraints=critical,CA:true",
            "-addext", "keyUsage=critical,keyCertSign,cRLSign",
            "-keyout", str(key_out),
            "-out", str(cert_out),
        ])
        _write_owned(CA_CERT_PATH, cert_out.read_bytes(), 0o644)
        _write_owned(CA_KEY_PATH, key_out.read_bytes(), 0o600)
        try:
            shutil.chown(CA_KEY_PATH, user="root", group="root")
        except (LookupError, PermissionError, OSError):
            pass


def issue_from_local_ca(hostname: str, extra_sans: list[str] | None = None, days: int = 825) -> None:
    ensure_local_ca()
    sans = [f"DNS:{hostname}"]
    for name in extra_sans or []:
        sans.append(f"IP:{name}" if _looks_like_ip(name) else f"DNS:{name}")
    san_arg = ",".join(dict.fromkeys(sans))
    with tempfile.TemporaryDirectory(dir=str(STAGING_DIR)) as tmp:
        tmp_path = Path(tmp)
        key_out = tmp_path / "leaf.key"
        csr_out = tmp_path / "leaf.csr"
        cert_out = tmp_path / "leaf.crt"
        ext_file = tmp_path / "leaf.ext"
        ext_file.write_text(f"subjectAltName={san_arg}\n")
        run(["openssl", "genrsa", "-out", str(key_out), "3072"])
        run(["openssl", "req", "-new", "-key", str(key_out), "-subj", f"/CN={hostname}", "-out", str(csr_out)])
        run([
            "openssl", "x509", "-req", "-in", str(csr_out),
            "-CA", str(CA_CERT_PATH), "-CAkey", str(CA_KEY_PATH), "-CAcreateserial", "-CAserial", str(CA_SERIAL_PATH),
            "-days", str(days), "-sha256", "-extfile", str(ext_file),
            "-out", str(cert_out),
        ])
        combined = cert_out.read_bytes() + b"\n" + CA_CERT_PATH.read_bytes()
        _write_owned(CERT_PATH_DEFAULT, combined, 0o644)
        _write_owned(KEY_PATH_DEFAULT, key_out.read_bytes(), 0o640)


def accept_uploaded(cert_bytes: bytes, key_bytes: bytes) -> None:
    with tempfile.TemporaryDirectory(dir=str(STAGING_DIR)) as tmp:
        tmp_path = Path(tmp)
        cert_tmp = tmp_path / "uploaded.crt"
        key_tmp = tmp_path / "uploaded.key"
        cert_tmp.write_bytes(cert_bytes)
        key_tmp.write_bytes(key_bytes)
        run(["openssl", "x509", "-in", str(cert_tmp), "-noout"])
        run(["openssl", "pkey", "-in", str(key_tmp), "-noout"])
        if not validate_cert_key_match(cert_tmp, key_tmp):
            raise EncryptionError("uploaded certificate and key do not match")
        _write_owned(UPLOADED_CERT_PATH, cert_bytes, 0o644)
        _write_owned(UPLOADED_KEY_PATH, key_bytes, 0o640)


def accept_pending_upload() -> bool:
    """Consume a certificate/key pair staged by the web app. Returns True if
    a pending upload was found and installed."""
    if not (PENDING_UPLOAD_CERT.exists() and PENDING_UPLOAD_KEY.exists()):
        return False
    accept_uploaded(PENDING_UPLOAD_CERT.read_bytes(), PENDING_UPLOAD_KEY.read_bytes())
    PENDING_UPLOAD_CERT.unlink(missing_ok=True)
    PENDING_UPLOAD_KEY.unlink(missing_ok=True)
    return True


def request_cert_upload(cert_bytes: bytes, key_bytes: bytes) -> None:
    """Called from the unprivileged web process: stage bytes for the
    privileged deploy step to validate and install."""
    STAGING_DIR.mkdir(parents=True, exist_ok=True)
    PENDING_UPLOAD_CERT.write_bytes(cert_bytes)
    PENDING_UPLOAD_KEY.write_bytes(key_bytes)


def request_cert_action(action: str) -> None:
    if action not in {"none", "generate_self_signed", "generate_local_ca"}:
        raise EncryptionError(f"unknown certificate action {action!r}")
    with connect() as conn:
        init_db(conn)
        conn.execute(
            "INSERT INTO encryption_settings(key, value) VALUES ('pending_cert_action', ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (action,),
        )


def validate_cert_key_match(cert_path: Path, key_path: Path) -> bool:
    cert_result = run(["openssl", "x509", "-in", str(cert_path), "-noout", "-modulus"], check=False)
    if cert_result.returncode != 0 or not cert_result.stdout.strip():
        return False
    cert_mod = cert_result.stdout.strip()
    key_result = run(["openssl", "pkey", "-in", str(key_path), "-noout", "-modulus"], check=False)
    key_mod = key_result.stdout.strip() if key_result.returncode == 0 else ""
    if not key_mod:
        key_result = run(["openssl", "rsa", "-in", str(key_path), "-noout", "-modulus"], check=False)
        key_mod = key_result.stdout.strip() if key_result.returncode == 0 else ""
    return bool(key_mod) and cert_mod == key_mod


def resolve_active_cert_paths(cfg: dict[str, str]) -> tuple[Path, Path]:
    mode = cfg.get("cert_mode", "self_signed")
    if mode == "uploaded":
        return UPLOADED_CERT_PATH, UPLOADED_KEY_PATH
    if mode == "existing_path":
        return Path(cfg["cert_path"]), Path(cfg["key_path"])
    return CERT_PATH_DEFAULT, KEY_PATH_DEFAULT


def cert_info(cert_path: Path) -> dict[str, Any]:
    if not cert_path.exists():
        return {"available": False}
    subject = run(["openssl", "x509", "-in", str(cert_path), "-noout", "-subject"], check=False).stdout.strip()
    issuer = run(["openssl", "x509", "-in", str(cert_path), "-noout", "-issuer"], check=False).stdout.strip()
    enddate = run(["openssl", "x509", "-in", str(cert_path), "-noout", "-enddate"], check=False).stdout.strip()
    startdate = run(["openssl", "x509", "-in", str(cert_path), "-noout", "-startdate"], check=False).stdout.strip()
    fingerprint = run(["openssl", "x509", "-in", str(cert_path), "-noout", "-fingerprint", "-sha256"], check=False).stdout.strip()
    san_raw = run(["openssl", "x509", "-in", str(cert_path), "-noout", "-ext", "subjectAltName"], check=False).stdout
    sans = [part.strip() for part in san_raw.replace("\n", "").split("Subject Alternative Name:")[-1].split(",") if part.strip()]
    days_remaining = None
    not_after = enddate.split("=", 1)[-1].strip() if "=" in enddate else ""
    if not_after:
        try:
            parsed = dt.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=dt.timezone.utc)
            days_remaining = (parsed - dt.datetime.now(dt.timezone.utc)).days
        except ValueError:
            pass
    subject_cn = subject.split("=", 1)[-1].strip() if "=" in subject else subject
    issuer_cn = issuer.split("=", 1)[-1].strip() if "=" in issuer else issuer
    return {
        "available": True,
        "subject": subject_cn,
        "issuer": issuer_cn,
        "not_before": startdate.split("=", 1)[-1].strip() if "=" in startdate else startdate,
        "not_after": not_after,
        "days_remaining": days_remaining,
        "expiring_soon": days_remaining is not None and days_remaining < 30,
        "expired": days_remaining is not None and days_remaining < 0,
        "fingerprint_sha256": fingerprint.split("=", 1)[-1].strip() if "=" in fingerprint else fingerprint,
        "sans": sans,
        "self_signed": subject_cn == issuer_cn,
    }


# ---------------------------------------------------------------------------
# DNSCrypt
# ---------------------------------------------------------------------------

def ensure_dnscrypt_provider_keys() -> None:
    if DNSCRYPT_PROVIDER_PUBLIC.exists() and DNSCRYPT_PROVIDER_PRIVATE.exists():
        return
    # dnsdist's generateDNSCryptProviderKeys/generateDNSCryptCertificate are
    # console Lua functions (help() confirms this exact signature) intended
    # to be run interactively against the control socket. In this
    # environment they reliably print a provider fingerprint but do not
    # persist key files to disk in either standalone one-shot (`-l ... -e`)
    # or live-console (`-c ... -e`) invocation, and the live console path is
    # additionally blocked by dnsdist.service's systemd sandboxing
    # (PrivateTmp, ProtectSystem=full, no ReadWritePaths for
    # /etc/alderpointdns/certs). Rather than guess further at an unverifiable
    # invocation, this raises so callers (see deploy_encryption) treat
    # DNSCrypt as unavailable and disable it for the deployment instead of
    # claiming a certificate that does not exist.
    with tempfile.TemporaryDirectory(dir=str(STAGING_DIR)) as tmp:
        tmp_path = Path(tmp)
        pub = tmp_path / "provider.public"
        priv = tmp_path / "provider.private"
        script = f'generateDNSCryptProviderKeys("{pub}", "{priv}")'
        run(["dnsdist", "-l", "127.0.0.1:0", "-e", script])
        if not (pub.exists() and priv.exists()):
            raise EncryptionError("dnsdist did not write DNSCrypt provider key files")
        _write_owned(DNSCRYPT_PROVIDER_PUBLIC, pub.read_bytes(), 0o644)
        _write_owned(DNSCRYPT_PROVIDER_PRIVATE, priv.read_bytes(), 0o600)
        try:
            shutil.chown(DNSCRYPT_PROVIDER_PRIVATE, user="root", group="root")
        except (LookupError, PermissionError, OSError):
            pass


def issue_dnscrypt_certificate(days: int = 365) -> None:
    ensure_dnscrypt_provider_keys()
    with connect() as conn:
        init_db(conn)
        row = conn.execute("SELECT value FROM encryption_settings WHERE key='dnscrypt_cert_serial'").fetchone()
        serial = int(row["value"]) + 1 if row else 1
        conn.execute(
            "INSERT INTO encryption_settings(key, value) VALUES ('dnscrypt_cert_serial', ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (str(serial),),
        )
        conn.commit()
    valid_from = int(time.time())
    valid_until = valid_from + days * 86400
    with tempfile.TemporaryDirectory(dir=str(STAGING_DIR)) as tmp:
        tmp_path = Path(tmp)
        cert_out = tmp_path / "resolver.cert"
        key_out = tmp_path / "resolver.key"
        script = (
            f'generateDNSCryptCertificate("{DNSCRYPT_PROVIDER_PRIVATE}", "{cert_out}", "{key_out}", '
            f"{serial}, {valid_from}, {valid_until})"
        )
        run(["dnsdist", "-l", "127.0.0.1:0", "-e", script])
        if not (cert_out.exists() and key_out.exists()):
            raise EncryptionError("dnsdist did not write DNSCrypt resolver certificate files")
        _write_owned(DNSCRYPT_CERT, cert_out.read_bytes(), 0o644)
        _write_owned(DNSCRYPT_KEY, key_out.read_bytes(), 0o640)


def dnscrypt_provider_fingerprint() -> str | None:
    if not DNSCRYPT_PROVIDER_PUBLIC.exists():
        return None
    return DNSCRYPT_PROVIDER_PUBLIC.read_bytes().hex().upper()


# ---------------------------------------------------------------------------
# dnsdist.conf parameterization migration (one-time, idempotent)
# ---------------------------------------------------------------------------

def ensure_dnsdist_conf_parameterized(template_path: Path) -> bool:
    """Idempotently migrate the live dnsdist.conf to the parameterized
    template, preserving the currently-installed console/webserver secrets.
    Returns True if a change was made."""
    current = DNSDIST_CONF.read_text() if DNSDIST_CONF.exists() else ""
    if MIGRATION_MARKER in current and "ALDERPOINTDNS_DNS_LISTEN_IPV4" in current:
        return False
    key_match = re.search(r'setKey\("([^"]+)"\)', current)
    password_match = re.search(r'password="([^"]+)"', current)
    api_key_match = re.search(r'apiKey="([^"]+)"', current)
    if not (key_match and password_match and api_key_match):
        raise EncryptionError("could not locate existing dnsdist console/webserver secrets to preserve")
    template = template_path.read_text()
    new_content = template
    new_content = re.sub(r'setKey\("ALDERPOINTDNS_CONSOLE_KEY_PLACEHOLDER"\)', f'setKey("{key_match.group(1)}")', new_content)
    new_content = new_content.replace('password="ALDERPOINTDNS_WEBSERVER_PASSWORD_PLACEHOLDER"', f'password="{password_match.group(1)}"')
    new_content = new_content.replace('apiKey="ALDERPOINTDNS_WEBSERVER_API_KEY_PLACEHOLDER"', f'apiKey="{api_key_match.group(1)}"')
    if "ALDERPOINTDNS_CONSOLE_KEY_PLACEHOLDER" in new_content or "ALDERPOINTDNS_WEBSERVER_PASSWORD_PLACEHOLDER" in new_content or "ALDERPOINTDNS_WEBSERVER_API_KEY_PLACEHOLDER" in new_content:
        raise EncryptionError("template still contains unresolved secret placeholders")
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    backup = BACKUP_DIR / f"dnsdist.conf.pre-encryption.{int(time.time())}"
    if DNSDIST_CONF.exists():
        shutil.copy2(DNSDIST_CONF, backup)
    DNSDIST_CONF.write_text(new_content)
    return True


# ---------------------------------------------------------------------------
# Deploy
# ---------------------------------------------------------------------------

def render_env_override(cfg: dict[str, str]) -> str:
    lines = [
        "[Service]",
        "Environment=ALDERPOINTDNS_DNS_PLAIN=1",
        f"Environment=ALDERPOINTDNS_DNS_LISTEN_IPV4={cfg.get('listen_ipv4', DEFAULTS['listen_ipv4'])}",
        f"Environment=ALDERPOINTDNS_DNS_LISTEN_IPV6={cfg.get('listen_ipv6', DEFAULTS['listen_ipv6'])}",
        f"Environment=ALDERPOINTDNS_DNS_DOH={cfg['doh_enabled']}",
        f"Environment=ALDERPOINTDNS_DNS_DOT={cfg['dot_enabled']}",
        f"Environment=ALDERPOINTDNS_DNS_DOQ={cfg['doq_enabled']}",
        f"Environment=ALDERPOINTDNS_DNS_DOH3={cfg['doh3_enabled']}",
        f"Environment=ALDERPOINTDNS_DNS_DNSCRYPT={cfg['dnscrypt_enabled']}",
        f"Environment=ALDERPOINTDNS_TLS_CERT={cfg['cert_path']}",
        f"Environment=ALDERPOINTDNS_TLS_KEY={cfg['key_path']}",
        f"Environment=ALDERPOINTDNS_DOH_PATH={cfg['doh_path']}",
        f"Environment=ALDERPOINTDNS_DOH_PORT={cfg['doh_port']}",
        f"Environment=ALDERPOINTDNS_DOH3_PORT={cfg['doh3_port']}",
        f"Environment=ALDERPOINTDNS_DOT_PORT={cfg['dot_port']}",
        f"Environment=ALDERPOINTDNS_DOQ_PORT={cfg['doq_port']}",
        f"Environment=ALDERPOINTDNS_DNSCRYPT_PORT={cfg['dnscrypt_port']}",
        f"Environment=ALDERPOINTDNS_DNSCRYPT_PROVIDER={cfg['dnscrypt_provider']}",
        f"Environment=ALDERPOINTDNS_DNSCRYPT_CERT={DNSCRYPT_CERT}",
        f"Environment=ALDERPOINTDNS_DNSCRYPT_KEY={DNSCRYPT_KEY}",
    ]
    return "\n".join(lines) + "\n"


def _env_from_override(text: str) -> dict[str, str]:
    out = {}
    for line in text.splitlines():
        if line.startswith("Environment="):
            key, _, value = line[len("Environment="):].partition("=")
            out[key] = value
    return out


def dig(domain: str) -> subprocess.CompletedProcess[str]:
    return run(["dig", "@127.0.0.1", domain, "A", "+time=3", "+tries=1"], check=False)


def resolves_plain(domain: str) -> bool:
    result = dig(domain)
    return result.returncode == 0 and "status: NOERROR" in result.stdout and "\tA\t" in result.stdout


def test_protocols(cfg: dict[str, str], hostname: str, cert_path: Path) -> dict[str, str]:
    results: dict[str, str] = {}
    results["plain"] = "ok" if resolves_plain("cloudflare.com") else "failed"
    if cfg["doh_enabled"] == "1":
        results["doh"] = _test_doh(cfg["doh_port"], cfg["doh_path"], hostname, cert_path)
    if cfg["doh3_enabled"] == "1":
        results["doh3"] = _test_doh3(cfg["doh3_port"], cfg["doh_path"])
    if cfg["dot_enabled"] == "1":
        results["dot"] = _test_dot(cfg["dot_port"], hostname, cert_path)
    if cfg["doq_enabled"] == "1":
        results["doq"] = _test_doq(cfg["doq_port"])
    if cfg["dnscrypt_enabled"] == "1":
        results["dnscrypt"] = _test_port_listening(cfg["dnscrypt_port"])
    return results


def _test_doh(port: str, path: str, hostname: str, cert_path: Path) -> str:
    try:
        import dns.message
        import dns.query

        query = dns.message.make_query("cloudflare.com", "A")
        response = dns.query.https(query, f"https://127.0.0.1:{port}{path}", verify=False, timeout=4)
        return "ok" if response.rcode() == 0 else f"failed (rcode={response.rcode()})"
    except Exception as exc:
        return f"failed ({exc})"


def _test_doh3(port: str, path: str) -> str:
    try:
        import dns.message
        import dns.query

        query = dns.message.make_query("cloudflare.com", "A")
        response = dns.query.https(query, f"https://127.0.0.1:{port}{path}", verify=False, timeout=4, http_version=dns.query.HTTPVersion.H3)
        return "ok" if response.rcode() == 0 else f"failed (rcode={response.rcode()})"
    except Exception as exc:
        return f"failed ({exc})"


def _test_dot(port: str, hostname: str, cert_path: Path) -> str:
    result = run(
        ["kdig", "+tls", "@127.0.0.1", "-p", port, f"+tls-ca={cert_path}", f"+tls-hostname={hostname}", "cloudflare.com", "A", "+timeout=3", "+retry=1"],
        check=False,
    )
    return "ok" if result.returncode == 0 and "status: NOERROR" in result.stdout else "failed"


def _test_doq(port: str) -> str:
    try:
        import dns.message
        import dns.query

        query = dns.message.make_query("cloudflare.com", "A")
        response = dns.query.quic(query, "127.0.0.1", port=int(port), verify=False, timeout=4)
        return "ok" if response.rcode() == 0 else f"failed (rcode={response.rcode()})"
    except Exception as exc:
        return f"failed ({exc})"


def _test_port_listening(port: str) -> str:
    for family, sock_type in ((socket.AF_INET, socket.SOCK_DGRAM), (socket.AF_INET, socket.SOCK_STREAM)):
        sock = socket.socket(family, sock_type)
        sock.settimeout(1)
        try:
            if sock_type == socket.SOCK_STREAM:
                sock.connect(("127.0.0.1", int(port)))
            else:
                sock.sendto(b"", ("127.0.0.1", int(port)))
        except OSError:
            return "port not reachable (no application-layer test client available for this protocol)"
        finally:
            sock.close()
    return "port reachable (no application-layer test client available for this protocol)"


def deploy_encryption(conn: sqlite3.Connection | None = None, template_path: Path | None = None) -> int:
    close = conn is None
    db = conn or connect()
    init_db(db)
    started = now()
    cursor = db.execute("INSERT INTO encryption_deployments(started_at, status, message) VALUES (?, 'running', '')", (started,))
    deployment_id = cursor.lastrowid
    db.commit()
    STAGING_DIR.mkdir(parents=True, exist_ok=True)
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    status = "failed"
    message = ""
    protocol_tests: dict[str, str] = {}
    env_backup: Path | None = None
    conf_changed = False
    cert_material_changed = False
    try:
        cfg = settings(db)
        pending_action = cfg.get("pending_cert_action", "none")
        if pending_action == "generate_self_signed":
            generate_self_signed(cfg["server_hostname"], [cfg.get("bootstrap_ip", "")])
            cert_material_changed = True
        elif pending_action == "generate_local_ca":
            issue_from_local_ca(cfg["server_hostname"], [cfg.get("bootstrap_ip", "")])
            cert_material_changed = True
        if pending_action != "none":
            db.execute("UPDATE encryption_settings SET value='none' WHERE key='pending_cert_action'")
            db.commit()
        if cfg.get("cert_mode") == "uploaded":
            cert_material_changed = accept_pending_upload() or cert_material_changed
        cert_path, key_path = resolve_active_cert_paths(cfg)
        if not cert_path.exists() or not key_path.exists():
            raise EncryptionError(f"certificate material missing at {cert_path} / {key_path}")
        if not validate_cert_key_match(cert_path, key_path):
            raise EncryptionError("configured certificate and key do not match")
        dnscrypt_warning = ""
        if cfg["dnscrypt_enabled"] == "1" and not (DNSCRYPT_CERT.exists() and DNSCRYPT_KEY.exists()):
            try:
                issue_dnscrypt_certificate()
            except Exception as exc:
                # DNSCrypt requires generating provider/resolver key material
                # through dnsdist's own console Lua API. If that generation
                # is not reliably available in this environment, DNSCrypt is
                # disabled for this deployment rather than blocking every
                # other protocol or claiming a certificate that doesn't
                # actually exist.
                cfg["dnscrypt_enabled"] = "0"
                dnscrypt_warning = f"DNSCrypt certificate generation failed, DNSCrypt was disabled for this deployment: {exc}"
        conf_changed = ensure_dnsdist_conf_parameterized(template_path or Path("/opt/alderpointdns/packaging/dnsdist.conf"))
        new_env_text = render_env_override(cfg)
        current_env_text = DNSDIST_ENV_OVERRIDE.read_text() if DNSDIST_ENV_OVERRIDE.exists() else ""
        if new_env_text == current_env_text and not conf_changed and not cert_material_changed:
            status = "unchanged"
            message = "encryption settings already match the deployed configuration"
            if dnscrypt_warning:
                message = f"{message}; {dnscrypt_warning}"
        else:
            if DNSDIST_ENV_OVERRIDE.exists():
                env_backup = BACKUP_DIR / f"dnsdist-encryption.conf.last-good.{int(time.time())}"
                shutil.copy2(DNSDIST_ENV_OVERRIDE, env_backup)
            staged = STAGING_DIR / f"alderpointdns-encryption-{deployment_id}.conf"
            staged.write_text(new_env_text)
            DNSDIST_ENV_OVERRIDE.parent.mkdir(parents=True, exist_ok=True)
            os.replace(staged, DNSDIST_ENV_OVERRIDE)
            run(["systemctl", "daemon-reload"])
            check_env = {**os.environ, **_env_from_override(new_env_text)}
            run(["dnsdist", "--check-config", "-C", str(DNSDIST_CONF)], env=check_env)
            run(["systemctl", "restart", "dnsdist"])
            if not _wait_active("dnsdist", timeout=15):
                raise RuntimeError("dnsdist did not become active after restart")
            protocol_tests = test_protocols(cfg, cfg["server_hostname"], cert_path)
            failed = [name for name, result in protocol_tests.items() if not result.startswith("ok") and "reachable" not in result]
            if failed:
                raise RuntimeError(f"protocol test failed for: {', '.join(failed)} ({protocol_tests})")
            status = "deployed"
            message = f"deployed with protocols: {protocol_tests}"
            if dnscrypt_warning:
                message = f"{message}; {dnscrypt_warning}"
    except Exception as exc:
        message = str(exc)
        if env_backup is not None:
            try:
                shutil.copy2(env_backup, DNSDIST_ENV_OVERRIDE)
                run(["systemctl", "daemon-reload"], check=False)
                run(["systemctl", "restart", "dnsdist"], check=False)
                if _wait_active("dnsdist", timeout=15):
                    status = "rolled_back"
                else:
                    status = "rollback_failed"
                    message = f"{message}; rollback restart did not become active"
            except Exception as rollback_exc:
                status = "rollback_failed"
                message = f"{message}; rollback failed: {rollback_exc}"
        raise
    finally:
        db.execute(
            "UPDATE encryption_deployments SET finished_at=?, status=?, message=?, protocol_tests=? WHERE id=?",
            (now(), status, message, str(protocol_tests), deployment_id),
        )
        db.commit()
        if close:
            db.close()
    return deployment_id


def _wait_active(service: str, timeout: int = 15) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        result = run(["systemctl", "is-active", service], check=False)
        if result.stdout.strip() == "active":
            return True
        time.sleep(0.5)
    return run(["systemctl", "is-active", service], check=False).stdout.strip() == "active"


def last_deployment(conn: sqlite3.Connection | None = None) -> dict[str, Any] | None:
    close = conn is None
    db = conn or connect()
    try:
        init_db(db)
        row = db.execute("SELECT * FROM encryption_deployments ORDER BY id DESC LIMIT 1").fetchone()
        return dict(row) if row else None
    finally:
        if close:
            db.close()


# ---------------------------------------------------------------------------
# Client connection info and Apple profiles
# ---------------------------------------------------------------------------

def connection_info(cfg: dict[str, str]) -> dict[str, str]:
    hostname = cfg["server_hostname"]
    ip = cfg.get("bootstrap_ip") or detect_server_ip()
    info = {}
    if cfg["doh_enabled"] == "1":
        info["DoH"] = f"https://{hostname}:{cfg['doh_port']}{cfg['doh_path']}"
    if cfg["doh3_enabled"] == "1":
        info["DoH3"] = f"https://{hostname}:{cfg['doh3_port']}{cfg['doh_path']} (HTTP/3)"
    if cfg["dot_enabled"] == "1":
        info["DoT"] = f"tls://{hostname}:{cfg['dot_port']}"
    if cfg["doq_enabled"] == "1":
        info["DoQ"] = f"quic://{hostname}:{cfg['doq_port']}"
    if cfg["dnscrypt_enabled"] == "1":
        fp = dnscrypt_provider_fingerprint()
        info["DNSCrypt"] = f"provider {cfg['dnscrypt_provider']} on {ip}:{cfg['dnscrypt_port']}" + (f", provider public key {fp}" if fp else "")
    return info


def apple_mobileconfig(cfg: dict[str, str], protocol: str) -> bytes:
    hostname = cfg["server_hostname"]
    ip = cfg.get("bootstrap_ip") or detect_server_ip()
    payload_uuid = str(uuid.uuid4()).upper()
    profile_uuid = str(uuid.uuid4()).upper()
    if protocol == "doh":
        dns_settings: dict[str, Any] = {
            "DNSProtocol": "HTTPS",
            "ServerURL": f"https://{hostname}:{cfg['doh_port']}{cfg['doh_path']}",
            "ServerName": hostname,
        }
        label = "DNS-over-HTTPS"
    elif protocol == "dot":
        dns_settings = {
            "DNSProtocol": "TLS",
            "ServerName": hostname,
            "ServerAddresses": [ip],
        }
        label = "DNS-over-TLS"
    else:
        raise EncryptionError("Apple profiles are only generated for doh or dot")
    payload = {
        "PayloadType": "com.apple.dnsSettings.managed",
        "PayloadIdentifier": f"network.alderpointdns.dns.{protocol}",
        "PayloadUUID": payload_uuid,
        "PayloadVersion": 1,
        "PayloadDisplayName": f"Alderpoint DNS {label}",
        **dns_settings,
    }
    profile = {
        "PayloadContent": [payload],
        "PayloadDisplayName": f"Alderpoint DNS {label} ({hostname})",
        "PayloadIdentifier": f"network.alderpointdns.profile.{protocol}",
        "PayloadRemovalDisallowed": False,
        "PayloadType": "Configuration",
        "PayloadUUID": profile_uuid,
        "PayloadVersion": 1,
    }
    return plistlib.dumps(profile, fmt=plistlib.FMT_XML)
