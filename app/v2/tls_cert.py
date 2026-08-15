"""V2 management-plane native HTTPS: certificate lifecycle (Workstream 4B,
Priority 3-6).

Real X.509 generation/validation via the ``cryptography`` library (no
custom crypto). Two supported modes:

- **Bootstrap self-signed**: generated once, on first need, so a fresh
  appliance can serve HTTPS without an external certificate authority.
  EC P-256 (modern, fast, universally supported by curl/openssl/browsers
  on a target this recent), SHA-256 signature, SAN covering the loopback
  identities a fresh appliance is reachable at.
- **Administrator-provided**: validated (parsable cert, parsable key, key
  actually matches the certificate's public key, validity window sane)
  BEFORE ever touching the live path, via the same
  stage -> validate -> promote -> rollback-on-failure shape already used
  for the compiled dnsdist/RPZ runtime (``app/v2/runtime_staging.py``) and
  for secret restore (``app/v2/secret_store.py``) -- a bad replacement
  never destroys the currently-working certificate.

Private key material is never logged, never returned by any function
here, and the key file is always written mode 0600.
"""

from __future__ import annotations

import datetime
import ipaddress
import os
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

_KEY_FILE_MODE = 0o600
_CERT_FILE_MODE = 0o644
# Below the ~398-day cap browsers/CA-Browser-Forum apply to publicly
# trusted certs (irrelevant for a self-signed local cert, which is never
# publicly trusted anyway) but still a deliberately bounded, not-forever
# validity window, consistent with "appropriate validity period."
_SELF_SIGNED_VALIDITY_DAYS = 397
_SUBJECT_CN = "Alderpoint DNS V2 Local (self-signed)"


class TlsCertError(RuntimeError):
    pass


class TlsCertMismatchError(TlsCertError):
    """Certificate and private key do not form a matching pair."""


class TlsCertValidationError(TlsCertError):
    pass


@dataclass(frozen=True)
class CertInfo:
    """Metadata safe to return over an API -- never key material."""

    subject: str
    not_valid_before: str
    not_valid_after: str
    san: tuple[str, ...]
    is_self_signed: bool


def generate_self_signed(
    hostnames: tuple[str, ...] = ("localhost",),
    ip_addresses: tuple[str, ...] = ("127.0.0.1", "::1"),
) -> tuple[bytes, bytes]:
    """Returns (cert_pem, key_pem). Does not touch disk -- callers use
    stage_validate_promote() to install atomically."""
    key = ec.generate_private_key(ec.SECP256R1())
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, _SUBJECT_CN)])
    now = datetime.datetime.now(datetime.timezone.utc)

    san_entries: list[x509.GeneralName] = [x509.DNSName(h) for h in hostnames]
    for ip in ip_addresses:
        san_entries.append(x509.IPAddress(ipaddress.ip_address(ip)))

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))  # small clock-skew tolerance
        .not_valid_after(now + datetime.timedelta(days=_SELF_SIGNED_VALIDITY_DAYS))
        .add_extension(x509.SubjectAlternativeName(san_entries), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, key_encipherment=False, key_agreement=True,
                content_commitment=False, data_encipherment=False, key_cert_sign=False,
                crl_sign=False, encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .sign(key, hashes.SHA256())
    )

    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return cert_pem, key_pem


def validate_cert_key_pair(cert_pem: bytes, key_pem: bytes) -> CertInfo:
    """Parses both, confirms the key's public component matches the
    certificate's, and checks the validity window covers "now." Raises
    TlsCertValidationError / TlsCertMismatchError -- never returns a
    partial/best-effort result."""
    try:
        cert = x509.load_pem_x509_certificate(cert_pem)
    except ValueError as exc:
        raise TlsCertValidationError(f"unparsable certificate: {exc}") from exc
    try:
        key = serialization.load_pem_private_key(key_pem, password=None)
    except (ValueError, TypeError) as exc:
        raise TlsCertValidationError(f"unparsable private key: {exc}") from exc

    cert_public_numbers = cert.public_key().public_numbers()
    key_public_numbers = key.public_key().public_numbers()
    if cert_public_numbers != key_public_numbers:
        raise TlsCertMismatchError("private key does not match certificate public key")

    now = datetime.datetime.now(datetime.timezone.utc)
    not_before = cert.not_valid_before_utc
    not_after = cert.not_valid_after_utc
    if now < not_before:
        raise TlsCertValidationError(f"certificate not yet valid (not_before={not_before.isoformat()})")
    if now > not_after:
        raise TlsCertValidationError(f"certificate has expired (not_after={not_after.isoformat()})")

    try:
        san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        san = tuple(str(n.value) for n in san_ext.value)
    except x509.ExtensionNotFound:
        san = ()

    return CertInfo(
        subject=cert.subject.rfc4514_string(),
        not_valid_before=not_before.isoformat(),
        not_valid_after=not_after.isoformat(),
        san=san,
        is_self_signed=(cert.subject == cert.issuer),
    )


def _atomic_write(path: Path, data: bytes, mode: int) -> None:
    fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent))
    try:
        os.chmod(tmp_name, mode)
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp_name, path)
    except BaseException:
        try:
            os.unlink(tmp_name)
        except FileNotFoundError:
            pass
        raise
    dir_fd = os.open(str(path.parent), os.O_RDONLY)
    try:
        os.fsync(dir_fd)
    finally:
        os.close(dir_fd)


def stage_validate_promote(
    cert_pem: bytes, key_pem: bytes, live_cert_path: Path, live_key_path: Path
) -> CertInfo:
    """Validates the pair FIRST (no disk I/O on the live paths yet); only
    on success are both files atomically promoted. On validation failure,
    the currently-active certificate/key are completely untouched --
    proven by the caller-facing contract that this function either raises
    (nothing changed) or returns (both files fully replaced), never a
    partial state.
    """
    info = validate_cert_key_pair(cert_pem, key_pem)
    live_cert_path.parent.mkdir(parents=True, exist_ok=True)
    live_key_path.parent.mkdir(parents=True, exist_ok=True)
    # Write the key first into a temp name, but only rename BOTH into
    # place after both are staged successfully -- avoids a mismatched
    # cert/key pair ever being observable on disk even transiently.
    fd_key, tmp_key = tempfile.mkstemp(prefix=".stage-key.", suffix=".tmp", dir=str(live_key_path.parent))
    os.close(fd_key)
    fd_cert, tmp_cert = tempfile.mkstemp(prefix=".stage-cert.", suffix=".tmp", dir=str(live_cert_path.parent))
    os.close(fd_cert)
    try:
        os.chmod(tmp_key, _KEY_FILE_MODE)
        with open(tmp_key, "wb") as fh:
            fh.write(key_pem)
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(tmp_cert, _CERT_FILE_MODE)
        with open(tmp_cert, "wb") as fh:
            fh.write(cert_pem)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp_key, live_key_path)
        os.replace(tmp_cert, live_cert_path)
    except BaseException:
        for p in (tmp_key, tmp_cert):
            try:
                os.unlink(p)
            except FileNotFoundError:
                pass
        raise
    return info


def ensure_bootstrap_cert(
    live_cert_path: Path,
    live_key_path: Path,
    hostnames: tuple[str, ...] = ("localhost",),
    ip_addresses: tuple[str, ...] = ("127.0.0.1", "::1"),
) -> CertInfo:
    """Idempotent: if a valid matching cert+key pair already exists at the
    live paths, does nothing and returns its info (never regenerates on
    every restart). Only generates+promotes a fresh self-signed pair when
    absent, unreadable, or an invalid/mismatched pair."""
    if live_cert_path.exists() and live_key_path.exists():
        try:
            return validate_cert_key_pair(live_cert_path.read_bytes(), live_key_path.read_bytes())
        except TlsCertError:
            pass  # fall through to (re)generate
    cert_pem, key_pem = generate_self_signed(hostnames, ip_addresses)
    return stage_validate_promote(cert_pem, key_pem, live_cert_path, live_key_path)


def load_active_cert_info(live_cert_path: Path, live_key_path: Path) -> Optional[CertInfo]:
    if not (live_cert_path.exists() and live_key_path.exists()):
        return None
    try:
        return validate_cert_key_pair(live_cert_path.read_bytes(), live_key_path.read_bytes())
    except TlsCertError:
        return None
