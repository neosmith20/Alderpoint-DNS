"""V2 real DNSCrypt provider/resolver key material provisioning (roadmap
continuation: closes the last remaining row of the confirmed mandatory
encrypted-transport parity gap, see
``docs/v2/encrypted-transport-parity-gap.md``).

**Why this exists instead of hand-rolling the DNSCrypt binary formats in
Python.** DNSCrypt provider keys (Ed25519) and the signed resolver
certificate dnsdist actually verifies at query time are a real, exact
binary wire format (RFC-adjacent, not standardized the way X.509 is) --
getting a byte offset or the signing scope wrong produces broken or
insecure crypto that would only be caught, if at all, by a real client
failing a handshake in production. dnsdist itself is the authoritative
implementation (it is also the verifier), so this module always asks the
real installed ``dnsdist`` binary to generate the material via its own
``generateDNSCryptProviderKeys``/``generateDNSCryptCertificate`` console
functions, the same way an administrator would from the dnsdist console --
never reimplemented here.

**A real, live-reproduced dnsdist behavior this module works around.**
V1's own ``app/encryption.py`` (``ensure_dnscrypt_provider_keys``)
documents that invoking these functions via ``dnsdist -l ... -e script``
(one-shot, no console) reliably prints a provider fingerprint but does
NOT persist the key files to disk -- confirmed again, independently, live
against this exact real ``dnsdist`` binary during this session's design
work: ``generateDNSCryptProviderKeys`` via ``-l addr -e cmd`` prints
"Provider fingerprint is: ..." and writes nothing. The same call issued
as a genuine interactive console command (piped via stdin to
``dnsdist -C <config> -c``, against an already-running dnsdist process
with a real ``controlSocket``/``setKey``) reliably writes both files --
confirmed live, repeatedly, including a full real end-to-end resolution
through a real DNSCrypt client (``dnscrypt-proxy``) afterward. The
difference is almost certainly that ``-e`` disconnects immediately after
sending the command rather than waiting for the server to finish
processing it, racing the file write; a real console session only
disconnects when its stdin reaches EOF, after the server's result has
already been read back. This module therefore always drives generation
through a genuine, disposable, throwaway dnsdist instance with a real
console -- never ``-e``, never a bare one-shot ``-l`` listener.

**Why a disposable scratch instance, not the live production dnsdist.**
V2's real compiled runtime (``app/v2/dnsdist_policy_runtime.py``) has no
``controlSocket``/console at all -- confirmed by inspection, and a
deliberate choice: adding a permanent console to the live query-serving
process is real new attack surface (V1 does ship one, loopback-only with
a random key, but V2's policy-runtime architecture has had no need for
one until now). Provisioning is an infrequent, explicit administrative
action, not something the hot query path needs -- so it gets a fully
disposable, loopback-only, random-key, random-port dnsdist instance that
exists only for the few hundred milliseconds this module needs it,
torn down immediately after, never reachable from anywhere but this
process.
"""

from __future__ import annotations

import secrets
import socket
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

from app.v2.dnsdist_gen import _lua_string

PROVIDER_PUBLIC_KEY_LENGTH = 32
PROVIDER_PRIVATE_KEY_LENGTH = 64
RESOLVER_PRIVATE_KEY_LENGTH = 32
# The real DNSCrypt signed-certificate wire format dnsdist emits: 4-byte
# magic + 2-byte crypto-construction version + 2-byte protocol minor
# version + 64-byte Ed25519 signature + 32-byte short-term resolver public
# key + 8-byte client magic + 4-byte serial + 4-byte ts_start + 4-byte
# ts_end = 124 bytes total -- verified against a real generated cert this
# session, not assumed from memory.
DNSCRYPT_CERT_LENGTH = 124

_CONSOLE_TIMEOUT_SECONDS = 15
_READY_POLL_ATTEMPTS = 20
_READY_POLL_INTERVAL_SECONDS = 0.1


class DnsCryptProvisioningError(RuntimeError):
    pass


def _free_loopback_port() -> int:
    """Ask the OS for a currently-unused loopback port. Small TOCTOU race
    (the port could theoretically be grabbed by something else before
    dnsdist binds it) -- acceptable for a short-lived, admin-triggered,
    local-only provisioning action; the caller's dnsdist startup would
    simply fail closed and this function raises, rather than silently
    misbehaving."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _wait_until_connectable(port: int) -> None:
    import time

    for _ in range(_READY_POLL_ATTEMPTS):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.2)
            try:
                s.connect(("127.0.0.1", port))
                return
            except OSError:
                time.sleep(_READY_POLL_INTERVAL_SECONDS)
    raise DnsCryptProvisioningError(
        f"scratch dnsdist console on 127.0.0.1:{port} never became connectable"
    )


@dataclass(frozen=True)
class _ScratchInstance:
    process: subprocess.Popen
    config_path: Path


def _start_scratch_dnsdist(tmp_dir: Path, dnsdist_binary: str) -> _ScratchInstance:
    """Starts a disposable, loopback-only dnsdist instance with a real
    console (required -- see module docstring) and no DNS-serving
    listener at all (``setLocal`` is intentionally omitted; this instance
    never needs to answer a real query, only run console commands)."""
    console_port = _free_loopback_port()
    # dnsdist binds a default DNS listener on 127.0.0.1:53 when setLocal()
    # is never called at all -- confirmed live: omitting it entirely made
    # this "console-only" scratch instance collide with the real system
    # DNS service already using port 53 and fail to start. An explicit
    # scratch port with nothing behind it is otherwise harmless (this
    # instance never needs to answer a real query).
    dns_port = _free_loopback_port()
    console_key = secrets.token_bytes(32)
    import base64

    key_b64 = base64.b64encode(console_key).decode()
    config_path = tmp_dir / "scratch.conf"
    config_path.write_text(
        f'setLocal("127.0.0.1:{dns_port}")\n'
        f'controlSocket("127.0.0.1:{console_port}")\n'
        f'setKey({_lua_string(key_b64)})\n'
    )
    try:
        process = subprocess.Popen(
            [dnsdist_binary, "-C", str(config_path), "--supervised"],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
    except (OSError, FileNotFoundError) as exc:
        raise DnsCryptProvisioningError(f"could not start scratch dnsdist instance: {exc}") from None
    try:
        _wait_until_connectable(console_port)
    except DnsCryptProvisioningError:
        process.kill()
        process.wait(timeout=5)
        raise
    # The client config only needs controlSocket + setKey (the same two
    # directives, read fresh by -c) -- reuse the same file for the
    # console-client invocation below rather than constructing a second one.
    return _ScratchInstance(process=process, config_path=config_path)


def _stop_scratch_dnsdist(instance: _ScratchInstance) -> None:
    instance.process.kill()
    try:
        instance.process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        pass  # best-effort; a leaked scratch process with no DNS listener and
        # a random loopback-only key is not a live-service risk, and the
        # temp directory it was pointed at is cleaned up by the caller's
        # TemporaryDirectory context regardless.


def _run_console_commands(instance: _ScratchInstance, commands: list[str], dnsdist_binary: str) -> str:
    """Feeds ``commands`` to a real interactive console session over
    stdin (never ``-e`` -- see module docstring for why that path is
    unreliable) and returns combined stdout+stderr for error reporting."""
    try:
        result = subprocess.run(
            [dnsdist_binary, "-C", str(instance.config_path), "-c"],
            input="\n".join(commands) + "\n",
            capture_output=True,
            text=True,
            timeout=_CONSOLE_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired as exc:
        raise DnsCryptProvisioningError(f"dnsdist console session timed out: {exc}") from None
    return (result.stdout or "") + (result.stderr or "")


def generate_provider_keypair(dnsdist_binary: str = "dnsdist") -> tuple[bytes, bytes]:
    """Generates a real DNSCrypt provider (long-term, root-of-trust)
    Ed25519 keypair via the real dnsdist binary. Returns
    ``(public_key, private_key)`` as raw bytes -- callers are responsible
    for base64-encoding the private key before handing it to
    ``app.v2.secret_store.SecretStore`` (a string-value store) and for
    never logging it. The public key is not sensitive (it is the
    fingerprint every client pins against) but is also returned raw for
    the caller to encode/store however is convenient.
    """
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        instance = _start_scratch_dnsdist(tmp_path, dnsdist_binary)
        try:
            pub_path = tmp_path / "provider.public"
            priv_path = tmp_path / "provider.private"
            output = _run_console_commands(
                instance,
                [f"generateDNSCryptProviderKeys({_lua_string(str(pub_path))}, {_lua_string(str(priv_path))})"],
                dnsdist_binary,
            )
            if not (pub_path.exists() and priv_path.exists()):
                raise DnsCryptProvisioningError(
                    f"dnsdist did not write DNSCrypt provider key files; console output: {output!r}"
                )
            public_key = pub_path.read_bytes()
            private_key = priv_path.read_bytes()
        finally:
            _stop_scratch_dnsdist(instance)
    if len(public_key) != PROVIDER_PUBLIC_KEY_LENGTH:
        raise DnsCryptProvisioningError(
            f"unexpected provider public key length {len(public_key)} (expected {PROVIDER_PUBLIC_KEY_LENGTH})"
        )
    if len(private_key) != PROVIDER_PRIVATE_KEY_LENGTH:
        raise DnsCryptProvisioningError(
            f"unexpected provider private key length {len(private_key)} (expected {PROVIDER_PRIVATE_KEY_LENGTH})"
        )
    return public_key, private_key


def generate_resolver_certificate(
    provider_private_key: bytes,
    serial: int,
    valid_from: int,
    valid_until: int,
    dnsdist_binary: str = "dnsdist",
) -> tuple[bytes, bytes]:
    """Generates a real, signed, short-term DNSCrypt resolver certificate
    (the record clients actually fetch and verify before establishing an
    encrypted session) plus its matching X25519 private key, signed by
    ``provider_private_key``. Returns ``(cert_bytes, resolver_private_key)``
    as raw bytes.
    """
    if len(provider_private_key) != PROVIDER_PRIVATE_KEY_LENGTH:
        raise DnsCryptProvisioningError(
            f"provider_private_key must be {PROVIDER_PRIVATE_KEY_LENGTH} bytes, got {len(provider_private_key)}"
        )
    if not (isinstance(serial, int) and serial >= 1):
        raise DnsCryptProvisioningError(f"serial must be a positive integer, got {serial!r}")
    if not (isinstance(valid_from, int) and isinstance(valid_until, int) and valid_from < valid_until):
        raise DnsCryptProvisioningError(
            f"valid_from ({valid_from!r}) must be a smaller integer than valid_until ({valid_until!r})"
        )
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        instance = _start_scratch_dnsdist(tmp_path, dnsdist_binary)
        try:
            provider_priv_path = tmp_path / "provider.private"
            provider_priv_path.write_bytes(provider_private_key)
            cert_path = tmp_path / "resolver.cert"
            key_path = tmp_path / "resolver.key"
            output = _run_console_commands(
                instance,
                [
                    "generateDNSCryptCertificate("
                    f"{_lua_string(str(provider_priv_path))}, {_lua_string(str(cert_path))}, "
                    f"{_lua_string(str(key_path))}, {serial}, {valid_from}, {valid_until})"
                ],
                dnsdist_binary,
            )
            if not (cert_path.exists() and key_path.exists()):
                raise DnsCryptProvisioningError(
                    f"dnsdist did not write DNSCrypt resolver certificate files; console output: {output!r}"
                )
            cert_bytes = cert_path.read_bytes()
            resolver_key = key_path.read_bytes()
        finally:
            _stop_scratch_dnsdist(instance)
    if len(cert_bytes) != DNSCRYPT_CERT_LENGTH:
        raise DnsCryptProvisioningError(
            f"unexpected resolver certificate length {len(cert_bytes)} (expected {DNSCRYPT_CERT_LENGTH})"
        )
    if len(resolver_key) != RESOLVER_PRIVATE_KEY_LENGTH:
        raise DnsCryptProvisioningError(
            f"unexpected resolver private key length {len(resolver_key)} (expected {RESOLVER_PRIVATE_KEY_LENGTH})"
        )
    return cert_bytes, resolver_key


def provider_fingerprint(public_key: bytes) -> str:
    """Human-readable colon-grouped hex fingerprint, matching dnsdist's
    own ``generateDNSCryptProviderKeys``/``printDNSCryptProviderFingerprint``
    display format exactly (verified live against a real generated key
    this session) -- pure Python, no dnsdist invocation needed since this
    is simple hex formatting of already-known-real bytes, not generation."""
    if len(public_key) != PROVIDER_PUBLIC_KEY_LENGTH:
        raise DnsCryptProvisioningError(
            f"public_key must be {PROVIDER_PUBLIC_KEY_LENGTH} bytes, got {len(public_key)}"
        )
    hex_str = public_key.hex().upper()
    return ":".join(hex_str[i:i + 4] for i in range(0, len(hex_str), 4))
