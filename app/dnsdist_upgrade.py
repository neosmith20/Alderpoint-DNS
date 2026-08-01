#!/usr/bin/env python3
"""Opt-in installer for the PowerDNS-repository dnsdist 2.1 build.

Debian 13's own archive dnsdist package (1.9.x) does not include
dns-over-quic or dns-over-http3. The only way to get DoQ/DoH3 support is the
official PowerDNS project repository, which is a third-party software
source that changes where dnsdist security updates come from. Alderpoint DNS
never adds this repository automatically -- not from the .deb package's
post-install script, and not from the unprivileged web process, which has no
APT/sudo access at all. This module is only reachable through the explicit,
root-only `alderpointdns install-enhanced-dnsdist` CLI command.

This installs dnsdist *capability* only. It never touches Alderpoint's own
DoQ/DoH3 enabled/disabled settings -- those stay exactly as they were
before the command ran, and both protocols remain off until an
administrator explicitly turns them on in Encryption Settings and deploys.

Every step here is written to fail closed: a network failure, an
unexpected/wrong signing key, an APT candidate that doesn't look like the
build we expect, or a simulated install that would remove something
critical, all abort before anything is changed, or after the smallest,
individually-reversible change has been made. Running the whole command
twice must be a no-op the second time (idempotent), not a re-download or a
duplicated APT source.
"""

from __future__ import annotations

import datetime as dt
import os
import re
import shutil
import socket
import subprocess
import tarfile
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

KEY_URL = "https://repo.powerdns.com/FD380FBB-pub.asc"
REPO_HOST = "repo.powerdns.com"
REPO_CODENAME = "trixie-dnsdist-21"

KEYRING_PATH = Path("/etc/apt/keyrings/dnsdist-21-pub.asc")
SOURCES_LIST_PATH = Path("/etc/apt/sources.list.d/pdns.list")
PREFERENCES_PATH = Path("/etc/apt/preferences.d/dnsdist-21")

SOURCES_LIST_CONTENT = f"deb [signed-by={KEYRING_PATH}] http://{REPO_HOST}/debian {REPO_CODENAME} main\n"
PREFERENCES_CONTENT = "Package: dnsdist*\nPin: origin repo.powerdns.com\nPin-Priority: 600\n"

# Downloaded directly from https://repo.powerdns.com/FD380FBB-pub.asc over
# TLS and confirmed with `gpg --show-keys --with-fingerprint` against the
# PowerDNS Release Signing Key <powerdns.support@powerdns.com> uid. Re-verify
# independently (e.g. against https://repo.powerdns.com/ and PowerDNS's own
# published documentation) before ever changing this constant -- it is the
# only thing standing between this command and trusting an attacker-supplied
# signing key for a repository this tool will grant APT install privileges.
EXPECTED_KEY_FINGERPRINT = "9FAAA5577E8FCF62093D036C1B0C6205FD380FBB"

REQUIRED_CAPABILITY_FEATURES = ("dns-over-quic", "dns-over-http3")
REQUIRED_SERVICES = ("dnsdist", "named", "alderpointdns", "alderpointdns-analytics")

DNSDIST_CONF = Path("/etc/dnsdist/dnsdist.conf")
SERVICE_OVERRIDE_DIR = Path("/etc/systemd/system/dnsdist.service.d")
CERT_DIR = Path("/etc/alderpointdns/certs")
BACKUP_DIR = Path("/var/lib/alderpointdns/backups")

# Packages whose unexpected removal in the simulated install output means
# "stop": these are what keep Alderpoint DNS itself, its BIND backend, and
# dnsdist's own runtime dependencies alive.
CRITICAL_PACKAGES = {"alderpointdns", "bind9", "bind9-utils", "dnsdist", "libssl3", "libc6"}


class UpgradeError(RuntimeError):
    """Raised for any fail-closed abort. Message is the actionable error
    shown to the operator; str(exc) is safe to print directly."""


def run(command: list[str], check: bool = True, timeout: int | None = 60, input_text: str | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=check, timeout=timeout, input=input_text)


def now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()


@dataclass
class UpgradeReport:
    changed: bool = False
    already_satisfied: bool = False
    steps: list[str] = field(default_factory=list)
    backup_path: str | None = None
    version_before: str = ""
    version_after: str = ""
    capabilities_before: dict[str, bool] = field(default_factory=dict)
    capabilities_after: dict[str, bool] = field(default_factory=dict)
    rolled_back: bool = False

    def note(self, message: str) -> None:
        self.steps.append(message)


# ---------------------------------------------------------------------------
# Individual checks -- each one is a small, independently testable function.
# ---------------------------------------------------------------------------

def check_os_supported(os_release_path: Path = Path("/etc/os-release")) -> None:
    try:
        text = os_release_path.read_text()
    except OSError as exc:
        raise UpgradeError(f"could not read {os_release_path}: {exc}") from None
    fields = {key: quoted or bare for key, quoted, bare in re.findall(r'^(\w+)=(?:"([^"]*)"|(\S*))$', text, re.M)}
    os_id = fields.get("ID") or ""
    version_id = fields.get("VERSION_ID") or ""
    codename = fields.get("VERSION_CODENAME") or ""
    if os_id != "debian" or not (version_id == "13" or codename == "trixie"):
        raise UpgradeError(
            f"unsupported operating system (ID={os_id!r} VERSION_ID={version_id!r} VERSION_CODENAME={codename!r}); "
            "this command only supports Debian 13 (Trixie)"
        )


def detect_architecture() -> str:
    try:
        result = run(["dpkg", "--print-architecture"], check=False)
    except (OSError, FileNotFoundError) as exc:
        raise UpgradeError(f"could not detect architecture: {exc}") from None
    arch = result.stdout.strip()
    if result.returncode != 0 or not arch:
        raise UpgradeError("dpkg --print-architecture failed; cannot determine target architecture")
    return arch


def dnsdist_capabilities() -> dict[str, bool]:
    """Same detection approach as app.encryption.dnsdist_capabilities():
    parse `dnsdist --version`'s Enabled features line. Duplicated locally
    (rather than imported) so this module has no dependency on the
    database-backed encryption module and can run standalone as root
    outside the web process."""
    output = ""
    try:
        result = run(["dnsdist", "--version"], check=False)
        output = result.stdout or ""
    except (OSError, FileNotFoundError):
        pass
    lowered = output.lower()
    return {
        "doh": "dns-over-https" in lowered,
        "dot": "dns-over-tls" in lowered,
        "doq": "dns-over-quic" in lowered,
        "doh3": "dns-over-http3" in lowered,
        "dnscrypt": "dnscrypt" in lowered,
    }


def dnsdist_version() -> str:
    try:
        result = run(["dnsdist", "--version"], check=False)
    except (OSError, FileNotFoundError):
        return "not installed"
    first_line = (result.stdout or "").splitlines()[0] if result.stdout else ""
    return first_line or "unknown"


def has_required_capabilities(caps: dict[str, bool]) -> bool:
    return bool(caps.get("doq")) and bool(caps.get("doh3"))


def resolve_repo_host() -> None:
    try:
        socket.getaddrinfo(REPO_HOST, 443)
    except OSError as exc:
        raise UpgradeError(f"could not resolve {REPO_HOST}: {exc}") from None


def download_signing_key(dest: Path) -> None:
    """Fail-closed download: bounded retries/timeouts, --fail so an HTTP
    error status is a hard failure rather than an error page saved as if it
    were a key."""
    try:
        run(
            [
                "curl", "--fail", "--silent", "--show-error", "--location",
                "--retry", "3", "--retry-delay", "2", "--retry-connrefused",
                "--max-time", "20",
                "-o", str(dest), KEY_URL,
            ],
            timeout=90,
        )
    except subprocess.CalledProcessError as exc:
        raise UpgradeError(f"failed to download the PowerDNS signing key from {KEY_URL}: {exc.output}") from None
    except subprocess.TimeoutExpired:
        raise UpgradeError(f"timed out downloading the PowerDNS signing key from {KEY_URL}") from None
    if not dest.exists() or dest.stat().st_size == 0:
        raise UpgradeError("downloaded PowerDNS signing key is empty")


def verify_signing_key(key_path: Path, expected_fingerprint: str = EXPECTED_KEY_FINGERPRINT) -> None:
    text = key_path.read_text(errors="replace")
    if "-----BEGIN PGP PUBLIC KEY BLOCK-----" not in text:
        raise UpgradeError("downloaded file does not look like an ASCII-armored PGP public key; refusing to install it")
    try:
        result = run(["gpg", "--with-colons", "--show-keys", str(key_path)], check=False, timeout=15)
    except (OSError, FileNotFoundError) as exc:
        raise UpgradeError(f"gpg is required to verify the signing key fingerprint: {exc}") from None
    if result.returncode != 0:
        raise UpgradeError(f"gpg could not parse the downloaded key: {result.stdout}")
    fingerprints = [line.split(":")[9] for line in result.stdout.splitlines() if line.startswith("fpr:")]
    if not fingerprints:
        raise UpgradeError("could not extract a fingerprint from the downloaded key")
    if expected_fingerprint not in fingerprints:
        raise UpgradeError(
            f"PowerDNS signing key fingerprint mismatch: got {fingerprints}, expected {expected_fingerprint!r}; "
            "refusing to install a key that does not match the fingerprint published at repo.powerdns.com"
        )


def _atomic_write(path: Path, content: bytes, mode: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(dir=str(path.parent), prefix=f".{path.name}.")
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(content)
        os.chmod(tmp_name, mode)
        os.replace(tmp_name, path)
    except BaseException:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise


def install_keyring(key_path: Path) -> None:
    _atomic_write(KEYRING_PATH, key_path.read_bytes(), 0o644)


def write_apt_sources() -> None:
    _atomic_write(SOURCES_LIST_PATH, SOURCES_LIST_CONTENT.encode(), 0o644)
    _atomic_write(PREFERENCES_PATH, PREFERENCES_CONTENT.encode(), 0o644)


def apt_update() -> None:
    try:
        run(["apt-get", "update"], timeout=180)
    except subprocess.CalledProcessError as exc:
        raise UpgradeError(f"apt-get update failed: {exc.output}") from None
    except subprocess.TimeoutExpired:
        raise UpgradeError("apt-get update timed out") from None


CANDIDATE_RE = re.compile(r"^\s*Candidate:\s*(\S+)", re.M)
ORIGIN_LINE_RE = re.compile(r"^\s*(\d+)\s+http://repo\.powerdns\.com/debian\s+\S*/main\s", re.M)


def apt_policy_candidate() -> str:
    try:
        result = run(["apt-cache", "policy", "dnsdist"], check=False, timeout=30)
    except (OSError, FileNotFoundError) as exc:
        raise UpgradeError(f"apt-cache policy dnsdist failed: {exc}") from None
    match = CANDIDATE_RE.search(result.stdout or "")
    if not match:
        raise UpgradeError("could not determine the apt candidate version for dnsdist")
    candidate = match.group(1)
    if not re.match(r"^2\.1\.\d+", candidate):
        raise UpgradeError(
            f"apt policy selected dnsdist candidate {candidate!r}, which is not a supported 2.1.x PowerDNS build; "
            "refusing to install it"
        )
    if not ORIGIN_LINE_RE.search(result.stdout or ""):
        raise UpgradeError(
            f"dnsdist candidate {candidate!r} does not appear to originate from repo.powerdns.com at priority 600; "
            "refusing to install it (policy output did not match the expected origin line)"
        )
    return candidate


def backup_state() -> Path:
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    archive_path = BACKUP_DIR / f"dnsdist-upgrade.pre-2.1.{int(time.time())}.tar.gz"
    tmp_path = archive_path.with_suffix(archive_path.suffix + ".tmp")
    with tarfile.open(tmp_path, "w:gz") as archive:
        for source in (DNSDIST_CONF, SERVICE_OVERRIDE_DIR, CERT_DIR):
            if source.exists():
                archive.add(source, arcname=str(source).lstrip("/"))
    os.replace(tmp_path, archive_path)
    return archive_path


REMOVAL_RE = re.compile(r"^Remv\s+(\S+)", re.M)


def simulate_install() -> str:
    try:
        result = run(
            ["apt-get", "install", "-s", "-y", "-o", "Dpkg::Options::=--force-confold", "dnsdist"],
            check=False, timeout=60,
        )
    except (OSError, FileNotFoundError) as exc:
        raise UpgradeError(f"apt-get install simulation failed to run: {exc}") from None
    if result.returncode != 0:
        raise UpgradeError(f"apt-get install simulation failed: {result.stdout}")
    output = result.stdout or ""
    removed = {name.split(":")[0].split("[")[0] for name in REMOVAL_RE.findall(output)}
    unsafe = removed & CRITICAL_PACKAGES
    if unsafe:
        raise UpgradeError(
            f"simulated package operation would remove critical package(s) {sorted(unsafe)}; refusing to proceed. "
            f"Full simulation output:\n{output}"
        )
    return output


def apt_install() -> None:
    try:
        run(
            ["apt-get", "install", "-y", "-o", "Dpkg::Options::=--force-confold", "dnsdist"],
            timeout=180,
        )
    except subprocess.CalledProcessError as exc:
        raise UpgradeError(f"apt-get install dnsdist failed: {exc.output}") from None
    except subprocess.TimeoutExpired:
        raise UpgradeError("apt-get install dnsdist timed out") from None


def check_config() -> None:
    try:
        result = run(["dnsdist", "--check-config", "-C", str(DNSDIST_CONF)], check=False, timeout=30)
    except (OSError, FileNotFoundError) as exc:
        raise UpgradeError(f"dnsdist --check-config could not run: {exc}") from None
    if result.returncode != 0:
        raise UpgradeError(f"dnsdist --check-config failed after upgrade: {result.stdout}")


def restart_dnsdist_and_verify_services(timeout: int = 20) -> None:
    try:
        run(["systemctl", "restart", "dnsdist"], timeout=30)
    except subprocess.CalledProcessError as exc:
        raise UpgradeError(f"systemctl restart dnsdist failed: {exc.output}") from None
    deadline = time.monotonic() + timeout
    failed: list[str] = []
    while time.monotonic() < deadline:
        failed = [svc for svc in REQUIRED_SERVICES if run(["systemctl", "is-active", svc], check=False, timeout=10).stdout.strip() != "active"]
        if not failed:
            return
        time.sleep(0.5)
    raise UpgradeError(f"service(s) not active after restart: {', '.join(failed)}")


def baseline_dns_test() -> None:
    try:
        result = run(["dig", "@127.0.0.1", "cloudflare.com", "A", "+time=3", "+tries=1"], check=False, timeout=10)
    except (OSError, FileNotFoundError) as exc:
        raise UpgradeError(f"baseline DNS test could not run: {exc}") from None
    if result.returncode != 0 or "status: NOERROR" not in result.stdout:
        raise UpgradeError(f"baseline plain-DNS query after upgrade failed:\n{result.stdout}")


def restore_config_from_backup(backup_path: Path) -> None:
    with tarfile.open(backup_path, "r:gz") as archive:
        archive.extractall("/")


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------

def install_enhanced_dnsdist(expected_fingerprint: str = EXPECTED_KEY_FINGERPRINT) -> UpgradeReport:
    report = UpgradeReport()
    report.capabilities_before = dnsdist_capabilities()
    report.version_before = dnsdist_version()

    check_os_supported()
    report.note("operating system check passed (Debian 13/Trixie)")

    arch = detect_architecture()
    report.note(f"target architecture: {arch}")

    if has_required_capabilities(report.capabilities_before):
        report.already_satisfied = True
        report.capabilities_after = report.capabilities_before
        report.version_after = report.version_before
        report.note("dnsdist already reports dns-over-quic and dns-over-http3; nothing to do")
        return report

    resolve_repo_host()
    report.note(f"resolved {REPO_HOST}")

    backup_path = backup_state()
    report.backup_path = str(backup_path)
    report.note(f"backed up {DNSDIST_CONF}, {SERVICE_OVERRIDE_DIR}, {CERT_DIR} to {backup_path}")

    with tempfile.TemporaryDirectory() as tmp:
        key_path = Path(tmp) / "dnsdist-21-pub.asc"
        try:
            download_signing_key(key_path)
            report.note(f"downloaded signing key from {KEY_URL}")

            verify_signing_key(key_path, expected_fingerprint)
            report.note("signing key fingerprint verified against the published PowerDNS fingerprint")

            install_keyring(key_path)
            report.note(f"installed signing key to {KEYRING_PATH}")

            write_apt_sources()
            report.note(f"wrote {SOURCES_LIST_PATH} and {PREFERENCES_PATH}")

            apt_update()
            report.note("apt-get update completed")

            candidate = apt_policy_candidate()
            report.note(f"apt policy selected dnsdist candidate {candidate} from {REPO_HOST}")

            simulate_install()
            report.note("simulated install did not remove any critical package")

            apt_install()
            report.note(f"installed dnsdist candidate {candidate}")

            report.capabilities_after = dnsdist_capabilities()
            report.version_after = dnsdist_version()
            if not has_required_capabilities(report.capabilities_after):
                raise UpgradeError(
                    f"installed dnsdist ({report.version_after}) still does not report both "
                    f"{' and '.join(REQUIRED_CAPABILITY_FEATURES)}; capabilities: {report.capabilities_after}"
                )
            report.note("installed dnsdist reports dns-over-quic and dns-over-http3")

            check_config()
            report.note("dnsdist --check-config passed with the existing Alderpoint configuration")

            restart_dnsdist_and_verify_services()
            report.note(f"restarted dnsdist; all required services active: {', '.join(REQUIRED_SERVICES)}")

            baseline_dns_test()
            report.note("baseline plain-DNS query after upgrade succeeded")

            report.changed = True
            return report
        except UpgradeError as exc:
            try:
                restore_config_from_backup(backup_path)
                report.rolled_back = True
                rollback_note = f"restored {DNSDIST_CONF}, {SERVICE_OVERRIDE_DIR}, {CERT_DIR} from {backup_path}"
            except Exception as rollback_exc:  # noqa: BLE001 - report exact failure, never swallow
                rollback_note = f"automatic config restore from {backup_path} also failed: {rollback_exc}"
            raise UpgradeError(
                f"{exc}\n\n"
                f"Rollback: {rollback_note}. To fully roll back the APT source itself, run:\n"
                f"  sudo rm -f {SOURCES_LIST_PATH} {PREFERENCES_PATH} {KEYRING_PATH}\n"
                "  sudo apt-get update\n"
                "  sudo apt-get install -y --allow-downgrades dnsdist\n"
                "  sudo systemctl restart dnsdist\n"
                f"Backup archive of prior state: {backup_path}"
            ) from exc


def capabilities_report() -> dict[str, Any]:
    """Read-only diagnostic: `alderpointdns dnsdist-capabilities`."""
    caps = dnsdist_capabilities()
    origin = "unknown"
    try:
        result = run(["apt-cache", "policy", "dnsdist"], check=False, timeout=15)
        match = re.search(r"\*\*\*\s*\S+\s+\d+\s+(\S.*)", result.stdout or "")
        if match:
            origin = match.group(1).strip()
    except (OSError, FileNotFoundError):
        pass
    return {
        "version": dnsdist_version(),
        "origin": origin,
        "doh": caps["doh"],
        "dot": caps["dot"],
        "doq": caps["doq"],
        "doh3": caps["doh3"],
        "dnscrypt": caps["dnscrypt"],
    }
