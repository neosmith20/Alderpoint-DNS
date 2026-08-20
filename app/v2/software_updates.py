"""V2 Software Updates (beta-rescue priority 4).

V2 is private: there is no public release channel to check against, and
this module must never advertise one that does not exist. Reuses V1's
mature, already-tested, source-agnostic package-inspection primitives
(``inspect_deb``-style dpkg-deb parsing, ``dpkg --compare-versions``,
sha256, the Debian <-> source version-tag mapping) via
``app.software_updates`` -- none of that logic is V1-specific, it is
just "how to safely validate an arbitrary .deb before installing it" --
but implements V2's own channel/status model, job tracking, and apply
workflow from scratch, since V1's GitHub-releases-based channel has no
private equivalent and must not be reused or faked as one.

Privilege separation, matching the project's existing
``alderpointdns-v2-dnsdist-reload`` path/service pattern (see
packaging/v2/): the unprivileged web process only ever validates and
stages a candidate package plus writes an "apply requested" marker file.
A root-owned systemd .path unit watches that marker and triggers a
oneshot .service that re-verifies the staged package's checksum (never
trusting the web process's own claim across the privilege boundary) and
actually runs ``apt-get install`` -- see
scripts/v2/alderpointdns_v2_update_apply.py. The web process never gains
apt/root access itself.
"""

from __future__ import annotations

import json
import os
import shutil
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from app.software_updates import (
    SoftwareUpdateError as _V1SoftwareUpdateError,
    dpkg_compare,
    inspect_deb,
    sha256_file,
    source_version_to_deb_form,
)

DPKG_PACKAGE_NAME = "alderpointdns-v2"
STAGED_DEB_NAME = "staged.deb"
APPLY_MARKER_NAME = "apply-requested.json"


class SoftwareUpdateError(ValueError):
    pass


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def installed_source_version(app_root: Path) -> str:
    version_file = app_root / "VERSION"
    return version_file.read_text().strip() if version_file.exists() else "unknown"


def installed_package_version(run=None) -> Optional[str]:
    """None means this is not a dpkg-managed install (a source checkout
    or dev environment) -- treated as "cannot determine", the correct
    signal to disable install actions, not an error."""
    import subprocess

    runner = run or (lambda cmd: subprocess.run(cmd, text=True, capture_output=True))
    try:
        proc = runner(["dpkg-query", "-W", "-f=${Version}", DPKG_PACKAGE_NAME])
    except (OSError, FileNotFoundError):
        return None
    if proc.returncode != 0:
        return None
    return proc.stdout.strip() or None


@dataclass(frozen=True)
class PrivateFeedCandidate:
    version: str
    deb_filename: str
    sha256: str
    notes: str = ""


def check_private_feed(feed_dir: Optional[Path]) -> dict:
    """V2 has no public release channel. If the operator has configured
    a private feed directory (their own artifact server/share mounted
    locally, or a directory they drop a package into by hand), look for
    ``metadata.json`` describing exactly one candidate there. Otherwise
    -- the common, honest case -- report plainly that there is no public
    release available, rather than a fake "up to date" or a silent
    failure that could be mistaken for one.
    """
    if feed_dir is None:
        return {
            "channel": "private", "public_release_available": False, "feed_configured": False,
            "candidate": None,
            "message": "V2 is private -- there is no public release channel. Configure a private "
                       "update feed directory, or upload a package manually.",
        }
    metadata_path = feed_dir / "metadata.json"
    if not feed_dir.exists() or not metadata_path.exists():
        return {
            "channel": "private", "public_release_available": False, "feed_configured": True,
            "candidate": None,
            "message": f"private update feed {str(feed_dir)!r} is configured but has no metadata.json yet",
        }
    try:
        data = json.loads(metadata_path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise SoftwareUpdateError(f"private update feed metadata is invalid: {exc}") from exc
    candidate = PrivateFeedCandidate(
        version=str(data.get("version", "")), deb_filename=str(data.get("deb_filename", "")),
        sha256=str(data.get("sha256", "")), notes=str(data.get("notes", "")),
    )
    if not candidate.version or not candidate.deb_filename or not candidate.sha256:
        raise SoftwareUpdateError("private update feed metadata.json is missing version/deb_filename/sha256")
    return {
        "channel": "private", "public_release_available": True, "feed_configured": True,
        "candidate": {"version": candidate.version, "deb_filename": candidate.deb_filename, "notes": candidate.notes},
        "message": f"private update feed candidate {candidate.version} available",
    }


@dataclass(frozen=True)
class ValidatedPackage:
    fields: dict
    sha256: str
    candidate_version: str


def validate_candidate_package(deb_path: Path, installed_pkg_version: Optional[str]) -> ValidatedPackage:
    """Real, non-cosmetic validation before anything is staged for a
    privileged apply: correct package name, amd64-only architecture
    (matching the RC43 package-metadata fix -- V2 genuinely ships
    x86_64/CPython binary payloads, "all" would be inaccurate), and,
    when the installed version is known, strictly newer per dpkg's own
    comparison (never a same-version no-op reinstall, never a
    downgrade) via this updater path.
    """
    try:
        fields = inspect_deb(deb_path)
    except _V1SoftwareUpdateError as exc:
        raise SoftwareUpdateError(str(exc)) from exc
    if fields.get("Package") != DPKG_PACKAGE_NAME:
        raise SoftwareUpdateError(f"package name mismatch: expected {DPKG_PACKAGE_NAME!r}, got {fields.get('Package')!r}")
    if fields.get("Architecture") != "amd64":
        raise SoftwareUpdateError(f"unsupported package architecture: {fields.get('Architecture')!r} (V2 ships amd64 only)")
    candidate_version = fields.get("Version", "")
    if not candidate_version:
        raise SoftwareUpdateError("candidate package has no Version field")
    if installed_pkg_version is not None:
        try:
            same = dpkg_compare(candidate_version, "eq", installed_pkg_version)
            newer = dpkg_compare(candidate_version, "gt", installed_pkg_version)
        except _V1SoftwareUpdateError as exc:
            raise SoftwareUpdateError(str(exc)) from exc
        if same:
            raise SoftwareUpdateError(f"candidate version {candidate_version!r} is the same as the installed version; refusing a no-op reinstall")
        if not newer:
            raise SoftwareUpdateError(f"candidate version {candidate_version!r} is not newer than the installed version {installed_pkg_version!r}; refusing to downgrade")
    return ValidatedPackage(fields=fields, sha256=sha256_file(deb_path), candidate_version=candidate_version)


def stage_for_apply(update_dir: Path, deb_path: Path, validated: ValidatedPackage) -> Path:
    """Copies the already-validated package to the fixed staged path the
    privileged helper reads from. Never writes the apply-requested
    marker itself -- that only happens when the operator explicitly
    confirms (request_apply), so uploading/validating alone can never
    trigger a privileged install."""
    update_dir.mkdir(parents=True, exist_ok=True, mode=0o750)
    staged_path = update_dir / STAGED_DEB_NAME
    tmp = update_dir / f".{STAGED_DEB_NAME}.tmp"
    shutil.copy2(deb_path, tmp)
    os.replace(tmp, staged_path)
    os.chmod(staged_path, 0o640)
    return staged_path


def request_apply(update_dir: Path, job_id: int, validated: ValidatedPackage) -> Path:
    """Writes the marker the root-owned .path unit watches. The marker
    only ever names a job id and a checksum -- the privileged helper
    re-derives everything else itself and re-verifies the checksum
    against the staged file before doing anything, so a compromised or
    buggy web process cannot make it install an unverified payload by
    lying in the marker."""
    marker_path = update_dir / APPLY_MARKER_NAME
    payload = {"job_id": job_id, "sha256": validated.sha256, "requested_at": _now()}
    tmp = update_dir / f".{APPLY_MARKER_NAME}.tmp"
    tmp.write_text(json.dumps(payload))
    os.replace(tmp, marker_path)
    return marker_path


def read_apply_result(update_dir: Path, job_id: int) -> Optional[dict]:
    """Non-blocking: returns None if the privileged helper has not
    finished (or run) yet. The web app polls this rather than blocking a
    request on a privileged subprocess it does not itself run."""
    result_path = update_dir / f"result-{job_id}.json"
    if not result_path.exists():
        return None
    try:
        return json.loads(result_path.read_text())
    except (OSError, json.JSONDecodeError):
        return None
