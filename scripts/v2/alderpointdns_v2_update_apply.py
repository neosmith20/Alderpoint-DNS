#!/usr/bin/env python3
"""Privileged Software Updates apply helper (beta-rescue priority 4).

Runs as root, triggered by the packaged
``alderpointdns-v2-update-apply.path`` unit watching for
``apply-requested.json`` under
``/var/lib/alderpointdns-v2/updates/`` -- the unprivileged
``alderpointdns-v2-web`` process only ever validates a candidate package
and writes that marker; it never runs apt/dpkg itself. See
``app/v2/software_updates.py`` for the web-side half of this contract.

Safety:
- Re-derives the staged package path and re-verifies its sha256 against
  the marker's own claim before installing anything -- the marker is
  written by an unprivileged process and must never be trusted blindly
  across the privilege boundary, even though it was itself produced by
  this appliance's own web app.
- A checksum mismatch (staged file replaced/corrupted after validation)
  fails closed: no install is attempted, the marker is still removed
  (so a stale/tampered marker can't be retried forever), and the result
  file records exactly why.
- Every outcome (success or failure) is always written to
  ``result-<job_id>.json`` and the marker is always removed at the end,
  so a job can never be stuck "in progress" forever from the web app's
  point of view, and can never be silently re-applied on the next
  unrelated write to the state directory.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path

UPDATE_DIR = Path("/var/lib/alderpointdns-v2/updates")
STAGED_DEB_NAME = "staged.deb"
APPLY_MARKER_NAME = "apply-requested.json"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        while True:
            chunk = fh.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def main(update_dir: Path, install_fn=None) -> int:
    marker_path = update_dir / APPLY_MARKER_NAME
    staged_path = update_dir / STAGED_DEB_NAME
    if not marker_path.exists():
        return 0  # nothing requested; not an error (the .path unit can fire spuriously)

    try:
        marker = json.loads(marker_path.read_text())
        job_id = int(marker["job_id"])
        expected_sha256 = str(marker["sha256"])
    except (OSError, json.JSONDecodeError, KeyError, ValueError) as exc:
        # Can't even identify the job -- nothing to write a result file
        # against. Remove the unreadable marker so it doesn't spin
        # forever, and exit nonzero so systemd records the failure.
        marker_path.unlink(missing_ok=True)
        print(f"unreadable apply-requested marker: {exc}", file=sys.stderr)
        return 1

    result_path = update_dir / f"result-{job_id}.json"

    def _finish(status: str, detail: dict) -> int:
        payload = {"status": status, "finished_at": None, **detail}
        tmp = update_dir / f".result-{job_id}.json.tmp"
        tmp.write_text(json.dumps(payload))
        tmp.replace(result_path)
        marker_path.unlink(missing_ok=True)
        return 0 if status == "succeeded" else 1

    if not staged_path.exists():
        return _finish("failed", {"error": "staged package is missing"})

    actual_sha256 = sha256_file(staged_path)
    if actual_sha256 != expected_sha256:
        return _finish("failed", {
            "error": "staged package checksum does not match the validated checksum -- "
                     "refusing to install a package that changed after validation",
            "expected_sha256": expected_sha256, "actual_sha256": actual_sha256,
        })

    installer = install_fn or (lambda path: subprocess.run(
        ["apt-get", "install", "-y", "-o", "Dpkg::Options::=--force-confold", str(path)],
        text=True, capture_output=True, timeout=600,
    ))
    try:
        proc = installer(staged_path)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return _finish("failed", {"error": f"apt-get install failed to run: {exc}"})

    output = (getattr(proc, "stdout", "") or "") + (getattr(proc, "stderr", "") or "")
    if proc.returncode != 0:
        return _finish("failed", {"error": "apt-get install exited nonzero", "returncode": proc.returncode, "output": output[-4000:]})
    return _finish("succeeded", {"returncode": 0, "output": output[-4000:]})


if __name__ == "__main__":
    sys.exit(main(UPDATE_DIR))
