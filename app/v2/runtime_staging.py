"""V2 staged runtime deployment abstraction (Workstream 3, §10).

Generic pipeline: desired state -> compile -> stage -> validate -> promote
atomically -> health check -> rollback on failure. This module knows
nothing about dnsdist/BIND specifically — it operates on plain bytes/text
content plus a caller-supplied validator callable, so the same abstraction
can back dnsdist config, BIND config, RPZ zone files, or anything else that
needs "never promote a config that doesn't validate."

Tonight's scope: proven against isolated test roots only (see
``app/v2/dnsdist_gen.py`` for the first concrete user). Nothing in this
module is wired to `/etc/alderpointdns` or any live systemd unit.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional


class StagingError(Exception):
    pass


class ValidationFailedError(StagingError):
    def __init__(self, message: str, validator_output: str = ""):
        super().__init__(message)
        self.validator_output = validator_output


@dataclass(frozen=True)
class ValidationResult:
    ok: bool
    output: str


Validator = Callable[[Path], ValidationResult]
HealthCheck = Callable[[], bool]


@dataclass
class PromotionResult:
    promoted: bool
    staged_path: Path
    live_path: Optional[Path]
    validation: ValidationResult
    rolled_back: bool = False
    health_check_passed: Optional[bool] = None
    previous_content_backup: Optional[Path] = None


def _atomic_write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o750)
    tmp = path.parent / f".{path.name}.tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        fh.write(content)
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, path)
    dir_fd = os.open(str(path.parent), os.O_RDONLY)
    try:
        os.fsync(dir_fd)
    finally:
        os.close(dir_fd)


def stage(staging_root: Path, name: str, content: str) -> Path:
    """Write ``content`` atomically into ``staging_root/name`` — never
    directly into the live path. Returns the staged file path."""
    staged_path = Path(staging_root) / name
    _atomic_write(staged_path, content)
    return staged_path


def run_command_validator(command: list[str]) -> Validator:
    """Build a ``Validator`` that runs an external checker binary
    (``dnsdist --check-config``, ``named-checkconf``, ``named-checkzone``,
    ...) against the staged file path, substituted for the literal string
    ``{path}`` in ``command``. Exit code 0 => valid.
    """

    def _validate(staged_path: Path) -> ValidationResult:
        argv = [str(staged_path) if c == "{path}" else c for c in command]
        try:
            proc = subprocess.run(
                argv, capture_output=True, text=True, timeout=30
            )
        except (OSError, subprocess.SubprocessError) as exc:
            return ValidationResult(ok=False, output=f"validator invocation failed: {exc}")
        output = (proc.stdout or "") + (proc.stderr or "")
        return ValidationResult(ok=proc.returncode == 0, output=output)

    return _validate


@dataclass(frozen=True)
class Artifact:
    name: str
    content: str
    live_path: Path
    validator: Validator


def stage_validate_promote_all(
    staging_root: Path, artifacts: list["Artifact"]
) -> list[PromotionResult]:
    """Coherent multi-artifact promotion (BIND architecture correction,
    Gate #3): stages and validates *every* artifact first, and only
    promotes any of them if *all* validate. This is what makes the
    dnsdist+BIND generation pair (and the RPZ zone BIND loads) coherent --
    a BIND ``named.conf``/zone that fails ``named-checkconf``/
    ``named-checkzone`` must not leave the previously-promoted dnsdist
    config live while a stale or absent BIND config sits underneath it
    (or vice versa). Raises the same ``ValidationFailedError`` as
    ``stage_validate_promote`` on the first failing artifact, and -- the
    important difference -- promotes *nothing* in that case, leaving
    every artifact's previous known-good generation untouched.
    """
    staged: list[tuple[Artifact, Path, ValidationResult]] = []
    for artifact in artifacts:
        staged_path = stage(staging_root, artifact.name, artifact.content)
        validation = artifact.validator(staged_path)
        if not validation.ok:
            raise ValidationFailedError(
                f"validation failed for staged artifact {artifact.name!r} "
                f"-- no artifact in this generation was promoted",
                validator_output=validation.output,
            )
        staged.append((artifact, staged_path, validation))

    results = []
    for artifact, staged_path, validation in staged:
        live_path = Path(artifact.live_path)
        previous_backup: Optional[Path] = None
        if live_path.exists():
            previous_backup = staging_root / f".{artifact.name}.previous"
            shutil.copy2(live_path, previous_backup)
        _atomic_write(live_path, artifact.content)
        results.append(
            PromotionResult(
                promoted=True,
                staged_path=staged_path,
                live_path=live_path,
                validation=validation,
                previous_content_backup=previous_backup,
            )
        )
    return results


def stage_validate_promote(
    staging_root: Path,
    name: str,
    content: str,
    live_path: Path,
    validator: Validator,
    health_check: Optional[HealthCheck] = None,
) -> PromotionResult:
    """The full pipeline. Never writes ``live_path`` unless validation
    passes; if a health check is supplied and fails after promotion, the
    previous content (if any existed) is restored and the result records
    ``rolled_back=True`` — the caller must treat that as "promotion did not
    actually succeed" even though bytes briefly hit ``live_path``.
    """
    staged_path = stage(staging_root, name, content)
    validation = validator(staged_path)
    if not validation.ok:
        raise ValidationFailedError(
            f"validation failed for staged artifact {name!r}", validator_output=validation.output
        )

    live_path = Path(live_path)
    previous_backup: Optional[Path] = None
    had_previous = live_path.exists()
    if had_previous:
        previous_backup = staging_root / f".{name}.previous"
        shutil.copy2(live_path, previous_backup)

    _atomic_write(live_path, content)

    health_ok: Optional[bool] = None
    rolled_back = False
    if health_check is not None:
        health_ok = health_check()
        if not health_ok:
            if had_previous and previous_backup is not None:
                _atomic_write(live_path, previous_backup.read_text(encoding="utf-8"))
            else:
                live_path.unlink(missing_ok=True)
            rolled_back = True

    return PromotionResult(
        promoted=not rolled_back,
        staged_path=staged_path,
        live_path=live_path,
        validation=validation,
        rolled_back=rolled_back,
        health_check_passed=health_ok,
        previous_content_backup=previous_backup,
    )
