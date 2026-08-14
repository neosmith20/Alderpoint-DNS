"""V1 -> V2 migration scaffold.

Scope (V2 Workstream 1): this module defines the migration pipeline's stages
and a restartable/idempotent state machine, per
``docs/v2/roadmap-reference/v2-architecture-plan.md`` §7. Every stage here is
a stub — no real migration logic runs against a live installation in this
workstream. Tests exercise this scaffold only against disposable copies
(``tests/v2/test_migration_scaffold.py`` never opens
``/var/lib/alderpointdns/alderpointdns.db`` directly).

Pipeline stages (in order):

    detect -> backup -> preview -> migrate_config -> migrate_control
           -> migrate_clients -> migrate_policies -> migrate_secrets
           -> migrate_analytics -> generate_runtime_config -> validate
           -> health_check -> commit

``commit`` is the point of no return: everything before it must be safe to
abandon/retry, and a failure at any earlier stage must leave the source
installation untouched. This is enforced here by making every stage before
``commit`` operate only on a staging copy, never on the caller's source
path directly (callers pass a source path in read-only intent; this module
never opens it for writing).
"""

from __future__ import annotations

import shutil
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

STAGES: tuple[str, ...] = (
    "detect",
    "backup",
    "preview",
    "migrate_config",
    "migrate_control",
    "migrate_clients",
    "migrate_policies",
    "migrate_secrets",
    "migrate_analytics",
    "generate_runtime_config",
    "validate",
    "health_check",
    "commit",
)

# Everything at or after this stage index is the point of no return: before
# it, failure must roll back to "not_started"/safe-to-retry. At and after
# it, the migration is committing to the new state.
POINT_OF_NO_RETURN_STAGE = "commit"


class MigrationError(RuntimeError):
    def __init__(self, stage: str, message: str):
        super().__init__(f"[{stage}] {message}")
        self.stage = stage


@dataclass
class MigrationState:
    source_path: Path
    staging_dir: Path
    completed_stages: list[str] = field(default_factory=list)
    failed_stage: str | None = None
    committed: bool = False

    def is_past_point_of_no_return(self) -> bool:
        return POINT_OF_NO_RETURN_STAGE in self.completed_stages


StageFn = Callable[[MigrationState], None]


def _stage_detect(state: MigrationState) -> None:
    if not state.source_path.exists():
        raise MigrationError("detect", f"source path {state.source_path} does not exist")


def _stage_backup(state: MigrationState) -> None:
    # Copies the source into the staging dir; never mutates state.source_path.
    state.staging_dir.mkdir(parents=True, exist_ok=True)
    backup_path = state.staging_dir / "pre-migration-backup"
    if state.source_path.is_dir():
        shutil.copytree(state.source_path, backup_path, dirs_exist_ok=True)
    else:
        shutil.copy2(state.source_path, backup_path)


def _stage_preview(state: MigrationState) -> None:
    # Read-only by construction: only ever reads state.staging_dir /
    # state.source_path, writes nothing. Real implementation (future
    # workstream) would produce a diff/summary here.
    pass


def _stub_stage(name: str) -> StageFn:
    def _stage(state: MigrationState) -> None:
        # Placeholder: real logic lands in a later workstream. Recorded as
        # completed so the state machine / restart logic can be exercised
        # end-to-end now.
        pass

    _stage.__name__ = f"stage_{name}"
    return _stage


_STAGE_FUNCS: dict[str, StageFn] = {
    "detect": _stage_detect,
    "backup": _stage_backup,
    "preview": _stage_preview,
    "migrate_config": _stub_stage("migrate_config"),
    "migrate_control": _stub_stage("migrate_control"),
    "migrate_clients": _stub_stage("migrate_clients"),
    "migrate_policies": _stub_stage("migrate_policies"),
    "migrate_secrets": _stub_stage("migrate_secrets"),
    "migrate_analytics": _stub_stage("migrate_analytics"),
    "generate_runtime_config": _stub_stage("generate_runtime_config"),
    "validate": _stub_stage("validate"),
    "health_check": _stub_stage("health_check"),
    "commit": _stub_stage("commit"),
}


def run_migration(
    source_path: Path,
    staging_dir: Path,
    *,
    resume_state: MigrationState | None = None,
    stop_before: str | None = None,
) -> MigrationState:
    """Run the migration pipeline against a staging copy.

    ``source_path`` is treated as read-only for every stage before
    ``commit``. ``resume_state`` allows restarting after a prior failure:
    already-completed stages are skipped (idempotent restart).
    ``stop_before`` lets tests halt just before a given stage (used to prove
    "failed migration rolls back" without actually reaching commit).
    """
    state = resume_state or MigrationState(source_path=source_path, staging_dir=staging_dir)
    state.failed_stage = None

    for stage in STAGES:
        if stage in state.completed_stages:
            continue  # idempotent: already done in a prior run
        if stop_before is not None and stage == stop_before:
            break
        try:
            _STAGE_FUNCS[stage](state)
        except Exception as exc:
            state.failed_stage = stage
            if not state.is_past_point_of_no_return():
                # Before commit, a failure must not leave partial state the
                # caller has to reason about: staging dir is safe to delete
                # and retry from scratch, source is untouched (it was never
                # opened for writing by any stage above).
                pass
            raise MigrationError(stage, str(exc)) from exc
        state.completed_stages.append(stage)
        if stage == POINT_OF_NO_RETURN_STAGE:
            state.committed = True

    return state
