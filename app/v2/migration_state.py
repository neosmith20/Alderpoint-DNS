"""V2 durable migration state (Workstream 2, §12-13).

Workstream 1's ``app/v2/migration.py`` had an in-memory-only
``MigrationState`` — fine for exercising the stage pipeline shape, not
acceptable once migration can run against a real installation (Dex gate,
``docs/v2/handoff-workstream-2.md`` gate 2). This module adds the durable
half: state is persisted to a JSON file after every stage transition, using
the same atomic-write pattern used everywhere else in this codebase
(temp file + fsync + ``os.replace``), so a crash/reboot between stages
leaves a readable, trustworthy record of exactly how far the migration got.

This module intentionally does not persist into ``control.db`` — the target
control database may not exist yet for most of the pipeline (it's created by
the ``migrate_control`` stage), and migration state needs to survive from
before that point. The durable record lives beside the staging directory
instead (``<staging_dir>/migration_state.json`` by convention, though
callers may pass any path).
"""

from __future__ import annotations

import json
import os
import tempfile
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class MigrationRecord:
    migration_id: str
    source_version: str
    target_version: str
    staging_dir: str
    source_path: str
    status: str = "not_started"  # not_started|running|completed|failed|rolled_back
    completed_stages: list[str] = field(default_factory=list)
    failed_stage: str | None = None
    failure_diagnostics: str | None = None
    retry_count: int = 0
    commit_point_reached: bool = False
    started_at: str | None = None
    completed_at: str | None = None
    updated_at: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "MigrationRecord":
        known = {f for f in cls.__dataclass_fields__}
        filtered = {k: v for k, v in data.items() if k in known}
        return cls(**filtered)

    @classmethod
    def new(
        cls, *, source_version: str, target_version: str, staging_dir: str | os.PathLike,
        source_path: str | os.PathLike, migration_id: str | None = None,
    ) -> "MigrationRecord":
        return cls(
            migration_id=migration_id or uuid.uuid4().hex,
            source_version=source_version,
            target_version=target_version,
            staging_dir=str(staging_dir),
            source_path=str(source_path),
            started_at=_now_iso(),
            updated_at=_now_iso(),
        )


def save(path: str | os.PathLike, record: MigrationRecord) -> None:
    """Atomically persist ``record`` to ``path``. Same temp-file + fsync +
    os.replace pattern as app/v2/config.py's atomic_write — a reader can
    never observe a partially-written state file, including across a crash
    during this exact write."""
    record.updated_at = _now_iso()
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    text = json.dumps(record.to_dict(), indent=2)
    fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as tmp:
            tmp.write(text)
            tmp.flush()
            os.fsync(tmp.fileno())
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


def load(path: str | os.PathLike) -> MigrationRecord | None:
    """Returns None if no state file exists yet (fresh migration, nothing to
    resume). Raises if the file exists but is corrupt/truncated — a caller
    encountering a corrupt state file should treat that as "cannot safely
    determine progress" and require operator intervention, not guess."""
    path = Path(path)
    if not path.exists():
        return None
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)  # raises json.JSONDecodeError on corruption — intentionally not caught here
    return MigrationRecord.from_dict(data)


def mark_stage_completed(record: MigrationRecord, stage: str, *, is_commit_stage: bool) -> None:
    if stage not in record.completed_stages:
        record.completed_stages.append(stage)
    record.status = "running"
    record.failed_stage = None
    record.failure_diagnostics = None
    if is_commit_stage:
        record.commit_point_reached = True


def mark_failed(record: MigrationRecord, stage: str, diagnostics: str) -> None:
    record.status = "failed"
    record.failed_stage = stage
    record.failure_diagnostics = diagnostics


def mark_completed(record: MigrationRecord) -> None:
    record.status = "completed"
    record.completed_at = _now_iso()


def mark_rolled_back(record: MigrationRecord) -> None:
    record.status = "rolled_back"
