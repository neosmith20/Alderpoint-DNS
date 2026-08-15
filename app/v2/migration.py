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

import json
import shutil
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from app.v2 import migration_convert as mconv
from app.v2 import migration_state as mstate

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

    # Real-conversion outputs (Workstream 3 final continuation), all
    # populated by the real stage functions below as the pipeline
    # progresses; empty/None until the relevant stage has run.
    backup_manifest: dict = field(default_factory=dict)
    preview_report: dict = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)
    object_counts: dict = field(default_factory=dict)
    local_dns_records: list = field(default_factory=list)
    filtering: dict = field(default_factory=dict)
    generated_runtime: dict = field(default_factory=dict)
    health_check_result: dict = field(default_factory=dict)

    def target_root(self) -> Path:
        return self.staging_dir / "v2-target"

    def target_control_db(self) -> Path:
        return self.target_root() / "control.db"

    def target_secrets_dir(self) -> Path:
        return self.target_root() / "secrets"

    def target_config_path(self) -> Path:
        return self.target_root() / "alderpointdns.yaml"

    def is_past_point_of_no_return(self) -> bool:
        return POINT_OF_NO_RETURN_STAGE in self.completed_stages


StageFn = Callable[[MigrationState], None]


def _stage_detect(state: MigrationState) -> None:
    if not state.source_path.exists():
        raise MigrationError("detect", f"source path {state.source_path} does not exist")
    try:
        mconv.detect_source(state.source_path)
    except mconv.MigrationConvertError as exc:
        raise MigrationError("detect", str(exc)) from exc


def _stage_backup(state: MigrationState) -> None:
    # Copies the source into the staging dir; never mutates state.source_path.
    state.staging_dir.mkdir(parents=True, exist_ok=True)
    try:
        source = mconv.detect_source(state.source_path)
        manifest = mconv.create_backup(source.db_path, state.staging_dir)
        mconv.verify_backup(manifest)
        mconv.restore_test(manifest, state.staging_dir / "restore-test")
        state.backup_manifest = manifest
    except mconv.MigrationConvertError as exc:
        raise MigrationError("backup", str(exc)) from exc


def _backup_db_path(state: MigrationState) -> Path:
    """Crash-safe accessor: if this process resumed from a durable record
    (Workstream 2 §12) rather than continuing in-memory, ``state`` may have
    an empty ``backup_manifest`` even though the ``backup`` stage genuinely
    completed in a prior process run -- the durable record only tracks
    stage-completion bookkeeping, not full stage outputs. Since the backup
    stage already writes its manifest to disk under ``staging_dir``, that's
    the actual durable source of truth to fall back to here, not something
    the caller needs to re-derive or the durable record needs to duplicate.
    """
    if not state.backup_manifest:
        manifest_path = state.staging_dir / "pre-migration-backup.manifest.json"
        if manifest_path.exists():
            state.backup_manifest = json.loads(manifest_path.read_text())
        else:
            raise MigrationError(
                "preview", "backup stage has not run yet -- no verified backup to read"
            )
    return Path(state.backup_manifest["backup_path"])


def _stage_preview(state: MigrationState) -> None:
    # Read-only by construction: only ever reads the verified backup copy,
    # never state.source_path directly.
    try:
        state.preview_report = mconv.build_preview(_backup_db_path(state))
    except mconv.MigrationConvertError as exc:
        raise MigrationError("preview", str(exc)) from exc


def _stage_migrate_config(state: MigrationState) -> None:
    from app.v2 import config as v2config

    try:
        cfg = mconv.convert_config(_backup_db_path(state))
        v2config.atomic_write(state.target_config_path(), cfg)
        v2config.load_file(state.target_config_path())  # validate round-trip
    except mconv.MigrationConvertError as exc:
        raise MigrationError("migrate_config", str(exc)) from exc


def _stage_migrate_control(state: MigrationState) -> None:
    mconv.initialize_target_control_db(state.target_control_db())
    result = mconv.migrate_admins(_backup_db_path(state), state.target_control_db())
    if result["needs_rehash"]:
        state.warnings.append(
            f"admins requiring re-authentication (unrecognized hash format): "
            f"{result['needs_rehash']}"
        )
    state.object_counts["admins_migrated"] = result["migrated"]


def _stage_migrate_clients(state: MigrationState) -> None:
    result = mconv.migrate_clients(_backup_db_path(state), state.target_control_db())
    state.warnings.extend(result["warnings"])
    state.object_counts["clients_migrated"] = result["clients_migrated"]
    state.object_counts["client_identifiers_migrated"] = result["identifiers_migrated"]


def _stage_migrate_policies(state: MigrationState) -> None:
    policies_result = mconv.migrate_policies(_backup_db_path(state), state.target_control_db())
    state.warnings.extend(policies_result["warnings"])
    state.object_counts["networks_migrated"] = policies_result["networks_migrated"]

    local_dns_records, local_dns_warnings = mconv.migrate_local_dns(_backup_db_path(state))
    state.local_dns_records = local_dns_records
    state.warnings.extend(local_dns_warnings)
    state.object_counts["local_dns_records_migrated"] = len(local_dns_records)

    state.filtering = mconv.migrate_filtering(_backup_db_path(state))
    state.object_counts["filtering_blocked"] = len(state.filtering["blocked_domains"])
    state.object_counts["filtering_allowed"] = len(state.filtering["allowed_domains"])

    upstream_result = mconv.migrate_upstreams(_backup_db_path(state), state.target_control_db())
    state.warnings.extend(upstream_result["warnings"])
    state.object_counts["upstreams_migrated"] = upstream_result["migrated"]

    _persist_policies_output(state)


def _policies_output_path(state: MigrationState) -> Path:
    return state.target_root() / "migrate_policies_output.json"


def _persist_policies_output(state: MigrationState) -> None:
    # Same crash-safety concern as _backup_db_path: local_dns_records and
    # filtering are only in-memory unless persisted, and a durable-record
    # resume after a crash later in the pipeline (e.g. at
    # generate_runtime_config) would otherwise silently lose them.
    state.target_root().mkdir(parents=True, exist_ok=True)
    _policies_output_path(state).write_text(
        json.dumps(
            {
                "local_dns_records": [asdict(r) for r in state.local_dns_records],
                "filtering": state.filtering,
            },
            indent=2,
        )
    )


def _load_policies_output_if_needed(state: MigrationState) -> None:
    if state.local_dns_records or state.filtering:
        return
    path = _policies_output_path(state)
    if not path.exists():
        raise MigrationError(
            "generate_runtime_config",
            "migrate_policies stage has not run yet -- no persisted output to read",
        )
    from app.v2.local_dns_gen import LocalDnsRecord

    data = json.loads(path.read_text())
    state.local_dns_records = [LocalDnsRecord(**r) for r in data["local_dns_records"]]
    state.filtering = data["filtering"]


def _stage_migrate_secrets(state: MigrationState) -> None:
    from app.v2.secret_store import SecretStore

    secrets = SecretStore(state.target_secrets_dir())
    result = mconv.migrate_notifications(
        _backup_db_path(state), state.target_control_db(), secrets
    )
    state.object_counts["notifications_migrated"] = result["migrated"]


def _stage_migrate_analytics(state: MigrationState) -> None:
    manifest = mconv.register_legacy_analytics_archive(_backup_db_path(state), state.target_root())
    state.object_counts["legacy_query_history_rows"] = manifest["row_count"]


def _stage_generate_runtime_config(state: MigrationState) -> None:
    from app.v2 import bind_rpz_gen, dnsdist_gen, local_dns_gen
    from app.v2 import policy_store as pstore
    from app.v2.blocking_response import BlockingResponse
    from app.v2 import control_db

    _load_policies_output_if_needed(state)

    runtime_dir = state.target_root() / "runtime"
    runtime_dir.mkdir(parents=True, exist_ok=True)

    with control_db.connect(state.target_control_db()) as conn:
        profile = pstore.load_upstream_profile(conn, "migrated-default")

    if profile is not None:
        # generate_dnsdist_config_from_profiles (not the simpler
        # generate_dnsdist_config) is used specifically because it applies
        # the profile's real transport (plain/dot/doh) to each backend --
        # using the plain-only generator here was a real bug found via the
        # health-check stage actually querying a migrated DoT upstream and
        # getting no response, since dnsdist treated the DoT port as plain.
        dnsdist_text = dnsdist_gen.generate_dnsdist_config_from_profiles(
            "127.0.0.1:15400", [], profile,
        )
        dnsdist_path = runtime_dir / "dnsdist.conf"
        result = dnsdist_gen.stage_and_validate_dnsdist_config(
            runtime_dir, dnsdist_text, dnsdist_path
        )
        state.generated_runtime["dnsdist_config"] = str(result.live_path)
        state.generated_runtime["dnsdist_valid"] = result.validation.ok

    blocked = {d: BlockingResponse(mode="nxdomain") for d in state.filtering.get("blocked_domains", [])}
    rpz_text = bind_rpz_gen.render_rpz_zone(
        blocked, state.filtering.get("allowed_domains", []), serial=1
    )
    rpz_path = runtime_dir / "alderpointdns-v2.rpz"
    rpz_result = bind_rpz_gen.stage_and_validate_rpz_zone(runtime_dir, rpz_text, rpz_path)
    state.generated_runtime["rpz_zone"] = str(rpz_result.live_path)
    state.generated_runtime["rpz_valid"] = rpz_result.validation.ok

    if state.local_dns_records:
        zone_text = local_dns_gen.render_local_dns_zone(state.local_dns_records, serial=1)
        zone_path = runtime_dir / "alderpointdns-v2-local.zone"
        zone_result = local_dns_gen.stage_and_validate_local_dns_zone(
            runtime_dir, zone_text, zone_path
        )
        state.generated_runtime["local_dns_zone"] = str(zone_result.live_path)
        state.generated_runtime["local_dns_valid"] = zone_result.validation.ok


def _reload_generated_runtime_if_needed(state: MigrationState) -> None:
    """Same crash-safety pattern as ``_backup_db_path``/
    ``_load_policies_output_if_needed``: ``generate_runtime_config``'s
    artifacts are real files already sitting under ``target_root()/runtime``
    (each write went through ``stage_validate_promote``, which only ever
    leaves a file in place if validation passed) -- so if a resumed process
    has an empty in-memory ``generated_runtime`` dict, the presence of
    those files on disk is itself sufficient proof they were validated
    when written, without needing a separate JSON sidecar.
    """
    if state.generated_runtime:
        return
    runtime_dir = state.target_root() / "runtime"
    dnsdist_path = runtime_dir / "dnsdist.conf"
    rpz_path = runtime_dir / "alderpointdns-v2.rpz"
    local_zone_path = runtime_dir / "alderpointdns-v2-local.zone"
    if dnsdist_path.exists():
        state.generated_runtime["dnsdist_config"] = str(dnsdist_path)
        state.generated_runtime["dnsdist_valid"] = True
    if rpz_path.exists():
        state.generated_runtime["rpz_zone"] = str(rpz_path)
        state.generated_runtime["rpz_valid"] = True
    if local_zone_path.exists():
        state.generated_runtime["local_dns_zone"] = str(local_zone_path)
        state.generated_runtime["local_dns_valid"] = True


def _stage_validate(state: MigrationState) -> None:
    _reload_generated_runtime_if_needed(state)
    from app.v2 import control_db as v2control_db

    integrity = v2control_db.connect(state.target_control_db())
    with integrity as conn:
        result = conn.execute("PRAGMA integrity_check").fetchone()[0]
    if result != "ok":
        raise MigrationError("validate", f"target control.db failed integrity_check: {result}")

    for key in ("dnsdist_valid", "rpz_valid", "local_dns_valid"):
        if key in state.generated_runtime and not state.generated_runtime[key]:
            raise MigrationError("validate", f"generated runtime artifact failed validation: {key}")


def _stage_health_check(state: MigrationState) -> None:
    _reload_generated_runtime_if_needed(state)
    dnsdist_config = state.generated_runtime.get("dnsdist_config")
    if dnsdist_config is None:
        state.health_check_result = {"skipped": "no upstream profile migrated, nothing to health-check"}
        return
    import shutil
    import socket
    import struct
    import subprocess
    import time as _time

    if shutil.which("dnsdist") is None:
        state.health_check_result = {"skipped": "dnsdist binary not installed on this host"}
        return

    proc = subprocess.Popen(
        ["dnsdist", "-C", dnsdist_config, "--supervised", "--disable-syslog"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    try:
        _time.sleep(1.0)
        if proc.poll() is not None:
            raise MigrationError("health_check", "generated dnsdist config failed to start")
        header = struct.pack(">HHHHHH", 1, 0x0100, 1, 0, 0, 0)
        qparts = b"".join(bytes([len(p)]) + p.encode() for p in "example.com".split("."))
        pkt = header + qparts + b"\x00" + struct.pack(">HH", 1, 1)
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(3)
        try:
            s.sendto(pkt, ("127.0.0.1", 15400))
            data, _ = s.recvfrom(4096)
            resolved = len(data) > 0
        except OSError:
            resolved = False
        finally:
            s.close()
        state.health_check_result = {"generated_runtime_started": True, "recursive_resolution_ok": resolved}
        if not resolved:
            raise MigrationError("health_check", "generated dnsdist config did not answer a test query")
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=5)


def _stage_commit(state: MigrationState) -> None:
    # Late commit point: everything above operates only on
    # state.staging_dir / state.target_root(); state.source_path is never
    # opened for writing at any stage, so "commit" here means "the
    # generated V2 state under target_root() is now considered final and
    # promotable" -- it does NOT itself promote anything over a live
    # appliance. A real deployment step (out of scope this session, see
    # docs/v2/handoff-workstream-4.md) would be a separate, explicitly
    # authorized action following this.
    pass


_STAGE_FUNCS: dict[str, StageFn] = {
    "detect": _stage_detect,
    "backup": _stage_backup,
    "preview": _stage_preview,
    "migrate_config": _stage_migrate_config,
    "migrate_control": _stage_migrate_control,
    "migrate_clients": _stage_migrate_clients,
    "migrate_policies": _stage_migrate_policies,
    "migrate_secrets": _stage_migrate_secrets,
    "migrate_analytics": _stage_migrate_analytics,
    "generate_runtime_config": _stage_generate_runtime_config,
    "validate": _stage_validate,
    "health_check": _stage_health_check,
    "commit": _stage_commit,
}


def run_migration(
    source_path: Path,
    staging_dir: Path,
    *,
    resume_state: MigrationState | None = None,
    stop_before: str | None = None,
    durable_record: "mstate.MigrationRecord | None" = None,
    state_path: Path | None = None,
) -> MigrationState:
    """Run the migration pipeline against a staging copy.

    ``source_path`` is treated as read-only for every stage before
    ``commit``. ``resume_state`` allows restarting after a prior failure:
    already-completed stages are skipped (idempotent restart).
    ``stop_before`` lets tests halt just before a given stage (used to prove
    "failed migration rolls back" without actually reaching commit).

    Durable state (Workstream 2 §12): when both ``durable_record`` and
    ``state_path`` are given, the record is updated and atomically persisted
    (``app/v2/migration_state.py``) after *every* stage attempt — success or
    failure — so a crash immediately after this call returns (or even a
    crash the caller can't observe, e.g. this process being killed) leaves a
    readable on-disk record of exactly which stages completed. This is
    orthogonal to ``resume_state``/``completed_stages`` (the in-memory
    mechanism from Workstream 1): a caller restarting after a real process
    crash has no in-memory ``MigrationState`` to pass as ``resume_state`` —
    it must reconstruct one from the durable record on disk instead (see
    ``app/v2/migration.py``'s test suite,
    ``TestDurableStateCrashRestart``, for the full round-trip).
    """
    state = resume_state or MigrationState(source_path=source_path, staging_dir=staging_dir)
    state.failed_stage = None

    if durable_record is not None and state_path is not None:
        # Persist immediately, before attempting the first stage, so even a
        # crash before any stage completes (or a stop_before on the very
        # first pending stage) still leaves a resumable record on disk —
        # otherwise a crash in that narrow window would have nothing to
        # reconstruct from.
        durable_record.status = "running"
        mstate.save(state_path, durable_record)

    for stage in STAGES:
        if stage in state.completed_stages:
            continue  # idempotent: already done in a prior run
        if stop_before is not None and stage == stop_before:
            break
        try:
            _STAGE_FUNCS[stage](state)
        except Exception as exc:
            state.failed_stage = stage
            if durable_record is not None and state_path is not None:
                mstate.mark_failed(durable_record, stage, f"{type(exc).__name__}: {exc}")
                mstate.save(state_path, durable_record)
            raise MigrationError(stage, str(exc)) from exc
        state.completed_stages.append(stage)
        is_commit_stage = stage == POINT_OF_NO_RETURN_STAGE
        if is_commit_stage:
            state.committed = True
        if durable_record is not None and state_path is not None:
            mstate.mark_stage_completed(durable_record, stage, is_commit_stage=is_commit_stage)
            if is_commit_stage:
                mstate.mark_completed(durable_record)
            mstate.save(state_path, durable_record)

    return state


def resume_state_from_durable_record(record: "mstate.MigrationRecord") -> MigrationState:
    """Reconstruct an in-memory ``MigrationState`` from a durable
    ``MigrationRecord`` loaded off disk — the bridge a real caller uses after
    a crash/reboot, when no in-memory state survived: load the record with
    ``migration_state.load(state_path)``, pass it here, then pass the result
    as ``run_migration``'s ``resume_state``."""
    state = MigrationState(
        source_path=Path(record.source_path),
        staging_dir=Path(record.staging_dir),
        completed_stages=list(record.completed_stages),
        failed_stage=record.failed_stage,
        committed=record.commit_point_reached,
    )
    return state
