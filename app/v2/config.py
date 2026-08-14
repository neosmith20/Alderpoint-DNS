"""V2 desired-state configuration schema and atomic file I/O.

Scope (V2 Workstream 1): this module defines the schema for the operator-facing
desired-state file at ``/etc/alderpointdns/alderpointdns.yaml`` (see
``docs/v2/roadmap-reference/v2-architecture-plan.md`` §3.1) and provides safe
load/validate/atomic-write primitives. It is NOT wired into the running v1.1.1
webapp — nothing here reads or writes the live path unless a caller passes it
in explicitly.

Only items classified CONFIG in ``docs/v2/storage-audit.md`` belong in this
schema. Secrets, control-plane/transactional state, and raw/aggregate
analytics never belong here — see ``docs/v2/storage-audit.md`` for the
per-table classification this schema is derived from.
"""

from __future__ import annotations

import contextlib
import os
import tempfile
from dataclasses import dataclass, field, fields
from pathlib import Path
from typing import Any

import yaml

# Bumped whenever the on-disk schema changes in a way that requires a
# migration step. V2 Workstream 1 starts this at 1.
CONFIG_SCHEMA_VERSION = 1

# File is operator-configuration, not a secret, but should still not be
# world-writable/readable beyond what's needed. Matches the existing
# /etc/alderpointdns convention of root:alderpointdns ownership with group
# read where appropriate; this module only controls the mode bits, not the
# owning group (that's a deployment-time chown, out of scope here).
_CONFIG_FILE_MODE = 0o640


class ConfigValidationError(ValueError):
    """Raised when a loaded or constructed config fails schema validation."""


_VALID_LISTENER_PROTOCOLS = frozenset({"udp", "tcp", "dot", "doh", "doq", "doh3"})
_VALID_UPSTREAM_STRATEGIES = frozenset(
    {"ordered", "load_balanced", "parallel", "fastest"}
)
_VALID_ANALYTICS_RETENTION_UNITS = frozenset({"days", "weeks"})


@dataclass
class Listener:
    protocol: str
    address: str = "0.0.0.0"
    port: int = 0

    def validate(self) -> list[str]:
        errors = []
        if self.protocol not in _VALID_LISTENER_PROTOCOLS:
            errors.append(
                f"listener.protocol {self.protocol!r} must be one of "
                f"{sorted(_VALID_LISTENER_PROTOCOLS)}"
            )
        if not (0 < self.port <= 65535):
            errors.append(f"listener.port {self.port!r} must be between 1 and 65535")
        return errors


@dataclass
class AnalyticsPolicy:
    """Operator-facing analytics retention/privacy policy.

    This governs the ANALYTICS-RAW / ANALYTICS-AGG stores classified in
    docs/v2/storage-audit.md; it does not itself hold any analytics data.
    """

    enabled: bool = True
    retention_value: int = 30
    retention_unit: str = "days"
    max_disk_mb: int | None = None

    def validate(self) -> list[str]:
        errors = []
        if self.retention_unit not in _VALID_ANALYTICS_RETENTION_UNITS:
            errors.append(
                f"analytics.retention_unit {self.retention_unit!r} must be one "
                f"of {sorted(_VALID_ANALYTICS_RETENTION_UNITS)}"
            )
        if self.retention_value <= 0:
            errors.append("analytics.retention_value must be positive")
        if self.max_disk_mb is not None and self.max_disk_mb <= 0:
            errors.append("analytics.max_disk_mb must be positive when set")
        return errors


@dataclass
class FeatureToggles:
    """Inert placeholders for later-workstream features.

    Per the original Workstream 1 brief §18, these are schema placeholders
    only so later features fit into this config layer cleanly. None of them
    are implemented or enforced by V2 Workstream 1 code.
    """

    safesearch_enabled: bool = False
    parental_controls_enabled: bool = False
    service_blocking_enabled: bool = False
    ecs_enabled: bool = False


@dataclass
class AlderpointV2Config:
    schema_version: int = CONFIG_SCHEMA_VERSION
    listeners: list[Listener] = field(default_factory=list)
    upstream_strategy: str = "ordered"
    analytics: AnalyticsPolicy = field(default_factory=AnalyticsPolicy)
    features: FeatureToggles = field(default_factory=FeatureToggles)

    def validate(self) -> list[str]:
        errors: list[str] = []
        if self.schema_version != CONFIG_SCHEMA_VERSION:
            errors.append(
                f"schema_version {self.schema_version!r} is not the supported "
                f"version {CONFIG_SCHEMA_VERSION!r} (no migrator registered yet)"
            )
        if self.upstream_strategy not in _VALID_UPSTREAM_STRATEGIES:
            errors.append(
                f"upstream_strategy {self.upstream_strategy!r} must be one of "
                f"{sorted(_VALID_UPSTREAM_STRATEGIES)}"
            )
        for i, listener in enumerate(self.listeners):
            for err in listener.validate():
                errors.append(f"listeners[{i}]: {err}")
        errors.extend(f"analytics: {e}" for e in self.analytics.validate())
        return errors

    def to_dict(self) -> dict[str, Any]:
        def _conv(obj: Any) -> Any:
            if hasattr(obj, "__dataclass_fields__"):
                return {f.name: _conv(getattr(obj, f.name)) for f in fields(obj)}
            if isinstance(obj, list):
                return [_conv(v) for v in obj]
            return obj

        return _conv(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "AlderpointV2Config":
        if not isinstance(data, dict):
            raise ConfigValidationError("top-level config must be a mapping")
        data = dict(data)
        listeners_raw = data.pop("listeners", []) or []
        if not isinstance(listeners_raw, list):
            raise ConfigValidationError("listeners must be a list")
        listeners = []
        for item in listeners_raw:
            if not isinstance(item, dict):
                raise ConfigValidationError("each listener must be a mapping")
            try:
                listeners.append(Listener(**item))
            except TypeError as exc:
                raise ConfigValidationError(f"invalid listener fields: {exc}") from exc

        analytics_raw = data.pop("analytics", {}) or {}
        if not isinstance(analytics_raw, dict):
            raise ConfigValidationError("analytics must be a mapping")
        try:
            analytics = AnalyticsPolicy(**analytics_raw)
        except TypeError as exc:
            raise ConfigValidationError(f"invalid analytics fields: {exc}") from exc

        features_raw = data.pop("features", {}) or {}
        if not isinstance(features_raw, dict):
            raise ConfigValidationError("features must be a mapping")
        try:
            features = FeatureToggles(**features_raw)
        except TypeError as exc:
            raise ConfigValidationError(f"invalid features fields: {exc}") from exc

        try:
            cfg = cls(
                listeners=listeners, analytics=analytics, features=features, **data
            )
        except TypeError as exc:
            raise ConfigValidationError(f"unknown top-level config field: {exc}") from exc

        errors = cfg.validate()
        if errors:
            raise ConfigValidationError("; ".join(errors))
        return cfg


def loads(text: str) -> AlderpointV2Config:
    """Parse and validate config YAML text. Raises ConfigValidationError."""
    try:
        raw = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise ConfigValidationError(f"invalid YAML: {exc}") from exc
    if raw is None:
        raise ConfigValidationError("config file is empty")
    return AlderpointV2Config.from_dict(raw)


def dumps(cfg: AlderpointV2Config) -> str:
    return yaml.safe_dump(cfg.to_dict(), default_flow_style=False, sort_keys=False)


def load_file(path: str | os.PathLike) -> AlderpointV2Config:
    with open(path, "r", encoding="utf-8") as fh:
        return loads(fh.read())


def atomic_write(path: str | os.PathLike, cfg: AlderpointV2Config) -> None:
    """Validate then atomically write config to ``path``.

    Writes to a temp file in the same directory, fsyncs it, then renames over
    the destination — the destination is never observed in a partially-written
    state (matches the pattern already used by the v1 compiler/deploy
    pipeline described in docs/architecture.md).
    """
    errors = cfg.validate()
    if errors:
        raise ConfigValidationError("; ".join(errors))

    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    text = dumps(cfg)

    fd, tmp_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent)
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as tmp:
            tmp.write(text)
            tmp.flush()
            os.fsync(tmp.fileno())
        os.chmod(tmp_name, _CONFIG_FILE_MODE)
        os.replace(tmp_name, path)
    except BaseException:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(tmp_name)
        raise

    dir_fd = os.open(str(path.parent), os.O_RDONLY)
    try:
        os.fsync(dir_fd)
    finally:
        os.close(dir_fd)
