"""DNS Cache view/flush (beta-rescue priority 3A).

V2's locked architecture has two distinct cache layers between a client
and an upstream:

  client -> dnsdist RAM packet cache -> compiled policy/routing
         -> BIND RAM recursive cache -> upstream

This module deliberately never conflates them: a flush always targets
one explicit layer, status is reported per layer, and there is no
"clear everything" button that quietly only clears one of the two (a
real V1.1.1 lesson -- V1 only ever had the one BIND-backed layer this
module's BIND half mirrors almost exactly, via the same `rndc`
mechanism V1 used).

BIND layer: a real, loopback-only `rndc` control channel (see
app/v2/bind_gen.py's `rndc_port`/`rndc_key_secret` params) lets this
module issue real `rndc flush` / `flushname` / `flushtree` commands and
read real cache hit/miss counters from BIND's existing statistics
channel (already wired for health reporting) -- both already-proven,
already-running real BIND machinery, nothing new added to the DNS hot
path itself.

dnsdist layer: the packet cache is process-local in-memory state with
no administrative channel configured in the compiled runtime (no
console, no webserver -- deliberately, to keep the attack surface
minimal). Rather than adding a new always-on privileged channel just
for this, a dnsdist-layer flush is a real, coalesced restart of the
`alderpointdns-v2-dnsdist` unit: it drops all in-memory cache state
(exactly what a flush means for this layer) without adding any
persistent dependency to the query path.
"""

from __future__ import annotations

import base64
import json
import os
import subprocess
import time
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from app.v2.bind_gen import BIND_RNDC_PORT, RNDC_KEY_NAME
from app.v2.secret_store import SecretStore

RNDC_KEY_SECRET_ID = "bind-rndc-key"


class CacheControlError(RuntimeError):
    pass


def ensure_rndc_key(secrets: SecretStore) -> str:
    """A single shared HMAC-SHA256 key used by every BIND context's rndc
    control channel (see bind_gen.py) -- rndc doesn't need a distinct key
    per context for security, only for the channel to exist at all."""
    if not secrets.exists(RNDC_KEY_SECRET_ID):
        key = base64.b64encode(os.urandom(32)).decode("ascii")
        secrets.create(key, secret_id=RNDC_KEY_SECRET_ID)
    return secrets.get(RNDC_KEY_SECRET_ID)


def render_rndc_conf(key_secret: str) -> str:
    return "\n".join([
        f'key "{RNDC_KEY_NAME}" {{',
        "\talgorithm hmac-sha256;",
        f'\tsecret "{key_secret}";',
        "};",
        "",
        f'options {{ default-key "{RNDC_KEY_NAME}"; }};',
        "",
    ]) + "\n"


@dataclass(frozen=True)
class FlushResult:
    context: str
    scope: str
    target: Optional[str]
    ok: bool
    message: str


def flush_bind_context(
    rndc_conf_path: Path, context_name: str, port: int, scope: str, target: Optional[str] = None,
    rndc_binary: str = "rndc",
) -> FlushResult:
    if scope not in ("all", "name", "tree"):
        raise CacheControlError(f"invalid flush scope: {scope!r}")
    if scope in ("name", "tree") and not target:
        raise CacheControlError(f"scope {scope!r} requires a target name")
    cmd = [rndc_binary, "-c", str(rndc_conf_path), "-s", "127.0.0.1", "-p", str(port)]
    if scope == "all":
        cmd += ["flush"]
    elif scope == "name":
        cmd += ["flushname", target]
    else:
        cmd += ["flushtree", target]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return FlushResult(context_name, scope, target, False, f"rndc failed to run: {exc}")
    ok = proc.returncode == 0
    message = (proc.stdout or proc.stderr or "").strip() or ("flushed" if ok else "rndc command failed")
    return FlushResult(context_name, scope, target, ok, message)


def bind_cache_stats(statistics_port: int, timeout: float = 3.0) -> dict:
    """Real hit/miss counters from BIND's own statistics-channel JSON
    (already enabled for health reporting -- see bind_gen.py's
    statistics-channels clause)."""
    url = f"http://127.0.0.1:{statistics_port}/json/v1/server"
    try:
        with urllib.request.urlopen(url, timeout=timeout) as response:
            raw = json.loads(response.read().decode())
    except Exception as exc:
        return {"available": False, "error": str(exc)}
    view = (raw.get("views") or {}).get("_default") or {}
    resolver = view.get("resolver") or {}
    stats = resolver.get("cachestats") or {}
    hits = int(stats.get("CacheHits", 0))
    misses = int(stats.get("CacheMisses", 0))
    total = hits + misses
    return {
        "available": True,
        "hits": hits,
        "misses": misses,
        "hit_ratio": round(hits / total, 4) if total else None,
        "cache_size_bytes": stats.get("TreeMemTotal"),
    }


_LAST_DNSDIST_FLUSH_PATH = Path("/var/lib/alderpointdns-v2/cache/last-dnsdist-flush")
_DNSDIST_FLUSH_MIN_INTERVAL_SECONDS = 10.0
COMPILED_DNSDIST_CONF_PATH = Path("/var/lib/alderpointdns-v2/compiled/dnsdist.conf")


def flush_dnsdist_cache(
    state_path: Path = _LAST_DNSDIST_FLUSH_PATH,
    min_interval: float = _DNSDIST_FLUSH_MIN_INTERVAL_SECONDS,
    compiled_conf_path: Path = COMPILED_DNSDIST_CONF_PATH,
) -> FlushResult:
    """Drops dnsdist's in-process packet cache -- the only way to do so
    without an administrative console we deliberately don't run --
    without ever needing this unprivileged web process (runs as
    `alderpointdns-v2`, ``NoNewPrivileges=true``, no sudoers grant) to
    itself call `systemctl restart` on a system unit, which a real
    packaged install would simply refuse (root-cause found during
    beta-rescue priority 4/Network Configuration privilege-model review;
    calling `systemctl restart` directly here silently could never have
    worked on a real install).

    Instead this rides the exact same, already-proven, root-owned
    reload path a normal policy promotion uses
    (`alderpointdns-v2-dnsdist-reload.path` watches this file and its
    `.service` runs `systemctl restart alderpointdns-v2-dnsdist.service`
    as root via PID 1, not this process): rewriting the compiled
    dnsdist.conf with its own unchanged content still produces a real
    open+write+close, which is what the `.path` unit's inotify watch
    triggers on, so a flush-with-no-config-change reliably fires the
    same restart a real config change would.

    Coalesced: a rapid double-click (or an automated retry) within
    `min_interval` of the last real restart is reported as a no-op
    success rather than triggering a second real restart, the same
    "don't pile up redundant privileged operations" lesson
    _DeployCoordinator encodes in V1."""
    state_path.parent.mkdir(parents=True, exist_ok=True)
    now = time.time()
    if state_path.exists():
        try:
            last = float(state_path.read_text().strip())
        except (OSError, ValueError):
            last = 0.0
        if now - last < min_interval:
            return FlushResult("dnsdist", "all", None, True, "already flushed within the last few seconds; not restarting again")
    if not compiled_conf_path.exists():
        return FlushResult("dnsdist", "all", None, False, f"no compiled dnsdist config at {compiled_conf_path}; nothing to flush")
    try:
        content = compiled_conf_path.read_text()
        compiled_conf_path.write_text(content)
        # write_text() alone is not guaranteed to visibly move mtime on
        # every filesystem's clock resolution when two flushes land in
        # the same tick; setting it explicitly makes the trigger
        # deterministic regardless of host fs mtime granularity.
        os.utime(compiled_conf_path, (now, now))
    except OSError as exc:
        return FlushResult("dnsdist", "all", None, False, f"could not touch compiled config to trigger reload: {exc}")
    state_path.write_text(str(now))
    return FlushResult("dnsdist", "all", None, True, "dnsdist reload triggered; packet cache will be cleared")
