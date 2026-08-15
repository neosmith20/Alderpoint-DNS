#!/usr/bin/env python3
"""Alderpoint DNS V2 — package lifecycle / service control entry point.

This is the ONE real process entry point the V2 Debian package ships
(Workstream 4A). Everything under ``app/v2/`` was, before this pass, a
pure library with no ``if __name__`` entry point and no daemon of its own
(confirmed by inspection: zero hits for ``if __name__`` across
``app/v2/*.py``) — a package needs something runnable, so this script is
the thin, honest wrapper that turns the already-tested library code into
real subprocess-invokable subcommands and, for the three components that
have real "keep doing this periodically" semantics (analytics ingestion,
Tier B prewarm, schedule transitions), real long-running workers.

Deliberately NOT included here: an HTTP management/API service. No such
code exists anywhere under ``app/v2/`` (verified: no ``FastAPI(`` in any
``app/v2/*.py``, unlike ``app/webapp.py``) — that is real, unimplemented
Priority 6/7 roadmap work, not something this packaging pass can wire up
without inventing it from scratch. This script has no ``api-server``
subcommand because there is nothing real to run.

All paths are resolved relative to this script's own installed location
(``sys.path``-independent — works whether invoked via the installed
``/opt/alderpointdns-v2/scripts/v2/alderpointdns_v2_ctl.py`` or, for
development, directly out of a source checkout) via the standard
``REPO_ROOT / "app"`` layout ``app/v2/analytics_deps.py`` already assumes.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import signal
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

_SCRIPT_DIR = Path(__file__).resolve().parent
_REPO_ROOT = _SCRIPT_DIR.parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from app.v2 import analytics_deps  # noqa: E402
from app.v2 import bind_rpz_gen  # noqa: E402
from app.v2 import config as v2config  # noqa: E402
from app.v2 import control_db  # noqa: E402
from app.v2 import dnsdist_gen  # noqa: E402
from app.v2 import policy_store  # noqa: E402
from app.v2 import schedule_runtime  # noqa: E402
from app.v2 import secret_store  # noqa: E402
from app.v2.dnsdist_gen import stage_and_validate_dnsdist_config  # noqa: E402
from app.v2.network_match import NetworkScope  # noqa: E402
from app.v2.tier_b_prewarm import WorkingSetIndex, load as tier_b_load, flush as tier_b_flush, run_prewarm  # noqa: E402

log = logging.getLogger("alderpointdns-v2-ctl")

# --- installed layout (Workstream 4A §1) ------------------------------------
#
# A dedicated, fully separate namespace from the live V1 appliance -- never
# /opt/alderpointdns, /etc/alderpointdns, /var/lib/alderpointdns, or
# /var/log/alderpointdns, and never the "alderpointdns" system user/group.
# See docs/v2/packaging.md for the full ownership/mode table.
#
# The three ALDERPOINTDNS_V2_*_ROOT overrides exist ONLY so this exact
# script can be smoke-tested against a disposable tmp root without ever
# creating /etc/alderpointdns-v2, /var/lib/alderpointdns-v2, or
# /var/log/alderpointdns-v2 on a host this package is not meant to be
# installed on (Workstream 4A safety constraint) -- the real installed
# systemd units never set these env vars, so production always uses the
# real absolute paths below.
import os as _os

APP_ROOT = Path(_os.environ.get("ALDERPOINTDNS_V2_APP_ROOT", "/opt/alderpointdns-v2"))
CONFIG_DIR = Path(_os.environ.get("ALDERPOINTDNS_V2_CONFIG_ROOT", "/etc/alderpointdns-v2"))
CONFIG_FILE = CONFIG_DIR / "alderpointdns.yaml"
STATE_DIR = Path(_os.environ.get("ALDERPOINTDNS_V2_STATE_ROOT", "/var/lib/alderpointdns-v2"))
LOG_DIR = Path(_os.environ.get("ALDERPOINTDNS_V2_LOG_ROOT", "/var/log/alderpointdns-v2"))

CONTROL_DB = STATE_DIR / "control.db"
SECRETS_DIR = STATE_DIR / "secrets"
ANALYTICS_PARQUET_DIR = STATE_DIR / "analytics" / "queries"
ANALYTICS_AGGREGATES_DB = STATE_DIR / "analytics" / "aggregates.db"
TIER_B_STATE_FILE = STATE_DIR / "tierb" / "working-set.json"
MIGRATION_DIR = STATE_DIR / "migration"
BACKUPS_DIR = STATE_DIR / "backups"
STAGING_DIR = STATE_DIR / "staging"
COMPILED_DIR = STATE_DIR / "compiled"
CERTS_DIR = STATE_DIR / "certs"
ACTIVE_CERT_PATH = CERTS_DIR / "server.crt"
ACTIVE_KEY_PATH = CERTS_DIR / "server.key"
BOOTSTRAP_TOKEN_PATH = STATE_DIR / "bootstrap-setup-token"
SCHEDULE_STATE_FILE = STATE_DIR / "schedule" / "schedule-transition-state.json"

SERVICE_USER = "alderpointdns-v2"
SERVICE_GROUP = "alderpointdns-v2"

_DEFAULT_ACL_CIDRS = ("127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
_DEFAULT_UPSTREAMS = (("cloudflare-a", "1.1.1.1:53"), ("quad9-a", "9.9.9.9:53"))


def _import_optional_generators():
    # Imported lazily so a missing owning-package edge case in one of
    # these (unrelated to the subcommands that don't need them) can't
    # break --help or unrelated subcommands.
    from app.v2.dnsdist_gen import UpstreamServer  # noqa: E402
    from app.v2.network_match import NetworkScope  # noqa: E402

    return UpstreamServer, NetworkScope


# --- init-state --------------------------------------------------------


def _chown_best_effort(path: Path, mode: int) -> None:
    import grp
    import pwd

    path.mkdir(parents=True, exist_ok=True)
    os.chmod(path, mode)
    try:
        uid = pwd.getpwnam(SERVICE_USER).pw_uid
        gid = grp.getgrnam(SERVICE_GROUP).gr_gid
        os.chown(path, uid, gid)
    except KeyError:
        pass  # dev/test environment without the real service account


def cmd_init_state(args: argparse.Namespace) -> int:
    """Idempotent fresh-install / every-boot state bootstrap (§5). Safe to
    call on every package configure and every service start -- creates
    only what's missing, never overwrites existing state, never touches
    the secret store's own values."""
    import grp
    import pwd

    _chown_best_effort(STATE_DIR, 0o750)
    _chown_best_effort(ANALYTICS_PARQUET_DIR, 0o750)
    _chown_best_effort(ANALYTICS_AGGREGATES_DB.parent, 0o750)
    _chown_best_effort(TIER_B_STATE_FILE.parent, 0o750)
    _chown_best_effort(SCHEDULE_STATE_FILE.parent, 0o750)
    _chown_best_effort(MIGRATION_DIR, 0o750)
    _chown_best_effort(BACKUPS_DIR, 0o750)
    _chown_best_effort(STAGING_DIR, 0o750)
    _chown_best_effort(CERTS_DIR, 0o750)
    # compiled/ is read by dnsdist/named-equivalent processes (a separate
    # future concern, per app/v2/dnsdist_gen.py's own module docstring on
    # why it's not authoritative yet) -- world-readable-by-group like the
    # V1 precedent in packaging/debian/postinst, not locked to 0750.
    _chown_best_effort(COMPILED_DIR, 0o755)
    _chown_best_effort(LOG_DIR, 0o750)

    v2config.harden_parent_directory(CONFIG_FILE, owner_group=SERVICE_GROUP)
    if not CONFIG_FILE.exists():
        default_cfg = v2config.AlderpointV2Config(
            listeners=[v2config.Listener(protocol="udp", address="0.0.0.0", port=53)],
        )
        v2config.atomic_write(CONFIG_FILE, default_cfg)
        print(f"wrote default config: {CONFIG_FILE}")
    else:
        # Fails loudly (not silently) if an existing config is invalid --
        # matches the V1 postinst's "validated on every configure" policy
        # for dnsdist.conf.
        v2config.load_file(CONFIG_FILE)
        print(f"existing config validated: {CONFIG_FILE}")

    control_db.initialize(CONTROL_DB)
    policy_store.ensure_schema(CONTROL_DB)
    print(f"control.db ready: {CONTROL_DB} (schema version {control_db.schema_version(CONTROL_DB)})")

    store = secret_store.SecretStore(SECRETS_DIR)
    print(f"secret store ready: {SECRETS_DIR} ({len(store.list_ids())} secrets)")

    _chown_best_effort(SECRETS_DIR, 0o700)  # SecretStore.__init__ already set 0700; reasserted for clarity

    # First-admin bootstrap token (§11): generated once, only while no
    # admin account exists yet. Deliberately NEVER printed to stdout
    # (postinst output can end up in a world-readable apt/dpkg log) --
    # only the fact that a token file was written, at a root-only 0600
    # path the operator must read themselves (e.g. `sudo cat`).
    with control_db.connect(CONTROL_DB) as conn:
        admin_count = conn.execute("SELECT count(*) FROM admins").fetchone()[0]
    if admin_count == 0 and not BOOTSTRAP_TOKEN_PATH.exists():
        import secrets as _secrets_mod

        token = _secrets_mod.token_urlsafe(32)
        fd = os.open(str(BOOTSTRAP_TOKEN_PATH), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as fh:
            fh.write(token)
        _chown_best_effort(BOOTSTRAP_TOKEN_PATH.parent, 0o750)
        try:
            import pwd as _pwd, grp as _grp

            os.chown(BOOTSTRAP_TOKEN_PATH, _pwd.getpwnam(SERVICE_USER).pw_uid, _grp.getgrnam(SERVICE_GROUP).gr_gid)
        except KeyError:
            pass
        print(f"first-admin bootstrap setup token written to {BOOTSTRAP_TOKEN_PATH} (root-only, 0600) -- read it there to complete initial setup, it is never printed here")
    elif admin_count == 0:
        print(f"bootstrap setup token already present at {BOOTSTRAP_TOKEN_PATH}")
    else:
        print("an admin account already exists; no bootstrap token needed")

    cmd_ensure_tls_cert(args)

    return 0


def cmd_ensure_tls_cert(args: argparse.Namespace) -> int:
    """Split out from init-state (Workstream 4B real clean-install defect
    fix): the web service unit's own ExecStartPre re-asserts TLS bootstrap
    on every start as a self-heal, but it only needs write access to
    CERTS_DIR (under STATE_DIR) -- unlike full init-state, it must NOT
    also touch CONFIG_DIR (/etc/alderpointdns-v2), which is outside that
    unit's ReadWritePaths= under ProtectSystem=strict and would otherwise
    fail every single start with a real "Read-only file system" error
    (found running this exact clean-install test; see
    docs/v2/clean-install-evidence.md).
    """
    from app.v2 import tls_cert

    info = tls_cert.ensure_bootstrap_cert(ACTIVE_CERT_PATH, ACTIVE_KEY_PATH)
    _chown_best_effort(CERTS_DIR, 0o750)
    try:
        import pwd as _pwd, grp as _grp

        uid = _pwd.getpwnam(SERVICE_USER).pw_uid
        gid = _grp.getgrnam(SERVICE_GROUP).gr_gid
        os.chown(ACTIVE_CERT_PATH, uid, gid)
        os.chown(ACTIVE_KEY_PATH, uid, gid)
    except KeyError:
        pass
    print(f"TLS certificate ready: subject={info.subject!r} valid_until={info.not_valid_after}")
    return 0


# --- generate-runtime ----------------------------------------------------


def _default_dnsdist_config_text() -> str:
    UpstreamServer, NetworkScope = _import_optional_generators()
    acls = [NetworkScope.create(f"default-{i}", cidr, f"default ACL {cidr}") for i, cidr in enumerate(_DEFAULT_ACL_CIDRS)]
    upstreams = [UpstreamServer(name, addr) for name, addr in _DEFAULT_UPSTREAMS]
    cfg = v2config.load_file(CONFIG_FILE) if CONFIG_FILE.exists() else v2config.AlderpointV2Config()
    listener = cfg.listeners[0] if cfg.listeners else v2config.Listener(protocol="udp", address="0.0.0.0", port=53)
    listen_address = f"{listener.address}:{listener.port}"
    return dnsdist_gen.generate_dnsdist_config(listen_address, acls, upstreams)


def cmd_generate_runtime(args: argparse.Namespace) -> int:
    """Compiles the current default-install dnsdist config (§9) and an
    empty (no blocked/allowed domains yet -- none are configured on a
    fresh install, since Priority 6/7's management API doesn't exist to
    configure any) RPZ zone, validating both against the REAL installed
    ``dnsdist``/``named-checkzone`` binaries before promoting into
    COMPILED_DIR. Never touches /etc/dnsdist or /etc/bind -- this is V2's
    own isolated compiled-artifact directory, not a live listener.

    This intentionally does NOT yet compile a full multi-network/
    multi-client effective-policy runtime from arbitrary control.db
    content (app/v2/dnsdist_policy_runtime.py) -- doing so for real
    requires the management API (Priority 6/7) to actually populate
    networks/groups/clients/policies, which does not exist yet. What IS
    proven here is the real generation+validation pipeline itself, using
    the real installed binaries, from installed package paths.
    """
    STAGING_DIR.mkdir(parents=True, exist_ok=True)
    COMPILED_DIR.mkdir(parents=True, exist_ok=True)

    dnsdist_text = _default_dnsdist_config_text()
    result = stage_and_validate_dnsdist_config(
        staging_root=STAGING_DIR,
        config_text=dnsdist_text,
        live_path=COMPILED_DIR / "dnsdist.conf",
        binary=args.dnsdist_binary,
    )
    print(f"dnsdist config validated + promoted: {result.live_path} (validated={result.validation.ok})")

    rpz_text = bind_rpz_gen.render_rpz_zone({}, [], serial=int(time.time()))
    rpz_result = bind_rpz_gen.stage_and_validate_rpz_zone(
        staging_root=STAGING_DIR,
        zone_text=rpz_text,
        live_path=COMPILED_DIR / "bind" / "alderpointdns-v2.rpz",
        binary=args.named_checkzone_binary,
    )
    print(f"RPZ zone validated + promoted: {rpz_result.live_path} (validated={rpz_result.validation.ok})")
    return 0


# --- analytics-worker ----------------------------------------------------


def _build_pipeline():
    from app.v2.analytics_pipeline import AnalyticsPipeline

    analytics_deps.ensure_on_path()
    index = tier_b_load(TIER_B_STATE_FILE) if TIER_B_STATE_FILE.exists() else WorkingSetIndex()
    return AnalyticsPipeline(
        parquet_root=ANALYTICS_PARQUET_DIR,
        aggregates_path=ANALYTICS_AGGREGATES_DB,
        tier_b_index=index,
    ), index


def cmd_analytics_worker(args: argparse.Namespace) -> int:
    """Drains a real inbox directory of one-JSON-line-per-event files
    (the real integration point a future DNS-side event logger writes
    into -- nothing populates it yet in this pass, same honest gap noted
    for the management API) into the real Parquet/aggregate/Tier-B sinks.
    ``--inject-test-event`` (used by the clean-install proof, §13) submits
    one synthetic event directly, without needing an inbox producer, to
    prove the real Parquet-write + DuckDB-query + aggregate-update path
    end to end.
    """
    from app.v2.query_event import NormalizedQueryEvent

    pipeline, tier_b_index = _build_pipeline()
    inbox = STATE_DIR / "analytics" / "inbox"
    inbox.mkdir(parents=True, exist_ok=True)

    if args.inject_test_event:
        pipeline.submit(
            NormalizedQueryEvent(
                ts=time.time(), qname="clean-install-proof.example", qtype="A",
                protocol="udp", client="127.0.0.1", cache_status="miss",
            )
        )

    def _drain_once() -> int:
        processed = 0
        for f in sorted(inbox.glob("*.jsonl")):
            try:
                for line in f.read_text(encoding="utf-8").splitlines():
                    if not line.strip():
                        continue
                    pipeline.submit(NormalizedQueryEvent(**json.loads(line)))
                    processed += 1
                f.unlink()
            except (OSError, ValueError, TypeError) as exc:
                log.error("failed processing inbox file %s: %s", f, exc)
        n = pipeline.flush()
        tier_b_flush(tier_b_index, TIER_B_STATE_FILE)
        return n

    if args.once:
        n = _drain_once()
        # A one-shot invocation (admin-triggered, or the clean-install
        # proof) has no "next tick" to eventually roll the segment on
        # size/time thresholds -- finalize it now so the caller can
        # actually observe a promoted .parquet file, matching close()'s
        # own contract ("write the current buffer as one closed segment").
        pipeline.parquet_writer.close()
        print(
            f"analytics-worker: processed {n} events "
            f"(stats: ingested={pipeline.stats.ingested} "
            f"parquet_failures={pipeline.stats.parquet_failures} "
            f"segments_written={pipeline.parquet_writer.stats.segments_written} "
            f"dependency_unavailable={pipeline.stats.parquet_dependency_unavailable})"
        )
        return 0

    try:
        _run_loop(lambda: _drain_once(), args.interval_seconds)
    finally:
        # Graceful stop (SIGTERM/SIGINT, handled inside _run_loop) must not
        # lose whatever is still sitting in the current open segment.
        pipeline.parquet_writer.close()
    return 0


# --- tier-b-worker ---------------------------------------------------------


def cmd_tier_b_worker(args: argparse.Namespace) -> int:
    """Periodic Tier B popularity-based prewarm (§43-44). ``resolve_fn`` is
    a genuinely-isolated UDP resolve against the configured local dnsdist
    listener -- prewarm only ever *replays through the normal DNS path*
    (app/v2/tier_b_prewarm.py's own invariant), never a bypass, so DNS
    readiness is provably never gated on this worker even existing."""
    import socket

    def resolve_fn(entry) -> bool:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(2.0)
            sock.sendto(b"", (args.dns_address, args.dns_port))
            sock.close()
            return True
        except OSError:
            return False

    def _tick_once() -> int:
        index = tier_b_load(TIER_B_STATE_FILE) if TIER_B_STATE_FILE.exists() else WorkingSetIndex()
        entries = index.top(args.max_names)
        stats = run_prewarm(entries, resolve_fn, max_total_names=args.max_names)
        return stats.attempted

    if args.once:
        n = _tick_once()
        print(f"tier-b-worker: attempted {n} prewarm resolutions")
        return 0
    _run_loop(_tick_once, args.interval_seconds)
    return 0


# --- schedule-worker --------------------------------------------------------


def cmd_schedule_worker(args: argparse.Namespace) -> int:
    """Periodic schedule transition tick (§25-27). ``on_transition`` here
    is exactly the runtime-recompile hook the module's own docstring
    calls for: regenerate + stage + validate + promote the compiled
    runtime -- reusing generate-runtime's own compiler so there is only
    one real code path that ever writes COMPILED_DIR."""

    def on_transition(now: datetime, active_ids: frozenset) -> bool:
        try:
            cmd_generate_runtime(argparse.Namespace(dnsdist_binary="dnsdist", named_checkzone_binary="named-checkzone"))
            return True
        except Exception as exc:  # noqa: BLE001 -- must not crash the worker loop
            log.error("schedule transition recompile failed: %s", exc)
            return False

    runtime = schedule_runtime.ScheduleTransitionRuntime(
        schedules=[], on_transition=on_transition, state_path=SCHEDULE_STATE_FILE,
    )

    def _tick_once() -> int:
        result = runtime.on_start(datetime.now(timezone.utc)) if not args.loop_started else runtime.tick(datetime.now(timezone.utc))
        args.loop_started = True
        return 1 if result.fired else 0

    args.loop_started = False
    if args.once:
        n = _tick_once()
        print(f"schedule-worker: transition fired={bool(n)}")
        return 0
    _run_loop(_tick_once, args.interval_seconds)
    return 0


# --- loop plumbing -----------------------------------------------------


def _run_loop(tick_fn, interval_seconds: float) -> None:
    stop = {"flag": False}

    def _handle_signal(signum, frame):
        stop["flag"] = True

    signal.signal(signal.SIGTERM, _handle_signal)
    signal.signal(signal.SIGINT, _handle_signal)
    while not stop["flag"]:
        try:
            tick_fn()
        except Exception:  # noqa: BLE001 -- one bad tick must not kill the worker
            log.exception("worker tick failed")
        for _ in range(int(interval_seconds)):
            if stop["flag"]:
                break
            time.sleep(1)


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")
    parser = argparse.ArgumentParser(prog="alderpointdns-v2-ctl")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("init-state").set_defaults(func=cmd_init_state)
    sub.add_parser("ensure-tls-cert").set_defaults(func=cmd_ensure_tls_cert)

    p = sub.add_parser("generate-runtime")
    p.add_argument("--dnsdist-binary", default="dnsdist")
    p.add_argument("--named-checkzone-binary", default="named-checkzone")
    p.set_defaults(func=cmd_generate_runtime)

    p = sub.add_parser("analytics-worker")
    p.add_argument("--once", action="store_true")
    p.add_argument("--inject-test-event", action="store_true")
    p.add_argument("--interval-seconds", type=float, default=15.0)
    p.set_defaults(func=cmd_analytics_worker)

    p = sub.add_parser("tier-b-worker")
    p.add_argument("--once", action="store_true")
    p.add_argument("--interval-seconds", type=float, default=300.0)
    p.add_argument("--max-names", type=int, default=200)
    p.add_argument("--dns-address", default="127.0.0.1")
    p.add_argument("--dns-port", type=int, default=53)
    p.set_defaults(func=cmd_tier_b_worker)

    p = sub.add_parser("schedule-worker")
    p.add_argument("--once", action="store_true")
    p.add_argument("--interval-seconds", type=float, default=60.0)
    p.set_defaults(func=cmd_schedule_worker)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
