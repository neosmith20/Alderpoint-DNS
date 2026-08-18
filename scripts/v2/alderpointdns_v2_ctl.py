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
import socket
import sqlite3
import struct
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

_SCRIPT_DIR = Path(__file__).resolve().parent
_REPO_ROOT = _SCRIPT_DIR.parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from app import dnsdist_upgrade  # noqa: E402
from app.v2 import analytics_deps  # noqa: E402
from app.v2 import bind_rpz_gen  # noqa: E402
from app.v2 import config as v2config  # noqa: E402
from app.v2 import control_db  # noqa: E402
from app.v2 import dnsdist_gen  # noqa: E402
from app.v2 import dnsdist_protobuf  # noqa: E402
from app.v2 import policy_store  # noqa: E402
from app.v2 import node_identity  # noqa: E402
from app.v2 import observed_clients  # noqa: E402
from app.v2 import replication_v2  # noqa: E402
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
REPLICATION_DIR = STATE_DIR / "replication"
REPLICATION_SERVER_CERT_PATH = REPLICATION_DIR / "server.crt"
REPLICATION_SERVER_KEY_PATH = REPLICATION_DIR / "server.key"
REPLICATION_CA_PATH = REPLICATION_DIR / "trust-ca.pem"
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


def _require_root() -> None:
    if os.geteuid() != 0:
        print("alderpointdns-v2-ctl: must be run as root (try: sudo alderpointdns-v2-ctl ...)", file=sys.stderr)
        raise SystemExit(1)


def cmd_install_enhanced_dnsdist(args: argparse.Namespace) -> int:
    """V2's own real entry point for the same opt-in, root-only PowerDNS-
    repository dnsdist 2.1 installer V1's ``alderpointdns install-
    enhanced-dnsdist`` already uses (``app.dnsdist_upgrade``, reused
    verbatim, not reimplemented) -- closes the DoQ/DoH3 confirmed
    mandatory-parity gap's real environment blocker (docs/v2/
    doh3-transport-implemented.md): the stock Debian archive dnsdist
    (1.9.x) has no QUIC support, and this is the only safe, maintainable
    way to get a build that does, without silently changing every V2
    appliance's default trust base the way a hard package Depends bump
    would. This installs dnsdist CAPABILITY only -- V2's own DoQ/DoH3
    admin toggles (PUT /api/dns-transports) still start out disabled and
    must be explicitly turned on afterward."""
    _require_root()
    try:
        report = dnsdist_upgrade.install_enhanced_dnsdist()
    except dnsdist_upgrade.UpgradeError as exc:
        print(f"alderpointdns-v2-ctl install-enhanced-dnsdist: FAILED\n{exc}", file=sys.stderr)
        return 1
    for step in report.steps:
        print(f"- {step}")
    print()
    if report.already_satisfied:
        print(
            f"Already satisfied: dnsdist {report.version_before} already has dns-over-quic "
            "and dns-over-http3 capability. Nothing changed."
        )
    else:
        print(f"dnsdist version: {report.version_before} -> {report.version_after}")
        print(f"dns-over-quic capability:  {report.capabilities_before.get('doq')} -> {report.capabilities_after.get('doq')}")
        print(f"dns-over-http3 capability: {report.capabilities_before.get('doh3')} -> {report.capabilities_after.get('doh3')}")
        print(f"backup of prior /etc/dnsdist, dnsdist.service.d, and certs: {report.backup_path}")
    print()
    print("This installed dnsdist CAPABILITY only. DoQ and DoH3 are still disabled in")
    print("Alderpoint DNS V2 -- turn them on via PUT /api/dns-transports (or the admin UI)")
    print("to start the real listeners.")
    return 0


def cmd_dnsdist_capabilities(args: argparse.Namespace) -> int:
    report = dnsdist_upgrade.capabilities_report()
    print(f"dnsdist version: {report['version']}")
    print(f"source/origin:   {report['origin']}")
    for label, key in (("DoH", "doh"), ("DoT", "dot"), ("DoQ", "doq"), ("DoH3", "doh3"), ("DNSCrypt", "dnscrypt")):
        print(f"{label:9s}: {'supported' if report[key] else 'not supported'}")
    return 0


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
    _chown_best_effort(REPLICATION_DIR, 0o750)
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
    node_identity.ensure_schema(CONTROL_DB)
    observed_clients.ensure_schema(CONTROL_DB)
    replication_v2.ensure_schema(CONTROL_DB)
    with control_db.connect(CONTROL_DB) as conn:
        ident = node_identity.get_or_create(conn)
    print(f"node identity ready: {ident.node_id}")
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


def cmd_init_replication_cert(args: argparse.Namespace) -> int:
    """Create a local private CA + node certificate for replication mTLS if
    absent. Operators may replace these with administrator-managed trust
    through the API; this bootstrap never overwrites known-good material.
    """
    REPLICATION_DIR.mkdir(parents=True, exist_ok=True)
    if REPLICATION_SERVER_CERT_PATH.exists() and REPLICATION_SERVER_KEY_PATH.exists() and REPLICATION_CA_PATH.exists():
        print(f"replication TLS material already present: {REPLICATION_DIR}")
        return 0
    replication_v2.ensure_schema(CONTROL_DB)
    with control_db.connect(CONTROL_DB) as conn:
        ident = node_identity.get_or_create(conn)
    ca_pem, ca_key_pem = replication_v2.generate_private_ca(f"apdns-v2-ca-{ident.node_id}")
    cert_pem, key_pem = replication_v2.issue_node_cert(ca_pem, ca_key_pem, ident.node_id, server_name="localhost")
    # Persist the CA private key (protected the same way every other
    # sensitive secret this appliance holds is) so this node can later
    # issue additional certs signed by its own CA for real peer
    # enrollment -- see replication_v2.REPLICATION_CA_KEY_SECRET_ID's
    # docstring for the real gap this closes (previously discarded
    # immediately after signing this node's own server cert, which meant
    # no tool could ever establish trust with a second, independent node).
    try:
        secret_store.SecretStore(SECRETS_DIR).create(ca_key_pem, secret_id=replication_v2.REPLICATION_CA_KEY_SECRET_ID)
    except secret_store.SecretStoreError:
        pass  # already present -- do not overwrite known-good key material
    fd = os.open(REPLICATION_CA_PATH, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(ca_pem)
    fd = os.open(REPLICATION_SERVER_CERT_PATH, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(cert_pem)
    fd = os.open(REPLICATION_SERVER_KEY_PATH, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(key_pem)
    _chown_best_effort(REPLICATION_DIR, 0o750)
    print(f"replication TLS material created: node_id={ident.node_id} fingerprint={replication_v2.cert_fingerprint_sha256(cert_pem)}")
    return 0


def cmd_issue_peer_cert(args: argparse.Namespace) -> int:
    """Real replication peer-enrollment step (previously missing entirely
    -- see replication_v2.REPLICATION_CA_KEY_SECRET_ID's docstring):
    issues a cert signed by THIS node's own replication CA for
    ``args.remote_node_id`` to use as its client cert when connecting to
    THIS node. Prints everything the *other* node's administrator needs
    to paste into that node's peer record for this one
    (``PUT /api/replication/peers/{this node's id}``): this node's own
    ca_pem, this node's own server-cert fingerprint, the freshly issued
    client cert+key, and that cert's own fingerprint -- to stdout by
    default, or to --out (a single JSON file) for scripted enrollment.

    One bundle only covers ONE direction (the remote node pushing to
    THIS node). For a real bidirectional peer relationship, run this
    command on BOTH nodes (each issuing a cert for the OTHER) and
    combine fields from both bundles into each node's own peer record:
    a node's own peer-record-for-the-other needs the OTHER bundle's
    ca_pem/expected_cert_sha256/client_cert_pem/client_key_pem (to call
    out) *plus* THIS bundle's issued_cert_sha256 as its own
    expected_incoming_cert_sha256 (to validate the other node's incoming
    push) -- see replication_v2.upsert_peer's docstring for exactly why
    these are two different real certificates, not the same value
    twice. direction="push" only needs one bundle and doesn't require
    this.
    """
    if not REPLICATION_CA_PATH.exists() or not REPLICATION_SERVER_CERT_PATH.exists():
        print("replication TLS material not initialized on this node -- run init-replication-cert first", file=sys.stderr)
        return 1
    ca_pem = REPLICATION_CA_PATH.read_text(encoding="utf-8")
    with control_db.connect(CONTROL_DB) as conn:
        ident = node_identity.get_or_create(conn)
    try:
        cert_pem, key_pem = replication_v2.issue_peer_client_cert(
            secret_store.SecretStore(SECRETS_DIR), ca_pem, args.remote_node_id, server_name=args.server_name
        )
    except replication_v2.ReplicationEnrollmentError as exc:
        print(f"cannot issue peer cert: {exc}", file=sys.stderr)
        return 1
    bundle = {
        "this_node_id": ident.node_id,
        "issued_for_node_id": args.remote_node_id,
        "ca_pem": ca_pem,
        "expected_cert_sha256": replication_v2.cert_fingerprint_sha256(REPLICATION_SERVER_CERT_PATH.read_text(encoding="utf-8")),
        "client_cert_pem": cert_pem,
        "client_key_pem": key_pem,
        "issued_cert_sha256": replication_v2.cert_fingerprint_sha256(cert_pem),
    }
    if args.out:
        Path(args.out).write_text(json.dumps(bundle, indent=2), encoding="utf-8")
        os.chmod(args.out, 0o600)
        print(f"enrollment bundle written to {args.out} -- copy it to {args.remote_node_id}'s administrator, "
              f"who pastes ca_pem/expected_cert_sha256/client_cert_pem/client_key_pem into "
              f"PUT /api/replication/peers/{ident.node_id} on that node (direction='push'); for a "
              f"bidirectional relationship they also need this bundle's issued_cert_sha256 as THEIR "
              f"own peer-record-for-{ident.node_id}'s expected_incoming_cert_sha256 -- see this "
              f"command's own --help/docstring")
    else:
        print(json.dumps(bundle, indent=2))
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


# --- migrate ---------------------------------------------------------------


def cmd_migrate(args: argparse.Namespace) -> int:
    """The real, package-invokable V1 -> V2 migration entry point.

    Previously ``app/v2/migration.py``'s full pipeline (detect -> backup ->
    preview -> per-object migrate -> generate_runtime_config -> validate ->
    health_check -> commit) existed only as a library other tests called
    directly -- no CLI command, no API route, no way for a real installed
    package to actually run it. This closes that gap: `migrate` runs the
    staging pipeline (resuming from ``MIGRATION_DIR/state.json`` if a prior
    run left one, exactly like the durable-state tests exercise) and, on
    ``--promote``, calls ``app.v2.migration.promote_to_live`` to write the
    result onto this host's real live V2 paths. Without ``--promote`` the
    command only stages and reports -- safe to run repeatedly to preview.
    """
    from app.v2 import migration as mig
    from app.v2 import migration_state as mstate

    source_path = Path(args.source)
    staging_dir = MIGRATION_DIR / "staging"
    state_path = MIGRATION_DIR / "state.json"
    MIGRATION_DIR.mkdir(parents=True, exist_ok=True)

    existing = mstate.load(state_path)
    if existing is not None and existing.source_path == str(source_path):
        print(f"resuming migration {existing.migration_id} (status={existing.status})")
        record = existing
        resume_state = mig.resume_state_from_durable_record(existing)
    else:
        record = mstate.MigrationRecord.new(
            source_version="1.1.1", target_version=f"v2-config-schema-{v2config.CONFIG_SCHEMA_VERSION}",
            staging_dir=str(staging_dir), source_path=str(source_path),
        )
        resume_state = None

    try:
        state = mig.run_migration(
            source_path, staging_dir, resume_state=resume_state,
            durable_record=record, state_path=state_path,
        )
    except mig.MigrationError as exc:
        print(f"migration FAILED at stage {exc.args[0] if exc.args else '?'}: {exc}", file=sys.stderr)
        return 1

    print(f"migration staged and committed: {state.object_counts}")
    for warning in state.warnings:
        print(f"WARNING: {warning}")

    if not args.promote:
        print("staged only (pass --promote to write this onto the live install)")
        return 0

    try:
        promoted = mig.promote_to_live(
            state,
            live_control_db=CONTROL_DB,
            live_secrets_dir=SECRETS_DIR,
            live_compiled_dir=COMPILED_DIR,
            live_listen_address=args.live_listen_address,
            dnsdist_binary=args.dnsdist_binary,
            named_checkzone_binary=args.named_checkzone_binary,
            allow_overwrite=args.allow_overwrite,
        )
    except mig.PromotionError as exc:
        print(f"promotion FAILED (staged migration is intact and retryable): {exc}", file=sys.stderr)
        return 1

    print(f"promoted onto live install: {promoted}")
    print("reload the affected services (e.g. via the dnsdist-reload path unit / "
          "systemctl restart alderpointdns-v2-web) to pick up the promoted state")
    return 0


# --- generate-runtime ----------------------------------------------------


def _configured_listen_address() -> str:
    """The real appliance-configured DNS listen address ("host:port").
    Shared by the install-time bootstrap dnsdist config and the
    replication server's post-apply recompile -- both need the real
    configured listener, not runtime_compile.recompile_and_promote()'s
    own loopback-only default (see webapp.py's identical helper for the
    live policy-mutation path's version of this same requirement)."""
    cfg = v2config.load_file(CONFIG_FILE) if CONFIG_FILE.exists() else v2config.AlderpointV2Config()
    listener = cfg.listeners[0] if cfg.listeners else v2config.Listener(protocol="udp", address="0.0.0.0", port=53)
    return f"{listener.address}:{listener.port}"


def _default_dnsdist_config_text() -> str:
    UpstreamServer, NetworkScope = _import_optional_generators()
    acls = [NetworkScope.create(f"default-{i}", cidr, f"default ACL {cidr}") for i, cidr in enumerate(_DEFAULT_ACL_CIDRS)]
    upstreams = [UpstreamServer(name, addr) for name, addr in _DEFAULT_UPSTREAMS]
    return dnsdist_gen.generate_dnsdist_config(_configured_listen_address(), acls, upstreams)


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


def _effective_flags_for_client(conn, client_ip: str, now):
    """Resolves the real effective (query_log_enabled, statistics_enabled,
    cache_profile_id, policy, client_name) for a client IP, via the same
    control.db policy chain (client -> group -> network -> global) the
    rest of V2 already uses -- closes the real gap where every event from the
    analytics-protobuf-receiver was unconditionally logged regardless of
    a per-client exclusion an admin had actually configured. An IP that
    doesn't match any registered client still gets a real answer
    (network/global layers only, per compile_effective_policy's own
    client_layer=None support), not a hardcoded default. ``policy`` (the
    compiled ``EffectivePolicy``, or ``None`` for the excluded prewarm
    identity) is returned so the caller can also resolve a real
    per-qname blocked/allowed/rewritten decision (see
    ``_action_for_event``) without a second, separate policy compile.

    Real defect found live during the RC13/RC14/RC15 continuation
    (docs/v2/cache-profile-id-not-populated-fix.md): every real
    dnsdist-sourced analytics event's ``cache_profile_id`` was always
    "" -- a real, admin-facing filterable/sortable query-log column
    (app/v2/analytics_query.py's ``_FILTERABLE_COLUMNS``/
    ``_SORTABLE_COLUMNS``) that was silently non-functional for all
    real traffic, even though the exact machinery to compute it
    correctly (``compile_cache_profile``) was already one call away
    from the policy object this function already compiles for the
    query-log/statistics flags. Now resolved here too, in the same
    single per-client policy compile, rather than left blank.

    The appliance's own Tier B prewarm traffic (see
    app/v2/tier_b_worker.py's PREWARM_SOURCE_IP) is excluded here
    unconditionally, not via the normal policy chain -- it is an
    architectural invariant (self-generated cache-warming traffic is
    never a real client's activity), not something an admin's network/
    client policy should need to know to configure correctly.
    """
    from app.v2.tier_b_worker import PREWARM_SOURCE_IP

    if client_ip == PREWARM_SOURCE_IP:
        return False, False, "", None, ""

    from app.v2 import policy_service
    from app.v2.policy_compiler import compile_cache_profile, compile_effective_policy

    client_id = observed_clients.managed_client_for_ip(conn, client_ip)
    client_name = ""
    if client_id is not None:
        policy = policy_service.compile_effective_policy_from_store(
            conn, policy_service.ClientResolutionContext(client_id=client_id, client_ip=client_ip), now=now
        )
        # Real defect found in the same pass as cache_profile_id/action/
        # upstream_profile_id: client_name (a real projectable/sortable
        # query-log column, app/v2/analytics_query.py) was also always
        # left blank for every real event with a registered client --
        # the client_id needed to look it up was already resolved right
        # here and simply never used for this.
        row = conn.execute("SELECT name FROM clients WHERE id=?", (client_id,)).fetchone()
        if row is not None:
            client_name = row[0]
    else:
        global_layer = policy_store.load_policy_layer(conn, "global", "singleton")
        network_layer = None
        network_source = None
        match = policy_store.load_network_table(conn).match(client_ip)
        if match is not None:
            network_layer = policy_store.load_policy_layer(conn, "network", match.network_id)
            network_source = match.network_id
        policy = compile_effective_policy(
            global_layer=global_layer, network_layer=network_layer, network_source=network_source
        )
    cache_profile_id = compile_cache_profile(policy).profile_id
    return policy.query_log_enabled, policy.statistics_enabled, cache_profile_id, policy, client_name


def _action_for_event(conn, policy, qname: str) -> tuple[str, str]:
    """Resolves the real (action, block_reason) for one event's qname
    against its client's already-compiled effective policy.

    Real defect found live during the RC13-RC16 continuation
    (docs/v2/blocked-action-not-populated-fix.md): every real
    dnsdist-sourced analytics event defaulted to
    ``action="allowed"``/``block_reason=""`` unconditionally --
    app/v2/filtering_decision.py's ``evaluate_filtering`` (the real,
    tested "why was this blocked" decision engine §47 calls for) was
    never actually invoked anywhere in production. Confirmed live:
    blocking is enforced entirely via terminal dnsdist actions
    (SpoofAction/RCodeAction, see app/v2/dnsdist_policy_runtime.py) --
    the same terminally-answered shape as local-DNS/SafeSearch, so a
    genuinely blocked query was silently logged as "allowed" with
    whatever rcode the spoofed answer carried (real live evidence: the
    entire "blocked queries" dashboard was non-functional for real
    traffic). ``app/v2/bind_rpz_gen.py``'s RPZ zone is confirmed always
    empty in the real running system (``cmd_generate_runtime`` calls
    ``render_rpz_zone({}, [], ...)`` unconditionally) -- all real
    blocking, including migrated V1 custom block/allow lists
    (``app/v2/migration_convert.py``'s ``migrate_filtering_to_control_db``),
    goes through the same ``service_definitions``/``service_domains``
    mechanism ``evaluate_filtering`` already reads, so this is the
    complete real decision source, not a partial one.

    Fails safe: any error here defaults to ("allowed", "") rather than
    risking a false "blocked" classification or crashing the drain
    loop over one malformed qname.
    """
    if policy is None:
        return "allowed", ""
    from app.v2.filtering_decision import evaluate_filtering

    try:
        decision = evaluate_filtering(conn, policy, qname)
    except Exception:
        log.exception("filtering decision failed for qname %s, defaulting to allowed", qname)
        return "allowed", ""
    if decision.action == "blocked":
        return "blocked", decision.reason
    return decision.action, ""


def cmd_analytics_worker(args: argparse.Namespace) -> int:
    """Drains a real inbox directory of one-JSON-line-per-event files --
    fed by the real analytics-protobuf-receiver service for real DNS
    traffic through the packaged dnsdist runtime (see
    docs/v2/analytics-ingestion-not-wired-to-live-dns.md for the gap
    that closed) -- into the real Parquet/aggregate/Tier-B sinks.
    ``--inject-test-event`` (used by the clean-install proof, §13) submits
    one synthetic event directly, without needing an inbox producer, to
    prove the real Parquet-write + DuckDB-query + aggregate-update path
    end to end.

    Real per-client query_log_enabled/statistics_enabled exclusions are
    resolved here (not in the receiver, which stays a lightweight,
    control.db-independent TCP sink by design) against the real
    effective policy chain for each event's client IP, cached per
    client IP for the duration of one drain cycle -- a real
    control.db-backed policy compile per unique client, not per event,
    since the same handful of clients repeat constantly in real
    traffic.
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
        flag_cache: dict[str, tuple[bool, bool]] = {}
        # Real regression found live during RC9 clean-install acceptance
        # testing: this service's systemd unit (like every other V2
        # worker) is deliberately hardened with ProtectSystem=strict and
        # a narrow ReadWritePaths= that never included control.db --
        # this worker never touched it before this session's per-client
        # policy-exclusion feature. control_db.connect()'s unconditional
        # `PRAGMA journal_mode = WAL` needs to create/write real -wal/
        # -shm sibling files in control.db's own directory --
        # ProtectSystem=strict blocked that outside ReadWritePaths,
        # "unable to open database file" every single drain tick.
        # First attempt at a fix used a real SQLite read-only URI
        # connection (mode=ro) hoping to avoid needing write access at
        # all -- confirmed live this does NOT work: a genuine SQLite WAL
        # constraint means even a read-only connection to a database
        # another process holds open in WAL mode still needs write
        # access to that database's own -shm locking file, so mode=ro
        # alone still failed identically. Real fix: the packaged systemd
        # unit's ReadWritePaths now covers the whole state directory,
        # matching the web/discovery services (which genuinely write
        # control.db) -- this worker still only ever reads it, connected
        # read-only at the SQLite level below as real defense in depth
        # (this process cannot execute a write against control.db's
        # actual tables even though the OS layer now permits the -shm
        # write SQLite's WAL locking requires).
        conn = None
        if CONTROL_DB.exists():
            try:
                conn = sqlite3.connect(f"file:{CONTROL_DB}?mode=ro", uri=True)
            except sqlite3.Error:
                log.exception("could not open control.db read-only for policy lookups; logging everything")
        try:
            now = datetime.now(timezone.utc)
            for f in sorted(inbox.glob("*.jsonl")):
                try:
                    for line in f.read_text(encoding="utf-8").splitlines():
                        if not line.strip():
                            continue
                        record = json.loads(line)
                        client_ip = record.get("client", "")
                        if client_ip and conn is not None:
                            if client_ip not in flag_cache:
                                try:
                                    flag_cache[client_ip] = _effective_flags_for_client(conn, client_ip, now)
                                except Exception:
                                    log.exception("policy lookup failed for client %s, defaulting to logged", client_ip)
                                    flag_cache[client_ip] = (True, True, "", None, "")
                            log_enabled, stats_enabled, cache_profile_id, policy, client_name = flag_cache[client_ip]
                            record.setdefault("query_log_enabled", log_enabled)
                            record.setdefault("statistics_enabled", stats_enabled)
                            record.setdefault("effective_cache_profile_id", cache_profile_id)
                            record.setdefault("client_name", client_name)
                            action, block_reason = _action_for_event(conn, policy, record.get("qname", ""))
                            record.setdefault("action", action)
                            record.setdefault("block_reason", block_reason)
                            # Real defect found live in the same pass as
                            # cache_profile_id/action: upstream_profile_id
                            # (the "upstream" filterable query-log column,
                            # app/v2/analytics_query.py) was also always
                            # left blank for every real event, for the
                            # exact same reason -- the policy object was
                            # already compiled right here and simply never
                            # read for this field either.
                            record.setdefault("upstream_profile_id", policy.upstream_profile_id if policy else "")
                        pipeline.submit(NormalizedQueryEvent(**record))
                        processed += 1
                    f.unlink()
                except (OSError, ValueError, TypeError) as exc:
                    log.error("failed processing inbox file %s: %s", f, exc)
        finally:
            if conn is not None:
                conn.close()
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


def cmd_discovery_worker(args: argparse.Namespace) -> int:
    """Drains JSONL DNS-observation inbox files into bounded observed-client
    state. A DNS-side producer writes tiny records here; failures are
    recorded and never affect DNS answering.
    """
    observed_clients.ensure_schema(CONTROL_DB)
    inbox = STATE_DIR / "discovery" / "inbox"
    inbox.mkdir(parents=True, exist_ok=True)

    def _drain_once() -> int:
        processed = 0
        with control_db.connect(CONTROL_DB) as conn:
            for f in sorted(inbox.glob("*.jsonl")):
                try:
                    observations = []
                    for line in f.read_text(encoding="utf-8").splitlines():
                        if not line.strip():
                            continue
                        obj = json.loads(line)
                        observations.append(
                            observed_clients.Observation(
                                obj["source_ip"],
                                obj.get("hostname_candidate", ""),
                                obj.get("hostname_source", "dns"),
                                float(obj.get("ts", time.time())),
                            )
                        )
                    processed += observed_clients.apply_observations(conn, observations)
                    f.unlink()
                except Exception as exc:  # noqa: BLE001
                    log.error("failed processing discovery inbox file %s: %s", f, exc)
                    conn.execute("UPDATE observed_client_stats SET last_error=? WHERE id=1", (str(exc)[:512],))
        return processed

    if args.once:
        n = _drain_once()
        print(f"discovery-worker: processed {n} observations")
        return 0
    _run_loop(_drain_once, args.interval_seconds)
    return 0


def _parse_dns_qname(packet: bytes) -> tuple[str, int, int, bytes]:
    """Return qname/qtype/qclass/original-question for a simple DNS query.

    The observation ingress is intentionally small: it only needs enough DNS
    parsing to preserve the question in a valid response and optionally carry
    a bounded hostname candidate into discovery. Malformed packets raise
    ValueError and still receive a bounded FORMERR response.
    """
    if len(packet) < 12:
        raise ValueError("short dns packet")
    offset = 12
    labels: list[str] = []
    while True:
        if offset >= len(packet):
            raise ValueError("unterminated qname")
        ln = packet[offset]
        offset += 1
        if ln == 0:
            break
        if ln & 0xC0:
            raise ValueError("compressed qname not accepted in query")
        if ln > 63 or offset + ln > len(packet):
            raise ValueError("invalid qname label")
        labels.append(packet[offset : offset + ln].decode("ascii", "ignore"))
        offset += ln
    if offset + 4 > len(packet):
        raise ValueError("missing qtype/qclass")
    qtype, qclass = struct.unpack("!HH", packet[offset : offset + 4])
    return ".".join(labels), qtype, qclass, packet[12 : offset + 4]


def _dns_response(packet: bytes, *, rcode: int = 0) -> bytes:
    if len(packet) < 2:
        return b""
    txid = packet[:2]
    try:
        qname, qtype, qclass, question = _parse_dns_qname(packet)
    except ValueError:
        flags = 0x8000 | 0x0080 | 1
        return txid + struct.pack("!HHHHH", flags, 0, 0, 0, 0)
    flags_in = struct.unpack("!H", packet[2:4])[0] if len(packet) >= 4 else 0
    flags = 0x8000 | 0x0080 | (flags_in & 0x0100) | (rcode & 0xF)
    answers = b""
    ancount = 0
    if rcode == 0 and qclass == 1 and qtype == 1 and qname:
        # TEST-NET-1 answer; this observation-only ingress proves a real DNS
        # packet path without becoming the authoritative runtime.
        answers = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 30, 4) + socket.inet_aton("192.0.2.1")
        ancount = 1
    header = txid + struct.pack("!HHHHH", flags, 1, ancount, 0, 0)
    return header + question + answers


def _write_observation_batch(inbox: Path, observations: list[observed_clients.Observation]) -> None:
    if not observations:
        return
    inbox.mkdir(parents=True, exist_ok=True)
    tmp = inbox / f"dns-{int(time.time() * 1000)}-{os.getpid()}-{threading.get_ident()}.jsonl.tmp"
    final = tmp.with_suffix("")
    with tmp.open("w", encoding="utf-8") as fh:
        for obs in observations[:1024]:
            fh.write(json.dumps({
                "source_ip": obs.source_ip,
                "hostname_candidate": obs.hostname_candidate,
                "hostname_source": obs.hostname_source,
                "ts": obs.ts,
            }, separators=(",", ":")) + "\n")
    os.replace(tmp, final)


def _write_analytics_events_batch(inbox: Path, events: list[dict]) -> None:
    """Same atomic-write-then-rename pattern as
    _write_observation_batch -- a reader draining the inbox (see
    cmd_analytics_worker) never observes a partially-written file."""
    if not events:
        return
    inbox.mkdir(parents=True, exist_ok=True)
    tmp = inbox / f"pb-{int(time.time() * 1000)}-{os.getpid()}-{threading.get_ident()}.jsonl.tmp"
    final = tmp.with_suffix("")
    with tmp.open("w", encoding="utf-8") as fh:
        for event in events[:4096]:
            fh.write(json.dumps(event, separators=(",", ":")) + "\n")
    os.replace(tmp, final)


def _event_from_response(decoded: "dnsdist_protobuf.DecodedResponse") -> dict:
    return {
        "ts": decoded.ts, "qname": decoded.qname, "qtype": decoded.qtype,
        "protocol": decoded.protocol, "client": decoded.client, "rcode": decoded.rcode,
    }


def _event_from_unmatched_query(decoded: "dnsdist_protobuf.DecodedQuery", recent_answer: tuple[str, bool] | None = None) -> dict:
    # A query message with no matching response ever arrived within the
    # correlation window. Real, verified dnsdist 2.1.1 behavior confirmed
    # live during the RC13 continuation covers TWO distinct real cases
    # this shape can mean, not one:
    #
    # 1. A terminally-spoofed query (SpoofAction/SpoofCNAMEAction:
    #    blocked domains, SafeSearch, local DNS records) -- answers
    #    entirely within the query-processing stage and never produces a
    #    RemoteLogResponseAction event. Always NOERROR (a synthesized
    #    answer), which is what this function originally assumed
    #    unconditionally.
    # 2. A packet-cache HIT of a previously backend-resolved answer --
    #    live-verified (docs/v2/cache-hit-response-not-logged-rc13.md)
    #    that RemoteLogResponseAction *also* never fires for these, with
    #    a real repeated NXDOMAIN query proving the old NOERROR
    #    assumption is flatly wrong for this case: the real cached
    #    answer can be any rcode, not just NOERROR.
    #
    # dnsdist's protobuf stream gives no direct signal distinguishing
    # case 1 from case 2, and no rcode at all for case 2. ``recent_answer``
    # is this receiver's own bounded, best-effort memory of the last real
    # rcode seen for this exact (qname, qtype) from an actual
    # RemoteLogResponseAction event -- if present, this unmatched query
    # is almost certainly a real cache hit of that exact answer (case 2),
    # so its real rcode is reused and cache_status is honestly reported
    # as "hit" instead of silently defaulting to "miss". If no such
    # memory exists (a qname never seen answered before in this
    # receiver's process lifetime), this is either case 1 or an
    # unresolvable case-2 blind spot -- NOERROR remains the fallback,
    # which is correct for case 1 and merely honestly wrong (same as
    # before this fix) for the rare unresolvable case-2 instance.
    if recent_answer is not None:
        rcode, _is_cache = recent_answer
        return {
            "ts": decoded.ts, "qname": decoded.qname, "qtype": decoded.qtype,
            "protocol": decoded.protocol, "client": decoded.client, "rcode": rcode,
            "cache_status": "hit",
        }
    return {
        "ts": decoded.ts, "qname": decoded.qname, "qtype": decoded.qtype,
        "protocol": decoded.protocol, "client": decoded.client, "rcode": "NOERROR",
    }


# Bounds how long an in-flight query waits for its matching response
# before being flushed as an assumed-spoofed event, and how many
# in-flight queries a single connection tracks at once (defense against
# unbounded growth if responses are somehow never arriving at all --
# same bounded-queue principle as replication_v2.MAX_SEEN_MESSAGES /
# observed_clients.ObservationQueue elsewhere in this codebase).
_PENDING_QUERY_FLUSH_SECONDS = 2.0
_PENDING_QUERY_MAX = 8192

# Bounds the best-effort (qname, qtype) -> (rcode, monotonic insert time)
# memory used to recover the real rcode for a packet-cache-hit query
# (see _event_from_unmatched_query). Not a real TTL-accurate mirror of
# dnsdist's own packet cache -- just a bounded, honest heuristic that is
# strictly more accurate than always assuming NOERROR.
_QNAME_RCODE_CACHE_MAX = 4096
_QNAME_RCODE_CACHE_TTL_SECONDS = 3600.0


def cmd_analytics_protobuf_receiver(args: argparse.Namespace) -> int:
    """Real DNS-side event producer for analytics ingestion (roadmap
    Priority 6 continuation -- see
    docs/v2/analytics-ingestion-not-wired-to-live-dns.md for the real
    gap this closes: before this, nothing populated the analytics
    inbox for real traffic through the packaged dnsdist runtime at
    all). A real TCP server for dnsdist's real, native protobuf
    "remote logger" protocol (newRemoteLogger + RemoteLogAction +
    RemoteLogResponseAction, wired into the generated config by
    dnsdist_gen.py/dnsdist_policy_runtime.py) -- dnsdist connects to
    this as a client and streams one length-prefixed PBDNSMessage per
    query and, for backend-forwarded queries, a second one per
    response.

    Both hooks are read and correlated by the real DNS transaction id
    (verified identical between a real query message and its matching
    response message): a real response message is preferred when it
    arrives (has the real rcode); a query message with no matching
    response after a short window is assumed spoofed/locally-answered
    and flushed on its own -- see app/v2/dnsdist_protobuf.py's module
    docstring for the live verification this design is based on
    (RemoteLogResponseAction alone was found to never fire at all for
    blocked/SafeSearch/local-DNS answers).

    This is a passive, best-effort log sink: a malformed/undecodable
    message is logged and skipped, never raised past this function,
    and a receiver failure/crash cannot affect DNS answering -- dnsdist
    treats a remote logger it can't reach as fire-and-forget (per its
    own documented behavior) and keeps answering queries regardless.
    """
    inbox = STATE_DIR / "analytics" / "inbox"
    inbox.mkdir(parents=True, exist_ok=True)
    stop = {"flag": False}

    def _handle_signal(signum, frame):
        stop["flag"] = True

    signal.signal(signal.SIGTERM, _handle_signal)
    signal.signal(signal.SIGINT, _handle_signal)

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((args.host, args.port))
    server.listen(8)
    server.settimeout(0.5)
    print(f"analytics-protobuf-receiver: listening on {args.host}:{args.port}")

    def _handle_connection(conn: socket.socket) -> None:
        conn.settimeout(2.0)
        batch: list[dict] = []
        last_flush = time.monotonic()
        # (client, msg_id) -> (DecodedQuery, monotonic insert time)
        pending: dict[tuple[str, int], tuple["dnsdist_protobuf.DecodedQuery", float]] = {}
        # (qname, qtype) -> (rcode, monotonic insert time) -- see
        # _event_from_unmatched_query's docstring for why this exists.
        qname_rcode_cache: dict[tuple[str, str], tuple[str, float]] = {}

        def _remember_answer(decoded: "dnsdist_protobuf.DecodedResponse") -> None:
            if len(qname_rcode_cache) >= _QNAME_RCODE_CACHE_MAX:
                oldest_key = min(qname_rcode_cache, key=lambda k: qname_rcode_cache[k][1])
                qname_rcode_cache.pop(oldest_key, None)
            qname_rcode_cache[(decoded.qname, decoded.qtype)] = (decoded.rcode, time.monotonic())

        def _recent_answer_for(decoded: "dnsdist_protobuf.DecodedQuery") -> tuple[str, bool] | None:
            entry = qname_rcode_cache.get((decoded.qname, decoded.qtype))
            if entry is None:
                return None
            rcode, t0 = entry
            if time.monotonic() - t0 >= _QNAME_RCODE_CACHE_TTL_SECONDS:
                qname_rcode_cache.pop((decoded.qname, decoded.qtype), None)
                return None
            return rcode, True

        def _emit_unmatched(q: "dnsdist_protobuf.DecodedQuery") -> None:
            batch.append(_event_from_unmatched_query(q, _recent_answer_for(q)))

        def _sweep_expired_pending() -> None:
            now = time.monotonic()
            expired = [k for k, (_q, t0) in pending.items() if now - t0 >= args.spoof_flush_seconds]
            for k in expired:
                q, _t0 = pending.pop(k)
                _emit_unmatched(q)

        try:
            while not stop["flag"]:
                try:
                    body = dnsdist_protobuf.read_framed_messages(conn.recv)
                except socket.timeout:
                    body = None
                except dnsdist_protobuf.ProtobufDecodeError as exc:
                    log.warning("analytics-protobuf-receiver: framing error, closing connection: %s", exc)
                    break
                if body == b"":
                    break  # clean close
                if body:
                    try:
                        decoded = dnsdist_protobuf.decode_message(body)
                    except dnsdist_protobuf.ProtobufDecodeError as exc:
                        log.warning("analytics-protobuf-receiver: skipped undecodable message: %s", exc)
                        decoded = None
                    if isinstance(decoded, dnsdist_protobuf.DecodedResponse):
                        key = (decoded.client, decoded.msg_id)
                        pending.pop(key, None)  # matched -- the response is authoritative, drop any pending query
                        _remember_answer(decoded)
                        batch.append(_event_from_response(decoded))
                    elif isinstance(decoded, dnsdist_protobuf.DecodedQuery):
                        if len(pending) >= _PENDING_QUERY_MAX:
                            # Defense in depth only: drop the oldest
                            # in-flight entry rather than grow unbounded
                            # if responses are somehow never arriving.
                            oldest_key = min(pending, key=lambda k: pending[k][1])
                            q, _t0 = pending.pop(oldest_key)
                            _emit_unmatched(q)
                        pending[(decoded.client, decoded.msg_id)] = (decoded, time.monotonic())
                _sweep_expired_pending()
                now = time.monotonic()
                if len(batch) >= args.flush_batch_size or (batch and now - last_flush >= args.flush_interval_seconds):
                    _write_analytics_events_batch(inbox, batch)
                    batch = []
                    last_flush = now
        finally:
            for q, _t0 in pending.values():
                _emit_unmatched(q)
            _write_analytics_events_batch(inbox, batch)
            try:
                conn.close()
            except OSError:
                pass

    threads: list[threading.Thread] = []
    try:
        while not stop["flag"]:
            try:
                conn, _addr = server.accept()
            except socket.timeout:
                continue
            except OSError:
                if stop["flag"]:
                    break
                raise
            t = threading.Thread(target=_handle_connection, args=(conn,), daemon=True)
            t.start()
            threads.append(t)
            threads = [th for th in threads if th.is_alive()]
    finally:
        server.close()
    return 0


def cmd_dns_observer(args: argparse.Namespace) -> int:
    """Observation-only UDP DNS ingress for package-first discovery tests.

    This is deliberately not the future authoritative dnsdist/BIND runtime.
    It proves the mandatory packet-origin path by accepting real DNS packets,
    returning bounded DNS responses, and asynchronously handing source-address
    observations to the existing discovery worker through the JSONL inbox.
    """
    queue = observed_clients.ObservationQueue(capacity=args.queue_capacity)
    inbox = STATE_DIR / "discovery" / "inbox"
    stop = {"flag": False}

    def _handle_signal(signum, frame):
        stop["flag"] = True

    def _flush_loop() -> None:
        while not stop["flag"]:
            try:
                _write_observation_batch(inbox, queue.drain(args.flush_batch_size))
            except Exception:
                log.exception("dns-observer flush failed")
            time.sleep(args.flush_interval_seconds)
        try:
            _write_observation_batch(inbox, queue.drain(args.queue_capacity))
        except Exception:
            log.exception("dns-observer final flush failed")

    signal.signal(signal.SIGTERM, _handle_signal)
    signal.signal(signal.SIGINT, _handle_signal)
    flusher = threading.Thread(target=_flush_loop, daemon=True)
    flusher.start()

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(0.5)
    sock.bind((args.host, args.port))
    print(f"dns-observer: listening on {args.host}:{args.port}")
    try:
        while not stop["flag"]:
            try:
                packet, addr = sock.recvfrom(args.max_packet_bytes)
            except socket.timeout:
                continue
            except OSError:
                if stop["flag"]:
                    break
                raise
            source_ip = addr[0]
            hostname = ""
            try:
                hostname, _qtype, _qclass, _question = _parse_dns_qname(packet)
            except ValueError:
                pass
            queue.submit(source_ip, hostname_candidate=hostname, hostname_source="dns-query")
            response = _dns_response(packet)
            if response:
                try:
                    sock.sendto(response, addr)
                except OSError:
                    log.debug("dns-observer response send failed", exc_info=True)
    finally:
        stop["flag"] = True
        sock.close()
        flusher.join(timeout=2.0)
    return 0


def cmd_replication_server(args: argparse.Namespace) -> int:
    cmd_init_replication_cert(args)
    replication_v2.ensure_schema(CONTROL_DB)
    httpd = replication_v2.serve(
        bind=(args.host, args.port),
        server_cert=REPLICATION_SERVER_CERT_PATH,
        server_key=REPLICATION_SERVER_KEY_PATH,
        ca_file=REPLICATION_CA_PATH,
        control_db_path=CONTROL_DB,
        secrets_dir=SECRETS_DIR,
        staging_dir=STAGING_DIR,
        live_dnsdist_conf_path=COMPILED_DIR / "dnsdist.conf",
        listen_address=_configured_listen_address(),
    )
    print(f"replication-server: listening on {args.host}:{args.port}")
    try:
        httpd.serve_forever()
    finally:
        httpd.server_close()
    return 0


# --- tier-b-worker ---------------------------------------------------------


def cmd_tier_b_worker(args: argparse.Namespace) -> int:
    """Periodic Tier B popularity-based prewarm (§43-44). ``resolve_fn`` is
    a genuinely-isolated UDP resolve against the configured local dnsdist
    listener -- prewarm only ever *replays through the normal DNS path*
    (app/v2/tier_b_prewarm.py's own invariant), never a bypass, so DNS
    readiness is provably never gated on this worker even existing.

    Real defect found by hands-on Tier B load testing (roadmap Priority 6):
    this previously had its own inline ``resolve_fn`` that sent a
    zero-byte UDP packet and returned True as soon as ``sendto`` didn't
    raise -- it never built a real DNS query, never used
    ``entry.qname``/``entry.qtype`` at all, and never waited for or
    checked a response. It always "succeeded" regardless of whether the
    replayed name actually got a real answer or landed in dnsdist's
    packet cache, so prewarm's reported stats were meaningless and cold
    caches never actually got warmed by this worker in production. A
    real, already-implemented and already-tested resolve function
    (``app/v2/tier_b_worker.py``'s ``make_udp_resolve_fn`` --
    ``tests/v2/test_tier_b_worker.py``) existed the whole time but was
    never wired into this, the actual packaged/systemd-invoked entry
    point -- only used by tests exercising the library directly.
    """
    from app.v2.tier_b_worker import make_udp_resolve_fn

    resolve_fn = make_udp_resolve_fn(args.dns_address, args.dns_port, timeout=2.0)

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
    sub.add_parser("init-replication-cert").set_defaults(func=cmd_init_replication_cert)

    sub.add_parser(
        "install-enhanced-dnsdist",
        help=(
            "opt in to the official PowerDNS dnsdist 2.1 repository to install DoQ/DoH3 "
            "CAPABILITY (requires local root); does not itself enable DoQ/DoH3 -- turn "
            "them on afterward via PUT /api/dns-transports"
        ),
    ).set_defaults(func=cmd_install_enhanced_dnsdist)

    sub.add_parser(
        "dnsdist-capabilities",
        help="report the installed dnsdist version and which encrypted-DNS transports it supports",
    ).set_defaults(func=cmd_dnsdist_capabilities)

    p = sub.add_parser("issue-peer-cert", help="issue a replication client cert for a remote node, signed by this node's own CA")
    p.add_argument("remote_node_id", help="the remote node's node_id (from its /api/node-identity)")
    p.add_argument("--server-name", default="localhost", help="hostname/IP the issued cert's SAN should carry (informational; not enforced by this node)")
    p.add_argument("--out", help="write the enrollment bundle as JSON to this path (0600) instead of stdout")
    p.set_defaults(func=cmd_issue_peer_cert)

    p = sub.add_parser("migrate")
    p.add_argument("source", help="path to a V1 install root (containing alderpointdns.db)")
    p.add_argument("--promote", action="store_true",
                    help="write the staged, committed migration onto this host's live V2 install")
    p.add_argument("--allow-overwrite", action="store_true",
                    help="permit --promote to overwrite an already-configured live install/secrets")
    p.add_argument("--live-listen-address", default="0.0.0.0:53")
    p.add_argument("--dnsdist-binary", default="dnsdist")
    p.add_argument("--named-checkzone-binary", default="named-checkzone")
    p.set_defaults(func=cmd_migrate)

    p = sub.add_parser("generate-runtime")
    p.add_argument("--dnsdist-binary", default="dnsdist")
    p.add_argument("--named-checkzone-binary", default="named-checkzone")
    p.set_defaults(func=cmd_generate_runtime)

    p = sub.add_parser("analytics-worker")
    p.add_argument("--once", action="store_true")
    p.add_argument("--inject-test-event", action="store_true")
    p.add_argument("--interval-seconds", type=float, default=15.0)
    p.set_defaults(func=cmd_analytics_worker)

    p = sub.add_parser("discovery-worker")
    p.add_argument("--once", action="store_true")
    p.add_argument("--interval-seconds", type=float, default=15.0)
    p.set_defaults(func=cmd_discovery_worker)

    p = sub.add_parser("dns-observer")
    p.add_argument("--host", default="0.0.0.0")
    p.add_argument("--port", type=int, default=1053)
    p.add_argument("--queue-capacity", type=int, default=2048)
    p.add_argument("--flush-batch-size", type=int, default=512)
    p.add_argument("--flush-interval-seconds", type=float, default=0.5)
    p.add_argument("--max-packet-bytes", type=int, default=4096)
    p.set_defaults(func=cmd_dns_observer)

    p = sub.add_parser("analytics-protobuf-receiver", help="real dnsdist protobuf remote-logger receiver, feeds the analytics inbox")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=5391)
    p.add_argument("--flush-batch-size", type=int, default=512)
    p.add_argument("--flush-interval-seconds", type=float, default=1.0)
    p.add_argument("--spoof-flush-seconds", type=float, default=_PENDING_QUERY_FLUSH_SECONDS,
                    help="how long to wait for a query's matching response before assuming it was spoofed/locally-answered")
    p.set_defaults(func=cmd_analytics_protobuf_receiver)

    p = sub.add_parser("replication-server")
    p.add_argument("--host", default="0.0.0.0")
    p.add_argument("--port", type=int, default=9443)
    p.set_defaults(func=cmd_replication_server)

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
