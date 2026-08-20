"""Appliance host network configuration (beta-rescue priority 4/"Network
Configuration"): managing the Alderpoint appliance's OWN interface/
address (DHCP vs static IPv4/IPv6, gateway) -- distinct from turning
Alderpoint into a router. No DHCP server, no NAT, no firewall, no
routing/gateway functionality is added here or anywhere else in V2.

Reuses app.network_config wholesale (verbatim backend detection/
staging/validation/apply/rollback logic for networkd, netplan,
NetworkManager, and ifupdown -- pure OS introspection plus real, already
production-proven staged-apply-then-auto-rollback-unless-confirmed
safety architecture; confirmed by AST inspection to have no dangerous
module-level side effects, same reuse rationale as every other V1
module already reused this pass) rather than reimplementing a second,
unproven copy of a safety-critical subsystem. The only things this
wrapper changes:

- Redirects the shared module's own path constants (state file,
  rollback log, rollback systemd unit prefix) to V2's own namespace at
  import time, so V1 and V2 network-change state never collide even if
  both happen to be installed on the same host.
- Points the rollback watchdog's callback at V2's own ctl script
  (`alderpointdns_v2_ctl.py network-rollback-check`) instead of V1's
  compiler entry point.

Everything else -- detect_backend, list_interfaces, read_current_config,
validate_proposed, apply_change, confirm_change, rollback_check,
perform_rollback -- is the exact same, already-tested logic.
"""

from __future__ import annotations

import os
import time
from pathlib import Path

from app import network_config as _v1

# Same ALDERPOINTDNS_V2_STATE_ROOT/ALDERPOINTDNS_V2_LOG_ROOT overrides
# scripts/v2/alderpointdns_v2_ctl.py and app/v2/webapp.py already read --
# real production never sets these (the real installed systemd units
# don't), but a test/dev root needs this module's paths redirectable the
# same way every other V2 module already is, not hardcoded absolutes
# that would collide with (or silently touch) a real host's state.
_STATE_ROOT = Path(os.environ.get("ALDERPOINTDNS_V2_STATE_ROOT", "/var/lib/alderpointdns-v2"))
_LOG_ROOT = Path(os.environ.get("ALDERPOINTDNS_V2_LOG_ROOT", "/var/log/alderpointdns-v2"))

STATE_DIR = _STATE_ROOT / "network"
ROLLBACK_STATE_FILE = STATE_DIR / "rollback-state.json"
ROLLBACK_LOG = _LOG_ROOT / "network-rollback.log"
ROLLBACK_SYSTEMD_UNIT = "alderpointdns-v2-network-rollback"

# Redirect the shared module's own globals -- these are read directly out
# of app.network_config's module namespace by every function inside it
# (not passed as parameters), so reassigning them here really does
# retarget every call made through this wrapper, including the ones
# invoked transitively (apply_change -> _write_state_file ->
# ROLLBACK_STATE_FILE, etc).
_v1.STATE_DIR = STATE_DIR
_v1.ROLLBACK_STATE_FILE = ROLLBACK_STATE_FILE
_v1.ROLLBACK_LOG = ROLLBACK_LOG
_v1.ROLLBACK_SYSTEMD_UNIT = ROLLBACK_SYSTEMD_UNIT

NetworkConfigError = _v1.NetworkConfigError
ROLLBACK_TIMEOUT_SECONDS = _v1.ROLLBACK_TIMEOUT_SECONDS

detect_backend = _v1.detect_backend
list_interfaces = _v1.list_interfaces
interface_addresses = _v1.interface_addresses
all_local_addresses = _v1.all_local_addresses
default_gateway = _v1.default_gateway
read_current_config = _v1.read_current_config
validate_proposed = _v1.validate_proposed
read_rollback_state = _v1.read_rollback_state
apply_change = _v1.apply_change
audit_ip_references = _v1.audit_ip_references


def schedule_rollback_timer(timeout_seconds: int = _v1.ROLLBACK_TIMEOUT_SECONDS) -> str:
    """V2's own version of app.network_config.schedule_rollback_timer:
    identical safety mechanism (a systemd-run transient timer, owned by
    PID 1, independent of this web process/request/browser surviving),
    but calls V2's own ctl script's network-rollback-check subcommand
    rather than V1's compiler entry point."""
    unit_name = f"{ROLLBACK_SYSTEMD_UNIT}-{int(time.time())}"
    _v1.run([
        "systemd-run", f"--unit={unit_name}",
        "--description=Alderpoint DNS V2 network config rollback watchdog",
        f"--on-active={timeout_seconds}s", "--",
        "/usr/bin/python3", "/opt/alderpointdns-v2/scripts/v2/alderpointdns_v2_ctl.py", "network-rollback-check",
    ])
    return unit_name


def cancel_rollback_timer(unit_name: str) -> None:
    _v1.run(["systemctl", "stop", unit_name], check=False)
    _v1.run(["systemctl", "reset-failed", unit_name], check=False)


# apply_change/confirm_change/rollback_check all reference
# schedule_rollback_timer/cancel_rollback_timer via the shared module's
# own namespace, so those also need redirecting to this wrapper's
# V2-specific versions -- otherwise a V2 apply would schedule a rollback
# watchdog that calls V1's (likely absent, on a V2-only install) compiler
# script.
_v1.schedule_rollback_timer = schedule_rollback_timer
_v1.cancel_rollback_timer = cancel_rollback_timer

confirm_change = _v1.confirm_change
rollback_check = _v1.rollback_check
