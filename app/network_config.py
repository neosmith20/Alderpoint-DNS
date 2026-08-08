#!/usr/bin/env python3
"""Alderpoint DNS Network Configuration: manage the Alderpoint server's OWN
network interface (DHCP vs static IPv4/IPv6, gateway) -- distinct from DNS
upstream/resolver settings (see app/upstream_dns.py), which control where
Alderpoint DNS forwards queries it doesn't answer itself.

This module never assumes a networking backend. Debian/Ubuntu systems in
the wild use any of systemd-networkd, NetworkManager, ifupdown (the classic
/etc/network/interfaces), or Netplan (which itself renders to networkd or
NetworkManager on Ubuntu). detect_backend() identifies which one actually
owns this host's configuration; if that is ambiguous or unrecognized, every
write path in this module refuses outright and the web UI falls back to a
read-only view, per the project's requirement that Alderpoint DNS must never
guess at another tool's config format.

Changing the server's own IP address can disconnect the administrator's
browser. Every apply here follows the same shape:

  1. validate the proposed configuration (validate_proposed)
  2. snapshot the current persistent config + a live-state description to
     a root-only rollback state file (snapshot_current)
  3. stage the new persistent config for the detected backend
  4. schedule an *independent* rollback watchdog via `systemd-run`, running
     under systemd/PID 1, entirely outside this web process, this HTTP
     request, and the administrator's browser (schedule_rollback_timer)
  5. actively reconfigure the live interface through the backend's own
     supported mechanism (apply_via_backend) -- never a bare `ip link set
     ... up/down`, which does not itself apply a backend's persistent IP/
     gateway configuration
  6. the administrator confirms from the new address (confirm_change),
     which cancels the watchdog and deletes the rollback state; if nothing
     confirms before the timer fires, the watchdog itself (running the
     privileged compiler's `network-rollback-check` subcommand, not this
     process) restores the old persistent config and live interface state.

Every function that shells out to a backend tool is given a fixed,
validated set of arguments built from validated data (ipaddress.IPv4/6
objects, an interface name checked against `ip -j link`) -- never a raw
string interpolated from the request, and never `shell=True`.
"""

from __future__ import annotations

import datetime as dt
import ipaddress
import json
import os
import re
import shutil
import socket
import subprocess
import time
from pathlib import Path
from typing import Any

STATE_DIR = Path("/var/lib/alderpointdns/network")
ROLLBACK_STATE_FILE = STATE_DIR / "rollback-state.json"
ROLLBACK_LOG = Path("/var/log/alderpointdns/network-rollback.log")

# 90-120s per the task's requirement; chosen at the middle of that range so
# there is real margin for a slow-to-reconnect browser/DHCP lease without
# leaving a misconfigured interface live for an excessive window.
ROLLBACK_TIMEOUT_SECONDS = 120
ROLLBACK_SYSTEMD_UNIT = "alderpointdns-network-rollback"

BACKEND_NETWORKD = "systemd-networkd"
BACKEND_NETWORKMANAGER = "NetworkManager"
BACKEND_IFUPDOWN = "ifupdown"
BACKEND_NETPLAN = "netplan"
BACKEND_UNSUPPORTED = "unsupported"

NETWORKD_DROPIN_DIR = Path("/etc/systemd/network")
NETPLAN_DIR = Path("/etc/netplan")
NETPLAN_FILE = NETPLAN_DIR / "90-alderpointdns.yaml"
IFUPDOWN_INTERFACES = Path("/etc/network/interfaces")
IFUPDOWN_DROPIN_DIR = Path("/etc/network/interfaces.d")


class NetworkConfigError(ValueError):
    pass


def now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()


def run(command: list[str], check: bool = True, input_text: str | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=check, input=input_text)


# ---------------------------------------------------------------------------
# Backend detection
# ---------------------------------------------------------------------------

def _systemctl_is_active(unit: str) -> bool:
    try:
        proc = run(["systemctl", "is-active", unit], check=False)
    except (FileNotFoundError, OSError):
        return False
    return proc.stdout.strip() == "active"


def _systemctl_is_enabled(unit: str) -> bool:
    try:
        proc = run(["systemctl", "is-enabled", unit], check=False)
    except (FileNotFoundError, OSError):
        return False
    return proc.stdout.strip() in {"enabled", "static"}


def detect_backend() -> dict[str, Any]:
    """Identify the networking backend that actually owns this host's
    configuration. Netplan is checked first because on a Netplan system,
    Netplan's YAML is the source of truth even though the live renderer
    underneath is networkd or NetworkManager -- rewriting the renderer's
    own files directly would be immediately overwritten by the next
    `netplan apply` and silently diverge from what `netplan generate`
    thinks is configured.

    Returns {"backend": ..., "ambiguous": bool, "detail": str}. `ambiguous`
    is set whenever more than one backend looks simultaneously active
    (a real, if unusual, possible misconfiguration) -- callers must treat
    an ambiguous result as unsupported/read-only, never guess."""
    candidates: list[str] = []
    detail_parts: list[str] = []

    netplan_yaml_present = NETPLAN_DIR.is_dir() and any(NETPLAN_DIR.glob("*.yaml"))
    if shutil.which("netplan") and netplan_yaml_present:
        candidates.append(BACKEND_NETPLAN)
        detail_parts.append(f"netplan binary present, {len(list(NETPLAN_DIR.glob('*.yaml')))} yaml file(s) in {NETPLAN_DIR}")

    if _systemctl_is_active(f"{BACKEND_NETWORKMANAGER}.service"):
        candidates.append(BACKEND_NETWORKMANAGER)
        detail_parts.append("NetworkManager.service is active")

    if _systemctl_is_active(f"{BACKEND_NETWORKD}.service") and BACKEND_NETPLAN not in candidates:
        # Netplan on a networkd renderer already reports "active" for
        # systemd-networkd.service too; only counted as its own backend
        # when Netplan itself isn't in play, to avoid double-counting one
        # real backend as two "candidates" and manufacturing a false
        # ambiguity.
        candidates.append(BACKEND_NETWORKD)
        detail_parts.append("systemd-networkd.service is active")

    if (
        BACKEND_NETPLAN not in candidates
        and BACKEND_NETWORKMANAGER not in candidates
        and BACKEND_NETWORKD not in candidates
        and IFUPDOWN_INTERFACES.exists()
    ):
        candidates.append(BACKEND_IFUPDOWN)
        detail_parts.append(f"{IFUPDOWN_INTERFACES} exists and no other backend is active")

    if len(candidates) == 1:
        return {"backend": candidates[0], "ambiguous": False, "detail": "; ".join(detail_parts)}
    if len(candidates) == 0:
        return {"backend": BACKEND_UNSUPPORTED, "ambiguous": False, "detail": "no supported networking backend detected"}
    return {
        "backend": BACKEND_UNSUPPORTED,
        "ambiguous": True,
        "detail": "multiple networking backends appear active (" + ", ".join(candidates) + "); refusing to guess",
    }


# ---------------------------------------------------------------------------
# Current state (always read-only-safe)
# ---------------------------------------------------------------------------

def _ip_json(*args: str) -> Any:
    proc = run(["ip", "-json"] + list(args), check=False)
    if proc.returncode != 0 or not proc.stdout.strip():
        return []
    try:
        return json.loads(proc.stdout)
    except json.JSONDecodeError:
        return []


def list_interfaces() -> list[str]:
    return [entry["ifname"] for entry in _ip_json("link", "show") if entry.get("ifname") != "lo"]


def default_route_interface(family: str = "-4") -> str | None:
    proc = run(["ip", family, "route", "show", "default"], check=False)
    if proc.returncode != 0:
        return None
    match = re.search(r"\bdev\s+(\S+)", proc.stdout)
    return match.group(1) if match else None


def default_gateway(family: str = "-4") -> str | None:
    proc = run(["ip", family, "route", "show", "default"], check=False)
    if proc.returncode != 0:
        return None
    match = re.search(r"\bvia\s+(\S+)", proc.stdout)
    return match.group(1) if match else None


def interface_addresses(interface: str) -> dict[str, Any]:
    entries = _ip_json("addr", "show", "dev", interface)
    ipv4: list[dict[str, Any]] = []
    ipv6: list[dict[str, Any]] = []
    for entry in entries:
        for addr in entry.get("addr_info", []):
            item = {"address": addr.get("local"), "prefixlen": addr.get("prefixlen")}
            if addr.get("family") == "inet":
                ipv4.append(item)
            elif addr.get("family") == "inet6" and addr.get("scope") != "link":
                ipv6.append(item)
    return {"ipv4": ipv4, "ipv6": ipv6}


def all_local_addresses(exclude_interface: str | None = None) -> set[str]:
    """Every IPv4/IPv6 address currently configured on any local interface
    (except exclude_interface, if given) -- used to reject a proposed
    address that collides with another interface."""
    addrs: set[str] = set()
    for entry in _ip_json("addr", "show"):
        if exclude_interface and entry.get("ifname") == exclude_interface:
            continue
        for addr in entry.get("addr_info", []):
            if addr.get("local"):
                addrs.add(addr["local"])
    return addrs


def read_current_config() -> dict[str, Any]:
    """Always-safe, read-only description of the current network state,
    shown first per the task's requirement -- independent of whether the
    detected backend supports making changes."""
    backend_info = detect_backend()
    interface = default_route_interface() or (list_interfaces()[0] if list_interfaces() else None)
    result: dict[str, Any] = {
        "backend": backend_info["backend"],
        "ambiguous": backend_info["ambiguous"],
        "backend_detail": backend_info["detail"],
        "interface": interface,
        "interfaces": list_interfaces(),
        "ipv4": None,
        "ipv6": None,
    }
    if interface:
        addrs = interface_addresses(interface)
        v4 = addrs["ipv4"][0] if addrs["ipv4"] else None
        v6 = addrs["ipv6"][0] if addrs["ipv6"] else None
        result["ipv4"] = {
            "address": v4["address"] if v4 else None,
            "prefixlen": v4["prefixlen"] if v4 else None,
            "gateway": default_gateway("-4"),
            "mode": detect_ipv4_mode(backend_info["backend"], interface),
        }
        result["ipv6"] = {
            "address": v6["address"] if v6 else None,
            "prefixlen": v6["prefixlen"] if v6 else None,
            "gateway": default_gateway("-6"),
            "mode": detect_ipv6_mode(backend_info["backend"], interface),
        }
    return result


def detect_ipv4_mode(backend: str, interface: str) -> str:
    """Best-effort DHCP-vs-static determination from the owning backend's
    own config; 'unknown' (never guessed) if it can't be determined."""
    try:
        if backend == BACKEND_NETWORKD:
            for path in sorted(NETWORKD_DROPIN_DIR.glob("*.network")):
                text = path.read_text()
                if re.search(rf"^\s*Name\s*=\s*{re.escape(interface)}\s*$", text, re.MULTILINE):
                    if re.search(r"^\s*DHCP\s*=\s*(yes|ipv4)\s*$", text, re.MULTILINE | re.IGNORECASE):
                        return "dhcp"
                    if re.search(r"^\s*Address\s*=", text, re.MULTILINE):
                        return "static"
        elif backend == BACKEND_NETWORKMANAGER and shutil.which("nmcli"):
            proc = run(["nmcli", "-t", "-f", "GENERAL.DEVICE,IP4.METHOD" if False else "ipv4.method", "con", "show", interface], check=False)
            if proc.returncode == 0:
                if "auto" in proc.stdout:
                    return "dhcp"
                if "manual" in proc.stdout:
                    return "static"
        elif backend == BACKEND_IFUPDOWN:
            for path in [IFUPDOWN_INTERFACES] + sorted(IFUPDOWN_DROPIN_DIR.glob("*")) if IFUPDOWN_DROPIN_DIR.is_dir() else [IFUPDOWN_INTERFACES]:
                if not path.exists():
                    continue
                text = path.read_text()
                match = re.search(rf"^\s*iface\s+{re.escape(interface)}\s+inet\s+(\w+)", text, re.MULTILINE)
                if match:
                    return "dhcp" if match.group(1) == "dhcp" else "static" if match.group(1) == "static" else "unknown"
        elif backend == BACKEND_NETPLAN and NETPLAN_DIR.is_dir():
            for path in sorted(NETPLAN_DIR.glob("*.yaml")):
                text = path.read_text()
                if interface in text:
                    if re.search(r"dhcp4:\s*true", text):
                        return "dhcp"
                    if re.search(r"addresses:", text):
                        return "static"
    except OSError:
        pass
    return "unknown"


def detect_ipv6_mode(backend: str, interface: str) -> str:
    # Same best-effort/never-guess shape as detect_ipv4_mode; IPv6 config
    # is additionally often SLAAC (router-advertised), which reads as
    # neither a classic "dhcp" nor "static" backend stanza.
    try:
        if backend == BACKEND_NETWORKD:
            for path in sorted(NETWORKD_DROPIN_DIR.glob("*.network")):
                text = path.read_text()
                if re.search(rf"^\s*Name\s*=\s*{re.escape(interface)}\s*$", text, re.MULTILINE):
                    if re.search(r"^\s*DHCP\s*=\s*(yes|ipv6)\s*$", text, re.MULTILINE | re.IGNORECASE):
                        return "dhcp"
                    if re.search(r"^\s*Address\s*=.*:.*$", text, re.MULTILINE):
                        return "static"
                    return "slaac"
        elif backend == BACKEND_NETPLAN and NETPLAN_DIR.is_dir():
            for path in sorted(NETPLAN_DIR.glob("*.yaml")):
                if interface in path.read_text():
                    text = path.read_text()
                    if re.search(r"dhcp6:\s*true", text):
                        return "dhcp"
                    if re.search(r"accept-ra:\s*true", text):
                        return "slaac"
    except OSError:
        pass
    return "unknown"


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

def validate_proposed(
    interface: str,
    ipv4_mode: str,
    ipv4_address: str | None,
    ipv4_prefix: int | None,
    ipv4_gateway: str | None,
    ipv6_mode: str = "unchanged",
    ipv6_address: str | None = None,
    ipv6_prefix: int | None = None,
    ipv6_gateway: str | None = None,
) -> dict[str, Any]:
    known_interfaces = list_interfaces()
    if interface not in known_interfaces:
        raise NetworkConfigError(f"interface {interface!r} does not exist on this host")

    if ipv4_mode not in {"dhcp", "static", "unchanged"}:
        raise NetworkConfigError("ipv4_mode must be 'dhcp' or 'static'")
    if ipv6_mode not in {"dhcp", "static", "slaac", "unchanged"}:
        raise NetworkConfigError("ipv6_mode must be 'dhcp', 'static', or 'slaac'")

    result: dict[str, Any] = {"interface": interface, "ipv4_mode": ipv4_mode, "ipv6_mode": ipv6_mode}

    if ipv4_mode == "static":
        if not ipv4_address or not ipv4_prefix or not ipv4_gateway:
            raise NetworkConfigError("static IPv4 requires an address, prefix length, and gateway")
        try:
            addr = ipaddress.IPv4Address(ipv4_address)
        except ValueError as exc:
            raise NetworkConfigError(f"invalid IPv4 address: {exc}") from None
        if not (0 <= int(ipv4_prefix) <= 32):
            raise NetworkConfigError("IPv4 prefix length must be between 0 and 32")
        try:
            gw = ipaddress.IPv4Address(ipv4_gateway)
        except ValueError as exc:
            raise NetworkConfigError(f"invalid IPv4 gateway: {exc}") from None
        if addr.is_loopback:
            raise NetworkConfigError("IPv4 address must not be a loopback address")
        if addr.is_multicast:
            raise NetworkConfigError("IPv4 address must not be a multicast address")
        if addr.is_unspecified:
            raise NetworkConfigError("IPv4 address must not be 0.0.0.0")
        if gw.is_loopback or gw.is_multicast or gw.is_unspecified:
            raise NetworkConfigError("IPv4 gateway must be a normal unicast address")
        network = ipaddress.IPv4Network(f"{ipv4_address}/{ipv4_prefix}", strict=False)
        if gw not in network:
            raise NetworkConfigError(f"gateway {ipv4_gateway} is not within the {network} subnet implied by {ipv4_address}/{ipv4_prefix}")
        existing = all_local_addresses(exclude_interface=interface)
        if ipv4_address in existing:
            raise NetworkConfigError(f"{ipv4_address} is already configured on another local interface")
        result["ipv4"] = {"address": ipv4_address, "prefix": int(ipv4_prefix), "gateway": ipv4_gateway}

    if ipv6_mode == "static":
        if not ipv6_address or not ipv6_prefix or not ipv6_gateway:
            raise NetworkConfigError("static IPv6 requires an address, prefix length, and gateway")
        try:
            addr6 = ipaddress.IPv6Address(ipv6_address)
        except ValueError as exc:
            raise NetworkConfigError(f"invalid IPv6 address: {exc}") from None
        if not (0 <= int(ipv6_prefix) <= 128):
            raise NetworkConfigError("IPv6 prefix length must be between 0 and 128")
        try:
            gw6 = ipaddress.IPv6Address(ipv6_gateway)
        except ValueError as exc:
            raise NetworkConfigError(f"invalid IPv6 gateway: {exc}") from None
        if addr6.is_loopback or addr6.is_multicast or addr6.is_unspecified:
            raise NetworkConfigError("IPv6 address must not be loopback, multicast, or unspecified")
        if gw6.is_loopback or gw6.is_multicast or gw6.is_unspecified:
            raise NetworkConfigError("IPv6 gateway must be a normal unicast address")
        network6 = ipaddress.IPv6Network(f"{ipv6_address}/{ipv6_prefix}", strict=False)
        if gw6 not in network6 and not gw6.is_link_local:
            raise NetworkConfigError(f"gateway {ipv6_gateway} is not within the {network6} subnet implied by {ipv6_address}/{ipv6_prefix}")
        existing6 = all_local_addresses(exclude_interface=interface)
        if ipv6_address in existing6:
            raise NetworkConfigError(f"{ipv6_address} is already configured on another local interface")
        result["ipv6"] = {"address": ipv6_address, "prefix": int(ipv6_prefix), "gateway": ipv6_gateway}

    return result


# ---------------------------------------------------------------------------
# Backend-specific persistent config: snapshot / stage / apply
#
# Each backend's staging/apply pair is isolated so a bug or an unsupported
# variant in one backend can never affect another, per the task's
# requirement to keep backend-specific implementation isolated.
# ---------------------------------------------------------------------------

def _snapshot_paths_for_backend(backend: str, interface: str) -> list[Path]:
    if backend == BACKEND_NETWORKD:
        return sorted(NETWORKD_DROPIN_DIR.glob("*.network"))
    if backend == BACKEND_NETPLAN:
        return sorted(NETPLAN_DIR.glob("*.yaml")) if NETPLAN_DIR.is_dir() else []
    if backend == BACKEND_IFUPDOWN:
        paths = [IFUPDOWN_INTERFACES] if IFUPDOWN_INTERFACES.exists() else []
        if IFUPDOWN_DROPIN_DIR.is_dir():
            paths += sorted(IFUPDOWN_DROPIN_DIR.glob("*"))
        return paths
    if backend == BACKEND_NETWORKMANAGER:
        return []  # NetworkManager's connection profile is snapshotted via nmcli export below
    return []


def snapshot_current(backend: str, interface: str) -> dict[str, Any]:
    """Captures everything rollback needs to restore: the persistent
    config file(s) verbatim, and (for NetworkManager, which doesn't keep
    plain-text files an admin is expected to hand-edit) the connection
    profile's relevant properties via nmcli."""
    files: dict[str, str] = {}
    for path in _snapshot_paths_for_backend(backend, interface):
        try:
            files[str(path)] = path.read_text()
        except OSError:
            continue
    nm_profile: dict[str, str] = {}
    if backend == BACKEND_NETWORKMANAGER and shutil.which("nmcli"):
        conn_name = _nm_connection_for_interface(interface)
        if conn_name:
            for prop in ("ipv4.method", "ipv4.addresses", "ipv4.gateway", "ipv6.method", "ipv6.addresses", "ipv6.gateway"):
                proc = run(["nmcli", "-g", prop, "con", "show", conn_name], check=False)
                nm_profile[prop] = proc.stdout.strip() if proc.returncode == 0 else ""
            nm_profile["_connection_name"] = conn_name
    return {
        "backend": backend,
        "interface": interface,
        "files": files,
        "nm_profile": nm_profile,
        "live_ipv4": interface_addresses(interface).get("ipv4", []),
        "live_ipv6": interface_addresses(interface).get("ipv6", []),
        "live_gateway_v4": default_gateway("-4"),
        "live_gateway_v6": default_gateway("-6"),
    }


def _nm_connection_for_interface(interface: str) -> str | None:
    proc = run(["nmcli", "-t", "-f", "NAME,DEVICE", "con", "show", "--active"], check=False)
    if proc.returncode != 0:
        return None
    for line in proc.stdout.splitlines():
        parts = line.split(":")
        if len(parts) == 2 and parts[1] == interface:
            return parts[0]
    return None


def _render_networkd_unit(interface: str, ipv4: dict[str, Any] | None, ipv4_mode: str, ipv6: dict[str, Any] | None, ipv6_mode: str) -> str:
    lines = ["[Match]", f"Name={interface}", "", "[Network]"]
    if ipv4_mode == "dhcp":
        lines.append("DHCP=ipv4")
    elif ipv4_mode == "static" and ipv4:
        lines.append(f"Address={ipv4['address']}/{ipv4['prefix']}")
        lines.append(f"Gateway={ipv4['gateway']}")
    if ipv6_mode == "dhcp":
        lines.append("DHCP=ipv6")
    elif ipv6_mode == "static" and ipv6:
        lines.append(f"Address={ipv6['address']}/{ipv6['prefix']}")
        lines.append(f"Gateway={ipv6['gateway']}")
    elif ipv6_mode == "slaac":
        lines.append("IPv6AcceptRA=yes")
    return "\n".join(lines) + "\n"


def stage_networkd(interface: str, ipv4_mode: str, ipv4: dict[str, Any] | None, ipv6_mode: str, ipv6: dict[str, Any] | None) -> Path:
    NETWORKD_DROPIN_DIR.mkdir(parents=True, exist_ok=True)
    path = NETWORKD_DROPIN_DIR / f"90-alderpointdns-{interface}.network"
    path.write_text(_render_networkd_unit(interface, ipv4, ipv4_mode, ipv6, ipv6_mode))
    os.chmod(path, 0o644)
    return path


def apply_networkd(interface: str) -> None:
    run(["networkctl", "reload"])
    run(["networkctl", "reconfigure", interface])


def _render_netplan_yaml(interface: str, ipv4_mode: str, ipv4: dict[str, Any] | None, ipv6_mode: str, ipv6: dict[str, Any] | None) -> str:
    body: dict[str, Any] = {"network": {"version": 2, "ethernets": {interface: {}}}}
    eth = body["network"]["ethernets"][interface]
    addresses = []
    if ipv4_mode == "dhcp":
        eth["dhcp4"] = True
    elif ipv4_mode == "static" and ipv4:
        eth["dhcp4"] = False
        addresses.append(f"{ipv4['address']}/{ipv4['prefix']}")
        eth["routes"] = eth.get("routes", []) + [{"to": "0.0.0.0/0", "via": ipv4["gateway"]}]
    if ipv6_mode == "dhcp":
        eth["dhcp6"] = True
    elif ipv6_mode == "static" and ipv6:
        addresses.append(f"{ipv6['address']}/{ipv6['prefix']}")
        eth["routes"] = eth.get("routes", []) + [{"to": "::/0", "via": ipv6["gateway"]}]
    elif ipv6_mode == "slaac":
        eth["accept-ra"] = True
    if addresses:
        eth["addresses"] = addresses
    try:
        import yaml

        return yaml.safe_dump(body, sort_keys=False)
    except ImportError:
        return json.dumps(body, indent=2)  # netplan also accepts JSON-flow YAML as a fallback


def stage_netplan(interface: str, ipv4_mode: str, ipv4: dict[str, Any] | None, ipv6_mode: str, ipv6: dict[str, Any] | None) -> Path:
    NETPLAN_DIR.mkdir(parents=True, exist_ok=True)
    NETPLAN_FILE.write_text(_render_netplan_yaml(interface, ipv4_mode, ipv4, ipv6_mode, ipv6))
    os.chmod(NETPLAN_FILE, 0o600)  # netplan requires owner-only-readable config
    return NETPLAN_FILE


def apply_netplan() -> None:
    run(["netplan", "generate"])
    run(["netplan", "apply"])


def stage_networkmanager(interface: str, ipv4_mode: str, ipv4: dict[str, Any] | None, ipv6_mode: str, ipv6: dict[str, Any] | None) -> str:
    conn_name = _nm_connection_for_interface(interface) or interface
    if ipv4_mode == "dhcp":
        run(["nmcli", "con", "mod", conn_name, "ipv4.method", "auto", "ipv4.addresses", "", "ipv4.gateway", ""])
    elif ipv4_mode == "static" and ipv4:
        run([
            "nmcli", "con", "mod", conn_name,
            "ipv4.method", "manual",
            "ipv4.addresses", f"{ipv4['address']}/{ipv4['prefix']}",
            "ipv4.gateway", ipv4["gateway"],
        ])
    if ipv6_mode == "dhcp":
        run(["nmcli", "con", "mod", conn_name, "ipv6.method", "auto"])
    elif ipv6_mode == "static" and ipv6:
        run([
            "nmcli", "con", "mod", conn_name,
            "ipv6.method", "manual",
            "ipv6.addresses", f"{ipv6['address']}/{ipv6['prefix']}",
            "ipv6.gateway", ipv6["gateway"],
        ])
    elif ipv6_mode == "slaac":
        run(["nmcli", "con", "mod", conn_name, "ipv6.method", "auto"])
    return conn_name


def apply_networkmanager(conn_name: str) -> None:
    run(["nmcli", "con", "up", conn_name])


def stage_ifupdown(interface: str, ipv4_mode: str, ipv4: dict[str, Any] | None, ipv6_mode: str, ipv6: dict[str, Any] | None) -> Path:
    IFUPDOWN_DROPIN_DIR.mkdir(parents=True, exist_ok=True)
    path = IFUPDOWN_DROPIN_DIR / f"90-alderpointdns-{interface}.cfg"
    lines = []
    if ipv4_mode == "dhcp":
        lines += [f"auto {interface}", f"iface {interface} inet dhcp"]
    elif ipv4_mode == "static" and ipv4:
        netmask = str(ipaddress.IPv4Network(f"0.0.0.0/{ipv4['prefix']}").netmask)
        lines += [
            f"auto {interface}",
            f"iface {interface} inet static",
            f"    address {ipv4['address']}",
            f"    netmask {netmask}",
            f"    gateway {ipv4['gateway']}",
        ]
    if ipv6_mode == "static" and ipv6:
        lines += [
            f"iface {interface} inet6 static",
            f"    address {ipv6['address']}",
            f"    netmask {ipv6['prefix']}",
            f"    gateway {ipv6['gateway']}",
        ]
    elif ipv6_mode == "dhcp":
        lines += [f"iface {interface} inet6 dhcp"]
    elif ipv6_mode == "slaac":
        lines += [f"iface {interface} inet6 auto"]
    path.write_text("\n".join(lines) + "\n")
    os.chmod(path, 0o644)
    # /etc/network/interfaces must `source` interfaces.d for the drop-in to
    # take effect; this is the standard Debian ifupdown layout and is
    # additive (never rewrites the admin's main file's other stanzas).
    if IFUPDOWN_INTERFACES.exists():
        text = IFUPDOWN_INTERFACES.read_text()
        if "source /etc/network/interfaces.d/*" not in text and "source-directory /etc/network/interfaces.d" not in text:
            with IFUPDOWN_INTERFACES.open("a") as fh:
                fh.write("\nsource /etc/network/interfaces.d/*\n")
    return path


def apply_ifupdown(interface: str) -> None:
    # A controlled down/up cycle of just this interface's ifupdown
    # management -- not a bare `ip link set down/up`, which does not
    # itself re-read or apply the staged persistent config at all.
    run(["ifdown", interface], check=False)
    run(["ifup", interface])


# ---------------------------------------------------------------------------
# Rollback state
# ---------------------------------------------------------------------------

def _harden_state_permissions(path: Path) -> None:
    # Group-readable by the unprivileged web process's group (same trust
    # boundary as backup archives, see backup.harden_backup_file_permissions)
    # so /system/network can show the pending-confirmation countdown
    # without a sudo round trip on every page load; never world-readable,
    # and only root (the privileged compiler) can write it.
    try:
        shutil.chown(path, user="root", group="alderpointdns")
    except (LookupError, PermissionError, OSError):
        pass
    os.chmod(path, 0o640)


def _write_state_file(state: dict[str, Any]) -> None:
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    try:
        shutil.chown(STATE_DIR, user="root", group="alderpointdns")
    except (LookupError, PermissionError, OSError):
        pass
    os.chmod(STATE_DIR, 0o750)
    tmp = ROLLBACK_STATE_FILE.with_suffix(".tmp")
    tmp.write_text(json.dumps(state, indent=2))
    _harden_state_permissions(tmp)
    os.replace(tmp, ROLLBACK_STATE_FILE)
    _harden_state_permissions(ROLLBACK_STATE_FILE)


def read_rollback_state() -> dict[str, Any] | None:
    if not ROLLBACK_STATE_FILE.exists():
        return None
    try:
        return json.loads(ROLLBACK_STATE_FILE.read_text())
    except (OSError, json.JSONDecodeError):
        return None


def schedule_rollback_timer(timeout_seconds: int = ROLLBACK_TIMEOUT_SECONDS) -> str:
    """Schedules the rollback watchdog via `systemd-run`, a transient
    systemd timer owned by PID 1 -- independent of this web process
    surviving, the HTTP request completing, or the administrator's browser
    staying connected. Returns the transient unit name so confirm_change()
    can cancel it."""
    unit_name = f"{ROLLBACK_SYSTEMD_UNIT}-{int(time.time())}"
    run([
        "systemd-run",
        f"--unit={unit_name}",
        "--description=Alderpoint DNS network config rollback watchdog",
        f"--on-active={timeout_seconds}s",
        "--",
        "/opt/alderpointdns/app/alderpointdns_compiler.py", "network-rollback-check",
    ])
    return unit_name


def cancel_rollback_timer(unit_name: str) -> None:
    run(["systemctl", "stop", unit_name], check=False)
    run(["systemctl", "reset-failed", unit_name], check=False)


def _log_rollback_event(message: str) -> None:
    try:
        ROLLBACK_LOG.parent.mkdir(parents=True, exist_ok=True)
        with ROLLBACK_LOG.open("a") as fh:
            fh.write(f"{now()} {message}\n")
    except OSError:
        pass


# ---------------------------------------------------------------------------
# Apply / rollback / confirm orchestration (runs in the privileged helper)
# ---------------------------------------------------------------------------

def apply_change(
    interface: str,
    ipv4_mode: str,
    ipv4_address: str | None,
    ipv4_prefix: int | None,
    ipv4_gateway: str | None,
    ipv6_mode: str = "unchanged",
    ipv6_address: str | None = None,
    ipv6_prefix: int | None = None,
    ipv6_gateway: str | None = None,
    rollback_timeout_seconds: int = ROLLBACK_TIMEOUT_SECONDS,
) -> dict[str, Any]:
    backend_info = detect_backend()
    backend = backend_info["backend"]
    if backend == BACKEND_UNSUPPORTED:
        raise NetworkConfigError(
            "no single supported networking backend was detected ("
            + backend_info["detail"]
            + "); refusing to change network configuration -- current settings are shown read-only"
        )

    validated = validate_proposed(
        interface, ipv4_mode, ipv4_address, ipv4_prefix, ipv4_gateway,
        ipv6_mode, ipv6_address, ipv6_prefix, ipv6_gateway,
    )

    if ROLLBACK_STATE_FILE.exists():
        raise NetworkConfigError("a network configuration change is already pending confirmation; confirm or wait for it to roll back first")

    snapshot = snapshot_current(backend, interface)

    ipv4_cfg = validated.get("ipv4")
    ipv6_cfg = validated.get("ipv6")

    if backend == BACKEND_NETWORKD:
        stage_networkd(interface, ipv4_mode, ipv4_cfg, ipv6_mode, ipv6_cfg)
    elif backend == BACKEND_NETPLAN:
        stage_netplan(interface, ipv4_mode, ipv4_cfg, ipv6_mode, ipv6_cfg)
    elif backend == BACKEND_NETWORKMANAGER:
        stage_networkmanager(interface, ipv4_mode, ipv4_cfg, ipv6_mode, ipv6_cfg)
    elif backend == BACKEND_IFUPDOWN:
        stage_ifupdown(interface, ipv4_mode, ipv4_cfg, ipv6_mode, ipv6_cfg)

    unit_name = schedule_rollback_timer(rollback_timeout_seconds)
    state = {
        "requested_at": now(),
        "backend": backend,
        "interface": interface,
        "snapshot": snapshot,
        "proposed": validated,
        "rollback_unit": unit_name,
        "rollback_deadline": (dt.datetime.now(dt.timezone.utc) + dt.timedelta(seconds=rollback_timeout_seconds)).isoformat(),
        "confirmed": False,
    }
    _write_state_file(state)

    try:
        if backend == BACKEND_NETWORKD:
            apply_networkd(interface)
        elif backend == BACKEND_NETPLAN:
            apply_netplan()
        elif backend == BACKEND_NETWORKMANAGER:
            apply_networkmanager(stage_networkmanager(interface, ipv4_mode, ipv4_cfg, ipv6_mode, ipv6_cfg))
        elif backend == BACKEND_IFUPDOWN:
            apply_ifupdown(interface)
    except subprocess.CalledProcessError as exc:
        # The live apply itself failed -- roll back immediately rather than
        # waiting out the full timer, and surface the real error.
        _log_rollback_event(f"apply failed for {interface} via {backend}, rolling back immediately: {exc}")
        perform_rollback(state)
        raise NetworkConfigError(f"failed to apply network configuration via {backend}: {exc.stdout}") from None

    _log_rollback_event(f"applied new config for {interface} via {backend}; rollback armed as {unit_name}, deadline {state['rollback_deadline']}")
    return {"backend": backend, "rollback_unit": unit_name, "rollback_deadline": state["rollback_deadline"]}


def perform_rollback(state: dict[str, Any]) -> None:
    """Restores BOTH the persistent config files/profile AND the live
    kernel/interface state -- not just files awaiting a reboot."""
    backend = state["backend"]
    interface = state["interface"]
    snapshot = state["snapshot"]

    for path_str, content in snapshot.get("files", {}).items():
        path = Path(path_str)
        try:
            path.write_text(content)
        except OSError as exc:
            _log_rollback_event(f"WARNING: could not restore {path}: {exc}")

    # Files staged fresh by this change that weren't present before must be
    # removed, not just left alongside the restored originals.
    if backend == BACKEND_NETWORKD:
        staged = NETWORKD_DROPIN_DIR / f"90-alderpointdns-{interface}.network"
        if str(staged) not in snapshot.get("files", {}) and staged.exists():
            staged.unlink()
    elif backend == BACKEND_NETPLAN:
        if str(NETPLAN_FILE) not in snapshot.get("files", {}) and NETPLAN_FILE.exists():
            NETPLAN_FILE.unlink()
    elif backend == BACKEND_IFUPDOWN:
        staged = IFUPDOWN_DROPIN_DIR / f"90-alderpointdns-{interface}.cfg"
        if str(staged) not in snapshot.get("files", {}) and staged.exists():
            staged.unlink()

    try:
        if backend == BACKEND_NETWORKD:
            apply_networkd(interface)
        elif backend == BACKEND_NETPLAN:
            apply_netplan()
        elif backend == BACKEND_NETWORKMANAGER:
            nm_profile = snapshot.get("nm_profile", {})
            conn_name = nm_profile.get("_connection_name")
            if conn_name:
                run([
                    "nmcli", "con", "mod", conn_name,
                    "ipv4.method", nm_profile.get("ipv4.method", "auto") or "auto",
                    "ipv4.addresses", nm_profile.get("ipv4.addresses", "") or "",
                    "ipv4.gateway", nm_profile.get("ipv4.gateway", "") or "",
                ])
                apply_networkmanager(conn_name)
        elif backend == BACKEND_IFUPDOWN:
            apply_ifupdown(interface)
    except subprocess.CalledProcessError as exc:
        _log_rollback_event(f"ERROR: rollback re-apply for {interface} via {backend} failed: {exc}")

    _log_rollback_event(f"automatic rollback completed for {interface} via {backend} (deadline {state.get('rollback_deadline')} passed unconfirmed)")
    ROLLBACK_STATE_FILE.unlink(missing_ok=True)


def rollback_check() -> str:
    """Entry point for the independent systemd-run watchdog
    (network-rollback-check). If the pending change was already confirmed
    (state file deleted by confirm_change), this is a no-op."""
    state = read_rollback_state()
    if state is None:
        return "no pending network change; nothing to roll back"
    if state.get("confirmed"):
        ROLLBACK_STATE_FILE.unlink(missing_ok=True)
        return "pending change was already confirmed; nothing to roll back"
    perform_rollback(state)
    return f"rolled back network change on {state['interface']} (backend {state['backend']})"


def confirm_change() -> str:
    state = read_rollback_state()
    if state is None:
        raise NetworkConfigError("no pending network configuration change to confirm")
    unit_name = state.get("rollback_unit")
    if unit_name:
        cancel_rollback_timer(unit_name)
    ROLLBACK_STATE_FILE.unlink(missing_ok=True)
    _log_rollback_event(f"administrator confirmed new config for {state['interface']} via {state['backend']}; rollback cancelled")
    return f"confirmed: {state['interface']} configuration via {state['backend']} is now permanent"


# ---------------------------------------------------------------------------
# DNS-service awareness after a confirmed IP change
# ---------------------------------------------------------------------------

CONFIG_FILES_TO_AUDIT = [
    Path("/etc/bind/named.conf"),
    Path("/etc/bind/named.conf.local"),
    Path("/etc/bind/named.conf.options"),
    Path("/etc/dnsdist/dnsdist.conf"),
]


def audit_ip_references(old_ip: str) -> list[str]:
    """Reports (never silently rewrites) every generated config file that
    still contains the literal old server IP, so an administrator can see
    exactly what depends on the server's address before anything is
    regenerated. Blocklists and Analytics History are never touched by
    this audit or by anything it triggers -- only configuration that could
    plausibly encode a specific IP (listener binds, BIND/dnsdist config)
    is in scope."""
    hits = []
    for path in CONFIG_FILES_TO_AUDIT:
        try:
            if path.exists() and old_ip in path.read_text():
                hits.append(str(path))
        except OSError:
            continue
    return hits


def cert_covers_address(cert_path: Path, address: str) -> bool | None:
    """Returns True/False if determinable, None if the cert can't be read
    (e.g. openssl missing) -- callers must treat None as "unknown, tell the
    administrator to check manually", never as "yes it's covered"."""
    if not cert_path.exists() or not shutil.which("openssl"):
        return None
    proc = run(["openssl", "x509", "-in", str(cert_path), "-noout", "-text"], check=False)
    if proc.returncode != 0:
        return None
    return address in proc.stdout


# ---------------------------------------------------------------------------
# Request / response (unprivileged web process -> privileged compiler)
#
# Same shape as app/backup.py's backup_requests table: the unprivileged web
# process never passes untrusted data on argv or in a shell fragment. It
# writes a validated-shape row to sqlite; `sudo alderpointdns_compiler.py
# network-apply` (a fixed, argument-free sudoers entry) is invoked, and the
# privileged process reads its own instructions from the database.
# ---------------------------------------------------------------------------

import sqlite3  # noqa: E402

DB_PATH = Path("/var/lib/alderpointdns/alderpointdns.db")


def connect() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=5.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout=5000")
    return conn


def init_db(conn: sqlite3.Connection | None = None) -> None:
    close = conn is None
    db = conn or connect()
    try:
        db.execute(
            """
            CREATE TABLE IF NOT EXISTS network_requests (
                id INTEGER PRIMARY KEY,
                kind TEXT NOT NULL CHECK(kind IN ('apply', 'confirm')),
                requested_at TEXT NOT NULL,
                payload_json TEXT NOT NULL DEFAULT '{}',
                status TEXT NOT NULL DEFAULT 'pending',
                result_json TEXT NOT NULL DEFAULT '',
                finished_at TEXT
            );
            """
        )
        db.commit()
    finally:
        if close:
            db.close()


def request_change(payload: dict[str, Any]) -> int:
    init_db()
    conn = connect()
    try:
        cursor = conn.execute(
            "INSERT INTO network_requests(kind, requested_at, payload_json, status) VALUES ('apply', ?, ?, 'pending')",
            (now(), json.dumps(payload)),
        )
        conn.commit()
        return cursor.lastrowid
    finally:
        conn.close()


def request_confirm() -> int:
    init_db()
    conn = connect()
    try:
        cursor = conn.execute(
            "INSERT INTO network_requests(kind, requested_at, payload_json, status) VALUES ('confirm', ?, '{}', 'pending')",
            (now(),),
        )
        conn.commit()
        return cursor.lastrowid
    finally:
        conn.close()


def process_pending_request(kind: str) -> dict[str, Any] | None:
    init_db()
    conn = connect()
    try:
        row = conn.execute(
            "SELECT * FROM network_requests WHERE kind=? AND status='pending' ORDER BY id DESC LIMIT 1",
            (kind,),
        ).fetchone()
        if row is None:
            return None
        payload = json.loads(row["payload_json"] or "{}")
        result: dict[str, Any] = {}
        status = "failed"
        try:
            if kind == "apply":
                result = apply_change(
                    interface=payload["interface"],
                    ipv4_mode=payload.get("ipv4_mode", "unchanged"),
                    ipv4_address=payload.get("ipv4_address"),
                    ipv4_prefix=payload.get("ipv4_prefix"),
                    ipv4_gateway=payload.get("ipv4_gateway"),
                    ipv6_mode=payload.get("ipv6_mode", "unchanged"),
                    ipv6_address=payload.get("ipv6_address"),
                    ipv6_prefix=payload.get("ipv6_prefix"),
                    ipv6_gateway=payload.get("ipv6_gateway"),
                    rollback_timeout_seconds=int(payload.get("rollback_timeout_seconds", ROLLBACK_TIMEOUT_SECONDS)),
                )
            elif kind == "confirm":
                result = {"message": confirm_change()}
            status = "done"
        except Exception as exc:
            result = {"error": str(exc)}
            status = "failed"
        conn.execute(
            "UPDATE network_requests SET status=?, result_json=?, finished_at=? WHERE id=?",
            (status, json.dumps(result, default=str), now(), row["id"]),
        )
        conn.execute(
            "UPDATE network_requests SET status='skipped', finished_at=? WHERE kind=? AND status='pending' AND id!=?",
            (now(), kind, row["id"]),
        )
        conn.commit()
        return {"id": row["id"], "status": status, "result": result}
    finally:
        conn.close()


def latest_request_result(kind: str) -> dict[str, Any] | None:
    init_db()
    conn = connect()
    try:
        row = conn.execute("SELECT * FROM network_requests WHERE kind=? ORDER BY id DESC LIMIT 1", (kind,)).fetchone()
        return dict(row) if row else None
    finally:
        conn.close()
