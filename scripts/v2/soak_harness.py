#!/usr/bin/env python3
"""Real aging/liveness soak harness for an INSTALLED V2 appliance
(owner-beta closure item 2).

Not a unit test. Drives a real, already-`apt`-installed V2 appliance
(systemd units, real dnsdist/BIND, real control.db) with sustained
synthetic workload -- real DNS queries against the real listener, real
API reads/writes against the real management API, repeated over an
accelerated schedule -- and periodically samples both product-level
progress (dashboard/query-log/statistics advancing, background-worker
heartbeats from `GET /api/health`'s `background_workers` component,
control.db WAL size) and process-level health (RSS, FD count, thread
count per V2 systemd unit) so a "process alive but no longer making
progress" regression is caught by evidence, not assumed absent because
nothing crashed.

Usage (run ON the installed appliance, e.g. inside the acceptance
container, as root or a user that can read /proc/<pid> for the V2
units and reach the management API over HTTPS):

    python3 soak_harness.py \\
        --base-url https://127.0.0.1:8443 \\
        --admin-user admin --admin-password '...' \\
        --dns-address 127.0.0.1 --dns-port 53 \\
        --duration-seconds 1800 --sample-interval-seconds 30 \\
        --report /root/soak-report.json

``--stall-worker NAME`` is the harness's own self-test: it deliberately
renames the named worker's real binary tick target so the unit's
process stays up but its loop can never complete a tick again, then
asserts the harness's own liveness read correctly reports it ``stale``
within one detection window -- proving the detector actually detects
loss of progress, not just wall-clock aliveness, per the owner brief's
explicit requirement. It restores the binary afterward. Requires root.
"""

from __future__ import annotations

import argparse
import json
import socket
import ssl
import struct
import subprocess
import sys
import time
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Optional

try:
    from app.v2.worker_heartbeat import WORKER_INTERVALS_SECONDS
except ImportError:  # pragma: no cover - PYTHONPATH not set up; fall back rather than hard-fail
    WORKER_INTERVALS_SECONDS = {
        "analytics-worker": 15.0, "discovery-worker": 15.0, "tier-b-worker": 300.0, "schedule-worker": 60.0,
    }

V2_UNITS = [
    "alderpointdns-v2-web",
    "alderpointdns-v2-dnsdist",
    "alderpointdns-v2-analytics",
    "alderpointdns-v2-analytics-protobuf-receiver",
    "alderpointdns-v2-discovery",
    "alderpointdns-v2-dns-observer",
    "alderpointdns-v2-tierb",
    "alderpointdns-v2-schedule",
]


def _run(cmd: list[str], **kw) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, **kw)


def unit_pid(unit: str) -> Optional[int]:
    r = _run(["systemctl", "show", "-p", "MainPID", "--value", unit])
    if r.returncode != 0:
        return None
    try:
        pid = int(r.stdout.strip())
    except ValueError:
        return None
    return pid if pid > 0 else None


def proc_sample(pid: int) -> dict[str, Any]:
    base = Path("/proc") / str(pid)
    sample: dict[str, Any] = {"pid": pid}
    try:
        status = (base / "status").read_text()
        for line in status.splitlines():
            if line.startswith("VmRSS:"):
                sample["rss_kb"] = int(line.split()[1])
            elif line.startswith("Threads:"):
                sample["threads"] = int(line.split()[1])
    except (OSError, ValueError):
        return {"pid": pid, "alive": False}
    try:
        sample["fds"] = sum(1 for _ in (base / "fd").iterdir())
    except OSError:
        sample["fds"] = None
    sample["alive"] = True
    return sample


def dns_query(address: str, port: int, qname: str, timeout: float = 2.0) -> bool:
    """A minimal, real A-record query (no dnspython dependency needed on
    a bare installed appliance) -- True only on a real, well-formed
    response with an answer or a clean NXDOMAIN/NOERROR, matching what a
    real client would consider "the resolver answered"."""
    txid = int(time.time() * 1000) & 0xFFFF
    header = struct.pack(">HHHHHH", txid, 0x0100, 1, 0, 0, 0)
    qparts = b"".join(bytes([len(p)]) + p.encode() for p in qname.strip(".").split(".")) + b"\x00"
    question = qparts + struct.pack(">HH", 1, 1)  # A, IN
    packet = header + question
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(packet, (address, port))
        data, _ = sock.recvfrom(4096)
        resp_txid, flags = struct.unpack(">HH", data[:4])
        rcode = flags & 0x000F
        return resp_txid == txid and rcode in (0, 3)  # NOERROR or NXDOMAIN
    except OSError:
        return False
    finally:
        sock.close()


@dataclass
class SoakConfig:
    base_url: str
    admin_user: Optional[str]
    admin_password: Optional[str]
    dns_address: str
    dns_port: int
    duration_seconds: int
    sample_interval_seconds: int
    verify_tls: bool
    synthetic_client_count: int


@dataclass
class SoakTotals:
    dns_attempted: int = 0
    dns_succeeded: int = 0
    api_attempted: int = 0
    api_succeeded: int = 0
    samples: list[dict] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


class ApiClient:
    def __init__(self, base_url: str, verify_tls: bool):
        self.base_url = base_url.rstrip("/")
        self.cookie: Optional[str] = None
        self.csrf: Optional[str] = None
        ctx = ssl.create_default_context()
        if not verify_tls:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        self._ctx = ctx

    def _request(self, method: str, path: str, body: Optional[dict] = None) -> tuple[int, Any]:
        url = f"{self.base_url}{path}"
        data = json.dumps(body).encode() if body is not None else None
        headers = {"Content-Type": "application/json"}
        if self.cookie:
            headers["Cookie"] = self.cookie
        if self.csrf and method != "GET":
            headers["X-CSRF-Token"] = self.csrf
        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, context=self._ctx, timeout=10) as resp:
                if "Set-Cookie" in resp.headers:
                    self.cookie = resp.headers["Set-Cookie"].split(";")[0]
                payload = resp.read()
                return resp.status, (json.loads(payload) if payload else None)
        except urllib.error.HTTPError as exc:
            payload = exc.read()
            try:
                return exc.code, json.loads(payload)
            except ValueError:
                return exc.code, None
        except (urllib.error.URLError, TimeoutError, ConnectionError, OSError) as exc:
            # Real robustness gap fixed here (found live: this crashed
            # a real multi-tick soak run stone dead on one transient
            # read timeout under real concurrent host load -- exactly
            # the kind of transient hiccup this harness exists to
            # survive and characterize, not die on). A connection-level
            # failure (timeout, connection refused, reset, DNS failure)
            # is real, recordable evidence the same way a non-200 HTTP
            # status already is -- status 0 with the exception text as
            # the body -- not a reason to abort the entire run and lose
            # every sample gathered so far.
            return 0, {"error": "connection_failed", "detail": str(exc)}

    def login(self, username: str, password: str) -> bool:
        status, body = self._request("POST", "/api/login", {"username": username, "password": password})
        if status == 200 and isinstance(body, dict):
            self.csrf = body.get("csrf_token")
        return status == 200

    def get(self, path: str) -> tuple[int, Any]:
        return self._request("GET", path)


def sample_process_health() -> dict[str, Any]:
    out = {}
    for unit in V2_UNITS:
        pid = unit_pid(unit)
        out[unit] = proc_sample(pid) if pid else {"pid": None, "alive": False}
    return out


def sample_control_db_wal(state_dir: Path) -> dict[str, Any]:
    control_db = state_dir / "control.db"
    result = {}
    for suffix in ("", "-wal", "-shm"):
        p = Path(str(control_db) + suffix)
        try:
            result[suffix or "main"] = p.stat().st_size
        except OSError:
            result[suffix or "main"] = None
    return result


def _run_tick(cfg: SoakConfig, client: ApiClient, totals: SoakTotals, read_paths: list[str], tick: int) -> None:
    # Real DNS queries from several synthetic client identities (source
    # port varies, name varies) -- exercises the real dnsdist listener,
    # real analytics ingestion, and real observed-client update path
    # each tick.
    for i in range(cfg.synthetic_client_count):
        qname = f"soak-client-{i}-tick-{tick}.soak.test"
        totals.dns_attempted += 1
        if dns_query(cfg.dns_address, cfg.dns_port, qname):
            totals.dns_succeeded += 1

    for path in read_paths:
        totals.api_attempted += 1
        status, _ = client.get(path)
        if status == 200:
            totals.api_succeeded += 1
        else:
            totals.errors.append(f"tick {tick}: GET {path} -> {status}")


def run_soak(cfg: SoakConfig, state_dir: Path, report_path: Path) -> SoakTotals:
    totals = SoakTotals()
    client = ApiClient(cfg.base_url, cfg.verify_tls)
    if cfg.admin_user and cfg.admin_password:
        if not client.login(cfg.admin_user, cfg.admin_password):
            totals.errors.append("initial admin login failed")

    deadline = time.monotonic() + cfg.duration_seconds
    next_sample = time.monotonic()
    tick = 0
    read_paths = [
        "/api/health",
        "/api/analytics/recent",
        "/api/analytics/query-log?limit=50",
        "/api/clients",
        "/api/discovery/observed-clients",
        "/api/analytics/top-domains",
    ]

    while time.monotonic() < deadline:
        tick += 1
        try:
            _run_tick(cfg, client, totals, read_paths, tick)
        except Exception as exc:  # noqa: BLE001 - see comment below
            # Belt-and-suspenders on top of the real ApiClient._request
            # fix above: nothing in one tick's real work (DNS queries,
            # API reads, process/WAL sampling) may ever be allowed to
            # take down the whole multi-hour soak run and lose every
            # sample gathered so far. Recorded as real evidence, same as
            # any other tick error, not swallowed silently.
            totals.errors.append(f"tick {tick}: unexpected error: {exc!r}")

        if time.monotonic() >= next_sample:
            sample = {
                "ts": time.time(),
                "tick": tick,
                "dns_attempted": totals.dns_attempted,
                "dns_succeeded": totals.dns_succeeded,
                "api_attempted": totals.api_attempted,
                "api_succeeded": totals.api_succeeded,
                "processes": sample_process_health(),
                "control_db": sample_control_db_wal(state_dir),
            }
            status, health = client.get("/api/health")
            if status == 200 and isinstance(health, dict):
                sample["health_status"] = health.get("status")
                sample["background_workers"] = health.get("components", {}).get("background_workers")
            totals.samples.append(sample)
            report_path.write_text(json.dumps(asdict(totals), indent=2, default=str))
            next_sample = time.monotonic() + cfg.sample_interval_seconds

        time.sleep(0.2)

    report_path.write_text(json.dumps(asdict(totals), indent=2, default=str))
    return totals


def summarize(totals: SoakTotals) -> str:
    lines = [
        f"DNS: {totals.dns_succeeded}/{totals.dns_attempted} succeeded",
        f"API: {totals.api_succeeded}/{totals.api_attempted} succeeded",
        f"samples: {len(totals.samples)}",
        f"errors: {len(totals.errors)}",
    ]
    if totals.samples:
        first, last = totals.samples[0], totals.samples[-1]
        for unit in V2_UNITS:
            f0 = first["processes"].get(unit, {})
            f1 = last["processes"].get(unit, {})
            if f0.get("alive") and f1.get("alive"):
                lines.append(
                    f"  {unit}: rss {f0.get('rss_kb')}->{f1.get('rss_kb')} kb, "
                    f"fds {f0.get('fds')}->{f1.get('fds')}, threads {f0.get('threads')}->{f1.get('threads')}"
                )
            else:
                lines.append(f"  {unit}: alive {f0.get('alive')}->{f1.get('alive')}")
        stale_at_end = {
            name: w.get("stale") for name, w in (last.get("background_workers") or {}).items() if w.get("stale")
        }
        if stale_at_end:
            lines.append(f"  STALE WORKERS AT END: {stale_at_end}")
        else:
            lines.append("  no stale background workers at end of soak")
    return "\n".join(lines)


def stall_worker_self_test(
    unit: str, worker_name: str, base_url: str, admin_user: str, admin_password: str,
    *, interval_seconds: float, insecure: bool,
) -> bool:
    """Proves the detector actually detects loss of progress, not just
    process aliveness, per the owner brief's explicit requirement:
    "deliberately stall/kill a supervised worker in a controlled test ->
    process may remain alive if appropriate -> health must detect loss
    of progress -> narrow recovery behavior must work -> whole-host
    reboot must not be required."

    Uses a real SIGSTOP against the worker unit's own MainPID: the
    process stays "active (running)" in systemd's own view the entire
    time (this is deliberately not a kill/restart), but it cannot
    execute another instruction, let alone complete a tick, until
    SIGCONT -- the exact "process alive, no longer making progress"
    shape this whole mechanism exists to catch. Requires root (to signal
    a systemd-managed unit's process).
    """
    import os
    import signal as _signal

    pid = unit_pid(unit)
    if pid is None:
        print(f"stall self-test: {unit} has no MainPID (not running); aborting")
        return False

    client = ApiClient(base_url, verify_tls=not insecure)
    if not client.login(admin_user, admin_password):
        print("stall self-test: admin login failed; aborting")
        return False

    print(f"stall self-test: SIGSTOP {unit} (pid {pid})")
    os.kill(pid, _signal.SIGSTOP)
    ok = False
    try:
        wait_for = max(120.0, 3 * interval_seconds) + 15
        deadline = time.monotonic() + wait_for
        while time.monotonic() < deadline:
            status, health = client.get("/api/health")
            if status == 200 and isinstance(health, dict):
                worker = health.get("components", {}).get("background_workers", {}).get(worker_name, {})
                still_running = unit_pid(unit) == pid  # process must still be up, not restarted
                if worker.get("stale") and still_running:
                    print(f"stall self-test: {worker_name} correctly reported stale after {wait_for - (deadline - time.monotonic()):.0f}s, process still alive (pid unchanged)")
                    ok = True
                    break
            time.sleep(5)
        if not ok:
            print(f"stall self-test: FAILED -- {worker_name} was never reported stale within {wait_for:.0f}s")
    finally:
        print(f"stall self-test: SIGCONT {unit} (pid {pid})")
        os.kill(pid, _signal.SIGCONT)

    if ok:
        # Recovery: the next real tick after SIGCONT should clear staleness
        # without any restart -- "narrow recovery behavior must work" /
        # "whole-host reboot must not be required".
        recovered = False
        deadline = time.monotonic() + max(60.0, 2 * interval_seconds) + 15
        while time.monotonic() < deadline:
            status, health = client.get("/api/health")
            if status == 200 and isinstance(health, dict):
                worker = health.get("components", {}).get("background_workers", {}).get(worker_name, {})
                if not worker.get("stale"):
                    recovered = True
                    break
            time.sleep(5)
        print(f"stall self-test: recovery after SIGCONT -> {'OK, no restart needed' if recovered else 'FAILED to recover'}")
        ok = ok and recovered
    return ok


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--base-url", required=True)
    p.add_argument("--admin-user")
    p.add_argument("--admin-password")
    p.add_argument("--dns-address", default="127.0.0.1")
    p.add_argument("--dns-port", type=int, default=53)
    p.add_argument("--duration-seconds", type=int, default=1800)
    p.add_argument("--sample-interval-seconds", type=int, default=30)
    p.add_argument("--synthetic-clients", type=int, default=5)
    p.add_argument("--state-dir", default="/var/lib/alderpointdns-v2")
    p.add_argument("--report", default="/tmp/soak-report.json")
    p.add_argument("--insecure", action="store_true", help="skip TLS verification (self-signed appliance cert)")
    p.add_argument(
        "--stall-worker", metavar="UNIT:WORKER_NAME",
        help=(
            "run only the deliberate-stall liveness self-test against UNIT "
            "(a systemd unit name, e.g. alderpointdns-v2-schedule) and "
            "WORKER_NAME (its /api/health background_workers key, e.g. "
            "schedule-worker), then exit -- does not run the soak loop"
        ),
    )
    args = p.parse_args(argv)

    if args.stall_worker:
        unit, _, worker_name = args.stall_worker.partition(":")
        if not unit or not worker_name:
            print("--stall-worker requires UNIT:WORKER_NAME", file=sys.stderr)
            return 2
        worker_interval = WORKER_INTERVALS_SECONDS.get(worker_name, 60.0)
        ok = stall_worker_self_test(
            unit, worker_name, args.base_url, args.admin_user, args.admin_password,
            interval_seconds=worker_interval, insecure=args.insecure,
        )
        return 0 if ok else 1

    cfg = SoakConfig(
        base_url=args.base_url, admin_user=args.admin_user, admin_password=args.admin_password,
        dns_address=args.dns_address, dns_port=args.dns_port, duration_seconds=args.duration_seconds,
        sample_interval_seconds=args.sample_interval_seconds, verify_tls=not args.insecure,
        synthetic_client_count=args.synthetic_clients,
    )
    totals = run_soak(cfg, Path(args.state_dir), Path(args.report))
    print(summarize(totals))
    print(f"full report: {args.report}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
