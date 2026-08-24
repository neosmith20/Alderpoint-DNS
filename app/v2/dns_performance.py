"""Bounded DNS performance report storage and safe benchmark runner."""

from __future__ import annotations

import json
import http.client
import math
import os
import random
import socket
import ssl
import statistics
import struct
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

STATE_ROOT = Path(os.environ.get("ALDERPOINTDNS_V2_STATE_ROOT", "/var/lib/alderpointdns-v2"))
REPORT_DIR = STATE_ROOT / "dns-performance"
REPORT_PATH = REPORT_DIR / "latest-report.json"


def _question(name: str, qtype: int = 1) -> bytes:
    labels = [p for p in name.rstrip(".").split(".") if p]
    body = b"".join(bytes([len(p)]) + p.encode("idna") for p in labels)
    return body + b"\x00" + struct.pack(">HH", qtype, 1)


def _query_packet(name: str, qtype: int = 1) -> tuple[int, bytes]:
    query_id = random.randint(1, 65535)
    header = struct.pack(">HHHHHH", query_id, 0x0100, 1, 0, 0, 0)
    return query_id, header + _question(name, qtype)


def _rcode(packet: bytes) -> int | None:
    if len(packet) < 12:
        return None
    return packet[3] & 0x0F


def _recv_exact(sock: socket.socket | ssl.SSLSocket, size: int) -> bytes:
    data = b""
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            break
        data += chunk
    return data


def _tcp_dns_exchange(sock: socket.socket | ssl.SSLSocket, packet: bytes) -> bytes:
    sock.sendall(struct.pack(">H", len(packet)) + packet)
    hdr = _recv_exact(sock, 2)
    if len(hdr) != 2:
        raise TimeoutError("short TCP length header")
    size = struct.unpack(">H", hdr)[0]
    return _recv_exact(sock, size)


def _tls_context() -> ssl.SSLContext:
    # This is an internal performance diagnostic. Certificate chain
    # validation is intentionally excluded from query-latency timing; TLS
    # handshake timing is measured separately from established-query timing.
    return ssl._create_unverified_context()


def _https_dns_exchange(conn: http.client.HTTPSConnection, path: str, packet: bytes) -> bytes:
    conn.request("POST", path, body=packet, headers={"content-type": "application/dns-message", "accept": "application/dns-message"})
    res = conn.getresponse()
    data = res.read()
    if res.status != 200:
        raise OSError(f"DoH HTTP {res.status}")
    return data


def query_once(
    server: str,
    port: int,
    name: str,
    qtype: int = 1,
    protocol: str = "udp",
    timeout: float = 2.0,
    path: str = "/dns-query",
) -> dict[str, Any]:
    query_id, packet = _query_packet(name, qtype)
    started = time.perf_counter_ns()
    try:
        if protocol == "tcp":
            with socket.create_connection((server, port), timeout=timeout) as sock:
                sock.settimeout(timeout)
                data = _tcp_dns_exchange(sock, packet)
        elif protocol == "dot":
            with socket.create_connection((server, port), timeout=timeout) as raw:
                raw.settimeout(timeout)
                with _tls_context().wrap_socket(raw, server_hostname=server) as sock:
                    sock.settimeout(timeout)
                    data = _tcp_dns_exchange(sock, packet)
        elif protocol == "doh":
            conn = http.client.HTTPSConnection(server, port, timeout=timeout, context=_tls_context())
            try:
                data = _https_dns_exchange(conn, path, packet)
            finally:
                conn.close()
        else:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.settimeout(timeout)
                sock.sendto(packet, (server, port))
                data, _addr = sock.recvfrom(4096)
        elapsed_ms = (time.perf_counter_ns() - started) / 1_000_000.0
        response_id = struct.unpack(">H", data[:2])[0] if len(data) >= 2 else None
        return {
            "ok": response_id == query_id,
            "timeout": False,
            "latency_ms": elapsed_ms,
            "rcode": _rcode(data),
            "bytes": len(data),
        }
    except (OSError, TimeoutError, http.client.HTTPException, ssl.SSLError) as exc:
        return {"ok": False, "timeout": True, "latency_ms": (time.perf_counter_ns() - started) / 1_000_000.0, "error": str(exc)}


def query_many_established(case: "BenchmarkCase") -> list[dict[str, Any]]:
    samples: list[dict[str, Any]] = []
    protocol = case.protocol.replace("-established", "")
    try:
        if protocol == "dot":
            raw = socket.create_connection((case.server, case.port), timeout=case.timeout)
            raw.settimeout(case.timeout)
            conn: Any = _tls_context().wrap_socket(raw, server_hostname=case.server)
            conn.settimeout(case.timeout)
        elif protocol == "doh":
            conn = http.client.HTTPSConnection(case.server, case.port, timeout=case.timeout, context=_tls_context())
        else:
            raise ValueError(f"unsupported established protocol: {case.protocol}")
        try:
            for _ in range(max(1, case.queries)):
                query_id, packet = _query_packet(case.domain, case.qtype)
                started = time.perf_counter_ns()
                try:
                    data = _tcp_dns_exchange(conn, packet) if protocol == "dot" else _https_dns_exchange(conn, case.path, packet)
                    elapsed_ms = (time.perf_counter_ns() - started) / 1_000_000.0
                    response_id = struct.unpack(">H", data[:2])[0] if len(data) >= 2 else None
                    samples.append({"ok": response_id == query_id, "timeout": False, "latency_ms": elapsed_ms, "rcode": _rcode(data), "bytes": len(data)})
                except (OSError, TimeoutError, http.client.HTTPException, ssl.SSLError) as exc:
                    samples.append({"ok": False, "timeout": True, "latency_ms": (time.perf_counter_ns() - started) / 1_000_000.0, "error": str(exc)})
        finally:
            conn.close()
    except (OSError, TimeoutError, http.client.HTTPException, ssl.SSLError) as exc:
        samples.append({"ok": False, "timeout": True, "latency_ms": 0.0, "error": f"connection setup failed: {exc}"})
    return samples


def _percentile(values: list[float], pct: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    idx = min(len(ordered) - 1, max(0, math.ceil((pct / 100.0) * len(ordered)) - 1))
    return ordered[idx]


def summarize(samples: list[dict[str, Any]]) -> dict[str, Any]:
    latencies = [float(s["latency_ms"]) for s in samples if s.get("ok") and not s.get("timeout")]
    errors = [s for s in samples if not s.get("ok")]
    return {
        "count": len(samples),
        "success": len(latencies),
        "timeouts": sum(1 for s in samples if s.get("timeout")),
        "errors": len(errors),
        "p50_ms": round(statistics.median(latencies), 3) if latencies else None,
        "p95_ms": round(_percentile(latencies, 95) or 0, 3) if latencies else None,
        "p99_ms": round(_percentile(latencies, 99) or 0, 3) if latencies else None,
        "max_ms": round(max(latencies), 3) if latencies else None,
        "servfail": sum(1 for s in samples if s.get("rcode") == 2),
        "nxdomain": sum(1 for s in samples if s.get("rcode") == 3),
    }


@dataclass(frozen=True)
class BenchmarkCase:
    name: str
    scope: str
    server: str
    port: int
    domain: str
    qtype: int = 1
    protocol: str = "udp"
    queries: int = 100
    timeout: float = 2.0
    path: str = "/dns-query"


def run_benchmark(cases: list[BenchmarkCase], *, pause_seconds: float = 0.0) -> dict[str, Any]:
    started = time.time()
    results = []
    for case in cases:
        samples = []
        for _ in range(max(1, case.queries)):
            if case.protocol.endswith("-established"):
                samples = query_many_established(case)
                break
            samples.append(query_once(case.server, case.port, case.domain, case.qtype, case.protocol, case.timeout, case.path))
            if pause_seconds:
                time.sleep(pause_seconds)
        results.append({
            "name": case.name,
            "scope": case.scope,
            "server": case.server,
            "port": case.port,
            "domain": case.domain,
            "qtype": case.qtype,
            "protocol": case.protocol,
            "latency_scope": "established connection" if case.protocol.endswith("-established") else "includes connection setup for TCP/TLS protocols",
            "summary": summarize(samples),
        })
    finished = time.time()
    return {
        "schema": 1,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(finished)),
        "duration_seconds": round(finished - started, 3),
        "notes": [
            "Client-observed timings use a monotonic high-resolution timer around the DNS exchange.",
            "Cold external totals include upstream/authoritative network waiting outside Alderpoint control.",
            "Alderpoint-controlled hot/local/block targets are measured separately from cold external targets.",
            "DoT/DoH initial TLS handshake and established-connection query latency are reported as separate cases.",
        ],
        "cases": results,
    }


def save_report(report: dict[str, Any], path: Path = REPORT_PATH) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")
    tmp.chmod(0o644)
    tmp.replace(path)


def read_report(path: Path = REPORT_PATH) -> dict[str, Any] | None:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return None
    except PermissionError:
        return {"schema": 1, "error": "stored DNS performance report is not readable by the management service"}
    except json.JSONDecodeError:
        return {"schema": 1, "error": "stored DNS performance report is malformed"}
