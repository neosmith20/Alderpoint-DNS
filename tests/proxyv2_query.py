#!/usr/bin/env python3
from __future__ import annotations

import argparse
import ipaddress
import socket
import struct
import sys


PROXY_V2_SIGNATURE = b"\r\n\r\n\0\r\nQUIT\n"


def dns_query(name: str) -> bytes:
    labels = name.rstrip(".").split(".")
    question = b"".join(bytes([len(label)]) + label.encode("ascii") for label in labels) + b"\0"
    header = struct.pack("!HHHHHH", 0xB67D, 0x0100, 1, 0, 0, 0)
    return header + question + struct.pack("!HH", 1, 1)


def proxy_header(source_ip: str) -> bytes:
    src = ipaddress.ip_address(source_ip)
    dst = ipaddress.ip_address("127.0.0.1")
    if src.version != 4:
        raise ValueError("this test helper currently sends IPv4 PROXYv2 headers")
    payload = src.packed + dst.packed + struct.pack("!HH", 53000, 5354)
    return PROXY_V2_SIGNATURE + b"\x21\x11" + struct.pack("!H", len(payload)) + payload


def query(source_ip: str, name: str) -> int:
    wire_query = dns_query(name)
    request = proxy_header(source_ip) + struct.pack("!H", len(wire_query)) + wire_query
    with socket.create_connection(("127.0.0.1", 5354), timeout=5) as sock:
        sock.sendall(request)
        raw_len = sock.recv(2)
        if len(raw_len) != 2:
            raise RuntimeError("short DNS response length")
        response_len = struct.unpack("!H", raw_len)[0]
        response = b""
        while len(response) < response_len:
            chunk = sock.recv(response_len - len(response))
            if not chunk:
                break
            response += chunk
    if len(response) < 4:
        raise RuntimeError("short DNS response")
    return response[3] & 0x0F


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("name")
    parser.add_argument("--source-ip", required=True)
    parser.add_argument("--expect-rcode", type=int, required=True)
    args = parser.parse_args()

    rcode = query(args.source_ip, args.name)
    if rcode != args.expect_rcode:
        print(f"expected rcode {args.expect_rcode}, got {rcode}", file=sys.stderr)
        return 1
    print(f"proxyv2 query source={args.source_ip} rcode={rcode}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
