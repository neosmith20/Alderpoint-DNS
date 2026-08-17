"""Gate #2 Blocker 1: DoH upstream profiles must never silently downgrade
to plaintext. Real dnsdist 2.1.1 DoH backend support was verified against
the installed binary (a live isolated instance completed a real DoH
request over HTTPS/443 to Cloudflare, backend health check logged
``backend.protocol="DoH"``) -- so this is IMPLEMENT-IT-CORRECTLY, not
reject-at-compile-time.
"""

from __future__ import annotations

import shutil
import socket
import struct
import subprocess
import time
from pathlib import Path

import pytest

from app.v2 import control_db, policy_store as store
from app.v2.dnsdist_gen import (
    DnsdistGenError,
    generate_dnsdist_config_from_profiles,
    stage_and_validate_dnsdist_config,
)

from tests.v2._network_probe import network_reachable

DNSDIST_INSTALLED = shutil.which("dnsdist") is not None

# Real round-trip probe, not just route existence -- see
# docs/v2/handoff-workstream-6-cc-session.md. TestRealEndToEndDoH below
# genuinely needs real internet+TLS (a real Cloudflare DoH handshake is
# the point of that test), so it stays network-gated rather than moved
# to a local backend.
NETWORK_OK = network_reachable()


@pytest.fixture()
def conn(tmp_path):
    path = tmp_path / "control.db"
    store.ensure_schema(path)
    with control_db.connect(path) as c:
        yield c


class TestDoHProfileCreationValidation:
    def test_doh_without_tls_hostname_rejected_at_creation(self, conn):
        eps = [store.UpstreamEndpointRecord("1.1.1.1:443", None, 0, 1, None)]
        with pytest.raises(store.PolicyStoreError):
            store.create_upstream_profile(conn, "doh1", "DoH", "doh", eps)

    def test_doh_with_tls_hostname_accepted(self, conn):
        eps = [
            store.UpstreamEndpointRecord(
                "1.1.1.1:443", "cloudflare-dns.com", 0, 1, None, doh_path="/dns-query"
            )
        ]
        store.create_upstream_profile(conn, "doh2", "DoH", "doh", eps)
        loaded = store.load_upstream_profile(conn, "doh2")
        assert loaded.endpoints[0].doh_path == "/dns-query"

    def test_doh_path_defaults_when_omitted(self, conn):
        eps = [store.UpstreamEndpointRecord("1.1.1.1:443", "cloudflare-dns.com", 0, 1, None)]
        store.create_upstream_profile(conn, "doh3", "DoH", "doh", eps)
        loaded = store.load_upstream_profile(conn, "doh3")
        assert loaded.endpoints[0].doh_path == "/dns-query"

    def test_malformed_doh_path_rejected(self, conn):
        eps = [
            store.UpstreamEndpointRecord(
                "1.1.1.1:443", "cloudflare-dns.com", 0, 1, None, doh_path="no-leading-slash"
            )
        ]
        with pytest.raises(store.PolicyStoreError):
            store.create_upstream_profile(conn, "doh4", "DoH", "doh", eps)

    def test_doh_path_with_newline_rejected(self, conn):
        eps = [
            store.UpstreamEndpointRecord(
                "1.1.1.1:443", "cloudflare-dns.com", 0, 1, None, doh_path="/dns-query\nEvil: x"
            )
        ]
        with pytest.raises(store.PolicyStoreError):
            store.create_upstream_profile(conn, "doh5", "DoH", "doh", eps)


class TestGenerationNeverDowngrades:
    def _doh_profile(self):
        eps = (
            store.UpstreamEndpointRecord(
                "1.1.1.1:443", "cloudflare-dns.com", 0, 1, None, doh_path="/dns-query"
            ),
        )
        return store.UpstreamProfileRecord("doh-default", "DoH", "doh", "ordered", eps)

    def test_generated_config_never_contains_bare_plaintext_443_server(self):
        text = generate_dnsdist_config_from_profiles("127.0.0.1:5300", [], self._doh_profile())
        assert 'newServer({address="1.1.1.1:443"})' not in text
        assert 'tls="openssl"' in text
        assert 'dohPath="/dns-query"' in text
        assert 'subjectName="cloudflare-dns.com"' in text

    def test_dot_still_generates_correctly(self):
        eps = (store.UpstreamEndpointRecord("9.9.9.9:853", "dns.quad9.net", 0, 1, None),)
        profile = store.UpstreamProfileRecord("dot1", "DoT", "dot", "ordered", eps)
        text = generate_dnsdist_config_from_profiles("127.0.0.1:5300", [], profile)
        assert 'tls="openssl"' in text
        assert "dohPath" not in text

    def test_plain_still_generates_correctly(self):
        eps = (store.UpstreamEndpointRecord("8.8.8.8:53", None, 0, 1, None),)
        profile = store.UpstreamProfileRecord("plain1", "Plain", "plain", "ordered", eps)
        text = generate_dnsdist_config_from_profiles("127.0.0.1:5300", [], profile)
        assert 'newServer({address="8.8.8.8:53"})' in text
        assert "tls=" not in text

    def test_generator_refuses_to_synthesize_doh_without_tls_hostname_defense_in_depth(self):
        # Bypasses policy_store's own guard by constructing the record
        # directly -- generation itself must be the second layer of
        # defense, never trusting that every caller went through
        # create_upstream_profile.
        eps = (store.UpstreamEndpointRecord("1.1.1.1:443", None, 0, 1, None, doh_path="/dns-query"),)
        profile = store.UpstreamProfileRecord("doh-bad", "Bad DoH", "doh", "ordered", eps)
        with pytest.raises(DnsdistGenError):
            generate_dnsdist_config_from_profiles("127.0.0.1:5300", [], profile)


@pytest.mark.skipif(
    not (DNSDIST_INSTALLED and NETWORK_OK), reason="requires installed dnsdist and network"
)
class TestRealEndToEndDoH:
    def test_generated_doh_config_validates_and_actually_resolves_over_https(self, tmp_path):
        eps = (
            store.UpstreamEndpointRecord(
                "1.1.1.1:443", "cloudflare-dns.com", 0, 1, None, doh_path="/dns-query"
            ),
        )
        profile = store.UpstreamProfileRecord("doh-e2e", "DoH E2E", "doh", "ordered", eps)
        text = generate_dnsdist_config_from_profiles("127.0.0.1:15340", [], profile)

        staging = tmp_path / "staging"
        staging.mkdir()
        live = tmp_path / "live" / "dnsdist.conf"
        result = stage_and_validate_dnsdist_config(staging, text, live)
        assert result.promoted

        proc = subprocess.Popen(
            ["dnsdist", "-C", str(live), "--supervised", "--disable-syslog"],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        )
        try:
            time.sleep(1.5)
            header = struct.pack(">HHHHHH", 1, 0x0100, 1, 0, 0, 0)
            qparts = b"".join(bytes([len(p)]) + p.encode() for p in "example.com".split("."))
            pkt = header + qparts + b"\x00" + struct.pack(">HH", 1, 1)
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(5)
            s.sendto(pkt, ("127.0.0.1", 15340))
            data, _ = s.recvfrom(4096)
            s.close()
            assert len(data) > 0
            rcode = struct.unpack(">H", data[2:4])[0] & 0xF
            assert rcode == 0
        finally:
            proc.terminate()
            out = proc.communicate(timeout=5)[0]
            # Confirm the backend was actually established as DoH, not
            # silently treated as a plain/Do53 backend by dnsdist itself.
            assert 'backend.protocol="DoH"' in out


class TestMigrationDoHHandling:
    def test_source_doh_resolver_without_tls_hostname_skipped_not_downgraded(self, tmp_path):
        import sqlite3

        from app.v2 import migration_convert as mconv
        from tests.v2._v1_fixture import build_v1_fixture

        source = tmp_path / "v1-install"
        db_path = build_v1_fixture(source / "alderpointdns.db")
        conn = sqlite3.connect(str(db_path))
        conn.execute("DELETE FROM upstream_resolvers")
        conn.execute(
            "INSERT INTO upstream_resolvers VALUES (2, 'Bad DoH', 'doh', '1.1.1.1', 443, "
            "'/dns-query', '', 1, 0, '2026-01-01T00:00:00', '2026-01-01T00:00:00')"
        )
        conn.commit()
        conn.close()

        manifest = mconv.create_backup(db_path, tmp_path / "staging")
        target = tmp_path / "control.db"
        mconv.initialize_target_control_db(target)
        result = mconv.migrate_upstreams(Path(manifest["backup_path"]), target)
        assert result["migrated"] == 0
        assert any("DoH" in w for w in result["warnings"])
        with control_db.connect(target) as c:
            profile = store.load_upstream_profile(c, "migrated-default")
        assert profile is None  # never created with a silently-downgraded transport
