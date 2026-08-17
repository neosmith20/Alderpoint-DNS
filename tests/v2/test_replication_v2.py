import json
import inspect
import socket
import ssl
from pathlib import Path

import pytest

from app.v2 import control_db, node_identity, observed_clients, policy_store, replication_v2
from app.v2.secret_store import SecretStore


def _init(path: Path):
    control_db.initialize(path)
    policy_store.ensure_schema(path)
    replication_v2.ensure_schema(path)


def _trust_pair(conn_a, conn_b, tmp_path):
    ca_pem, ca_key = replication_v2.generate_private_ca("test-ca")
    id_a = node_identity.get_or_create(conn_a).node_id
    id_b = node_identity.get_or_create(conn_b).node_id
    cert_a, key_a = replication_v2.issue_node_cert(ca_pem, ca_key, id_a)
    cert_b, key_b = replication_v2.issue_node_cert(ca_pem, ca_key, id_b)
    replication_v2.upsert_peer(
        conn_a,
        peer_node_id=id_b,
        display_name="b",
        url="https://localhost:1/replication/v1/apply",
        ca_pem=ca_pem,
        expected_cert_sha256=replication_v2.cert_fingerprint_sha256(cert_b),
        client_cert_pem=cert_a,
        client_key_pem=key_a,
    )
    replication_v2.upsert_peer(
        conn_b,
        peer_node_id=id_a,
        display_name="a",
        url="https://localhost:1/replication/v1/apply",
        ca_pem=ca_pem,
        expected_cert_sha256=replication_v2.cert_fingerprint_sha256(cert_a),
        client_cert_pem=cert_b,
        client_key_pem=key_b,
    )
    return ca_pem, (cert_a, key_a), (cert_b, key_b)


def test_node_identity_stable_and_explicit_regeneration(tmp_path):
    db = tmp_path / "control.db"
    _init(db)
    with control_db.connect(db) as conn:
        first = node_identity.get_or_create(conn)
        second = node_identity.get_or_create(conn)
        assert first.node_id == second.node_id
        regenerated = node_identity.regenerate_node_identity(conn)
        assert regenerated.node_id != first.node_id
        assert regenerated.regenerated_at is not None


def test_control_and_secret_snapshot_applies_without_control_db_secret_leak(tmp_path):
    db_a = tmp_path / "a.db"
    db_b = tmp_path / "b.db"
    _init(db_a)
    _init(db_b)
    secret_marker = "WS4C-CANARY-plain-secret-value"
    secrets_a = SecretStore(tmp_path / "secrets-a")
    secrets_b = SecretStore(tmp_path / "secrets-b")
    secrets_a.create(secret_marker, secret_id="notify-token")
    with control_db.connect(db_a) as a, control_db.connect(db_b) as b:
        _trust_pair(a, b, tmp_path)
        policy_store.create_network(a, "lan", "10.4.0.0/24")
        msg = replication_v2.build_message(a, secrets_a)
        result = replication_v2.apply_message(b, secrets_b, msg)
        assert result["applied"] is True
        assert b.execute("SELECT cidr FROM policy_networks WHERE network_id='lan'").fetchone()[0] == "10.4.0.0/24"
    assert secrets_b.get("notify-token") == secret_marker
    assert secret_marker.encode() not in db_b.read_bytes()


def test_unknown_peer_and_identity_mismatch_fail_closed(tmp_path):
    db_a = tmp_path / "a.db"
    db_b = tmp_path / "b.db"
    _init(db_a)
    _init(db_b)
    with control_db.connect(db_a) as a, control_db.connect(db_b) as b:
        msg = replication_v2.build_message(a, SecretStore(tmp_path / "sa"))
        with pytest.raises(replication_v2.ReplicationAuthError):
            replication_v2.apply_message(b, SecretStore(tmp_path / "sb"), msg)
        ca, ca_key = replication_v2.generate_private_ca("test-ca")
        cert_wrong, _ = replication_v2.issue_node_cert(ca, ca_key, "different-node")
        sender = msg["sender_node_id"]
        replication_v2.upsert_peer(
            b,
            peer_node_id=sender,
            display_name="a",
            url="https://localhost:1/replication/v1/apply",
            ca_pem=ca,
            expected_cert_sha256=replication_v2.cert_fingerprint_sha256(cert_wrong),
        )
        with pytest.raises(replication_v2.ReplicationAuthError):
            replication_v2.apply_message(b, SecretStore(tmp_path / "sb"), msg, peer_cert_pem=cert_wrong)


def test_replay_stale_and_conflict_semantics(tmp_path):
    db_a = tmp_path / "a.db"
    db_b = tmp_path / "b.db"
    _init(db_a)
    _init(db_b)
    with control_db.connect(db_a) as a, control_db.connect(db_b) as b:
        _trust_pair(a, b, tmp_path)
        msg = replication_v2.build_message(a, SecretStore(tmp_path / "sa"), message_id="m1")
        assert replication_v2.apply_message(b, SecretStore(tmp_path / "sb"), msg)["applied"] is True
        with pytest.raises(replication_v2.ReplicationAuthError):
            replication_v2.apply_message(b, SecretStore(tmp_path / "sb"), msg)
        stale = dict(msg)
        stale["message_id"] = "m2"
        stale["generation"] = msg["generation"] - 1
        assert replication_v2.apply_message(b, SecretStore(tmp_path / "sb"), stale)["reason"] == "stale_generation"
        conflict = dict(msg)
        conflict["message_id"] = "m3"
        conflict["content_hash"] = "0" * 64
        with pytest.raises(replication_v2.ReplicationError):
            replication_v2.apply_message(b, SecretStore(tmp_path / "sb"), conflict)


def test_apply_message_real_recompile_uses_configured_listen_address_not_loopback_default(tmp_path):
    # Real regression found live during RC1 clean-install acceptance
    # testing: a real (non-mocked) recompile triggered by applying
    # replicated state used to call runtime_compile.recompile_and_promote()
    # without threading through any listen_address at all, silently
    # falling back to its own loopback-only default -- rebinding this
    # node's dnsdist away from real LAN clients the moment it applied any
    # replicated change, with no error. Real dnsdist validation, no mocks.
    db_a = tmp_path / "a.db"
    db_b = tmp_path / "b.db"
    _init(db_a)
    _init(db_b)
    with control_db.connect(db_a) as a, control_db.connect(db_b) as b:
        _trust_pair(a, b, tmp_path)
        msg = replication_v2.build_message(a, SecretStore(tmp_path / "sa"))
        result = replication_v2.apply_message(
            b,
            SecretStore(tmp_path / "sb"),
            msg,
            staging_dir=tmp_path / "staging",
            live_dnsdist_conf_path=tmp_path / "dnsdist.conf",
            listen_address="10.20.30.40:53",
        )
    assert result["applied"] is True
    conf_text = (tmp_path / "dnsdist.conf").read_text()
    assert 'setLocal("10.20.30.40:53")' in conf_text
    assert 'setLocal("127.0.0.1:53")' not in conf_text


def test_apply_message_real_recompile_defaults_to_sane_listen_address(tmp_path):
    # Omitting listen_address entirely (e.g. an older caller) must still
    # fail toward "reachable," not silently loopback-only.
    db_a = tmp_path / "a.db"
    db_b = tmp_path / "b.db"
    _init(db_a)
    _init(db_b)
    with control_db.connect(db_a) as a, control_db.connect(db_b) as b:
        _trust_pair(a, b, tmp_path)
        msg = replication_v2.build_message(a, SecretStore(tmp_path / "sa"))
        replication_v2.apply_message(
            b,
            SecretStore(tmp_path / "sb"),
            msg,
            staging_dir=tmp_path / "staging",
            live_dnsdist_conf_path=tmp_path / "dnsdist.conf",
        )
    conf_text = (tmp_path / "dnsdist.conf").read_text()
    assert 'setLocal("0.0.0.0:53")' in conf_text


def test_push_to_peer_does_not_shadow_http_module():
    source = inspect.getsource(replication_v2.push_to_peer)
    assert "http = http.client" not in source
    assert "client = http.client.HTTPSConnection" in source


def test_real_mtls_server_rejects_missing_client_cert_and_accepts_authorized_peer(tmp_path, monkeypatch):
    monkeypatch.setattr(replication_v2.runtime_compile, "recompile_and_promote", lambda *a, **k: None)
    try:
        probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        probe.close()
    except PermissionError as exc:
        pytest.skip(f"environment denies socket creation: {exc}")
    db_a = tmp_path / "a.db"
    db_b = tmp_path / "b.db"
    _init(db_a)
    _init(db_b)
    with control_db.connect(db_a) as a, control_db.connect(db_b) as b:
        ca, (cert_a, key_a), (cert_b, key_b) = _trust_pair(a, b, tmp_path)
        msg = replication_v2.build_message(a, SecretStore(tmp_path / "sa"))
    cert_b_path = tmp_path / "server.crt"
    key_b_path = tmp_path / "server.key"
    ca_path = tmp_path / "ca.pem"
    cert_b_path.write_text(cert_b)
    key_b_path.write_text(key_b)
    ca_path.write_text(ca)
    server, thread = replication_v2.serve_forever_in_thread(
        bind=("127.0.0.1", 0),
        server_cert=cert_b_path,
        server_key=key_b_path,
        ca_file=ca_path,
        control_db_path=db_b,
        secrets_dir=tmp_path / "sb",
        staging_dir=tmp_path / "staging",
        live_dnsdist_conf_path=tmp_path / "dnsdist.conf",
    )
    port = server.server_address[1]
    try:
        with control_db.connect(db_b) as b_lookup:
            peer_b = node_identity.get_or_create(b_lookup).node_id
        with control_db.connect(db_a) as a:
            replication_v2.upsert_peer(
                a,
                peer_node_id=peer_b,
                display_name="b",
                url=f"https://localhost:{port}/replication/v1/apply",
                ca_pem=ca,
                expected_cert_sha256=replication_v2.cert_fingerprint_sha256(cert_a),
                client_cert_pem=cert_a,
                client_key_pem=key_a,
            )
            with pytest.raises(replication_v2.ReplicationAuthError, match="server certificate fingerprint mismatch"):
                replication_v2.push_to_peer(a, SecretStore(tmp_path / "sa"), peer_b, tmp_path / "tmp")
            replication_v2.upsert_peer(
                a,
                peer_node_id=peer_b,
                display_name="b",
                url=f"https://localhost:{port}/replication/v1/apply",
                ca_pem=ca,
                expected_cert_sha256=replication_v2.cert_fingerprint_sha256(cert_b),
                client_cert_pem=cert_a,
                client_key_pem=key_a,
            )
        import http.client

        no_cert_ctx = ssl.create_default_context(cafile=str(ca_path))
        with pytest.raises(ssl.SSLError):
            c = http.client.HTTPSConnection("localhost", port, context=no_cert_ctx, timeout=2)
            c.request("GET", "/replication/v1/health")
            c.getresponse()
        cert_a_path = tmp_path / "client.crt"
        key_a_path = tmp_path / "client.key"
        cert_a_path.write_text(cert_a)
        key_a_path.write_text(key_a)
        ctx = ssl.create_default_context(cafile=str(ca_path))
        ctx.load_cert_chain(str(cert_a_path), str(key_a_path))
        c = http.client.HTTPSConnection("localhost", port, context=ctx, timeout=5)
        c.request("POST", "/replication/v1/apply", body=json.dumps(msg), headers={"Content-Type": "application/json"})
        r = c.getresponse()
        assert r.status == 200, r.read()
    finally:
        server.shutdown()
        server.server_close()
