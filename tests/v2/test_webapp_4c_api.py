import importlib
import os
import sys


def _fresh_webapp(tmp_path, monkeypatch):
    monkeypatch.setenv("ALDERPOINTDNS_V2_STATE_ROOT", str(tmp_path / "state"))
    monkeypatch.setenv("ALDERPOINTDNS_V2_CONFIG_ROOT", str(tmp_path / "etc"))
    monkeypatch.setenv("ALDERPOINTDNS_V2_COOKIE_SECURE", "0")
    (tmp_path / "state").mkdir(parents=True, exist_ok=True)
    sys.modules.pop("app.v2.webapp", None)
    return importlib.import_module("app.v2.webapp")


def test_4c_api_routes_are_registered(tmp_path, monkeypatch):
    webapp = _fresh_webapp(tmp_path, monkeypatch)
    paths = {route.path for route in webapp.app.routes}
    expected = {
        "/api/node-identity",
        "/api/replication/peers",
        "/api/replication/health",
        "/api/replication/peers/{peer_node_id}/sync",
        "/api/discovery/observed-clients",
        "/api/discovery/observed-clients/{source_ip}",
        "/api/discovery/observed-clients/{source_ip}/promote",
        "/api/discovery/status",
        "/api/discovery/settings",
        "/api/discovery/observe",
    }
    assert expected.issubset(paths)


def test_replication_peer_public_api_never_exposes_private_key(tmp_path, monkeypatch):
    webapp = _fresh_webapp(tmp_path, monkeypatch)
    peer = webapp.replication_v2.Peer(
        peer_node_id="peer",
        display_name="Peer",
        url="https://peer.example:9443/replication/v1/apply",
        ca_pem="ca",
        expected_cert_sha256="a" * 64,
        expected_incoming_cert_sha256="c" * 64,
        client_cert_pem="cert",
        client_key_pem="VERY-SECRET-KEY",
        authorized=True,
        direction="bidirectional",
        last_attempt_at=None,
        last_success_at=None,
        last_error="",
        local_generation=3,
        remote_known_generation=1,
    )
    public = peer.public_dict()
    assert "client_key_pem" not in public
    assert "VERY-SECRET-KEY" not in str(public)
    assert public["lag"] == 2


def test_request_models_validate_bounds(tmp_path, monkeypatch):
    webapp = _fresh_webapp(tmp_path, monkeypatch)
    peer = webapp.ReplicationPeerUpsert(
        peer_node_id="peer",
        url="https://peer.example:9443/replication/v1/apply",
        ca_pem="ca",
        expected_cert_sha256="b" * 64,
    )
    assert peer.authorized is True
    promote = webapp.PromoteObservedRequest(display_name="client")
    assert promote.groups == []
