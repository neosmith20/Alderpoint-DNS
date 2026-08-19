"""Real regression for the replication peer-enrollment gap found live
during RC3 replication acceptance testing (roadmap Priority 12): a real
administrator with two real, independently installed V2 appliances had
no shipped CLI or API workflow to establish replication trust between
them at all -- each node's replication CA private key was generated
purely in memory by `init-replication-cert` and discarded immediately
after signing that node's own server cert, so no tool could ever issue
an *additional* cert signed by that CA for a second node.

Exercises the actual packaged `alderpointdns_v2_ctl.py` module (the
real systemd-invoked entry point), not just the underlying
`app.v2.replication_v2` library functions directly.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
CTL_PATH = REPO_ROOT / "scripts" / "v2" / "alderpointdns_v2_ctl.py"


@pytest.fixture()
def ctl_module(tmp_path, monkeypatch):
    monkeypatch.setenv("ALDERPOINTDNS_V2_APP_ROOT", str(tmp_path / "opt"))
    monkeypatch.setenv("ALDERPOINTDNS_V2_CONFIG_ROOT", str(tmp_path / "etc"))
    monkeypatch.setenv("ALDERPOINTDNS_V2_STATE_ROOT", str(tmp_path / "var" / "lib"))
    monkeypatch.setenv("ALDERPOINTDNS_V2_LOG_ROOT", str(tmp_path / "var" / "log"))
    for mod in list(sys.modules):
        if mod == "alderpointdns_v2_ctl":
            del sys.modules[mod]
    spec = importlib.util.spec_from_file_location("alderpointdns_v2_ctl", CTL_PATH)
    module = importlib.util.module_from_spec(spec)
    sys.modules["alderpointdns_v2_ctl"] = module
    spec.loader.exec_module(module)
    return module


class TestInitReplicationCertPersistsCAKey:
    def test_ca_key_persisted_to_secret_store_not_discarded(self, ctl_module):
        rc = ctl_module.cmd_init_replication_cert(argparse.Namespace())
        assert rc == 0
        from app.v2.secret_store import SecretStore
        from app.v2 import replication_v2

        secrets = SecretStore(ctl_module.SECRETS_DIR)
        ca_key_pem = secrets.get(replication_v2.REPLICATION_CA_KEY_SECRET_ID)
        assert "PRIVATE KEY" in ca_key_pem
        # The persisted key must actually be the one that signed the real
        # server cert this bootstrap wrote to disk -- not some unrelated
        # placeholder.
        ca_pem = ctl_module.REPLICATION_CA_PATH.read_text()
        server_cert_pem = ctl_module.REPLICATION_SERVER_CERT_PATH.read_text()
        cert_pem2, _key_pem2 = replication_v2.issue_node_cert(ca_pem, ca_key_pem, "sanity-check-node")
        # A cert freshly signed with the persisted key must chain to the
        # same CA as the real server cert (same issuer subject).
        from cryptography import x509

        assert x509.load_pem_x509_certificate(cert_pem2.encode()).issuer == \
            x509.load_pem_x509_certificate(server_cert_pem.encode()).issuer

    def test_rerun_does_not_overwrite_existing_material(self, ctl_module):
        ctl_module.cmd_init_replication_cert(argparse.Namespace())
        ca_pem_before = ctl_module.REPLICATION_CA_PATH.read_text()
        rc = ctl_module.cmd_init_replication_cert(argparse.Namespace())
        assert rc == 0
        assert ctl_module.REPLICATION_CA_PATH.read_text() == ca_pem_before


class TestIssuePeerCertCommand:
    def test_fails_clearly_when_replication_not_initialized(self, ctl_module, capsys):
        rc = ctl_module.cmd_issue_peer_cert(argparse.Namespace(remote_node_id="remote-1", server_name="localhost", out=None))
        assert rc == 1
        assert "not initialized" in capsys.readouterr().err

    def test_issues_a_real_cert_bundle_for_the_remote_node(self, ctl_module, capsys):
        ctl_module.cmd_init_replication_cert(argparse.Namespace())
        capsys.readouterr()  # discard init-replication-cert's own stdout
        rc = ctl_module.cmd_issue_peer_cert(argparse.Namespace(remote_node_id="remote-node-42", server_name="10.5.5.5", out=None))
        assert rc == 0
        bundle = json.loads(capsys.readouterr().out)
        from app.v2 import replication_v2

        assert replication_v2.cert_node_id(bundle["client_cert_pem"]) == "remote-node-42"
        assert bundle["ca_pem"] == ctl_module.REPLICATION_CA_PATH.read_text()
        assert bundle["expected_cert_sha256"] == replication_v2.cert_fingerprint_sha256(
            ctl_module.REPLICATION_SERVER_CERT_PATH.read_text()
        )
        assert bundle["issued_cert_sha256"] == replication_v2.cert_fingerprint_sha256(bundle["client_cert_pem"])
        assert "PRIVATE KEY" not in bundle["ca_pem"]  # never leaks the CA key itself

    def test_out_file_written_with_restricted_permissions(self, ctl_module, tmp_path):
        ctl_module.cmd_init_replication_cert(argparse.Namespace())
        out_path = tmp_path / "bundle.json"
        rc = ctl_module.cmd_issue_peer_cert(
            argparse.Namespace(remote_node_id="remote-node-7", server_name="localhost", out=str(out_path))
        )
        assert rc == 0
        assert out_path.exists()
        assert (out_path.stat().st_mode & 0o777) == 0o600
        bundle = json.loads(out_path.read_text())
        assert bundle["issued_for_node_id"] == "remote-node-7"

    def test_out_file_guidance_tells_recipient_to_use_their_own_bundle_for_incoming(self, ctl_module, tmp_path, capsys):
        # Real defect found live during a real two-node bidirectional
        # replication acceptance test: this printed guidance previously
        # told the recipient to use the fingerprint from the bundle THEY
        # JUST RECEIVED as their own expected_incoming_cert_sha256 -- but
        # that fingerprint is the cert the recipient presents OUTGOING
        # (already covered by client_cert_pem/client_key_pem above), not
        # the cert the sender presents when pushing INCOMING to the
        # recipient. A real administrator following that instruction
        # literally would set expected_incoming_cert_sha256 to a
        # completely unrelated cert, and every real incoming push from
        # the sender would then fail closed with "peer certificate
        # fingerprint mismatch" (see replication_v2._validate_message).
        # Proven correct end-to-end: a real two-node bidirectional
        # replication test using the CORRECTED mapping (each node's OWN
        # issued bundle's issued_cert_sha256 for its own
        # expected_incoming_cert_sha256) applied cleanly in both
        # directions; using the old wrong mapping does not.
        ctl_module.cmd_init_replication_cert(argparse.Namespace())
        capsys.readouterr()
        out_path = tmp_path / "bundle.json"
        ctl_module.cmd_issue_peer_cert(
            argparse.Namespace(remote_node_id="remote-node-9", server_name="localhost", out=str(out_path))
        )
        message = capsys.readouterr().out
        assert "their own bundle's issued_cert_sha256" in message.lower() \
            or "own bundle's issued_cert_sha256" in message.lower()
        assert "this bundle's issued_cert_sha256 as their own" not in message.lower()
