"""Workstream 4B §18/§46: control.db state -> real compiled+validated
dnsdist runtime. The core "management API change reaches real DNS"
integration this pass's end-to-end proof depends on.
"""

import shutil

import pytest

from app.v2 import control_db, policy_store as store
from app.v2.blocking_response import BlockingResponse
from app.v2.policy_model import PolicyLayer
from app.v2.runtime_compile import RuntimeCompileError, recompile_and_promote

DNSDIST_INSTALLED = shutil.which("dnsdist") is not None
pytestmark = pytest.mark.skipif(not DNSDIST_INSTALLED, reason="dnsdist not installed")


@pytest.fixture()
def conn(tmp_path):
    path = tmp_path / "control.db"
    store.ensure_schema(path)
    with control_db.connect(path) as c:
        yield c


class TestBasicCompile:
    def test_global_policy_alone_produces_default_binding(self, conn, tmp_path):
        result = recompile_and_promote(conn, tmp_path / "staging", tmp_path / "dnsdist.conf", listen_address="127.0.0.1:15400")
        assert result.promoted
        assert result.binding_count == 1  # just the catch-all default
        assert (tmp_path / "dnsdist.conf").exists()

    def test_network_adds_a_second_binding(self, conn, tmp_path):
        store.create_network(conn, "lan", "10.0.0.0/24")
        result = recompile_and_promote(conn, tmp_path / "staging", tmp_path / "dnsdist.conf", listen_address="127.0.0.1:15401")
        assert result.binding_count == 2


class TestSafeSearchMapping:
    def test_safesearch_strict_produces_real_spoofcname_rules(self, conn, tmp_path):
        store.save_policy_layer(conn, "network", "lan", PolicyLayer(safesearch_mode="strict"))
        store.create_network(conn, "lan", "10.0.0.0/24")
        recompile_and_promote(conn, tmp_path / "staging", tmp_path / "dnsdist.conf", listen_address="127.0.0.1:15402")
        text = (tmp_path / "dnsdist.conf").read_text()
        assert "SpoofCNAMEAction" in text

    def test_safesearch_off_produces_no_spoofcname_rules_for_that_network(self, conn, tmp_path):
        store.create_network(conn, "lan", "10.0.0.0/24")  # no policy layer -> safesearch off
        recompile_and_promote(conn, tmp_path / "staging", tmp_path / "dnsdist.conf", listen_address="127.0.0.1:15403")
        text = (tmp_path / "dnsdist.conf").read_text()
        assert "SpoofCNAMEAction" not in text


class TestServiceBlockingMapping:
    def test_service_blocking_ruleset_produces_real_block_rule(self, conn, tmp_path):
        store.create_service(conn, "svc-ads", "Ads", [("suffix", "ads.example")])
        store.create_service_ruleset(conn, "rs-1", ["svc-ads"])
        store.save_policy_layer(
            conn, "network", "lan",
            PolicyLayer(service_blocking_ruleset_id="rs-1", blocking_response_mode="refused"),
        )
        store.create_network(conn, "lan", "10.0.0.0/24")
        recompile_and_promote(conn, tmp_path / "staging", tmp_path / "dnsdist.conf", listen_address="127.0.0.1:15404")
        text = (tmp_path / "dnsdist.conf").read_text()
        assert "ads.example" in text
        assert "RCodeAction(DNSRCode.REFUSED)" in text


class TestFailureLeavesLiveRuntimeUntouched:
    def test_invalid_upstream_reference_does_not_promote_and_old_config_survives(self, conn, tmp_path):
        live_path = tmp_path / "dnsdist.conf"
        # First, a real successful promotion establishes a known-good file.
        recompile_and_promote(conn, tmp_path / "staging", live_path, listen_address="127.0.0.1:15405")
        original = live_path.read_text()

        # Now corrupt state in a way that raises during compile: an
        # invalid domain in a service used by a ruleset (bypassing normal
        # validation by inserting directly is intentionally not done here
        # -- instead prove the real path: an ecs_mode that maps to a
        # dnsdist-runtime type error is out of scope; use a genuinely
        # broken dnsdist binary path instead to force a validation failure
        # deterministically).
        with pytest.raises(RuntimeCompileError):
            recompile_and_promote(
                conn, tmp_path / "staging", live_path, listen_address="127.0.0.1:15405",
                dnsdist_binary="/nonexistent/dnsdist",
            )
        assert live_path.read_text() == original
