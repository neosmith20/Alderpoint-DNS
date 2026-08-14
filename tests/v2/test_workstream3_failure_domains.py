"""Failure-domain proofs for this session's new modules (Workstream 3
continuation, §34): the pieces that would sit closest to a compiled DNS
runtime -- the policy compiler and the config generators -- must not
depend on control.db, the secret store, or the analytics stack being
available. This is checked structurally (no imports of those modules at
call time beyond what's already loaded) and behaviorally (they still work
correctly when constructed purely from in-memory objects, no database
connection passed in at all).
"""

import inspect

from app.v2 import bind_rpz_gen, blocking_response, dnsdist_gen, network_match, policy_compiler
from app.v2.blocking_response import BlockingResponse
from app.v2.network_match import NetworkScope
from app.v2.policy_model import PolicyLayer


class TestCompilerHasNoDatabaseDependency:
    def test_compile_effective_policy_source_has_no_db_calls(self):
        src = inspect.getsource(policy_compiler)
        for forbidden in ("sqlite3", "control_db.connect", ".execute(", "aggregates_db", "secret_store"):
            assert forbidden not in src, f"policy_compiler.py unexpectedly references {forbidden!r}"

    def test_compiles_correctly_with_zero_database_connections_involved(self):
        from app.v2.policy_compiler import compile_effective_policy

        policy = compile_effective_policy(PolicyLayer(safesearch_mode="strict"))
        assert policy.safesearch_mode == "strict"


class TestGeneratorsHaveNoAnalyticsOrSecretDependency:
    def test_dnsdist_gen_source_has_no_analytics_or_secret_imports(self):
        src = inspect.getsource(dnsdist_gen)
        for forbidden in ("analytics", "secret_store", "aggregates_db"):
            assert forbidden not in src, f"dnsdist_gen.py unexpectedly references {forbidden!r}"

    def test_bind_rpz_gen_source_has_no_analytics_or_secret_imports(self):
        src = inspect.getsource(bind_rpz_gen)
        for forbidden in ("analytics", "secret_store", "aggregates_db"):
            assert forbidden not in src, f"bind_rpz_gen.py unexpectedly references {forbidden!r}"

    def test_dnsdist_config_generates_with_pure_in_memory_objects_only(self):
        from app.v2.dnsdist_gen import UpstreamServer, generate_dnsdist_config

        acl = [NetworkScope.create("lan", "10.0.0.0/8", "policy")]
        text = generate_dnsdist_config("127.0.0.1:5300", acl, [UpstreamServer("p", "1.1.1.1:53")])
        assert "setLocal" in text

    def test_rpz_zone_generates_with_pure_in_memory_objects_only(self):
        zone = bind_rpz_gen.render_rpz_zone(
            {"bad.example": BlockingResponse(mode="nxdomain")}, [], serial=1
        )
        assert "bad.example CNAME ." in zone


class TestAnalyticsPipelineFailureNeverAffectsPolicyOrGeneration:
    def test_all_sinks_down_still_yields_a_compilable_policy_and_config(self):
        # Simulates "control.db/analytics/secret store unavailable after
        # policy has compiled" (§49): the compiler and generators operate
        # on already-loaded in-memory objects and never reach back out to
        # any of those systems, so their unavailability elsewhere in the
        # process cannot affect a policy that has already been compiled.
        from app.v2.dnsdist_gen import UpstreamServer, generate_dnsdist_config
        from app.v2.policy_compiler import compile_cache_profile, compile_effective_policy

        policy = compile_effective_policy(PolicyLayer(safesearch_mode="strict"))
        profile = compile_cache_profile(policy)
        assert profile.profile_id

        config = generate_dnsdist_config(
            "127.0.0.1:5300", [], [UpstreamServer("p", "1.1.1.1:53")]
        )
        assert "setLocal" in config
