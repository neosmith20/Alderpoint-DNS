"""Regression coverage for the RC42 beta-rescue P0: "effective policy does
not match runtime." Independent RC42 teardown found that
``app/v2/runtime_compile.py::build_bindings`` only ever emitted one binding
per configured network plus a catch-all default -- managed-client, group,
and schedule-derived policy (correctly resolved by
``policy_service.explain_policy_for_client``) never reached the compiled
dnsdist runtime at all, and stored domain-routing rules never propagated
into a binding regardless of configuration.

These tests reproduce the exact owner scenario (a managed client in a
"Kids" group with strict SafeSearch, a client-level response-mode
override, a security ruleset from an active schedule, and a global
domain-routing rule) and assert that ``build_bindings`` produces a binding
whose fields match ``policy_service.explain_policy_for_client`` field for
field -- i.e. there is one effective-policy resolution, not two.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from app.v2 import control_db, policy_store as store
from app.v2.blocking_response import BlockingResponse
from app.v2.dnsdist_policy_runtime import compile_multi_policy_dnsdist_config
from app.v2.policy_model import PolicyLayer
from app.v2.policy_service import ClientResolutionContext, explain_policy_for_client
from app.v2.runtime_compile import build_bindings, _DEFAULT_NETWORK_ID
from app.v2.schedule_policy import make_window


@pytest.fixture()
def conn(tmp_path):
    path = tmp_path / "control.db"
    store.ensure_schema(path)
    with control_db.connect(path) as c:
        yield c


def _create_client(conn, name: str) -> int:
    now = datetime.now(timezone.utc).isoformat()
    cur = conn.execute(
        "INSERT INTO clients(name, description, enabled, created_at, updated_at) VALUES (?, ?, 1, ?, ?)",
        (name, "", now, now),
    )
    return cur.lastrowid


def _add_identifier(conn, client_id: int, kind: str, value: str) -> None:
    now = datetime.now(timezone.utc).isoformat()
    conn.execute(
        "INSERT INTO client_identifiers(client_id, kind, value, created_at) VALUES (?, ?, ?, ?)",
        (client_id, kind, value, now),
    )


def _binding_for_client_ip(bindings, ip: str):
    for b in bindings:
        if str(b.network._net.network_address) == ip and b.network._net.prefixlen in (32, 128):
            return b
    return None


class TestOwnerReportedClientGroupScheduleScenario:
    """The exact reproduced example from the beta-rescue brief: managed
    client 10.0.0.42, member of "Kids" group, strict SafeSearch from the
    group, refused response mode from the client override, a security
    ruleset from an active schedule, and a domain-routing rule from
    global policy.
    """

    def test_runtime_binding_matches_explain_field_for_field(self, conn):
        client_id = _create_client(conn, "kids-laptop")
        _add_identifier(conn, client_id, "ipv4", "10.0.0.42")

        store.create_group(conn, "kids", "Kids", priority=10)
        store.add_client_to_group(conn, client_id, "kids")
        store.save_policy_layer(conn, "group", "kids", PolicyLayer(safesearch_mode="strict"))

        store.save_policy_layer(
            conn, "client", str(client_id), PolicyLayer(blocking_response_mode="refused")
        )

        store.create_service(conn, "svc-malware", "Malware", [("suffix", "malware.example")])
        store.create_service_ruleset(conn, "security-rs", ["svc-malware"])

        # An always-active schedule window (every day, every hour) so
        # this test is not time-of-day-flaky while still proving the
        # active-schedule code path, not a hand-wired shortcut.
        store.create_schedule(
            conn, "always-on", "UTC",
            [make_window("00:00", "23:59", ["mon", "tue", "wed", "thu", "fri", "sat", "sun"])],
        )
        store.save_policy_layer(
            conn, "schedule", "always-on", PolicyLayer(security_policy_id="security-rs")
        )

        store.create_upstream_profile(
            conn, "isp-doh", "ISP DoH",
            transport="doh",
            endpoints=[store.UpstreamEndpointRecord("9.9.9.9:443", "dns.example", 0, 1, None, "/dns-query")],
        )
        store.add_domain_routing_rule(conn, "global-routes", "suffix", "routed.example", "isp-doh")
        store.save_policy_layer(
            conn, "global", "singleton", PolicyLayer(domain_routing_ruleset_id="global-routes")
        )

        now = datetime.now(timezone.utc)
        explained = explain_policy_for_client(
            conn, ClientResolutionContext(client_id=client_id, client_ip="10.0.0.42"), now=now
        )

        bindings = build_bindings(conn, now=now)
        client_binding = _binding_for_client_ip(bindings, "10.0.0.42")
        assert client_binding is not None, (
            "no runtime binding was materialized for the managed client at all -- "
            "this is the exact P0 defect: Explain resolves an effective policy "
            "that the compiled runtime never receives"
        )

        # SafeSearch: strict, inherited from the "Kids" group.
        assert explained["fields"]["safesearch_mode"]["value"] == "strict"
        assert explained["fields"]["safesearch_mode"]["source"] == "group:Kids"
        assert client_binding.safesearch_providers, "group-derived SafeSearch never reached the runtime binding"

        # Response mode: refused, from the client-level override.
        assert explained["fields"]["blocking_response_mode"]["value"] == "refused"
        assert explained["fields"]["blocking_response_mode"]["source"] == "client"

        # Security ruleset: from the active schedule.
        assert explained["schedule_active"] == "always-on"
        assert explained["fields"]["security_policy_id"]["value"] == "security-rs"
        assert explained["fields"]["security_policy_id"]["source"] == "schedule:always-on"
        assert "malware.example" in client_binding.blocked_domains, (
            "schedule-derived security ruleset never reached the runtime binding"
        )
        assert client_binding.blocked_domains["malware.example"].mode == "refused", (
            "runtime block used a different response mode than Explain reported -- "
            "two competing definitions of effective policy"
        )

        # Domain routing: from global policy.
        assert explained["fields"]["domain_routing_ruleset_id"]["value"] == "global-routes"
        route_domains = {r[0] for r in client_binding.domain_routes}
        assert "routed.example" in route_domains, (
            "global domain-routing rule never propagated into the runtime binding"
        )

    def test_unaffected_client_is_isolated_from_the_kids_group_policy(self, conn):
        kid_id = _create_client(conn, "kids-laptop")
        _add_identifier(conn, kid_id, "ipv4", "10.0.0.42")
        adult_id = _create_client(conn, "parent-laptop")
        _add_identifier(conn, adult_id, "ipv4", "10.0.0.43")

        store.create_group(conn, "kids", "Kids", priority=10)
        store.add_client_to_group(conn, kid_id, "kids")
        store.save_policy_layer(conn, "group", "kids", PolicyLayer(safesearch_mode="strict"))

        bindings = build_bindings(conn)
        kid_binding = _binding_for_client_ip(bindings, "10.0.0.42")
        adult_binding = _binding_for_client_ip(bindings, "10.0.0.43")
        assert kid_binding.safesearch_providers
        assert not adult_binding.safesearch_providers, (
            "an unrelated client picked up the Kids group's SafeSearch policy -- "
            "cross-client policy isolation violated"
        )

    def test_client_binding_outranks_broader_network_binding_when_compiled(self, conn):
        """Precedence proof, not just field values: the client's own
        binding must be the most specific network match so it actually
        wins at real dnsdist rule-evaluation time (§4's most-specific-
        wins contract), not merely exist as an extra, shadowed entry.
        """
        store.create_network(conn, "lan", "10.0.0.0/24")
        store.save_policy_layer(conn, "network", "lan", PolicyLayer(safesearch_mode="moderate"))
        client_id = _create_client(conn, "kid")
        _add_identifier(conn, client_id, "ipv4", "10.0.0.42")
        store.save_policy_layer(conn, "client", str(client_id), PolicyLayer(safesearch_mode="strict"))

        bindings = build_bindings(conn)
        config_text = compile_multi_policy_dnsdist_config("127.0.0.1:15500", bindings)
        client_rule_pos = config_text.find("10.0.0.42/32")
        lan_rule_pos = config_text.find("10.0.0.0/24")
        assert client_rule_pos != -1 and lan_rule_pos != -1
        assert client_rule_pos < lan_rule_pos, (
            "the /24 network rule was emitted before the /32 client rule -- "
            "dnsdist evaluates addAction rules in order, so this would let the "
            "broader network policy shadow the client override at real query time"
        )


class TestFilteringProfileNowWiredToRuntime:
    def test_filtering_profile_domains_are_actually_blocked(self, conn):
        store.create_service(conn, "svc-ads", "Ads", [("suffix", "ads.example")])
        store.create_service_ruleset(conn, "filter-1", ["svc-ads"])
        store.save_policy_layer(conn, "global", "singleton", PolicyLayer(filtering_profile_id="filter-1"))

        bindings = build_bindings(conn)
        default_binding = next(b for b in bindings if b.network.network_id == _DEFAULT_NETWORK_ID)
        assert "ads.example" in default_binding.blocked_domains, (
            "filtering_profile_id was stored but never reached the compiled runtime "
            "(RC42's documented 'not yet mapped' gap)"
        )


class TestDomainRoutingMatchKindPreserved:
    def test_exact_match_rule_does_not_shadow_unrelated_subdomains(self, conn):
        store.create_upstream_profile(
            conn, "alt", "Alt", transport="plain",
            endpoints=[store.UpstreamEndpointRecord("198.51.100.1:53", None, 0, 1, None)],
        )
        store.add_domain_routing_rule(conn, "rs", "exact", "exact.example", "alt")
        store.save_policy_layer(conn, "global", "singleton", PolicyLayer(domain_routing_ruleset_id="rs"))

        bindings = build_bindings(conn)
        default_binding = next(b for b in bindings if b.network.network_id == _DEFAULT_NETWORK_ID)
        config_text = compile_multi_policy_dnsdist_config("127.0.0.1:15501", bindings)
        assert 'QNameRule("exact.example.")' in config_text
        assert 'SuffixMatchNodeRule({"exact.example."})' not in config_text


class TestUpstreamStrategyActuallyDiffers:
    def test_ordered_and_load_balanced_compile_to_different_pool_policies(self, conn):
        store.create_upstream_profile(
            conn, "ordered-profile", "Ordered", transport="plain", strategy="ordered",
            endpoints=[
                store.UpstreamEndpointRecord("198.51.100.1:53", None, 0, 1, None),
                store.UpstreamEndpointRecord("198.51.100.2:53", None, 1, 1, None),
            ],
        )
        store.save_policy_layer(conn, "global", "singleton", PolicyLayer(upstream_profile_id="ordered-profile"))
        bindings = build_bindings(conn)
        ordered_text = compile_multi_policy_dnsdist_config("127.0.0.1:15502", bindings)
        assert "setPoolServerPolicy(firstAvailable" in ordered_text

        store.save_policy_layer(conn, "global", "singleton", PolicyLayer())
        store.create_upstream_profile(
            conn, "lb-profile", "LB", transport="plain", strategy="load_balanced",
            endpoints=[
                store.UpstreamEndpointRecord("198.51.100.1:53", None, 0, 1, None),
                store.UpstreamEndpointRecord("198.51.100.2:53", None, 0, 1, None),
            ],
        )
        store.save_policy_layer(conn, "global", "singleton", PolicyLayer(upstream_profile_id="lb-profile"))
        bindings2 = build_bindings(conn)
        lb_text = compile_multi_policy_dnsdist_config("127.0.0.1:15503", bindings2)
        assert "setPoolServerPolicy(wrandom" in lb_text
        assert "setPoolServerPolicy(firstAvailable" not in lb_text


class TestCustomIpBlockingResponseNowWiredToRuntime:
    """RC42 reproduction: custom_ip could be selected/stored while
    runtime compilation lacked the required address and crashed. custom_
    ipv4/custom_ipv6 now have real storage in PolicyLayer/policy_layers,
    and the compiler passes the effective address through instead of
    silently omitting it.
    """

    def test_custom_ip_with_address_compiles_a_real_spoof_action(self, conn):
        store.create_service(conn, "svc-ads", "Ads", [("suffix", "ads.example")])
        store.create_service_ruleset(conn, "rs-1", ["svc-ads"])
        store.save_policy_layer(
            conn, "global", "singleton",
            PolicyLayer(
                service_blocking_ruleset_id="rs-1",
                blocking_response_mode="custom_ip",
                custom_ipv4="10.9.9.9",
                custom_ipv6="fd00::9",
            ),
        )
        bindings = build_bindings(conn)  # must not raise
        config_text = compile_multi_policy_dnsdist_config("127.0.0.1:15504", bindings)
        assert 'SpoofAction({"10.9.9.9", "fd00::9"})' in config_text

    def test_custom_ip_with_no_configured_address_fails_the_compile_cleanly(self, conn):
        from app.v2.blocking_response import InvalidBlockingResponseError

        store.create_service(conn, "svc-ads", "Ads", [("suffix", "ads.example")])
        store.create_service_ruleset(conn, "rs-1", ["svc-ads"])
        store.save_policy_layer(
            conn, "global", "singleton",
            PolicyLayer(service_blocking_ruleset_id="rs-1", blocking_response_mode="custom_ip"),
        )
        with pytest.raises(InvalidBlockingResponseError):
            build_bindings(conn)

    def test_custom_ip_survives_a_real_store_round_trip(self, conn):
        store.save_policy_layer(
            conn, "global", "singleton",
            PolicyLayer(blocking_response_mode="custom_ip", custom_ipv4="203.0.113.5"),
        )
        loaded = store.load_policy_layer(conn, "global", "singleton")
        assert loaded.custom_ipv4 == "203.0.113.5"
        assert loaded.blocking_response_mode == "custom_ip"


class TestSafeSearchModerateVsStrictActuallyDiffer:
    """RC42 reproduction: "moderate" and "strict" produced byte-identical
    runtime rewrites despite being exposed as distinct modes.
    """

    def test_youtube_moderate_and_strict_compile_different_targets(self, conn):
        store.save_policy_layer(conn, "global", "singleton", PolicyLayer(safesearch_mode="moderate"))
        moderate_text = compile_multi_policy_dnsdist_config(
            "127.0.0.1:15505", build_bindings(conn)
        )
        store.save_policy_layer(conn, "global", "singleton", PolicyLayer(safesearch_mode="strict"))
        strict_text = compile_multi_policy_dnsdist_config(
            "127.0.0.1:15506", build_bindings(conn)
        )
        assert "restrictmoderate.youtube.com" in moderate_text
        assert "restrictstrict.youtube.com" not in moderate_text
        assert "restrictstrict.youtube.com" in strict_text
        assert "restrictmoderate.youtube.com" not in strict_text
