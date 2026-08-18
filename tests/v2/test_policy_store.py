from datetime import datetime, timezone

import pytest

from app.v2 import control_db, policy_store as store
from app.v2.control_db import ForbiddenSchemaError
from app.v2.network_match import InvalidNetworkError
from app.v2.policy_compiler import compile_cache_profile, compile_effective_policy
from app.v2.policy_model import GroupPolicy, PolicyLayer
from app.v2.schedule_policy import make_window


@pytest.fixture()
def db(tmp_path):
    path = tmp_path / "control.db"
    store.ensure_schema(path)
    return path


@pytest.fixture()
def conn(db):
    with control_db.connect(db) as c:
        c.execute(
            "INSERT INTO clients (id, name, created_at, updated_at) VALUES (1, 'test-client', '', '')"
        )
        yield c


class TestSchema:
    def test_ensure_schema_idempotent(self, db):
        store.ensure_schema(db)  # second call must not raise/duplicate
        assert control_db.schema_version(db) == store.POLICY_STORE_SCHEMA_VERSION

    def test_forbidden_table_guard_still_enforced(self, db):
        with pytest.raises(ForbiddenSchemaError):
            control_db.apply_migration_in_transaction(
                db, ["CREATE TABLE query_events (id INTEGER)"], 999
            )


class TestPolicyLayerCRUD:
    def test_save_and_load_roundtrip(self, conn):
        layer = PolicyLayer(safesearch_mode="strict", upstream_profile_id="family")
        store.save_policy_layer(conn, "client", "42", layer)
        loaded = store.load_policy_layer(conn, "client", "42")
        assert loaded.safesearch_mode == "strict"
        assert loaded.upstream_profile_id == "family"
        assert loaded.ecs_mode is None  # untouched field stays None (inherit)

    def test_missing_layer_returns_all_none(self, conn):
        loaded = store.load_policy_layer(conn, "client", "nonexistent")
        assert loaded == PolicyLayer()

    def test_upsert_overwrites(self, conn):
        store.save_policy_layer(conn, "global", "singleton", PolicyLayer(safesearch_mode="off"))
        store.save_policy_layer(conn, "global", "singleton", PolicyLayer(safesearch_mode="strict"))
        assert store.load_policy_layer(conn, "global", "singleton").safesearch_mode == "strict"

    def test_bool_field_false_not_confused_with_none(self, conn):
        store.save_policy_layer(conn, "client", "1", PolicyLayer(query_log_enabled=False))
        loaded = store.load_policy_layer(conn, "client", "1")
        assert loaded.query_log_enabled is False

    def test_invalid_scope_rejected(self, conn):
        with pytest.raises(store.PolicyStoreError):
            store.save_policy_layer(conn, "planet", "x", PolicyLayer())


class TestNetworks:
    def test_create_and_match(self, conn):
        store.create_network(conn, "lan", "10.0.0.0/8")
        table = store.load_network_table(conn)
        assert table.match("10.1.2.3").network_id == "lan"

    def test_invalid_cidr_never_reaches_db(self, conn):
        with pytest.raises(InvalidNetworkError):
            store.create_network(conn, "bad", "not-a-cidr")
        assert conn.execute("SELECT COUNT(*) FROM policy_networks").fetchone()[0] == 0

    def test_duplicate_network_id_rejected(self, conn):
        store.create_network(conn, "lan", "10.0.0.0/8")
        with pytest.raises(store.PolicyStoreError):
            store.create_network(conn, "lan", "192.168.0.0/16")


class TestGroups:
    def test_create_group_and_membership(self, conn):
        store.create_group(conn, "kids", "Kids", priority=10)
        store.save_policy_layer(conn, "group", "kids", PolicyLayer(safesearch_mode="strict"))
        store.add_client_to_group(conn, client_id=1, group_id="kids")
        groups = store.load_groups_for_client(conn, client_id=1)
        assert len(groups) == 1
        assert groups[0].name == "Kids"
        assert groups[0].layer.safesearch_mode == "strict"

    def test_duplicate_group_id_rejected(self, conn):
        store.create_group(conn, "kids", "Kids", 10)
        with pytest.raises(store.PolicyStoreError):
            store.create_group(conn, "kids", "Kids2", 5)

    def test_unknown_group_membership_rejected(self, conn):
        with pytest.raises(store.PolicyStoreError):
            store.add_client_to_group(conn, client_id=1, group_id="ghost")

    def test_priority_ordering_preserved_from_store(self, conn):
        store.create_group(conn, "low", "Low", 1)
        store.create_group(conn, "high", "High", 10)
        store.add_client_to_group(conn, 1, "low")
        store.add_client_to_group(conn, 1, "high")
        groups = store.load_groups_for_client(conn, 1)
        assert [g.group_id for g in groups] == ["low", "high"]


class TestSchedules:
    def test_create_and_load_roundtrip(self, conn):
        w = make_window("22:00", "06:00", ["fri", "sat"])
        store.create_schedule(conn, "bedtime", "UTC", [w])
        loaded = store.load_schedule(conn, "bedtime")
        assert loaded is not None
        assert loaded.timezone == "UTC"
        assert len(loaded.windows) == 1
        active = datetime(2026, 8, 21, 23, 0, tzinfo=timezone.utc)  # Friday
        assert loaded.is_active(active)

    def test_missing_schedule_returns_none(self, conn):
        assert store.load_schedule(conn, "ghost") is None


class TestUpstreamProfiles:
    def test_create_and_load(self, conn):
        eps = [store.UpstreamEndpointRecord("1.1.1.1:853", "cloudflare-dns.com", 0, 1, None)]
        store.create_upstream_profile(conn, "family", "Family DoT", "dot", eps)
        loaded = store.load_upstream_profile(conn, "family")
        assert loaded.transport == "dot"
        assert loaded.endpoints[0].address == "1.1.1.1:853"

    def test_requires_endpoint(self, conn):
        with pytest.raises(store.PolicyStoreError):
            store.create_upstream_profile(conn, "empty", "Empty", "plain", [])

    def test_invalid_transport_rejected(self, conn):
        eps = [store.UpstreamEndpointRecord("1.1.1.1:53", None, 0, 1, None)]
        with pytest.raises(store.PolicyStoreError):
            store.create_upstream_profile(conn, "bad", "Bad", "carrier-pigeon", eps)

    def test_empty_secret_ref_rejected(self, conn):
        eps = [store.UpstreamEndpointRecord("1.1.1.1:53", None, 0, 1, "")]
        with pytest.raises(store.PolicyStoreError):
            store.create_upstream_profile(conn, "bad", "Bad", "plain", eps)


class TestDomainRouting:
    def test_exact_beats_suffix(self, conn):
        store.add_domain_routing_rule(conn, "r1", "suffix", "example.com", "default")
        store.add_domain_routing_rule(conn, "r1", "exact", "internal.example.com", "internal")
        assert store.resolve_domain_route(conn, "r1", "internal.example.com") == "internal"
        assert store.resolve_domain_route(conn, "r1", "www.example.com") == "default"

    def test_more_specific_suffix_wins(self, conn):
        store.add_domain_routing_rule(conn, "r1", "suffix", "example.com", "broad")
        store.add_domain_routing_rule(conn, "r1", "suffix", "corp.example.com", "narrow")
        assert store.resolve_domain_route(conn, "r1", "host.corp.example.com") == "narrow"

    def test_no_match_returns_none(self, conn):
        assert store.resolve_domain_route(conn, "r1", "unrelated.test") is None


class TestServiceBlocking:
    def test_service_and_ruleset(self, conn):
        store.create_service(conn, "svc-social", "Social Network", [("suffix", "social.example")])
        store.create_service_ruleset(conn, "teen-rules", ["svc-social"])
        assert store.is_domain_service_blocked(conn, "teen-rules", "www.social.example") == "svc-social"
        assert store.is_domain_service_blocked(conn, "teen-rules", "unrelated.test") is None

    def test_ruleset_references_unknown_service_rejected(self, conn):
        with pytest.raises(store.PolicyStoreError):
            store.create_service_ruleset(conn, "r1", ["ghost-service"])


class TestDnsTransportSettings:
    def test_defaults_disabled(self, conn):
        settings = store.load_dns_transport_settings(conn)
        assert settings.dot_enabled is False
        assert settings.dot_port == 853
        assert settings.doh_enabled is False
        assert settings.doh_port == 443
        assert settings.doh_path == "/dns-query"
        assert settings.doq_enabled is False
        assert settings.doq_port == 853
        assert settings.doh3_enabled is False
        assert settings.doh3_port == 443

    def test_round_trip(self, conn):
        store.save_dns_transport_settings(
            conn,
            store.DnsTransportSettings(
                dot_enabled=True, dot_port=8853, doh_enabled=True, doh_port=8443, doh_path="/custom-path",
                doq_enabled=True, doq_port=8853, doh3_enabled=True, doh3_port=8444,
            ),
        )
        conn.commit()
        settings = store.load_dns_transport_settings(conn)
        assert settings.dot_enabled is True
        assert settings.dot_port == 8853
        assert settings.doh_enabled is True
        assert settings.doh_port == 8443
        assert settings.doh_path == "/custom-path"
        assert settings.doq_enabled is True
        assert settings.doq_port == 8853
        assert settings.doh3_enabled is True
        assert settings.doh3_port == 8444

    def test_invalid_port_rejected(self, conn):
        with pytest.raises(store.PolicyStoreError):
            store.save_dns_transport_settings(conn, store.DnsTransportSettings(dot_port=0))
        with pytest.raises(store.PolicyStoreError):
            store.save_dns_transport_settings(conn, store.DnsTransportSettings(doh_port=99999))
        with pytest.raises(store.PolicyStoreError):
            store.save_dns_transport_settings(conn, store.DnsTransportSettings(doq_port=0))
        with pytest.raises(store.PolicyStoreError):
            store.save_dns_transport_settings(conn, store.DnsTransportSettings(doh3_port=0))

    def test_pre_doh3_schema_migrates_cleanly(self, db):
        # Real regression coverage for the incremental-migration path
        # (_ensure_dns_transport_settings_table): an existing install
        # whose dns_transport_settings table predates the doh3_enabled/
        # doh3_port columns must gain them via ALTER TABLE, not break.
        with control_db.connect(db) as c:
            c.execute("ALTER TABLE dns_transport_settings DROP COLUMN doh3_enabled")
            c.execute("ALTER TABLE dns_transport_settings DROP COLUMN doh3_port")
            c.commit()
        store._ensure_dns_transport_settings_table(db)
        with control_db.connect(db) as c:
            settings = store.load_dns_transport_settings(c)
        assert settings.doh3_enabled is False
        assert settings.doh3_port == 443

    def test_invalid_doh_path_rejected(self, conn):
        with pytest.raises(store.PolicyStoreError):
            store.save_dns_transport_settings(conn, store.DnsTransportSettings(doh_path="no-leading-slash"))

    def test_ensure_schema_is_idempotent_and_incremental(self, tmp_path):
        # Real regression coverage: re-running ensure_schema against an
        # already-migrated DB (simulating a package upgrade) must not
        # fail and must leave a functioning table -- the incremental
        # ALTER TABLE ADD COLUMN path (doh_enabled/doh_port/doh_path)
        # must be idempotent too, not just the CREATE TABLE.
        path = tmp_path / "control.db"
        store.ensure_schema(path)
        store.ensure_schema(path)
        store.ensure_schema(path)
        with control_db.connect(path) as conn:
            settings = store.load_dns_transport_settings(conn)
            assert settings.doh_port == 443


class TestRoundTrip:
    def test_control_db_backed_compile_matches_in_memory_fixture(self, conn):
        store.save_policy_layer(conn, "global", "singleton", PolicyLayer(safesearch_mode="off"))
        store.create_network(conn, "lan", "10.0.0.0/8")
        store.save_policy_layer(conn, "network", "lan", PolicyLayer(ecs_mode="preserve"))
        store.create_group(conn, "kids", "Kids", 10)
        store.save_policy_layer(conn, "group", "kids", PolicyLayer(safesearch_mode="strict"))
        store.add_client_to_group(conn, 1, "kids")
        store.save_policy_layer(conn, "client", "1", PolicyLayer(upstream_profile_id="family"))

        from app.v2.policy_service import ClientResolutionContext, compile_effective_policy_from_store

        from_store = compile_effective_policy_from_store(
            conn, ClientResolutionContext(client_id=1, client_ip="10.1.2.3")
        )

        from_memory = compile_effective_policy(
            PolicyLayer(safesearch_mode="off"),
            network_layer=PolicyLayer(ecs_mode="preserve"),
            network_source="lan",
            groups=[GroupPolicy("kids", "Kids", 10, PolicyLayer(safesearch_mode="strict"))],
            client_layer=PolicyLayer(upstream_profile_id="family"),
        )

        assert from_store.values == from_memory.values
        assert compile_cache_profile(from_store).profile_id == compile_cache_profile(from_memory).profile_id
