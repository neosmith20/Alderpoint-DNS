from datetime import datetime, timezone

import pytest

from app.v2 import control_db, policy_store as store
from app.v2.policy_model import PolicyLayer
from app.v2.policy_service import ClientResolutionContext, explain_policy_for_client
from app.v2.schedule_policy import make_window


@pytest.fixture()
def conn(tmp_path):
    path = tmp_path / "control.db"
    store.ensure_schema(path)
    with control_db.connect(path) as c:
        c.execute(
            "INSERT INTO clients (id, name, created_at, updated_at) VALUES (1, 'test-client', '', '')"
        )
        yield c


class TestExplain:
    def test_explain_has_no_secrets(self, conn):
        store.save_policy_layer(conn, "global", "singleton", PolicyLayer(safesearch_mode="strict"))
        result = explain_policy_for_client(conn, ClientResolutionContext(client_id=1))
        text = str(result)
        assert "secret" not in text.lower()
        assert "password" not in text.lower()
        assert "token" not in text.lower()

    def test_explain_reports_network_and_group_sources(self, conn):
        store.save_policy_layer(conn, "global", "singleton", PolicyLayer(safesearch_mode="off"))
        store.create_network(conn, "lan", "10.0.0.0/8")
        store.create_group(conn, "kids", "Kids", 10)
        store.save_policy_layer(conn, "group", "kids", PolicyLayer(safesearch_mode="strict"))
        store.add_client_to_group(conn, 1, "kids")

        result = explain_policy_for_client(
            conn, ClientResolutionContext(client_id=1, client_ip="10.5.5.5")
        )
        assert result["network_match"] == "network:lan"
        assert result["group_contributions"] == ["group:Kids"]
        assert result["fields"]["safesearch_mode"]["value"] == "strict"
        assert result["fields"]["safesearch_mode"]["source"] == "group:Kids"

    def test_explain_includes_cache_profile_id(self, conn):
        store.save_policy_layer(conn, "global", "singleton", PolicyLayer())
        result = explain_policy_for_client(conn, ClientResolutionContext(client_id=1))
        assert isinstance(result["effective_cache_profile_id"], str)
        assert len(result["effective_cache_profile_id"]) > 0

    def test_active_schedule_reflected(self, conn):
        w = make_window("00:00", "23:59", ["mon", "tue", "wed", "thu", "fri", "sat", "sun"])
        store.create_schedule(conn, "always-on", "UTC", [w])
        store.save_policy_layer(conn, "schedule", "always-on", PolicyLayer(safesearch_mode="strict"))
        store.save_policy_layer(conn, "global", "singleton", PolicyLayer(safesearch_mode="off"))

        now = datetime(2026, 8, 17, 12, 0, tzinfo=timezone.utc)
        result = explain_policy_for_client(conn, ClientResolutionContext(client_id=1), now=now)
        assert result["schedule_active"] == "always-on"
        assert result["fields"]["safesearch_mode"]["value"] == "strict"

    def test_no_active_schedule_reports_none(self, conn):
        w = make_window("00:00", "00:01", ["mon"])
        store.create_schedule(conn, "narrow", "UTC", [w])
        now = datetime(2026, 8, 17, 12, 0, tzinfo=timezone.utc)
        result = explain_policy_for_client(conn, ClientResolutionContext(client_id=1), now=now)
        assert result["schedule_active"] is None
