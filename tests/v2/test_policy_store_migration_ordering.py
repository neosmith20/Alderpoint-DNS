"""Regression test for a real ordering bug found and fixed in this pass:
app/v2/policy_store.py and app/v2/notification_store.py both apply
migrations against the same control.db using control_db.py's single shared
schema_migrations version counter. Gating policy_store's migration purely
on "current version < POLICY_STORE_SCHEMA_VERSION" was wrong -- if
notification_store.ensure_schema ran first (bumping the shared version past
policy_store's own target), policy_store.ensure_schema would then skip
creating its tables entirely, believing them already present. Fixed by
gating on actual table existence instead of the version counter.
"""

from app.v2 import control_db, notification_store as nstore, policy_store as store


def test_notification_store_first_then_policy_store_still_creates_policy_tables(tmp_path):
    path = tmp_path / "control.db"
    # Notification store's migration runs first, alone, bumping the shared
    # version counter past what policy_store would otherwise gate on.
    nstore.ensure_schema(path)
    assert control_db.schema_version(path) >= nstore.NOTIFICATION_SCHEMA_VERSION

    # Policy store's tables must still get created, not silently skipped.
    store.ensure_schema(path)
    with control_db.connect(path) as conn:
        assert store._table_exists(conn, "policy_layers")
        assert store._table_exists(conn, "policy_networks")
        assert store._table_exists(conn, "policy_groups")

    # And it must actually be usable, not just present as an empty shell.
    with control_db.connect(path) as conn:
        from app.v2.policy_model import PolicyLayer

        store.save_policy_layer(conn, "global", "singleton", PolicyLayer(safesearch_mode="strict"))
        loaded = store.load_policy_layer(conn, "global", "singleton")
        assert loaded.safesearch_mode == "strict"


def test_policy_store_first_then_notification_store_still_works(tmp_path):
    path = tmp_path / "control.db"
    store.ensure_schema(path)
    nstore.ensure_schema(path)
    with control_db.connect(path) as conn:
        assert store._table_exists(conn, "policy_layers")
        assert store._table_exists(conn, "notification_providers")


def test_repeated_ensure_schema_calls_are_idempotent_regardless_of_order(tmp_path):
    path = tmp_path / "control.db"
    nstore.ensure_schema(path)
    store.ensure_schema(path)
    store.ensure_schema(path)
    nstore.ensure_schema(path)
    with control_db.connect(path) as conn:
        assert store._table_exists(conn, "policy_layers")
        assert store._table_exists(conn, "notification_providers")
