from app.v2 import control_db, observed_clients, policy_store


def _init(path):
    control_db.initialize(path)
    policy_store.ensure_schema(path)
    observed_clients.ensure_schema(path)


def test_observations_coalesce_by_source_and_sanitize_hostnames(tmp_path):
    db = tmp_path / "control.db"
    _init(db)
    with control_db.connect(db) as conn:
        observed_clients.apply_observations(
            conn,
            [
                observed_clients.Observation("192.0.2.10", "<script>alert(1)</script>\n", "ptr"),
                observed_clients.Observation("192.0.2.10", "Laptop.EXAMPLE.", "ptr"),
            ],
        )
        row = observed_clients.get_observed(conn, "192.0.2.10")
        assert row["query_count"] == 2
        assert row["hostname_candidate"] == "laptop.example"
        assert "<" not in row["hostname_candidate"]


def test_retention_caps_observed_clients_without_deleting_managed(tmp_path):
    db = tmp_path / "control.db"
    _init(db)
    with control_db.connect(db) as conn:
        conn.execute("INSERT INTO clients(name, created_at, updated_at) VALUES ('managed', 'n', 'n')")
        client_id = conn.execute("SELECT id FROM clients").fetchone()[0]
        conn.execute("INSERT INTO client_identifiers(client_id, kind, value, created_at) VALUES (?, 'ipv4', '198.51.100.1', 'n')", (client_id,))
        observed_clients.update_settings(conn, max_entries=3)
        observed_clients.apply_observations(
            conn,
            [observed_clients.Observation(f"198.51.100.{i}") for i in range(1, 8)],
        )
        stats = observed_clients.stats(conn)
        assert stats["observed_count"] <= 3
        assert conn.execute("SELECT count(*) FROM clients").fetchone()[0] == 1
        assert observed_clients.get_observed(conn, "198.51.100.1")["managed_client_id"] == client_id


def test_promote_is_idempotent_and_policy_explain_works(tmp_path):
    db = tmp_path / "control.db"
    _init(db)
    with control_db.connect(db) as conn:
        observed_clients.apply_observations(conn, [observed_clients.Observation("2001:db8::1234", "phone")])
        a = observed_clients.promote(conn, "2001:db8::1234", display_name="phone")
        b = observed_clients.promote(conn, "2001:db8::1234", display_name="phone again")
        assert a == b
        assert conn.execute("SELECT count(*) FROM clients").fetchone()[0] == 1
        from app.v2 import policy_service

        explain = policy_service.explain_policy_for_client(
            conn, policy_service.ClientResolutionContext(client_id=a, client_ip="2001:db8::1234")
        )
        assert explain["client_id"] == a


def test_queue_drops_or_coalesces_without_blocking():
    q = observed_clients.ObservationQueue(capacity=2)
    assert q.submit("192.0.2.1")
    assert q.submit("192.0.2.1")
    assert q.coalesced >= 1
    q.submit("192.0.2.2")
    q.submit("192.0.2.3")
    q.submit("192.0.2.4")
    assert q.dropped >= 1 or len(q) <= 2
