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


def test_implausible_addresses_are_never_ingested_as_observations(tmp_path):
    # Real defect fixed here (owner-reported live): "192.168.32.0" (a
    # network address, not a real host) and "10.89.0.0" (this preview's
    # own Podman bridge network) both appeared as "clients". Neither a
    # network-looking address nor loopback/link-local/multicast/
    # unspecified/reserved traffic may ever become a manageable client,
    # regardless of which producer submitted it.
    db = tmp_path / "control.db"
    _init(db)
    with control_db.connect(db) as conn:
        observed_clients.apply_observations(
            conn,
            [
                observed_clients.Observation("192.168.32.0"),  # network address (owner's real repro)
                observed_clients.Observation("10.89.0.0"),  # network address (owner's real repro)
                observed_clients.Observation("127.0.0.1"),  # loopback
                observed_clients.Observation("169.254.1.5"),  # link-local
                observed_clients.Observation("224.0.0.251"),  # multicast
                observed_clients.Observation("0.0.0.0"),  # unspecified
                observed_clients.Observation("::1"),  # IPv6 loopback
                observed_clients.Observation("192.168.32.157"),  # a real, plausible host
            ],
        )
        rows = observed_clients.list_observed(conn)
        source_ips = {r["source_ip"] for r in rows["observed_clients"]}
        assert source_ips == {"192.168.32.157"}


def test_local_gateway_address_is_never_ingested_as_a_client(tmp_path, monkeypatch):
    # Real defect fixed here (confirmed against the live owner-preview
    # container: host-originated traffic through Podman's port-forward
    # NAT arrived at dnsdist as the bridge gateway's own address,
    # 10.89.0.1, indistinguishable from a real client by address shape
    # alone since it doesn't end in .0). Proven by monkeypatching the
    # gateway-detection helper directly (real /proc/net/route parsing is
    # covered implicitly by every other passing observed_clients test
    # not spuriously rejecting real addresses in this environment).
    monkeypatch.setattr(observed_clients, "_local_gateway_address", lambda: "10.89.0.1")
    db = tmp_path / "control.db"
    _init(db)
    with control_db.connect(db) as conn:
        observed_clients.apply_observations(
            conn,
            [
                observed_clients.Observation("10.89.0.1"),  # the (mocked) gateway itself
                observed_clients.Observation("10.89.0.42"),  # a real host on the same subnet
            ],
        )
        source_ips = {r["source_ip"] for r in observed_clients.list_observed(conn)["observed_clients"]}
        assert source_ips == {"10.89.0.42"}


def test_purge_implausible_cleans_up_already_persisted_bogus_rows_but_spares_managed(tmp_path):
    db = tmp_path / "control.db"
    _init(db)
    with control_db.connect(db) as conn:
        # Insert directly, bypassing apply_observations's own filter, to
        # simulate rows a past run of the now-fixed producer bug already
        # wrote before this fix existed.
        conn.execute(
            "INSERT INTO observed_clients(source_ip, address_family, first_seen, last_seen, query_count) "
            "VALUES ('192.168.32.0','ipv4','2026-01-01T00:00:00+00:00','2026-01-01T00:00:00+00:00',1)"
        )
        conn.execute(
            "INSERT INTO observed_clients(source_ip, address_family, first_seen, last_seen, query_count) "
            "VALUES ('192.168.32.157','ipv4','2026-01-01T00:00:00+00:00','2026-01-01T00:00:00+00:00',1)"
        )
        removed = observed_clients.purge_implausible(conn)
        assert removed == 1
        source_ips = {r[0] for r in conn.execute("SELECT source_ip FROM observed_clients")}
        assert source_ips == {"192.168.32.157"}


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
