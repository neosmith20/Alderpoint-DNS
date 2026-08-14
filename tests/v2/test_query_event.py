import pytest

from app.v2.query_event import NormalizedQueryEvent, next_event_id


def _event(**overrides):
    defaults = dict(
        ts=1000.0, qname="example.com", qtype="A", protocol="udp", client="10.0.0.1"
    )
    defaults.update(overrides)
    return NormalizedQueryEvent(**defaults)


class TestValidation:
    def test_empty_qname_rejected(self):
        with pytest.raises(ValueError):
            _event(qname="")

    def test_invalid_protocol_rejected(self):
        with pytest.raises(ValueError):
            _event(protocol="carrier-pigeon")

    def test_invalid_action_rejected(self):
        with pytest.raises(ValueError):
            _event(action="teleport")

    def test_invalid_cache_status_rejected(self):
        with pytest.raises(ValueError):
            _event(cache_status="teleport")


class TestNoSecrets:
    def test_dataclass_has_no_secret_field(self):
        field_names = {f for f in NormalizedQueryEvent.__dataclass_fields__}
        for forbidden in ("password", "secret", "token", "credential"):
            assert not any(forbidden in f.lower() for f in field_names)


class TestRawRecordShape:
    def test_to_raw_record_has_expected_keys(self):
        e = _event(blocked_domain_hint=None) if False else _event()
        rec = e.to_raw_record(event_id=5)
        expected = {
            "id", "ts", "client", "client_name", "domain", "qtype", "protocol",
            "rcode", "latency_ms", "blocked", "block_reason", "upstream",
            "cache_status", "cache_profile_id",
        }
        assert set(rec.keys()) == expected
        assert rec["id"] == 5
        assert rec["domain"] == "example.com"

    def test_blocked_action_sets_blocked_true(self):
        e = _event(action="blocked", block_reason="svc-social")
        rec = e.to_raw_record()
        assert rec["blocked"] is True
        assert rec["block_reason"] == "svc-social"

    def test_allowed_action_sets_blocked_false(self):
        e = _event(action="allowed")
        assert e.to_raw_record()["blocked"] is False

    def test_auto_generated_id_is_monotonic(self):
        a = next_event_id()
        b = next_event_id()
        assert b > a
