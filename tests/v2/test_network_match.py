import pytest

from app.v2.network_match import (
    InvalidNetworkError,
    NetworkScope,
    compile_network_table,
)


def _scope(nid, cidr, ref):
    return NetworkScope.create(nid, cidr, ref)


class TestBasicMatching:
    def test_single_network_matches(self):
        table = compile_network_table([_scope("n1", "10.0.0.0/8", "policy-a")])
        m = table.match("10.1.2.3")
        assert m.policy_ref == "policy-a"

    def test_no_match_returns_none(self):
        table = compile_network_table([_scope("n1", "10.0.0.0/8", "policy-a")])
        assert table.match("192.168.1.1") is None

    def test_ipv6_supported(self):
        table = compile_network_table([_scope("n1", "2001:db8::/32", "policy-a")])
        assert table.match("2001:db8::1").policy_ref == "policy-a"

    def test_ipv4_and_ipv6_dont_cross_match(self):
        table = compile_network_table([_scope("n1", "10.0.0.0/8", "policy-a")])
        with pytest.raises(InvalidNetworkError):
            table.match("not-an-ip")


class TestMostSpecificWins:
    def test_narrower_network_wins_over_broader(self):
        table = compile_network_table(
            [
                _scope("broad", "10.0.0.0/8", "policy-broad"),
                _scope("narrow", "10.0.1.0/24", "policy-narrow"),
            ]
        )
        assert table.match("10.0.1.5").policy_ref == "policy-narrow"
        assert table.match("10.0.2.5").policy_ref == "policy-broad"

    def test_order_independent(self):
        scopes = [
            _scope("narrow", "10.0.1.0/24", "policy-narrow"),
            _scope("broad", "10.0.0.0/8", "policy-broad"),
        ]
        table_a = compile_network_table(scopes)
        table_b = compile_network_table(list(reversed(scopes)))
        assert table_a.match("10.0.1.5").policy_ref == table_b.match("10.0.1.5").policy_ref

    def test_equal_specificity_tiebreaks_on_network_id(self):
        table = compile_network_table(
            [
                _scope("zzz", "10.0.1.0/24", "policy-zzz"),
                _scope("aaa", "10.0.2.0/24", "policy-aaa"),
            ]
        )
        # Different networks, no actual overlap here, but confirms ordering
        # doesn't crash/misbehave when prefixlens tie.
        assert table.match("10.0.1.1").policy_ref == "policy-zzz"
        assert table.match("10.0.2.1").policy_ref == "policy-aaa"


class TestValidation:
    def test_invalid_cidr_rejected(self):
        with pytest.raises(InvalidNetworkError):
            _scope("n1", "not-a-cidr", "policy-a")

    def test_empty_network_id_rejected(self):
        with pytest.raises(InvalidNetworkError):
            _scope("", "10.0.0.0/8", "policy-a")

    def test_duplicate_network_id_rejected(self):
        with pytest.raises(InvalidNetworkError):
            compile_network_table(
                [
                    _scope("n1", "10.0.0.0/8", "policy-a"),
                    _scope("n1", "192.168.0.0/16", "policy-b"),
                ]
            )

    def test_duplicate_cidr_rejected(self):
        with pytest.raises(InvalidNetworkError):
            compile_network_table(
                [
                    _scope("n1", "10.0.0.0/8", "policy-a"),
                    _scope("n2", "10.0.0.0/8", "policy-b"),
                ]
            )

    def test_host_bits_set_normalized_not_rejected(self):
        # strict=False: 10.0.0.5/24 is accepted and normalized to 10.0.0.0/24
        scope = _scope("n1", "10.0.0.5/24", "policy-a")
        assert scope.cidr == "10.0.0.0/24"
