"""Gate #2 residual P0-B: render_refused_block_rules() must route every
domain through the central validate_dns_name() path before render, same as
every other DNS generation call site (Gate #2 MEDIUM fix).
"""

import pytest

from app.v2.dnsdist_gen import DnsdistGenError, render_refused_block_rules

INJECTION_PAYLOADS = [
    "evil\nexample.com",
    "evil\rexample.com",
    "evil\texample.com",
    "evil\x00example.com",
    "evil example.com",
    "bad..example.com",
    "-bad.example.com",
    "bad-.example.com",
    "a" * 64 + ".example.com",
    "evil.example\nA 6.6.6.6\n;",
    '"; DROP TABLE x; --.example',
]


class TestLegacyRefusedValidatorRejectsInjection:
    @pytest.mark.parametrize("payload", INJECTION_PAYLOADS)
    def test_malicious_domain_rejected_before_render(self, payload):
        with pytest.raises(DnsdistGenError):
            render_refused_block_rules([payload])

    def test_valid_domains_still_accepted(self):
        lines = render_refused_block_rules(["blocked.example", "Other.Example."])
        text = "\n".join(lines)
        assert "blocked.example." in text
        assert "other.example." in text

    def test_one_bad_domain_among_good_ones_rejects_the_whole_batch(self):
        with pytest.raises(DnsdistGenError):
            render_refused_block_rules(["good.example", "evil\nexample.com"])

    def test_empty_list_still_returns_empty(self):
        assert render_refused_block_rules([]) == ()
