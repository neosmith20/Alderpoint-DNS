"""Gate #2 MEDIUM: central DNS name validator, tested directly."""

import pytest

from app.v2.dns_name_validate import InvalidDnsNameError, validate_dns_name, validate_dns_names


class TestValidNames:
    def test_simple_domain(self):
        assert validate_dns_name("example.com") == "example.com"

    def test_trailing_dot_stripped(self):
        assert validate_dns_name("example.com.") == "example.com"

    def test_uppercase_normalized_to_lowercase(self):
        assert validate_dns_name("EXAMPLE.com") == "example.com"

    def test_underscore_label_accepted(self):
        assert validate_dns_name("_dmarc.example.com") == "_dmarc.example.com"

    def test_unicode_domain_idna_encoded_but_returned_normalized(self):
        # Returns the normalized (lowercased) unicode form; the caller
        # renders it, and callers needing punycode for wire output would
        # ask for the IDNA-encoded bytes separately -- this function's
        # contract is "valid or not," not "already punycode."
        result = validate_dns_name("münchen.de")
        assert result == "münchen.de"

    def test_wildcard_label_accepted_when_allowed(self):
        assert validate_dns_name("*.example.com", allow_wildcard_label=True) == "*.example.com"

    def test_wildcard_label_rejected_by_default(self):
        with pytest.raises(InvalidDnsNameError):
            validate_dns_name("*.example.com")


class TestInjectionRejected:
    def test_embedded_newline_rejected(self):
        with pytest.raises(InvalidDnsNameError):
            validate_dns_name("bad\ndomain.com")

    def test_embedded_carriage_return_rejected(self):
        with pytest.raises(InvalidDnsNameError):
            validate_dns_name("bad\rdomain.com")

    def test_embedded_null_byte_rejected(self):
        with pytest.raises(InvalidDnsNameError):
            validate_dns_name("bad\x00domain.com")

    def test_embedded_space_rejected(self):
        with pytest.raises(InvalidDnsNameError):
            validate_dns_name("has space.com")

    def test_zone_file_injection_shape_rejected(self):
        with pytest.raises(InvalidDnsNameError):
            validate_dns_name("evil.example\nA 6.6.6.6\n;")

    def test_idna_codec_alone_would_have_accepted_this_proving_the_extra_check_matters(self):
        # Documents the real gap this module closes: the stdlib idna
        # codec alone does NOT reject this.
        payload = "bad\ndomain.com"
        assert payload.encode("idna") == payload.encode()  # stdlib alone: silently "fine"
        with pytest.raises(InvalidDnsNameError):
            validate_dns_name(payload)  # this module: correctly rejected

    def test_sql_metacharacters_rejected(self):
        with pytest.raises(InvalidDnsNameError):
            validate_dns_name("'; DROP TABLE x; --.example")

    def test_lua_string_escape_shape_rejected(self):
        with pytest.raises(InvalidDnsNameError):
            validate_dns_name('evil"}); os.execute("x")--.example')


class TestMalformedLabels:
    def test_empty_label_rejected(self):
        with pytest.raises(InvalidDnsNameError):
            validate_dns_name("bad..example.com")

    def test_empty_name_rejected(self):
        with pytest.raises(InvalidDnsNameError):
            validate_dns_name("")

    def test_only_dots_rejected(self):
        with pytest.raises(InvalidDnsNameError):
            validate_dns_name("...")

    def test_label_starting_with_hyphen_rejected(self):
        with pytest.raises(InvalidDnsNameError):
            validate_dns_name("-bad.example.com")

    def test_label_ending_with_hyphen_rejected(self):
        with pytest.raises(InvalidDnsNameError):
            validate_dns_name("bad-.example.com")

    def test_non_string_input_rejected(self):
        with pytest.raises(InvalidDnsNameError):
            validate_dns_name(12345)  # type: ignore[arg-type]


class TestOverlongNames:
    def test_label_over_63_bytes_rejected(self):
        with pytest.raises(InvalidDnsNameError):
            validate_dns_name("a" * 64 + ".example.com")

    def test_label_exactly_63_bytes_accepted(self):
        assert validate_dns_name("a" * 63 + ".example.com")

    def test_name_over_253_bytes_rejected(self):
        long_name = ".".join(["a" * 50] * 6)  # way over 253 bytes total
        with pytest.raises(InvalidDnsNameError):
            validate_dns_name(long_name)

    def test_reasonable_multi_label_name_accepted(self):
        name = ".".join(["a" * 50] * 4) + ".example"
        assert validate_dns_name(name) == name


class TestBatchValidation:
    def test_validate_dns_names_returns_all_normalized(self):
        result = validate_dns_names(["Example.COM", "test.example."])
        assert result == ["example.com", "test.example"]

    def test_validate_dns_names_raises_on_first_bad_entry(self):
        with pytest.raises(InvalidDnsNameError):
            validate_dns_names(["good.example", "bad\ndomain.com"])
