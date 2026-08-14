import pytest

from app.v2.safesearch import (
    SUPPORTED_PROVIDERS,
    is_supported_provider,
    render_rpz_rewrite_triggers,
    rewrites_for_providers,
)


class TestSupportTable:
    def test_google_supported(self):
        assert is_supported_provider("google")

    def test_unknown_provider_not_supported(self):
        assert not is_supported_provider("some-random-search-engine")


class TestRewrites:
    def test_google_rewrite_targets_forcesafesearch(self):
        rewrites = rewrites_for_providers(["google"])
        targets = {r.cname_target for r in rewrites}
        assert targets == {"forcesafesearch.google.com"}

    def test_unsupported_provider_raises_loudly(self):
        with pytest.raises(ValueError):
            rewrites_for_providers(["not-a-real-provider"])

    def test_multiple_providers_combine(self):
        rewrites = rewrites_for_providers(["google", "bing"])
        providers = {r.provider for r in rewrites}
        assert providers == {"google", "bing"}


class TestRpzRendering:
    def test_render_produces_cname_lines(self):
        rewrites = rewrites_for_providers(["duckduckgo"])
        lines = render_rpz_rewrite_triggers(rewrites)
        assert any("duckduckgo.com CNAME safe.duckduckgo.com." in l for l in lines)
