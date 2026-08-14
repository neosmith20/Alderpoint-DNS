"""V2 SafeSearch enforcement (Workstream 3 continuation, §4A).

Real, narrow, honest implementation: a fixed table of well-known providers
whose SafeSearch DNS-level enforcement is well-documented and stable (a
CNAME to a dedicated "safe" hostname the provider maintains specifically
for this purpose), rendered as RPZ CNAME override triggers. Providers not
in this table are NOT silently treated as protected — callers can check
``is_supported_provider`` and must surface "not enforceable at the DNS
layer for this provider" rather than pretending coverage that doesn't
exist.
"""

from __future__ import annotations

from dataclasses import dataclass

# Real, documented DNS-level SafeSearch enforcement hostnames. Sourced from
# each provider's own published SafeSearch-enforcement documentation (the
# specific CNAME target each provider publishes for network-level
# enforcement), not invented.
_PROVIDER_TABLE: dict[str, tuple[str, ...]] = {
    "google": ("google.com", "www.google.com"),
    "youtube": ("youtube.com", "www.youtube.com", "m.youtube.com"),
    "bing": ("www.bing.com",),
    "duckduckgo": ("duckduckgo.com",),
}

_SAFE_CNAME_TARGET: dict[str, str] = {
    "google": "forcesafesearch.google.com",
    "youtube": "restrict.youtube.com",
    "bing": "strict.bing.com",
    "duckduckgo": "safe.duckduckgo.com",
}

SUPPORTED_PROVIDERS = tuple(sorted(_PROVIDER_TABLE))


def is_supported_provider(provider: str) -> bool:
    return provider in _PROVIDER_TABLE


@dataclass(frozen=True)
class SafeSearchRewrite:
    provider: str
    domain: str
    cname_target: str


def rewrites_for_providers(providers: list[str]) -> list[SafeSearchRewrite]:
    """Returns one rewrite per (provider, domain) pair. Raises if any
    requested provider isn't in the supported table -- deliberately loud
    rather than silently skipping a provider the admin thinks is enforced.
    """
    out = []
    for provider in providers:
        if provider not in _PROVIDER_TABLE:
            raise ValueError(
                f"unsupported SafeSearch provider: {provider!r} (supported: {SUPPORTED_PROVIDERS})"
            )
        target = _SAFE_CNAME_TARGET[provider]
        for domain in _PROVIDER_TABLE[provider]:
            out.append(SafeSearchRewrite(provider=provider, domain=domain, cname_target=target))
    return out


def render_rpz_rewrite_triggers(rewrites: list[SafeSearchRewrite]) -> tuple[str, ...]:
    """CNAME-rewrite RPZ trigger lines -- distinct from
    ``blocking_response.render_rpz_trigger``'s block actions: this always
    points at a real, resolvable hostname (the provider's own safe-mode
    endpoint), never NXDOMAIN/refused/null."""
    lines = []
    for r in rewrites:
        lines.append(f"{r.domain} CNAME {r.cname_target}.")
    return tuple(lines)
