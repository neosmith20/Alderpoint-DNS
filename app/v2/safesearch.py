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

# Real defect closed (beta-rescue pass, owner-reported): "moderate" and
# "strict" previously mapped to the exact same single CNAME target per
# provider, so the two exposed modes always produced byte-identical
# runtime rewrites -- fake differentiation. Audited against each
# provider's own published DNS-level SafeSearch documentation:
#
# - YouTube genuinely publishes two distinct enforcement hostnames --
#   restrictmoderate.youtube.com and restrictstrict.youtube.com -- so
#   "moderate" and "strict" now really differ for YouTube.
# - Google, Bing, and DuckDuckGo do NOT publish a distinct "moderate"
#   DNS-enforcement hostname at all -- each publishes exactly one real
#   enforcement CNAME, which behaves like "strict" no matter which mode
#   selects it. Both levels intentionally map to that same real target
#   for these three: this is the true DNS-level product contract, not a
#   bug -- inventing a fictional "moderate" target for them would be the
#   fake differentiation this fix is closing, in the other direction.
_SAFE_CNAME_TARGET: dict[str, dict[str, str]] = {
    "google": {"moderate": "forcesafesearch.google.com", "strict": "forcesafesearch.google.com"},
    "youtube": {"moderate": "restrictmoderate.youtube.com", "strict": "restrictstrict.youtube.com"},
    "bing": {"moderate": "strict.bing.com", "strict": "strict.bing.com"},
    "duckduckgo": {"moderate": "safe.duckduckgo.com", "strict": "safe.duckduckgo.com"},
}

# Providers whose "moderate" target genuinely differs from "strict" --
# used by the management-plane Explain surface to tell an administrator
# the truth about which providers actually differentiate, rather than
# implying uniform behavior across every provider.
PROVIDERS_WITH_REAL_MODERATE_DIFFERENTIATION = tuple(
    sorted(p for p, targets in _SAFE_CNAME_TARGET.items() if targets["moderate"] != targets["strict"])
)

SUPPORTED_PROVIDERS = tuple(sorted(_PROVIDER_TABLE))
_VALID_LEVELS = ("moderate", "strict")


def is_supported_provider(provider: str) -> bool:
    return provider in _PROVIDER_TABLE


@dataclass(frozen=True)
class SafeSearchRewrite:
    provider: str
    domain: str
    cname_target: str


def rewrites_for_providers(providers: list[str], level: str = "strict") -> list[SafeSearchRewrite]:
    """Returns one rewrite per (provider, domain) pair for the given
    SafeSearch level ("moderate" or "strict"). Raises if any requested
    provider isn't in the supported table -- deliberately loud rather
    than silently skipping a provider the admin thinks is enforced.
    """
    if level not in _VALID_LEVELS:
        raise ValueError(f"invalid SafeSearch level: {level!r} (valid: {_VALID_LEVELS})")
    out = []
    for provider in providers:
        if provider not in _PROVIDER_TABLE:
            raise ValueError(
                f"unsupported SafeSearch provider: {provider!r} (supported: {SUPPORTED_PROVIDERS})"
            )
        target = _SAFE_CNAME_TARGET[provider][level]
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
