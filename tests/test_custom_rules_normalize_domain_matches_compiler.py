"""Real defect found live during the owner-beta closure soak/acceptance
pass (docs comment at app/custom_rules.py's _normalize_domain): V2 does
not ship app/alderpointdns_compiler.py (shipping it would cascade into
several other unshipped V1 modules), so custom_rules.py's own
_normalize_domain -- reached by a real V2 caller, blocklist subscription
refresh -- now carries its own inlined copy of
alderpointdns_compiler.normalize_domain instead of importing it.

This is the drift guard for that duplication: both implementations must
keep agreeing, across a real battery of inputs, or this fails --
catching the exact class of bug an inline-then-forget copy invites.
"""

from __future__ import annotations

import pytest

from app import custom_rules
from app.alderpointdns_compiler import normalize_domain as canonical_normalize_domain

CASES = [
    "example.com",
    "EXAMPLE.COM",
    "  example.com  ",
    "sub.example.com.",
    "a" * 64 + ".example.com",  # label too long
    "a" * 260,  # overall too long
    "",
    "   ",
    "192.168.1.1",
    "::1",
    "http://example.com",
    "example.com/path",
    "user@example.com",
    "xn--exmple-cua.com",
    "café.example",  # non-ascii, valid IDNA
    "not a domain",
    "example..com",
    ".example.com",
    "localhost",
    "-example.com",
    "example-.com",
]


class TestNormalizeDomainMatchesCanonicalCompilerVersion:
    @pytest.mark.parametrize("raw", CASES)
    def test_inlined_copy_agrees_with_canonical(self, raw):
        assert custom_rules._normalize_domain(raw) == canonical_normalize_domain(raw)

    def test_does_not_import_alderpointdns_compiler_at_runtime(self):
        """The whole point of the inlined copy: no dependency on the
        module V2 deliberately does not ship. A regression back to a
        cross-module import would reintroduce the real
        ModuleNotFoundError this closure item fixed."""
        import ast
        import inspect

        source = inspect.getsource(custom_rules._normalize_domain)
        tree = ast.parse(source)
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module == "app.alderpointdns_compiler":
                pytest.fail("_normalize_domain must not import app.alderpointdns_compiler")
