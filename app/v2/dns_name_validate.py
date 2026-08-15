"""V2 central DNS name validator (Gate #2 MEDIUM finding).

One strict validation path used before ANY generated RPZ owner name,
Local DNS name, rewrite target, SafeSearch domain, block/allow domain,
service-registry domain, or domain-routing suffix is rendered into zone/
config text. `named-checkzone`/`named-checkconf` remain defense-in-depth
(still run against every generated artifact), but invalid domain data
must never reach rendered text in the first place -- a newline embedded
in a domain string must be rejected HERE, not merely caught later by an
external validator tool.

**Real gap found while building this:** Python's stdlib ``str.encode
("idna")`` codec (RFC 3490) rejects empty/overlong labels but does
*not* reject embedded control characters, CR/LF, or whitespace within an
otherwise-ASCII label -- ``"bad\\ndomain.com".encode("idna")`` succeeds
unchanged. IDNA encoding alone is therefore NOT sufficient as an
injection defense; this module does its own explicit character-class
check first, then IDNA-encodes for Unicode/punycode correctness.
"""

from __future__ import annotations

import re

_MAX_LABEL_BYTES = 63
_MAX_NAME_BYTES = 253
_DANGEROUS_CHARS = frozenset(
    {"\n", "\r", "\t", "\x00", " ", "\x0b", "\x0c"}
    | {chr(c) for c in range(0x00, 0x20)}
    | {"\x7f"}
)
_LDH_LABEL_RE = re.compile(r"^[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?$")


class InvalidDnsNameError(ValueError):
    pass


def validate_dns_name(name: str, *, allow_wildcard_label: bool = False) -> str:
    """Returns the normalized (trailing-dot-stripped, lowercased) name on
    success, or raises ``InvalidDnsNameError`` naming exactly what's
    wrong. Applied uniformly across every domain-shaped string this
    package renders into generated zone/config text.
    """
    if not isinstance(name, str):
        raise InvalidDnsNameError(f"domain name must be a string, got {type(name).__name__}")

    # Explicit character-class check FIRST -- IDNA encoding alone does not
    # reject embedded control characters/whitespace (see module docstring).
    bad_chars = _DANGEROUS_CHARS & set(name)
    if bad_chars:
        raise InvalidDnsNameError(
            f"domain name {name!r} contains disallowed character(s): "
            f"{[hex(ord(c)) for c in sorted(bad_chars)]}"
        )

    normalized = name.strip().rstrip(".").lower()
    if not normalized:
        raise InvalidDnsNameError("domain name must not be empty")

    labels = normalized.split(".")
    if any(label == "" for label in labels):
        raise InvalidDnsNameError(f"domain name {name!r} has an empty label (e.g. '..')")

    encoded_labels = []
    for i, label in enumerate(labels):
        is_wildcard = allow_wildcard_label and i == 0 and label == "*"
        if is_wildcard:
            encoded_labels.append(b"*")
            continue
        if not label.isascii():
            try:
                encoded = label.encode("idna")
            except UnicodeError as exc:
                raise InvalidDnsNameError(f"invalid IDNA label {label!r} in {name!r}: {exc}") from exc
        else:
            if not _LDH_LABEL_RE.match(label):
                raise InvalidDnsNameError(
                    f"invalid label {label!r} in domain name {name!r} -- labels must be "
                    "letters/digits/hyphen/underscore, not start or end with a hyphen"
                )
            encoded = label.encode("ascii")
        if len(encoded) > _MAX_LABEL_BYTES:
            raise InvalidDnsNameError(f"label {label!r} in {name!r} exceeds {_MAX_LABEL_BYTES} bytes")
        encoded_labels.append(encoded)

    total_len = sum(len(l) for l in encoded_labels) + len(encoded_labels) - 1
    if total_len > _MAX_NAME_BYTES:
        raise InvalidDnsNameError(f"domain name {name!r} exceeds {_MAX_NAME_BYTES} bytes")

    return normalized


def validate_dns_names(names: list[str], **kwargs) -> list[str]:
    return [validate_dns_name(n, **kwargs) for n in names]
