#!/usr/bin/env python3
"""First-class custom filtering rules for Alderpoint DNS.

Stores every rule a user or importer supplies -- including unsupported and
invalid ones -- in `custom_filter_rules`, classifies them with an
AdGuard/Pi-hole/hosts-aware parser, and compiles the active, valid subset
into the RPZ zone (exact/wildcard blocks, rpz-passthru allows, A/AAAA
rewrites) plus a dnsdist-layer regex ruleset loaded from plain data files by
a static Lua include. No user-controlled text is ever interpolated into Lua.
"""

from __future__ import annotations

import datetime as dt
import ipaddress
import os
import re
import shutil
import sqlite3
import subprocess
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from app import local_dns


DB_PATH = Path("/var/lib/alderpointdns/alderpointdns.db")
COMPILED_DNSDIST_DIR = Path("/var/lib/alderpointdns/compiled/dnsdist")
DNSDIST_CONF = Path("/etc/dnsdist/dnsdist.conf")
DNSDIST_PACKAGING_CONF = Path("/opt/alderpointdns/packaging/dnsdist.conf")
BACKUP_DIR = Path("/var/lib/alderpointdns/backups")
STAGING_DIR = Path("/var/lib/alderpointdns/staging")
CUSTOM_RULES_LUA_NAME = "custom-rules.conf"
PASS_SUFFIX_DATA = "custom-pass-suffixes.txt"
PASS_EXACT_DATA = "custom-pass-exact.txt"
REGEX_ALLOW_DATA = "custom-regex-allow.txt"
REGEX_BLOCK_DATA = "custom-regex-block.txt"
MAX_REGEX_LENGTH = 512
IMPORTANT_PRIORITY = 100
# Hosts-file blocking sentinels: 0.0.0.0 and :: mean "block". Any other
# address (including 127.0.0.1/::1) is an explicit answer the user chose,
# so it becomes a rewrite rule returning exactly that address.
BLOCKING_SENTINELS = {"0.0.0.0", "::"}
RULE_TYPES = ("block", "allow", "rewrite", "regex_block", "regex_allow", "comment", "unsupported")

UNSUPPORTED_MODIFIER_REASONS = {
    "client": "modifier $client cannot be preserved: Alderpoint DNS has no per-client rule enforcement",
    "ctag": "modifier $ctag cannot be preserved: Alderpoint DNS has no client tags",
    "denyallow": "modifier $denyallow cannot be preserved: per-rule domain exclusions are not supported",
    "dnstype": "modifier $dnstype cannot be preserved: query-type restricted rules are not supported",
    "badfilter": "modifier $badfilter cannot be preserved: rule-cancellation rules are not supported",
}


class CustomRuleError(ValueError):
    pass


@dataclass
class ParsedRule:
    rule_text: str
    normalized: str = ""
    rule_type: str = "unsupported"
    action: str = "none"
    domain: str | None = None
    match_subdomains: bool = False
    pattern: str | None = None
    rewrite_address: str | None = None
    address_family: str | None = None
    qtype_restriction: str | None = None
    priority: int = 0
    validation_state: str = "valid"
    unsupported_reason: str = ""
    comment: str = ""


def now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()


def connect() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=5.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout=5000")
    return conn


def run(command: list[str], check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=check)


def _normalize_domain(raw: str) -> str | None:
    from app.alderpointdns_compiler import normalize_domain

    return normalize_domain(raw)


def _ensure_column(db: sqlite3.Connection, table: str, column: str, definition: str) -> None:
    columns = {row[1] for row in db.execute(f"PRAGMA table_info({table})")}
    if column not in columns:
        db.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")


def init_db(conn: sqlite3.Connection | None = None) -> None:
    close = conn is None
    db = conn or connect()
    try:
        if close:
            db.execute("PRAGMA journal_mode=WAL")
        # Individual execute() calls, not executescript(): executescript issues
        # an implicit COMMIT first, which would silently break callers (the
        # importer's transactional apply) that hold an open transaction while
        # calling add_rule(conn=...).
        db.execute(
            """
            CREATE TABLE IF NOT EXISTS custom_filter_rules (
                id INTEGER PRIMARY KEY,
                rule_text TEXT NOT NULL,
                normalized TEXT NOT NULL,
                rule_type TEXT NOT NULL CHECK(rule_type IN ('block','allow','rewrite','regex_block','regex_allow','comment','unsupported')),
                action TEXT NOT NULL CHECK(action IN ('block','allow','rewrite','none')),
                domain TEXT,
                match_subdomains INTEGER NOT NULL DEFAULT 0,
                pattern TEXT,
                rewrite_address TEXT,
                address_family TEXT CHECK(address_family IN ('ipv4','ipv6') OR address_family IS NULL),
                qtype_restriction TEXT,
                priority INTEGER NOT NULL DEFAULT 0,
                enabled INTEGER NOT NULL DEFAULT 1,
                validation_state TEXT NOT NULL DEFAULT 'valid' CHECK(validation_state IN ('valid','unsupported','invalid')),
                unsupported_reason TEXT NOT NULL DEFAULT '',
                source_system TEXT NOT NULL DEFAULT 'manual',
                import_job_id INTEGER,
                comment TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )
        db.execute("CREATE INDEX IF NOT EXISTS idx_custom_filter_rules_domain ON custom_filter_rules(domain)")
        db.execute("CREATE INDEX IF NOT EXISTS idx_custom_filter_rules_enabled ON custom_filter_rules(enabled)")
        _migrate_legacy_rules(db)
        if close:
            db.commit()
    finally:
        if close:
            db.close()


def _migrate_legacy_rules(db: sqlite3.Connection) -> None:
    """One-time, idempotent copy of legacy `custom_rules` rows into
    custom_filter_rules. The legacy table stays intact for backup and
    replication compatibility, but the compile path and UI read only
    custom_filter_rules once a row is marked migrated. Legacy RPZ rendering
    always emitted a wildcard alongside the exact name, so migrated rules
    keep match_subdomains=1 to preserve behavior."""
    if not db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='custom_rules'").fetchone():
        return
    _ensure_column(db, "custom_rules", "migrated_to_v2", "INTEGER NOT NULL DEFAULT 0")
    rows = db.execute("SELECT * FROM custom_rules WHERE migrated_to_v2=0 ORDER BY id").fetchall()
    for row in rows:
        text = ("@@||" if row["action"] == "allow" else "||") + row["domain"] + "^"
        existing = db.execute(
            "SELECT 1 FROM custom_filter_rules WHERE normalized=? AND action=?",
            (text, row["action"]),
        ).fetchone()
        if not existing:
            db.execute(
                """
                INSERT INTO custom_filter_rules(
                    rule_text, normalized, rule_type, action, domain, match_subdomains,
                    priority, enabled, validation_state, source_system, comment, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, 1, 0, ?, 'valid', 'legacy', ?, ?, ?)
                """,
                (
                    text,
                    text,
                    row["action"],
                    row["action"],
                    row["domain"],
                    1 if row["enabled"] else 0,
                    row["comment"] or "",
                    row["created_at"],
                    now(),
                ),
            )
        db.execute("UPDATE custom_rules SET migrated_to_v2=1 WHERE id=?", (row["id"],))


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------

def _invalid(text: str, reason: str) -> ParsedRule:
    return ParsedRule(rule_text=text, normalized=text, validation_state="invalid", unsupported_reason=reason)


def _unsupported(rule: ParsedRule, reason: str) -> ParsedRule:
    rule.rule_type = "unsupported"
    rule.action = "none"
    rule.validation_state = "unsupported"
    rule.unsupported_reason = reason
    return rule


def _class_end(pattern: str, start: int) -> int | None:
    i = start + 1
    if i < len(pattern) and pattern[i] == "^":
        i += 1
    if i < len(pattern) and pattern[i] == "]":
        i += 1
    while i < len(pattern):
        if pattern[i] == "\\":
            i += 2
            continue
        if pattern[i] == "]":
            return i
        i += 1
    return None


def posix_ere_incompatibility(pattern: str) -> str | None:
    """Conservative portability check: dnsdist's RegexRule compiles the
    pattern with POSIX regcomp(REG_EXTENDED), which has no Perl escapes,
    lookaround, backreferences, named groups, or non-greedy quantifiers.
    Returns a reason string when the pattern is not portable."""
    i = 0
    n = len(pattern)
    last_quantifiable = False
    while i < n:
        ch = pattern[i]
        if ch == "\\":
            if i + 1 >= n:
                return "pattern ends with a trailing backslash"
            nxt = pattern[i + 1]
            if nxt.isalnum():
                return f"escape sequence \\{nxt} is not portable to POSIX extended regex"
            i += 2
            last_quantifiable = False
            continue
        if ch == "[":
            end = _class_end(pattern, i)
            if end is None:
                return "unterminated character class"
            i = end + 1
            last_quantifiable = False
            continue
        if ch == "(" and pattern[i + 1 : i + 2] == "?":
            return "group constructs starting with (? are not portable to POSIX extended regex"
        if ch == "?" and last_quantifiable:
            return "non-greedy quantifiers are not portable to POSIX extended regex"
        last_quantifiable = ch in "*+?}"
        i += 1
    return None


_QUANTIFIER_START = "*+{"


def nested_quantifier_risk(pattern: str) -> str | None:
    """Reject the classic catastrophic-backtracking shape: a quantified atom
    directly inside a group that is itself quantified (`(a+)+`, `(a*)*`,
    `(ab+)*`, ...). dnsdist's own POSIX regcomp is a non-backtracking
    automaton and is not vulnerable to this, but the same stored pattern is
    also matched with Python's backtracking `re.search` for the admin-facing
    "Test a domain" evaluation panel (evaluate_domain -> _regex_matches), so
    it must never be classified valid regardless of POSIX portability."""
    i = 0
    n = len(pattern)
    stack = [False]  # one "has a quantified atom" flag per group nesting level
    last_quantifiable = False
    while i < n:
        ch = pattern[i]
        if ch == "\\":
            i += 2
            last_quantifiable = True
            continue
        if ch == "[":
            end = _class_end(pattern, i)
            if end is None:
                return None  # unterminated class: posix_ere_incompatibility reports this
            i = end + 1
            last_quantifiable = True
            continue
        if ch == "(":
            stack.append(False)
            last_quantifiable = False
            i += 1
            continue
        if ch == ")":
            inner_risk = stack.pop() if len(stack) > 1 else False
            i += 1
            if i < n and pattern[i] in _QUANTIFIER_START and inner_risk:
                return "pattern contains a quantified atom nested inside a quantified group (catastrophic backtracking risk, e.g. (a+)+)"
            last_quantifiable = True
            continue
        if ch in "*+":
            if last_quantifiable:
                stack[-1] = True
            last_quantifiable = False
            i += 1
            continue
        if ch == "{":
            end = pattern.find("}", i)
            if end == -1:
                last_quantifiable = False
                i += 1
                continue
            if last_quantifiable:
                stack[-1] = True
            last_quantifiable = False
            i = end + 1
            continue
        if ch in "|^$":
            last_quantifiable = False
            i += 1
            continue
        last_quantifiable = True
        i += 1
    return None


def deployed_pattern(pattern: str) -> str:
    """The pattern actually written to the dnsdist data file. dnsdist's
    RegexRule matches the query name via DNSName::toStringNoDot() with
    POSIX regcomp(REG_ICASE), so matching is case-insensitive and normally
    sees no trailing dot; a trailing $ anchor is rewritten to tolerate an
    optional trailing dot so the deployed pattern stays robust either way.
    The stored pattern is never modified."""
    if pattern.endswith("$"):
        body = pattern[:-1]
        trailing_backslashes = len(body) - len(body.rstrip("\\"))
        if trailing_backslashes % 2 == 0:
            return body + "\\.?$"
    return pattern


def _validate_regex(rule: ParsedRule) -> ParsedRule:
    pattern = rule.pattern or ""
    if len(pattern) > MAX_REGEX_LENGTH:
        return _unsupported(rule, f"regex exceeds the {MAX_REGEX_LENGTH} character limit")
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in pattern):
        return _unsupported(rule, "regex contains control characters or newlines")
    try:
        re.compile(pattern)
    except re.error as exc:
        return _unsupported(rule, f"regex does not compile: {exc}")
    reason = posix_ere_incompatibility(pattern)
    if reason:
        return _unsupported(rule, reason)
    reason = nested_quantifier_risk(pattern)
    if reason:
        return _unsupported(rule, reason)
    return rule


def _parse_dnsrewrite(value: str) -> tuple[ipaddress.IPv4Address | ipaddress.IPv6Address | None, str]:
    parts = value.split(";")
    if len(parts) == 1:
        candidate = parts[0].strip()
    elif len(parts) == 3 and parts[0].strip().upper() == "NOERROR" and parts[1].strip().upper() in {"A", "AAAA"}:
        candidate = parts[2].strip()
    else:
        return None, (
            f"modifier $dnsrewrite={value} cannot be preserved: only plain A/AAAA address rewrites are supported"
        )
    try:
        ip = ipaddress.ip_address(candidate)
    except ValueError:
        return None, (
            f"modifier $dnsrewrite={value} cannot be preserved: the rewrite target is not an IP address"
        )
    if len(parts) == 3:
        wanted = parts[1].strip().upper()
        family = "A" if isinstance(ip, ipaddress.IPv4Address) else "AAAA"
        if wanted != family:
            return None, f"modifier $dnsrewrite={value} cannot be preserved: record type does not match the address family"
    return ip, ""


def _parse_modifiers(rule: ParsedRule, modifier_text: str) -> ParsedRule:
    for raw in modifier_text.split(","):
        raw = raw.strip()
        if not raw:
            continue
        name, _, value = raw.partition("=")
        name = name.strip().lower()
        if name == "important":
            rule.priority = IMPORTANT_PRIORITY
            continue
        if name == "dnsrewrite":
            if rule.action == "allow":
                return _unsupported(rule, "modifier $dnsrewrite cannot be preserved on an exception rule")
            ip, reason = _parse_dnsrewrite(value)
            if ip is None:
                return _unsupported(rule, reason)
            rule.rule_type = "rewrite"
            rule.action = "rewrite"
            rule.rewrite_address = str(ip)
            rule.address_family = "ipv4" if isinstance(ip, ipaddress.IPv4Address) else "ipv6"
            continue
        reason = UNSUPPORTED_MODIFIER_REASONS.get(
            name,
            f"modifier ${name} is not supported; the rule was kept inactive instead of activating a broadened rule",
        )
        return _unsupported(rule, reason)
    return rule


def _parse_regex_rule(raw: str) -> ParsedRule:
    is_allow = raw.startswith("@@")
    body = raw[2:] if is_allow else raw
    modifier_text = ""
    if not body.endswith("/"):
        idx = body.rfind("/$")
        if idx > 0:
            modifier_text = body[idx + 2 :]
            body = body[: idx + 1]
    if len(body) < 3 or not body.startswith("/") or not body.endswith("/"):
        return _invalid(raw, "regex rules must be enclosed in / /")
    pattern = body[1:-1]
    rule = ParsedRule(
        rule_text=raw,
        normalized=("@@" if is_allow else "") + "/" + pattern + "/",
        rule_type="regex_allow" if is_allow else "regex_block",
        action="allow" if is_allow else "block",
        pattern=pattern,
    )
    rule = _validate_regex(rule)
    if rule.validation_state == "valid" and modifier_text:
        rule = _parse_modifiers(rule, modifier_text)
        if rule.rule_type == "rewrite":
            return _unsupported(rule, "modifier $dnsrewrite cannot be preserved on a regex rule")
    return rule


def _parse_hosts_line(raw: str) -> list[ParsedRule]:
    body, _, inline = raw.partition("#")
    inline_comment = inline.strip()
    parts = body.split()
    try:
        ip = ipaddress.ip_address(parts[0])
    except ValueError:
        return []
    if len(parts) < 2:
        return [_invalid(raw, "hosts entry has no hostname")]
    rules: list[ParsedRule] = []
    for host in parts[1:]:
        text = f"{parts[0]} {host}"
        domain = _normalize_domain(host)
        if domain is None:
            rules.append(_invalid(text, f"'{host}' is not a valid hostname"))
            continue
        if str(ip) in BLOCKING_SENTINELS:
            rules.append(
                ParsedRule(
                    rule_text=text,
                    normalized=f"|{domain}^",
                    rule_type="block",
                    action="block",
                    domain=domain,
                    match_subdomains=False,
                    comment=inline_comment,
                )
            )
        else:
            family = "ipv4" if isinstance(ip, ipaddress.IPv4Address) else "ipv6"
            rules.append(
                ParsedRule(
                    rule_text=text,
                    normalized=f"{ip} {domain}",
                    rule_type="rewrite",
                    action="rewrite",
                    domain=domain,
                    match_subdomains=False,
                    rewrite_address=str(ip),
                    address_family=family,
                    comment=inline_comment,
                )
            )
    return rules


def _normalized_form(rule: ParsedRule) -> str:
    if rule.rule_type == "rewrite":
        base = ("||" + rule.domain + "^") if rule.match_subdomains else ("|" + rule.domain + "^")
        return f"{base}$dnsrewrite={rule.rewrite_address}"
    prefix = "@@" if rule.action == "allow" else ""
    anchor = "||" if rule.match_subdomains else "|"
    return f"{prefix}{anchor}{rule.domain}^"


def parse_rule(text: str, source_system: str = "manual", plain_domain_subdomains: bool = True) -> list[ParsedRule]:
    """Classify one rule line. Returns a list because a hosts-file line with
    several hostnames becomes one rule per hostname; an empty line returns
    an empty list. `plain_domain_subdomains` selects AdGuard semantics
    (a plain domain blocks the domain and its subdomains) versus Pi-hole
    exact-domain semantics (exact host only)."""
    raw = text.strip()
    if not raw:
        return []
    if "\n" in raw or "\r" in raw:
        return [_invalid(raw.splitlines()[0][:120], "a rule must be a single line")]
    if any(ord(ch) < 32 and ch != "\t" or ord(ch) == 127 for ch in raw):
        return [_invalid(raw, "rule contains control characters")]
    if raw.startswith("!") or raw.startswith("#"):
        return [
            ParsedRule(
                rule_text=raw,
                normalized=raw,
                rule_type="comment",
                action="none",
                comment=raw.lstrip("!#").strip(),
            )
        ]
    if raw.startswith("/") or raw.startswith("@@/"):
        return [_parse_regex_rule(raw)]
    hosts_rules = _parse_hosts_line(raw)
    if hosts_rules:
        return hosts_rules
    if "##" in raw or "#@#" in raw or "#%#" in raw or "#$#" in raw:
        return [_unsupported(ParsedRule(rule_text=raw, normalized=raw), "cosmetic and scriptlet rules have no DNS effect and are not supported")]

    is_allow = raw.startswith("@@")
    body = raw[2:] if is_allow else raw
    base, _, modifier_text = body.partition("$")
    base = base.strip()
    rule = ParsedRule(rule_text=raw, normalized=raw, action="allow" if is_allow else "block")
    rule.rule_type = "allow" if is_allow else "block"
    if base.startswith("||"):
        rule.match_subdomains = True
        candidate = base[2:]
    elif base.startswith("|"):
        rule.match_subdomains = False
        candidate = base[1:]
    else:
        rule.match_subdomains = plain_domain_subdomains
        candidate = base
    for terminator in ("^", "|"):
        end = candidate.find(terminator)
        if end != -1:
            trailer = candidate[end + 1 :]
            if trailer:
                return [_unsupported(rule, "rules with a path or anchor after the domain are not supported for DNS filtering")]
            candidate = candidate[:end]
    domain = _normalize_domain(candidate)
    if domain is None:
        return [_invalid(raw, f"'{candidate}' is not a valid domain name")]
    rule.domain = domain
    if modifier_text:
        rule = _parse_modifiers(rule, modifier_text)
        if rule.validation_state != "valid":
            return [rule]
        if rule.rule_type == "rewrite":
            # $dnsrewrite follows the base rule's subdomain semantics.
            rule.normalized = _normalized_form(rule)
            return [rule]
    rule.normalized = _normalized_form(rule)
    return [rule]


# ---------------------------------------------------------------------------
# CRUD and queries
# ---------------------------------------------------------------------------

def find_duplicate(conn: sqlite3.Connection, normalized: str, action: str) -> sqlite3.Row | None:
    return conn.execute(
        "SELECT * FROM custom_filter_rules WHERE normalized=? AND action=? LIMIT 1",
        (normalized, action),
    ).fetchone()


def _insert_rule(
    db: sqlite3.Connection,
    rule: ParsedRule,
    source_system: str,
    comment: str,
    enabled: bool,
    import_job_id: int | None,
) -> dict[str, Any]:
    result = {
        "id": None,
        "status": "added",
        "rule_text": rule.rule_text,
        "rule_type": rule.rule_type,
        "action": rule.action,
        "validation_state": rule.validation_state,
        "reason": rule.unsupported_reason,
    }
    # Checked regardless of validation_state -- comments, and invalid/
    # unsupported rules kept inactive with a reason, are rows in
    # custom_filter_rules just like active block/allow/rewrite/regex rules;
    # re-importing the same source a second time must not pile up
    # duplicates of any of them.
    existing = find_duplicate(db, rule.normalized, rule.action)
    if existing:
        result.update(status="duplicate", id=existing["id"])
        return result
    if rule.validation_state != "valid":
        stored_enabled = 0
    elif rule.rule_type == "comment":
        stored_enabled = 1
    else:
        stored_enabled = 1 if enabled else 0
    ts = now()
    cursor = db.execute(
        """
        INSERT INTO custom_filter_rules(
            rule_text, normalized, rule_type, action, domain, match_subdomains,
            pattern, rewrite_address, address_family, qtype_restriction, priority,
            enabled, validation_state, unsupported_reason, source_system,
            import_job_id, comment, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            rule.rule_text,
            rule.normalized,
            rule.rule_type,
            rule.action,
            rule.domain,
            1 if rule.match_subdomains else 0,
            rule.pattern,
            rule.rewrite_address,
            rule.address_family,
            rule.qtype_restriction,
            rule.priority,
            stored_enabled,
            rule.validation_state,
            rule.unsupported_reason,
            source_system,
            import_job_id,
            rule.comment or comment or "",
            ts,
            ts,
        ),
    )
    result["id"] = cursor.lastrowid
    return result


def add_rule(
    text: str,
    source_system: str = "manual",
    comment: str = "",
    enabled: bool = True,
    import_job_id: int | None = None,
    plain_domain_subdomains: bool = True,
    conn: sqlite3.Connection | None = None,
) -> list[dict[str, Any]]:
    """Parse and store one rule line. Returns one result per stored rule
    (hosts lines with hostname aliases store one rule per hostname).
    Invalid and unsupported rules are stored inactive with their reason."""
    close = conn is None
    db = conn or connect()
    try:
        init_db(db)
        results = [
            _insert_rule(db, rule, source_system, comment, enabled, import_job_id)
            for rule in parse_rule(text, source_system, plain_domain_subdomains)
        ]
        if close:
            db.commit()
        return results
    finally:
        if close:
            db.close()


def add_rules_bulk(
    text: str,
    source_system: str = "manual",
    comment: str = "",
    enabled: bool = True,
    import_job_id: int | None = None,
    plain_domain_subdomains: bool = True,
    conn: sqlite3.Connection | None = None,
) -> dict[str, Any]:
    """Validate and store every line of a multi-line ruleset. Every line is
    reported individually; only valid lines activate, while invalid and
    unsupported lines are stored inactive and listed with their reasons."""
    close = conn is None
    db = conn or connect()
    try:
        init_db(db)
        summary: dict[str, Any] = {
            "lines": [],
            "added_active": 0,
            "added_inactive": 0,
            "duplicates": 0,
            "invalid": 0,
            "unsupported": 0,
            "comments": 0,
        }
        for line_number, line in enumerate(text.splitlines(), 1):
            if not line.strip():
                continue
            results = [
                _insert_rule(db, rule, source_system, comment, enabled, import_job_id)
                for rule in parse_rule(line, source_system, plain_domain_subdomains)
            ]
            summary["lines"].append({"line": line_number, "text": line.strip(), "results": results})
            for result in results:
                if result["status"] == "duplicate":
                    summary["duplicates"] += 1
                elif result["rule_type"] == "comment":
                    summary["comments"] += 1
                elif result["validation_state"] == "invalid":
                    summary["invalid"] += 1
                elif result["validation_state"] == "unsupported":
                    summary["unsupported"] += 1
                elif enabled:
                    summary["added_active"] += 1
                else:
                    summary["added_inactive"] += 1
        if close:
            db.commit()
        return summary
    finally:
        if close:
            db.close()


def get_rule(rule_id: int, conn: sqlite3.Connection | None = None) -> dict[str, Any] | None:
    close = conn is None
    db = conn or connect()
    try:
        init_db(db)
        row = db.execute("SELECT * FROM custom_filter_rules WHERE id=?", (rule_id,)).fetchone()
        return dict(row) if row else None
    finally:
        if close:
            db.close()


def update_rule(
    rule_id: int,
    text: str,
    comment: str = "",
    enabled: bool = True,
    plain_domain_subdomains: bool = True,
    conn: sqlite3.Connection | None = None,
) -> dict[str, Any]:
    close = conn is None
    db = conn or connect()
    try:
        init_db(db)
        row = db.execute("SELECT * FROM custom_filter_rules WHERE id=?", (rule_id,)).fetchone()
        if not row:
            raise CustomRuleError("rule not found")
        rules = parse_rule(text, row["source_system"], plain_domain_subdomains)
        if len(rules) != 1:
            raise CustomRuleError("an edit must contain exactly one rule")
        rule = rules[0]
        if rule.rule_type != "comment" and rule.validation_state == "valid":
            existing = find_duplicate(db, rule.normalized, rule.action)
            if existing and existing["id"] != rule_id:
                raise CustomRuleError("an identical rule already exists")
        if rule.validation_state != "valid":
            stored_enabled = 0
        else:
            stored_enabled = 1 if enabled else 0
        db.execute(
            """
            UPDATE custom_filter_rules
            SET rule_text=?, normalized=?, rule_type=?, action=?, domain=?, match_subdomains=?,
                pattern=?, rewrite_address=?, address_family=?, qtype_restriction=?, priority=?,
                enabled=?, validation_state=?, unsupported_reason=?, comment=?, updated_at=?
            WHERE id=?
            """,
            (
                rule.rule_text,
                rule.normalized,
                rule.rule_type,
                rule.action,
                rule.domain,
                1 if rule.match_subdomains else 0,
                rule.pattern,
                rule.rewrite_address,
                rule.address_family,
                rule.qtype_restriction,
                rule.priority,
                stored_enabled,
                rule.validation_state,
                rule.unsupported_reason,
                comment or rule.comment or "",
                now(),
                rule_id,
            ),
        )
        if close:
            db.commit()
        return {
            "id": rule_id,
            "validation_state": rule.validation_state,
            "reason": rule.unsupported_reason,
            "enabled": stored_enabled,
        }
    finally:
        if close:
            db.close()


def set_enabled(rule_id: int, enabled: bool, conn: sqlite3.Connection | None = None) -> None:
    close = conn is None
    db = conn or connect()
    try:
        init_db(db)
        row = db.execute("SELECT validation_state, unsupported_reason FROM custom_filter_rules WHERE id=?", (rule_id,)).fetchone()
        if not row:
            raise CustomRuleError("rule not found")
        if enabled and row["validation_state"] != "valid":
            raise CustomRuleError(
                f"this rule cannot be enabled ({row['validation_state']}): {row['unsupported_reason'] or 'no details'}"
            )
        db.execute(
            "UPDATE custom_filter_rules SET enabled=?, updated_at=? WHERE id=?",
            (1 if enabled else 0, now(), rule_id),
        )
        if close:
            db.commit()
    finally:
        if close:
            db.close()


def toggle_rule(rule_id: int, conn: sqlite3.Connection | None = None) -> None:
    close = conn is None
    db = conn or connect()
    try:
        init_db(db)
        row = db.execute("SELECT enabled FROM custom_filter_rules WHERE id=?", (rule_id,)).fetchone()
        if not row:
            raise CustomRuleError("rule not found")
        set_enabled(rule_id, not row["enabled"], db)
        if close:
            db.commit()
    finally:
        if close:
            db.close()


def delete_rule(rule_id: int, conn: sqlite3.Connection | None = None) -> None:
    close = conn is None
    db = conn or connect()
    try:
        init_db(db)
        db.execute("DELETE FROM custom_filter_rules WHERE id=?", (rule_id,))
        if close:
            db.commit()
    finally:
        if close:
            db.close()


def bulk_set_enabled(rule_ids: list[int], enabled: bool, conn: sqlite3.Connection | None = None) -> dict[str, int]:
    close = conn is None
    db = conn or connect()
    try:
        init_db(db)
        updated = 0
        skipped = 0
        for rule_id in rule_ids:
            row = db.execute("SELECT validation_state FROM custom_filter_rules WHERE id=?", (int(rule_id),)).fetchone()
            if not row:
                skipped += 1
                continue
            if enabled and row["validation_state"] != "valid":
                skipped += 1
                continue
            db.execute(
                "UPDATE custom_filter_rules SET enabled=?, updated_at=? WHERE id=?",
                (1 if enabled else 0, now(), int(rule_id)),
            )
            updated += 1
        if close:
            db.commit()
        return {"updated": updated, "skipped": skipped}
    finally:
        if close:
            db.close()


def bulk_delete(rule_ids: list[int], conn: sqlite3.Connection | None = None) -> int:
    close = conn is None
    db = conn or connect()
    try:
        init_db(db)
        deleted = 0
        for rule_id in rule_ids:
            cursor = db.execute("DELETE FROM custom_filter_rules WHERE id=?", (int(rule_id),))
            deleted += cursor.rowcount
        if close:
            db.commit()
        return deleted
    finally:
        if close:
            db.close()


def list_rules(
    search: str = "",
    rule_type: str = "",
    status: str = "",
    conn: sqlite3.Connection | None = None,
) -> list[dict[str, Any]]:
    close = conn is None
    db = conn or connect()
    try:
        init_db(db)
        clauses: list[str] = []
        params: list[Any] = []
        if search.strip():
            term = f"%{search.strip()}%"
            clauses.append("(rule_text LIKE ? OR domain LIKE ? OR pattern LIKE ? OR comment LIKE ?)")
            params.extend([term, term, term, term])
        if rule_type and rule_type in RULE_TYPES:
            clauses.append("rule_type=?")
            params.append(rule_type)
        if status == "enabled":
            clauses.append("validation_state='valid' AND enabled=1")
        elif status == "disabled":
            clauses.append("validation_state='valid' AND enabled=0")
        elif status in {"unsupported", "invalid"}:
            clauses.append("validation_state=?")
            params.append(status)
        where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        rows = db.execute(
            f"SELECT * FROM custom_filter_rules {where} ORDER BY id DESC",
            params,
        ).fetchall()
        return [dict(row) for row in rows]
    finally:
        if close:
            db.close()


def rule_counts(conn: sqlite3.Connection | None = None) -> dict[str, int]:
    close = conn is None
    db = conn or connect()
    try:
        init_db(db)
        counts = {
            "total": 0,
            "active": 0,
            "disabled": 0,
            "allow": 0,
            "block": 0,
            "rewrite": 0,
            "regex": 0,
            "comment": 0,
            "unsupported": 0,
            "invalid": 0,
        }
        for row in db.execute(
            "SELECT rule_type, validation_state, enabled, count(*) AS n FROM custom_filter_rules GROUP BY rule_type, validation_state, enabled"
        ):
            n = row["n"]
            counts["total"] += n
            if row["validation_state"] == "invalid":
                counts["invalid"] += n
                continue
            if row["validation_state"] == "unsupported":
                counts["unsupported"] += n
                continue
            if row["rule_type"] == "comment":
                counts["comment"] += n
                continue
            if row["enabled"]:
                counts["active"] += n
            else:
                counts["disabled"] += n
            if row["rule_type"] in {"regex_allow", "regex_block"}:
                counts["regex"] += n
            elif row["rule_type"] in counts:
                counts[row["rule_type"]] += n
        return counts
    finally:
        if close:
            db.close()


# ---------------------------------------------------------------------------
# Evaluation ("test a domain")
# ---------------------------------------------------------------------------

def _local_zone_names(conn: sqlite3.Connection) -> list[str]:
    if not conn.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='local_dns_records'").fetchone():
        return []
    row = conn.execute("SELECT value FROM local_dns_settings WHERE key='internal_domain'").fetchone()
    internal = row["value"] if row else local_dns.DEFAULT_DOMAIN
    zones = {internal}
    for record in conn.execute("SELECT fqdn, record_type FROM local_dns_records WHERE enabled=1"):
        if record["record_type"] in {"A", "AAAA", "CNAME"}:
            zones.add(local_dns.forward_zone_for_fqdn(record["fqdn"], internal))
        else:
            zones.add(".".join(record["fqdn"].split(".")[1:]))
    return sorted(zones)


def _rpz_status(qname: str) -> dict[str, Any]:
    """Reports whether the currently compiled RPZ file would answer this
    name, emulating RPZ precedence: an exact owner match beats a wildcard,
    and a wildcard with more labels beats a shorter one."""
    from app import alderpointdns_compiler as compiler

    status: dict[str, Any] = {"available": False, "blocked": False, "match": None, "entry": None, "rdata": None}
    path = compiler.COMPILED_RPZ
    if not path.exists():
        return status
    status["available"] = True
    owners: dict[str, list[str]] = {}
    for line in path.read_text().splitlines():
        parts = line.split(None, 1)
        if len(parts) != 2 or parts[0] in {"@", "$TTL"} or parts[0].startswith(";"):
            continue
        owners.setdefault(parts[0], []).append(parts[1].strip())
    best: tuple[int, int, str] | None = None
    if qname in owners:
        best = (1, qname.count(".") + 1, qname)
    labels = qname.split(".")
    for i in range(1, len(labels)):
        parent = ".".join(labels[i:])
        owner = f"*.{parent}"
        if owner in owners:
            candidate = (0, parent.count(".") + 1, owner)
            if best is None or candidate > best:
                best = candidate
    if best is None:
        return status
    owner = best[2]
    rdata = owners[owner]
    status["entry"] = owner
    status["match"] = "exact" if best[0] else "wildcard"
    status["rdata"] = "; ".join(rdata)
    status["blocked"] = any(r == "CNAME ." for r in rdata)
    return status


def _regex_matches(pattern: str, qname: str) -> bool:
    try:
        return re.search(deployed_pattern(pattern), qname, re.IGNORECASE) is not None
    except re.error:
        return False


def evaluate_domain(conn: sqlite3.Connection, domain: str) -> dict[str, Any]:
    """Deterministic verdict for one domain, walking the documented
    precedence: local zones, then the most specific matching custom domain
    rule (rewrite > allow > block at the same owner, with priority able to
    let an important block beat an allow), then regex allow/block, then the
    compiled external RPZ block set."""
    qname = _normalize_domain(str(domain or ""))
    if not qname:
        return {"domain": str(domain or "").strip(), "error": "not a valid domain name"}
    init_db(conn)
    result: dict[str, Any] = {
        "domain": qname,
        "error": None,
        "final_action": "resolve",
        "matched_rules": [],
        "local_zone": None,
        "rpz": _rpz_status(qname),
        "response": "resolves normally through the upstream path",
    }
    for zone in _local_zone_names(conn):
        if qname == zone or qname.endswith("." + zone):
            result["final_action"] = "local"
            result["local_zone"] = zone
            result["response"] = f"answered from local authoritative zone {zone} (always wins)"
            return result

    rows = conn.execute(
        "SELECT * FROM custom_filter_rules WHERE enabled=1 AND validation_state='valid'"
    ).fetchall()
    domain_matches: list[tuple[int, int, sqlite3.Row]] = []
    regex_allow_hits: list[sqlite3.Row] = []
    regex_block_hits: list[sqlite3.Row] = []
    for row in rows:
        if row["rule_type"] in {"rewrite", "allow", "block"} and row["domain"]:
            exact = qname == row["domain"]
            if exact or (row["match_subdomains"] and qname.endswith("." + row["domain"])):
                domain_matches.append((1 if exact else 0, row["domain"].count(".") + 1, row))
        elif row["rule_type"] == "regex_allow" and _regex_matches(row["pattern"], qname):
            regex_allow_hits.append(row)
        elif row["rule_type"] == "regex_block" and _regex_matches(row["pattern"], qname):
            regex_block_hits.append(row)

    def rule_summary(row: sqlite3.Row) -> dict[str, Any]:
        return {
            "id": row["id"],
            "rule_text": row["rule_text"],
            "rule_type": row["rule_type"],
            "action": row["action"],
            "priority": row["priority"],
        }

    if domain_matches:
        best_key = max((exact, labels) for exact, labels, _ in domain_matches)
        best = [row for exact, labels, row in domain_matches if (exact, labels) == best_key]
        rewrites = [row for row in best if row["rule_type"] == "rewrite"]
        allows = [row for row in best if row["rule_type"] == "allow"]
        blocks = [row for row in best if row["rule_type"] == "block"]
        if rewrites:
            addresses = ", ".join(row["rewrite_address"] for row in rewrites)
            result["final_action"] = "rewrite"
            result["matched_rules"] = [rule_summary(row) for row in rewrites]
            result["response"] = f"answers with {addresses}"
        elif allows and blocks and max(row["priority"] for row in blocks) > max(row["priority"] for row in allows):
            result["final_action"] = "block"
            result["matched_rules"] = [rule_summary(row) for row in blocks]
            result["response"] = "blocked (an important block rule outranks the allow rule)"
        elif allows:
            result["final_action"] = "allow"
            result["matched_rules"] = [rule_summary(row) for row in allows]
            result["response"] = "allowed (rpz-passthru overrides block rules and blocklists)"
        else:
            result["final_action"] = "block"
            result["matched_rules"] = [rule_summary(row) for row in blocks]
            result["response"] = "blocked (RPZ CNAME ., answers NXDOMAIN)"
        return result

    if regex_allow_hits:
        result["matched_rules"] = [rule_summary(row) for row in regex_allow_hits[:1]]
        if result["rpz"]["blocked"]:
            result["final_action"] = "block"
            result["response"] = (
                "the regex allow rule bypasses regex blocks, but the external blocklist RPZ entry still blocks this name"
            )
        else:
            result["final_action"] = "allow"
            result["response"] = "allowed (regex allow passes the query to BIND before regex blocks)"
        return result
    if regex_block_hits:
        result["final_action"] = "block"
        result["matched_rules"] = [rule_summary(row) for row in regex_block_hits[:1]]
        result["response"] = "blocked at the dnsdist layer (NXDOMAIN, no RPZ SOA in the response)"
        return result
    if result["rpz"]["blocked"]:
        result["final_action"] = "block"
        result["response"] = f"blocked by the compiled blocklist RPZ ({result['rpz']['match']} entry {result['rpz']['entry']})"
    return result


# ---------------------------------------------------------------------------
# Compilation: RPZ records and the dnsdist regex layer
# ---------------------------------------------------------------------------

@dataclass
class ActiveRuleSet:
    """The resolved, conflict-free view of every enabled valid rule.
    rewrites: name -> {"A": addr|None, "AAAA": addr|None, "subdomains": bool}
    allows/blocks: name -> {"exact": bool, "subdomains": bool, "priority": int}
    """

    rewrites: dict[str, dict[str, Any]] = field(default_factory=dict)
    allows: dict[str, dict[str, Any]] = field(default_factory=dict)
    blocks: dict[str, dict[str, Any]] = field(default_factory=dict)
    regex_allow: list[str] = field(default_factory=list)
    regex_block: list[str] = field(default_factory=list)


def collect_active(conn: sqlite3.Connection) -> ActiveRuleSet:
    init_db(conn)
    active = ActiveRuleSet()
    rows = conn.execute(
        "SELECT * FROM custom_filter_rules WHERE enabled=1 AND validation_state='valid' ORDER BY priority DESC, id"
    ).fetchall()
    for row in rows:
        rule_type = row["rule_type"]
        if rule_type == "rewrite":
            entry = active.rewrites.setdefault(row["domain"], {"A": None, "AAAA": None, "subdomains": False})
            rtype = "A" if row["address_family"] == "ipv4" else "AAAA"
            if entry[rtype] is None:
                entry[rtype] = row["rewrite_address"]
            if row["match_subdomains"]:
                entry["subdomains"] = True
        elif rule_type == "allow":
            entry = active.allows.setdefault(row["domain"], {"exact": False, "subdomains": False, "priority": 0})
            if row["match_subdomains"]:
                entry["subdomains"] = True
            else:
                entry["exact"] = True
            entry["priority"] = max(entry["priority"], row["priority"])
        elif rule_type == "block":
            entry = active.blocks.setdefault(row["domain"], {"exact": False, "subdomains": False, "priority": 0})
            if row["match_subdomains"]:
                entry["subdomains"] = True
            else:
                entry["exact"] = True
            entry["priority"] = max(entry["priority"], row["priority"])
        elif rule_type == "regex_allow":
            active.regex_allow.append(row["pattern"])
        elif rule_type == "regex_block":
            active.regex_block.append(row["pattern"])
    _resolve_conflicts(active)
    return active


def _resolve_conflicts(active: ActiveRuleSet) -> None:
    """RPZ cannot hold two conflicting records at one owner name, so
    same-owner conflicts are resolved at compile time: rewrite > allow >
    block, except that a block whose priority exceeds the allow's priority
    ($important) beats the allow entirely."""
    for name, blk in list(active.blocks.items()):
        rewrite = active.rewrites.get(name)
        allow = active.allows.get(name)
        if rewrite:
            blk["exact"] = False
            if rewrite["subdomains"]:
                blk["subdomains"] = False
        if allow is not None:
            if blk["priority"] > allow["priority"]:
                del active.allows[name]
            else:
                blk["exact"] = False
                if allow["subdomains"]:
                    blk["subdomains"] = False
        if not blk["exact"] and not blk["subdomains"]:
            del active.blocks[name]
    for name in list(active.allows):
        rewrite = active.rewrites.get(name)
        if not rewrite:
            continue
        if rewrite["subdomains"]:
            del active.allows[name]
        else:
            active.allows[name]["exact"] = False
            if not active.allows[name]["subdomains"]:
                del active.allows[name]


def subtract_allowed(domains: set[str], active: ActiveRuleSet) -> set[str]:
    """Subdomain-aware subtraction of custom allow rules from the merged
    external block set, recomputed on every compile so allows survive
    blocklist refreshes without ever modifying stored blocklist data. An
    exact allow removes the matching external entry (which always carries a
    wildcard) entirely, matching the legacy exact-name subtraction."""
    if not active.allows:
        return set(domains)
    subdomain_allows = [name for name, allow in active.allows.items() if allow["subdomains"]]
    remaining = set()
    for domain in domains:
        if domain in active.allows:
            continue
        if any(domain == name or domain.endswith("." + name) for name in subdomain_allows):
            continue
        remaining.add(domain)
    return remaining


def rpz_records(active: ActiveRuleSet) -> tuple[list[str], set[str]]:
    """Custom-rule RPZ record lines plus the set of owner names they occupy,
    so external blocklist rendering can skip conflicting owners. Exact rules
    emit no wildcard line, so an exact rewrite or block never takes over a
    parent zone or its siblings."""
    lines: list[str] = []
    occupied: set[str] = set()

    def emit(owner: str, rdata: str) -> None:
        lines.append(f"{owner} {rdata}")

    for name in sorted(active.rewrites):
        entry = active.rewrites[name]
        for rtype in ("A", "AAAA"):
            if entry[rtype]:
                emit(name, f"{rtype} {entry[rtype]}")
                if entry["subdomains"]:
                    emit(f"*.{name}", f"{rtype} {entry[rtype]}")
        occupied.add(name)
        if entry["subdomains"]:
            occupied.add(f"*.{name}")
    for name in sorted(active.allows):
        allow = active.allows[name]
        if (allow["exact"] or allow["subdomains"]) and name not in occupied:
            emit(name, "CNAME rpz-passthru.")
            occupied.add(name)
        if allow["subdomains"] and f"*.{name}" not in occupied:
            emit(f"*.{name}", "CNAME rpz-passthru.")
            occupied.add(f"*.{name}")
    for name in sorted(active.blocks):
        block = active.blocks[name]
        if block["exact"] and name not in occupied:
            emit(name, "CNAME .")
            occupied.add(name)
        if block["subdomains"]:
            if name not in occupied:
                emit(name, "CNAME .")
                occupied.add(name)
            if f"*.{name}" not in occupied:
                emit(f"*.{name}", "CNAME .")
                occupied.add(f"*.{name}")
    return lines, occupied


def custom_rules_lua_path() -> Path:
    return COMPILED_DNSDIST_DIR / CUSTOM_RULES_LUA_NAME


def _check_line_safe(entry: str) -> str:
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in entry):
        raise CustomRuleError("refusing to write a data-file entry containing control characters")
    return entry


def render_dnsdist_data(active: ActiveRuleSet, local_zones: list[str]) -> dict[str, str]:
    """Plain, line-oriented data files consumed by the static Lua loader.
    Pass suffixes preserve precedence 1-3 against dnsdist-layer regex
    blocks: local zones, subdomain allows, and subdomain rewrites pass as
    suffixes; exact allows and exact rewrites pass as exact names."""
    pass_suffixes = set(local_zones)
    pass_suffixes.update(name for name, allow in active.allows.items() if allow["subdomains"])
    pass_suffixes.update(name for name, rewrite in active.rewrites.items() if rewrite["subdomains"])
    pass_exact = {name for name, allow in active.allows.items() if allow["exact"] and not allow["subdomains"]}
    pass_exact.update(name for name, rewrite in active.rewrites.items() if not rewrite["subdomains"])
    pass_exact -= pass_suffixes

    def text(entries: list[str]) -> str:
        return "\n".join(_check_line_safe(entry) for entry in entries) + ("\n" if entries else "")

    return {
        PASS_SUFFIX_DATA: text(sorted(pass_suffixes)),
        PASS_EXACT_DATA: text(sorted(pass_exact)),
        REGEX_ALLOW_DATA: text([deployed_pattern(p) for p in active.regex_allow]),
        REGEX_BLOCK_DATA: text([deployed_pattern(p) for p in active.regex_block]),
    }


def render_dnsdist_lua(data_dir: Path) -> str:
    """Static Lua include. Every user-controlled value lives in the plain
    data files read here line by line; nothing a user typed is ever
    interpolated into this template."""
    return f"""-- Managed by Alderpoint DNS custom filtering rules. Do not edit by hand.
-- Static loader: user-controlled values live only in the data files below
-- (one entry per line); no user text is ever interpolated into Lua code.
local alderpointdnsCustomDataDir = "{data_dir}"

local function alderpointdnsCustomLines(name)
  local entries = {{}}
  local handle = io.open(alderpointdnsCustomDataDir .. "/" .. name, "r")
  if handle then
    for line in handle:lines() do
      if line ~= "" then
        table.insert(entries, line)
      end
    end
    handle:close()
  end
  return entries
end

-- 1. Local zones and subdomain allows/rewrites go straight to BIND.
local alderpointdnsPassSuffixes = alderpointdnsCustomLines("{PASS_SUFFIX_DATA}")
if #alderpointdnsPassSuffixes > 0 then
  local suffixes = newSuffixMatchNode()
  for _, entry in ipairs(alderpointdnsPassSuffixes) do
    suffixes:add(newDNSName(entry))
  end
  addAction(SuffixMatchNodeRule(suffixes), PoolAction("alderpointdns_bind"))
end

-- 2. Exact allows and exact rewrites go straight to BIND.
local alderpointdnsPassNames = alderpointdnsCustomLines("{PASS_EXACT_DATA}")
if #alderpointdnsPassNames > 0 then
  local names = newDNSNameSet()
  for _, entry in ipairs(alderpointdnsPassNames) do
    names:add(newDNSName(entry))
  end
  addAction(QNameSetRule(names), PoolAction("alderpointdns_bind"))
end

-- 3. Regex allows pass, then 4. regex blocks answer NXDOMAIN.
for _, entry in ipairs(alderpointdnsCustomLines("{REGEX_ALLOW_DATA}")) do
  addAction(RegexRule(entry), PoolAction("alderpointdns_bind"))
end
for _, entry in ipairs(alderpointdnsCustomLines("{REGEX_BLOCK_DATA}")) do
  addAction(RegexRule(entry), RCodeAction(DNSRCode.NXDOMAIN))
end
"""


def ensure_dnsdist_custom_include() -> bool:
    """Idempotently insert the guarded custom-rules dofile include into an
    existing dnsdist.conf that lacks it, after the REFUSED opcode rules and
    upstream routing, immediately before the default bind-pool action.
    Takes a backup copy first. Returns True when a change was made."""
    lua_path = custom_rules_lua_path()
    current = DNSDIST_CONF.read_text() if DNSDIST_CONF.exists() else DNSDIST_PACKAGING_CONF.read_text()
    if str(lua_path) in current:
        return False
    marker = 'addAction(AllRule(), PoolAction("alderpointdns_bind"))'
    if marker not in current:
        raise CustomRuleError("dnsdist.conf is missing the default bind-pool action marker")
    include_block = (
        f'local alderpointdnsCustomRulesConfig = "{lua_path}"\n'
        'local alderpointdnsCustomRulesFile = io.open(alderpointdnsCustomRulesConfig, "r")\n'
        'if alderpointdnsCustomRulesFile then\n'
        '  alderpointdnsCustomRulesFile:close()\n'
        '  dofile(alderpointdnsCustomRulesConfig)\n'
        'end\n'
    )
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    if DNSDIST_CONF.exists():
        shutil.copy2(DNSDIST_CONF, BACKUP_DIR / f"dnsdist.conf.pre-custom-rules.{int(time.time())}")
    DNSDIST_CONF.write_text(current.replace(marker, include_block + "\n" + marker, 1))
    return True


def dnsdist_layer_counts(active: ActiveRuleSet) -> dict[str, int]:
    return {
        "regex_allow": len(active.regex_allow),
        "regex_block": len(active.regex_block),
        "rewrites": len(active.rewrites),
        "allows": len(active.allows),
        "blocks": len(active.blocks),
    }


def deploy_dnsdist_layer(conn: sqlite3.Connection, active: ActiveRuleSet | None = None) -> dict[str, Any]:
    """Stage, validate, atomically install, and (only when content actually
    changed) restart dnsdist for the custom-rule regex layer. Restores its
    own files and restarts dnsdist on failure before re-raising, so the
    caller's RPZ rollback stays independent. Returns {"changed", "backups"}
    for the caller's outer rollback via rollback_dnsdist_layer()."""
    if active is None:
        active = collect_active(conn)
    data_files = render_dnsdist_data(active, _local_zone_names(conn))
    final_lua = render_dnsdist_lua(COMPILED_DNSDIST_DIR)
    targets: dict[Path, str] = {custom_rules_lua_path(): final_lua}
    for name, text in data_files.items():
        targets[COMPILED_DNSDIST_DIR / name] = text
    changed = any(not path.exists() or path.read_text() != text for path, text in targets.items())
    info: dict[str, Any] = {"changed": changed, "backups": [], "counts": dnsdist_layer_counts(active)}
    if not changed:
        return info
    STAGING_DIR.mkdir(parents=True, exist_ok=True)
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    stage = Path(tempfile.mkdtemp(prefix="alderpointdns-custom-rules-", dir=str(STAGING_DIR)))
    backups: list[tuple[Path, Path | None]] = []
    try:
        ensure_dnsdist_custom_include()
        # Validate against a staged composite: the live dnsdist.conf with the
        # include retargeted at a staged copy whose data dir is the stage.
        staged_lua = stage / CUSTOM_RULES_LUA_NAME
        staged_lua.write_text(render_dnsdist_lua(stage))
        for name, text in data_files.items():
            (stage / name).write_text(text)
        if DNSDIST_CONF.exists():
            composite = stage / "dnsdist-composite-check.conf"
            composite.write_text(DNSDIST_CONF.read_text().replace(str(custom_rules_lua_path()), str(staged_lua)))
            run(["dnsdist", "--check-config", "-C", str(composite)])
        COMPILED_DNSDIST_DIR.mkdir(parents=True, exist_ok=True)
        for path, text in targets.items():
            backup = BACKUP_DIR / f"{path.name}.last-good.{int(time.time())}" if path.exists() else None
            if backup:
                shutil.copy2(path, backup)
            backups.append((path, backup))
            staged_final = stage / f"final-{path.name}"
            staged_final.write_text(text)
            os.replace(staged_final, path)
        info["backups"] = backups
        run(["systemctl", "restart", "dnsdist"])
    except Exception:
        _restore_dnsdist_backups(backups)
        if backups:
            run(["systemctl", "restart", "dnsdist"], check=False)
        raise
    finally:
        shutil.rmtree(stage, ignore_errors=True)
    return info


def _restore_dnsdist_backups(backups: list[tuple[Path, Path | None]]) -> None:
    for path, backup in backups:
        try:
            if backup and backup.exists():
                shutil.copy2(backup, path)
            elif path.exists():
                path.unlink()
        except OSError:
            continue


def rollback_dnsdist_layer(info: dict[str, Any]) -> None:
    """Outer rollback hook for the compiler deploy path: restores the
    previously installed dnsdist-layer files and restarts dnsdist."""
    if not info.get("changed") or not info.get("backups"):
        return
    _restore_dnsdist_backups(info["backups"])
    run(["systemctl", "restart", "dnsdist"], check=False)
