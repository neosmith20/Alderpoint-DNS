#!/usr/bin/env python3
"""Managed categories for blocklist sources.

Reuses the ``categories`` table already seeded by
``alderpointdns_compiler.init_db()`` (it also backs the not-yet-exposed
network policy profile feature) as the taxonomy for the Blocklists page's
category dropdown, instead of the free-text field it replaces. Blocklist
sources reference a category by its stable ``key``, so renaming a category
only changes its display name and never requires touching every source row;
merging or deleting a category that is still in use repoints the affected
sources' ``category`` column.
"""

from __future__ import annotations

import re
import sqlite3
from pathlib import Path

DB_PATH = Path("/var/lib/alderpointdns/alderpointdns.db")
UNCATEGORIZED_KEY = "uncategorized"
KEY_RE = re.compile(r"[^a-z0-9]+")


class CategoryError(ValueError):
    pass


class AlderpointDNSConnection(sqlite3.Connection):
    def __enter__(self):
        self._alderpointdns_depth = getattr(self, "_alderpointdns_depth", 0) + 1
        return super().__enter__()

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        super().__exit__(exc_type, exc_value, traceback)
        self._alderpointdns_depth = getattr(self, "_alderpointdns_depth", 1) - 1
        if self._alderpointdns_depth <= 0:
            self.close()


def connect() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, factory=AlderpointDNSConnection, timeout=5.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout=5000")
    return conn


def normalize_name(raw: str) -> str:
    return re.sub(r"\s+", " ", (raw or "").strip())


def slugify(raw: str) -> str:
    key = KEY_RE.sub("_", (raw or "").strip().lower()).strip("_")
    return key


def _ensure_uncategorized(conn: sqlite3.Connection) -> None:
    conn.execute(
        "INSERT OR IGNORE INTO categories(key, name, description) VALUES (?, ?, ?)",
        (UNCATEGORIZED_KEY, "Uncategorized", "Blocklist sources without a specific category"),
    )


def list_categories(conn: sqlite3.Connection | None = None) -> list[dict]:
    owns_conn = conn is None
    conn = conn or connect()
    try:
        _ensure_uncategorized(conn)
        conn.commit()
        rows = conn.execute(
            """
            SELECT c.key, c.name, c.description, count(s.id) AS source_count
            FROM categories c
            LEFT JOIN sources s ON s.category = c.key
            GROUP BY c.key
            ORDER BY (c.key = 'uncategorized'), c.name COLLATE NOCASE
            """
        ).fetchall()
        return [dict(row) for row in rows]
    finally:
        if owns_conn:
            conn.close()


def migrate_existing_categories(conn: sqlite3.Connection | None = None) -> None:
    """Backfill a managed category row for every legacy free-text value.

    Historically ``sources.category`` was a free-text field an operator
    typed by hand, so existing databases may contain values that aren't a
    known category key (arbitrary capitalization/whitespace, typos,
    duplicates that only differ by case). This repoints those rows at a
    normalized, deduplicated category key without changing which category a
    source is conceptually in, and is a no-op once every source already
    references a real key.
    """
    owns_conn = conn is None
    conn = conn or connect()
    try:
        _ensure_uncategorized(conn)
        known_keys = {row["key"] for row in conn.execute("SELECT key FROM categories")}
        name_to_key = {
            row["name"].strip().lower(): row["key"] for row in conn.execute("SELECT key, name FROM categories")
        }
        raw_values = [
            row["category"]
            for row in conn.execute(
                "SELECT DISTINCT category FROM sources WHERE category IS NOT NULL AND category != ''"
            )
        ]
        for raw in raw_values:
            if raw in known_keys:
                continue
            name = normalize_name(raw)
            existing_key = name_to_key.get(name.lower())
            key = existing_key or slugify(name) or UNCATEGORIZED_KEY
            if key not in known_keys:
                conn.execute(
                    "INSERT OR IGNORE INTO categories(key, name, description) VALUES (?, ?, '')",
                    (key, name),
                )
                known_keys.add(key)
                name_to_key[name.lower()] = key
            if key != raw:
                conn.execute("UPDATE sources SET category=? WHERE category=?", (key, raw))
        conn.execute(
            "UPDATE sources SET category=? WHERE category IS NULL OR category=''",
            (UNCATEGORIZED_KEY,),
        )
        conn.commit()
    finally:
        if owns_conn:
            conn.close()


def create_category(name: str) -> str:
    clean_name = normalize_name(name)
    if not clean_name:
        raise CategoryError("category name is required")
    if len(clean_name) > 64:
        raise CategoryError("category name must be 64 characters or fewer")
    key = slugify(clean_name)
    if not key:
        raise CategoryError("category name must contain at least one letter or number")
    with connect() as conn:
        existing = conn.execute(
            "SELECT key FROM categories WHERE key=? OR name=? COLLATE NOCASE", (key, clean_name)
        ).fetchone()
        if existing:
            raise CategoryError(f'category "{clean_name}" already exists')
        conn.execute("INSERT INTO categories(key, name, description) VALUES (?, ?, '')", (key, clean_name))
        conn.commit()
    return key


def rename_category(key: str, new_name: str) -> None:
    if key == UNCATEGORIZED_KEY:
        raise CategoryError("the Uncategorized category cannot be renamed")
    clean_name = normalize_name(new_name)
    if not clean_name:
        raise CategoryError("category name is required")
    with connect() as conn:
        row = conn.execute("SELECT key FROM categories WHERE key=?", (key,)).fetchone()
        if not row:
            raise CategoryError("category not found")
        duplicate = conn.execute(
            "SELECT key FROM categories WHERE name=? COLLATE NOCASE AND key != ?", (clean_name, key)
        ).fetchone()
        if duplicate:
            raise CategoryError(f'category "{clean_name}" already exists')
        conn.execute("UPDATE categories SET name=? WHERE key=?", (clean_name, key))
        conn.commit()


def merge_category(source_key: str, target_key: str) -> None:
    if source_key == target_key:
        raise CategoryError("cannot merge a category into itself")
    with connect() as conn:
        source_row = conn.execute("SELECT key FROM categories WHERE key=?", (source_key,)).fetchone()
        target_row = conn.execute("SELECT key FROM categories WHERE key=?", (target_key,)).fetchone()
        if not source_row or not target_row:
            raise CategoryError("category not found")
        conn.execute("UPDATE sources SET category=? WHERE category=?", (target_key, source_key))
        if source_key != UNCATEGORIZED_KEY:
            conn.execute("DELETE FROM categories WHERE key=?", (source_key,))
        conn.commit()


def delete_category(key: str, reassign_to: str | None = None) -> None:
    if key == UNCATEGORIZED_KEY:
        raise CategoryError("the Uncategorized category cannot be deleted")
    with connect() as conn:
        row = conn.execute("SELECT key FROM categories WHERE key=?", (key,)).fetchone()
        if not row:
            raise CategoryError("category not found")
        in_use = conn.execute("SELECT count(*) FROM sources WHERE category=?", (key,)).fetchone()[0]
        if in_use:
            target = reassign_to or UNCATEGORIZED_KEY
            if target == key:
                raise CategoryError("choose a different category to reassign these sources to")
            target_row = conn.execute("SELECT key FROM categories WHERE key=?", (target,)).fetchone()
            if not target_row:
                raise CategoryError("reassignment category not found")
            conn.execute("UPDATE sources SET category=? WHERE category=?", (target, key))
        conn.execute("DELETE FROM categories WHERE key=?", (key,))
        conn.commit()
