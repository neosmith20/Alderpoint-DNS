#!/usr/bin/env python3
from __future__ import annotations

import sys
import tempfile
import unittest
import warnings
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
warnings.simplefilter("ignore", ResourceWarning)

from app import alderpointdns_compiler, blocklist_categories as bc  # noqa: E402


class BlocklistCategoriesTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="alderpointdns-categories-test-"))
        self.old_bc_db = bc.DB_PATH
        self.old_compiler_db = alderpointdns_compiler.DB_PATH
        db_path = self.tmp / "alderpointdns.db"
        bc.DB_PATH = db_path
        alderpointdns_compiler.DB_PATH = db_path
        alderpointdns_compiler.init_db()

    def tearDown(self) -> None:
        bc.DB_PATH = self.old_bc_db
        alderpointdns_compiler.DB_PATH = self.old_compiler_db

    def add_source(self, name: str, category: str | None) -> None:
        with bc.connect() as conn:
            conn.execute(
                "INSERT INTO sources(name, url, enabled, category) VALUES (?, 'http://x', 1, ?)",
                (name, category),
            )
            conn.commit()

    def test_default_categories_are_seeded_and_include_uncategorized(self) -> None:
        keys = {c["key"] for c in bc.list_categories()}
        self.assertIn("malware", keys)
        self.assertIn("ads_trackers", keys)
        self.assertIn(bc.UNCATEGORIZED_KEY, keys)

    def test_create_category_normalizes_and_slugifies(self) -> None:
        key = bc.create_category("  Streaming   Services  ")
        self.assertEqual(key, "streaming_services")
        names = {c["key"]: c["name"] for c in bc.list_categories()}
        self.assertEqual(names[key], "Streaming Services")

    def test_create_category_rejects_case_insensitive_duplicates(self) -> None:
        bc.create_category("Family Safe")
        with self.assertRaises(bc.CategoryError):
            bc.create_category("family safe")

    def test_create_category_rejects_empty_name(self) -> None:
        with self.assertRaises(bc.CategoryError):
            bc.create_category("   ")

    def test_rename_category_does_not_require_touching_sources(self) -> None:
        self.add_source("src1", "malware")
        bc.rename_category("malware", "Malware & Phishing")
        with bc.connect() as conn:
            source_category = conn.execute("SELECT category FROM sources WHERE name='src1'").fetchone()[0]
        self.assertEqual(source_category, "malware")  # key unchanged
        names = {c["key"]: c["name"] for c in bc.list_categories()}
        self.assertEqual(names["malware"], "Malware & Phishing")

    def test_rename_uncategorized_is_rejected(self) -> None:
        with self.assertRaises(bc.CategoryError):
            bc.rename_category(bc.UNCATEGORIZED_KEY, "Something Else")

    def test_merge_category_repoints_sources_and_removes_source_category(self) -> None:
        self.add_source("src1", "malware")
        self.add_source("src2", "malware")
        bc.merge_category("malware", "ads_trackers")
        with bc.connect() as conn:
            categories = {r["category"] for r in conn.execute("SELECT category FROM sources")}
            remaining_keys = {r["key"] for r in conn.execute("SELECT key FROM categories")}
        self.assertEqual(categories, {"ads_trackers"})
        self.assertNotIn("malware", remaining_keys)

    def test_delete_unused_category_succeeds(self) -> None:
        bc.delete_category("safesearch")
        keys = {c["key"] for c in bc.list_categories()}
        self.assertNotIn("safesearch", keys)

    def test_delete_category_in_use_without_reassignment_fails(self) -> None:
        self.add_source("src1", "malware")
        with self.assertRaises(bc.CategoryError):
            bc.delete_category("malware")

    def test_delete_category_in_use_reassigns_to_target(self) -> None:
        self.add_source("src1", "malware")
        bc.delete_category("malware", reassign_to="ads_trackers")
        with bc.connect() as conn:
            source_category = conn.execute("SELECT category FROM sources WHERE name='src1'").fetchone()[0]
        self.assertEqual(source_category, "ads_trackers")

    def test_delete_uncategorized_is_rejected(self) -> None:
        with self.assertRaises(bc.CategoryError):
            bc.delete_category(bc.UNCATEGORIZED_KEY)

    def test_migrate_merges_legacy_free_text_values_by_normalized_name(self) -> None:
        self.add_source("src1", "Ads and Trackers")  # differs only in case from "Ads and trackers"
        self.add_source("src2", "Some Custom Category")
        self.add_source("src3", "")
        bc.migrate_existing_categories()
        with bc.connect() as conn:
            rows = {r["name"]: r["category"] for r in conn.execute("SELECT name, category FROM sources")}
        self.assertEqual(rows["src1"], "ads_trackers")
        self.assertEqual(rows["src2"], "some_custom_category")
        self.assertEqual(rows["src3"], bc.UNCATEGORIZED_KEY)
        # idempotent
        bc.migrate_existing_categories()
        with bc.connect() as conn:
            rows_again = {r["name"]: r["category"] for r in conn.execute("SELECT name, category FROM sources")}
        self.assertEqual(rows, rows_again)


if __name__ == "__main__":
    unittest.main()
