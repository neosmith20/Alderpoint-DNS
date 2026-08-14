#!/usr/bin/env python3
"""Tests for app.v2.config — V2 desired-state config schema/load/write.

Never touches the real /etc/alderpointdns path; everything runs against
tempdirs.
"""
from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT))

from app.v2 import config as v2config  # noqa: E402


class TestConfigRoundtrip(unittest.TestCase):
    def test_default_config_is_valid(self):
        cfg = v2config.AlderpointV2Config()
        self.assertEqual(cfg.validate(), [])

    def test_roundtrip_via_yaml_text(self):
        cfg = v2config.AlderpointV2Config(
            listeners=[v2config.Listener(protocol="udp", port=53)],
            upstream_strategy="load_balanced",
        )
        text = v2config.dumps(cfg)
        loaded = v2config.loads(text)
        self.assertEqual(loaded.upstream_strategy, "load_balanced")
        self.assertEqual(len(loaded.listeners), 1)
        self.assertEqual(loaded.listeners[0].port, 53)

    def test_roundtrip_via_file(self):
        cfg = v2config.AlderpointV2Config(
            listeners=[v2config.Listener(protocol="dot", port=853)]
        )
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "alderpointdns.yaml"
            v2config.atomic_write(path, cfg)
            loaded = v2config.load_file(path)
            self.assertEqual(loaded.listeners[0].protocol, "dot")


class TestConfigValidation(unittest.TestCase):
    def test_rejects_bad_schema_version(self):
        with self.assertRaises(v2config.ConfigValidationError):
            v2config.AlderpointV2Config.from_dict({"schema_version": 999})

    def test_rejects_bad_upstream_strategy(self):
        with self.assertRaises(v2config.ConfigValidationError):
            v2config.AlderpointV2Config.from_dict({"upstream_strategy": "yolo"})

    def test_rejects_bad_listener_protocol(self):
        with self.assertRaises(v2config.ConfigValidationError):
            v2config.AlderpointV2Config.from_dict(
                {"listeners": [{"protocol": "carrier-pigeon", "port": 53}]}
            )

    def test_rejects_out_of_range_port(self):
        with self.assertRaises(v2config.ConfigValidationError):
            v2config.AlderpointV2Config.from_dict(
                {"listeners": [{"protocol": "udp", "port": 70000}]}
            )

    def test_rejects_non_mapping_top_level(self):
        with self.assertRaises(v2config.ConfigValidationError):
            v2config.loads("- just\n- a\n- list\n")

    def test_rejects_empty_file(self):
        with self.assertRaises(v2config.ConfigValidationError):
            v2config.loads("")

    def test_rejects_invalid_yaml(self):
        with self.assertRaises(v2config.ConfigValidationError):
            v2config.loads("key: [unclosed")

    def test_rejects_unknown_top_level_field(self):
        with self.assertRaises(v2config.ConfigValidationError):
            v2config.AlderpointV2Config.from_dict({"totally_made_up_field": 1})

    def test_rejects_bad_analytics_retention_unit(self):
        with self.assertRaises(v2config.ConfigValidationError):
            v2config.AlderpointV2Config.from_dict(
                {"analytics": {"retention_unit": "fortnights"}}
            )

    def test_rejects_nonpositive_retention_value(self):
        with self.assertRaises(v2config.ConfigValidationError):
            v2config.AlderpointV2Config.from_dict(
                {"analytics": {"retention_value": 0}}
            )


class TestAtomicWrite(unittest.TestCase):
    def test_atomic_write_leaves_no_tmp_file_on_success(self):
        cfg = v2config.AlderpointV2Config()
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "alderpointdns.yaml"
            v2config.atomic_write(path, cfg)
            leftover_tmp = [p for p in Path(td).iterdir() if p.name != path.name]
            self.assertEqual(leftover_tmp, [])

    def test_atomic_write_sets_restrictive_permissions(self):
        cfg = v2config.AlderpointV2Config()
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "alderpointdns.yaml"
            v2config.atomic_write(path, cfg)
            mode = os.stat(path).st_mode & 0o777
            self.assertEqual(mode, 0o640)

    def test_atomic_write_does_not_partially_write_on_validation_failure(self):
        cfg = v2config.AlderpointV2Config()
        cfg.upstream_strategy = "not-a-real-strategy"  # bypass constructor validation
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "alderpointdns.yaml"
            with self.assertRaises(v2config.ConfigValidationError):
                v2config.atomic_write(path, cfg)
            self.assertFalse(path.exists())
            self.assertEqual(list(Path(td).iterdir()), [])

    def test_atomic_write_overwrite_is_all_or_nothing(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "alderpointdns.yaml"
            good = v2config.AlderpointV2Config(upstream_strategy="ordered")
            v2config.atomic_write(path, good)
            original_text = path.read_text()

            bad = v2config.AlderpointV2Config()
            bad.upstream_strategy = "not-a-real-strategy"
            with self.assertRaises(v2config.ConfigValidationError):
                v2config.atomic_write(path, bad)

            # Destination must be untouched by the failed write.
            self.assertEqual(path.read_text(), original_text)


if __name__ == "__main__":
    unittest.main()
