#!/usr/bin/env python3
"""Regression tests for Vendor Lock -> actual GNU Make variable mapping."""
from __future__ import annotations
import importlib.util
from pathlib import Path
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "n60-vendor-lock.py"
SPEC = importlib.util.spec_from_file_location("n60_vendor_lock", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(MODULE)


class SourceVariableMappingTests(unittest.TestCase):
    def setUp(self):
        self.item = {
            "id": "mtwifi",
            "archive": "mt79xx_20250408-705eb4.tar.xz",
            "sha256": "b029d7b43c498193092dc6a3c857361c8835ce34bb306561c550ac0539784a78",
            "url": "https://raw.githubusercontent.com/vendor/project/dl/mt79xx_20250408-705eb4.tar.xz",
            "source_var": "PKG_SOURCE",
            "hash_var": "PKG_HASH",
            "source_url_var": "REPO_URL",
        }
        self.values = {
            "PKG_SOURCE": self.item["archive"],
            "PKG_HASH": self.item["sha256"],
            "REPO_URL": "https://raw.githubusercontent.com/vendor/project/dl",
            "PKG_SOURCE_URL": "",
        }

    def test_lock_mapped_repo_url_is_authoritative(self):
        self.assertEqual(MODULE.verify_source_declaration("mtwifi", self.item, self.values), "REPO_URL")

    def test_default_source_url_variable_is_supported(self):
        item = dict(self.item)
        item.pop("source_url_var")
        values = dict(self.values)
        values["PKG_SOURCE_URL"] = values.pop("REPO_URL")
        self.assertEqual(MODULE.verify_source_declaration("mtwifi", item, values), "PKG_SOURCE_URL")

    def test_mapped_url_mismatch_fails_closed(self):
        values = dict(self.values, REPO_URL="https://wrong.invalid/dl")
        with self.assertRaises(SystemExit):
            MODULE.verify_source_declaration("mtwifi", self.item, values)

    def test_archive_or_hash_mismatch_fails_closed(self):
        for key in ("PKG_SOURCE", "PKG_HASH"):
            values = dict(self.values, **{key: "wrong"})
            with self.subTest(key=key), self.assertRaises(SystemExit):
                MODULE.verify_source_declaration("mtwifi", self.item, values)


if __name__ == "__main__":
    unittest.main()
