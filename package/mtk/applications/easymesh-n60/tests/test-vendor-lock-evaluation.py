#!/usr/bin/env python3
"""Regression tests for Vendor Lock -> actual GNU Make variable mapping."""
from __future__ import annotations
import importlib.util
import sys
from pathlib import Path
import unittest

sys.dont_write_bytecode = True

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "n60-vendor-lock.py"
SPEC = importlib.util.spec_from_file_location("n60_vendor_lock", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(MODULE)

ATTESTATION_SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "verify-vendor-audit-attestation.py"
ATTESTATION_SPEC = importlib.util.spec_from_file_location("verify_vendor_audit_attestation", ATTESTATION_SCRIPT)
ATTESTATION_MODULE = importlib.util.module_from_spec(ATTESTATION_SPEC)
assert ATTESTATION_SPEC and ATTESTATION_SPEC.loader
ATTESTATION_SPEC.loader.exec_module(ATTESTATION_MODULE)


class InventoryRuntimeArtifactTests(unittest.TestCase):
    def test_python_bytecode_is_excluded_from_audit_inventory(self):
        for name in (
            "__pycache__/n60-vendor-lock.cpython-312.pyc",
            "scripts/module.pyc",
            "scripts/module.pyo",
        ):
            with self.subTest(name=name):
                self.assertTrue(ATTESTATION_MODULE.is_transient_python_artifact(Path(name)))

    def test_python_source_remains_in_audit_inventory(self):
        self.assertFalse(MODULE.is_transient_python_artifact(Path("scripts/module.py")))


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
