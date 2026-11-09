#!/usr/bin/env python3
"""Regression tests for Vendor Lock -> GNU Make mapping and active patch dependencies."""
from __future__ import annotations
import csv
import importlib.util
import json
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



class EasyMeshPatchDependencyManifestTests(unittest.TestCase):
    def setUp(self):
        self.repo = Path(__file__).resolve().parents[5]
        self.lock = json.loads(
            (self.repo / "package/mtk/vendor-sources.lock.json").read_text(encoding="utf-8")
        )
        self.patch_set = next(
            item for item in self.lock["patch_sets"] if item.get("id") == "easymesh"
        )
        with (self.repo / "docs/audit/easymesh-patch-dependencies.csv").open(
            newline="", encoding="utf-8"
        ) as stream:
            self.rows = list(csv.DictReader(stream))

    def test_manifest_matches_canonical_lock_order_and_phase(self):
        expected = {}
        for phase, names in (
            ("Build/Prepare", self.patch_set.get("application_order", [])),
            ("post_normalize", self.patch_set.get("post_normalize_order", [])),
        ):
            for order, name in enumerate(names, start=1 if phase == "Build/Prepare" else
                                         len(self.patch_set.get("application_order", [])) + 1):
                expected[name] = (phase, order)

        # The Lock is authoritative: adding a reviewed patch must not require
        # changing a second hard-coded patch count in this regression test.
        ids = [row["patch_id"] for row in self.rows]
        files = [row["patch_file"] for row in self.rows]
        expected_ids = {name[:3] for name in expected}
        self.assertEqual(len(self.rows), len(expected),
                         "dependency manifest row count must match canonical Lock")
        self.assertEqual(set(ids), expected_ids,
                         "dependency manifest patch IDs must match canonical Lock")
        self.assertEqual(len(set(ids)), len(ids),
                         "dependency manifest contains duplicate patch IDs")
        self.assertEqual(len(set(files)), len(files),
                         "dependency manifest contains duplicate patch files")

        by_id = {row["patch_id"]: row for row in self.rows}
        for row in self.rows:
            name = row["patch_file"]
            self.assertEqual(row["patch_id"], name[:3], f"{name}: patch ID does not match filename")
            self.assertIn(name, expected, f"{name} is not selected by the canonical Lock")
            phase, order = expected[name]
            self.assertEqual(row["application_phase"], phase, name)
            self.assertEqual(int(row["application_order"]), order, name)
            self.assertTrue((self.repo / self.patch_set["directory"] / name).is_file(), name)
            self.assertTrue(row["responsibility"].strip(), name)
            self.assertTrue(row["validation"].strip(), name)

        for row in self.rows:
            current_order = int(row["application_order"])
            for dependency in filter(None, (item.strip() for item in row["depends_on"].split(";"))):
                self.assertIn(dependency, by_id, f"{row['patch_id']} has unknown dependency {dependency}")
                self.assertLess(
                    int(by_id[dependency]["application_order"]),
                    current_order,
                    f"{row['patch_id']} is ordered before prerequisite {dependency}",
                )



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
        self.assertFalse(ATTESTATION_MODULE.is_transient_python_artifact(Path("scripts/module.py")))


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
