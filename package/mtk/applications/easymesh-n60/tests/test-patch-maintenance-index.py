#!/usr/bin/env python3
"""Validate the human-maintained EasyMesh patch grouping index against vendor Lock."""
import csv
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[5]
LOCK = ROOT / "package/mtk/vendor-sources.lock.json"
INDEX = ROOT / "docs/easymesh-patch-maintenance-groups.csv"

def fail(message: str) -> None:
    print(f"FAIL: {message}", file=sys.stderr)
    raise SystemExit(1)

try:
    lock = json.loads(LOCK.read_text(encoding="utf-8"))
    patch_set = next(item for item in lock["patch_sets"] if item["id"] == "easymesh")
except (OSError, ValueError, KeyError, StopIteration) as exc:
    fail(f"cannot read canonical EasyMesh Lock: {exc}")

expected = []
for phase, key in (("application", "application_order"),
                   ("post_normalize", "post_normalize_order")):
    for order, patch_name in enumerate(patch_set.get(key, []), 1):
        expected.append((phase, str(order), patch_name))

try:
    with INDEX.open(newline="", encoding="utf-8") as stream:
        rows = list(csv.DictReader(stream))
except OSError as exc:
    fail(f"cannot read patch maintenance index: {exc}")

required = {
    "lock_phase", "lock_order", "patch_id", "patch_file",
    "maintenance_group", "overlap_or_relation", "merge_decision",
}
if not rows:
    fail("patch maintenance index is empty")
if not required.issubset(rows[0]):
    fail(f"index columns missing: {sorted(required - set(rows[0]))}")

actual = []
seen = set()
patch_root = ROOT / patch_set["directory"]
for row in rows:
    key = (row["lock_phase"], row["lock_order"], row["patch_file"])
    if key in seen:
        fail(f"duplicate index row: {key}")
    seen.add(key)
    actual.append(key)

    if not row["patch_id"] or not row["maintenance_group"]:
        fail(f"missing patch_id or maintenance_group: {row['patch_file']}")
    if row["patch_id"] != row["patch_file"].split("-", 1)[0]:
        fail(f"patch_id does not match filename: {row['patch_file']}")
    patch_path = patch_root / row["patch_file"]
    if not patch_path.is_file() or patch_path.stat().st_size == 0:
        fail(f"indexed patch missing or empty: {patch_path}")
    if row["merge_decision"] not in {
        "keep-atomic", "keep-atomic-stage-bound",
        "candidate-target-for-009", "candidate-merge-into-002",
        "candidate-target-for-013", "candidate-merge-into-011",
    }:
        fail(f"unknown merge decision for {row['patch_file']}: {row['merge_decision']}")

if actual != expected:
    fail("index rows do not exactly match vendor Lock phase/order/name sequence\n"
         f"expected={expected}\nactual={actual}")

if len(rows) != 22:
    fail(f"expected 22 EasyMesh patches, found {len(rows)}")

print("PASS: EasyMesh patch maintenance index exactly matches all 22 Lock entries.")
print("PASS: application/post-normalize phase boundaries and order are preserved.")
print("PASS: every indexed patch exists and has a non-empty maintenance classification.")
