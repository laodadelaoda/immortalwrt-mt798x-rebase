#!/usr/bin/env python3
"""Validate the 40-API regression matrix against semantic-review evidence and executable C tests."""
import argparse
import csv
import json
from pathlib import Path

p = argparse.ArgumentParser()
p.add_argument("--review", type=Path, required=True)
p.add_argument("--matrix", type=Path, required=True)
p.add_argument("--test-source", type=Path, required=True)
p.add_argument("--additional-test-source", type=Path, action="append", default=[])
a = p.parse_args()

with a.review.open(encoding="utf-8", newline="") as f:
    review = list(csv.DictReader(f))
matrix = json.loads(a.matrix.read_text(encoding="utf-8"))
norm = lambda x: str(x).strip().strip(chr(96))
review_by = {norm(x["api"]): x for x in review}
coverage = matrix.get("api_test_coverage", [])
coverage_by = {norm(x.get("api")): x for x in coverage}
fail = []

if matrix.get("schema_version") != 1 or matrix.get("scope_id") != "n60-easymesh-openssl-3.5.9":
    fail.append("invalid regression matrix identity/schema")
if len(review) != 40 or len(review_by) != 40:
    fail.append(f"semantic review must contain 40 unique APIs; rows={len(review)} unique={len(review_by)}")
if sum(int(x.get("active_call_sites", 0)) for x in review) != 348:
    fail.append("semantic-review baseline callsite total must remain 348")
if matrix.get("expected_api_count") != 40 or matrix.get("expected_active_call_sites") != 348:
    fail.append("regression matrix baseline constants changed")
if len(coverage) != 40 or len(coverage_by) != 40 or set(review_by) != set(coverage_by):
    fail.append("regression matrix must cover exactly the 40 semantic-review APIs")

test_sources = [a.test_source, *a.additional_test_source]
source_texts = []
for source in test_sources:
    if not source.is_file():
        fail.append("API migration regression C source is missing: " + str(source))
    else:
        source_texts.append(source.read_text(encoding="utf-8"))
for test_id in matrix.get("required_test_ids", []):
    if not any(f'PASS("{test_id}")' in src for src in source_texts):
        fail.append("missing executable PASS test ID: " + str(test_id))

for api, row in review_by.items():
    item = coverage_by.get(api, {})
    ids = item.get("test_ids", [])
    if not ids or any(x not in matrix.get("required_test_ids", []) for x in ids):
        fail.append(api + ": missing/unknown regression test IDs")
    for field in ("review_decision", "semantic_invariants", "review_basis"):
        if not row.get(field, "").strip():
            fail.append(api + ": incomplete " + field)

if fail:
    print(json.dumps({"complete": False, "api_count": len(review_by),
                      "coverage_count": len(coverage_by), "failures": fail}, indent=2))
    raise SystemExit(1)
print(json.dumps({"complete": True, "api_count": 40, "baseline_call_sites": 348,
                  "regression_test_ids": matrix["required_test_ids"], "failures": []}, indent=2))
