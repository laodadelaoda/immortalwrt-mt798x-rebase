#!/usr/bin/env python3
"""Create/verify a fail-closed attestation for the 40-item EasyMesh OpenSSL migration gate."""
import argparse
import csv
import hashlib
import json
import re
import subprocess
from pathlib import Path

SCOPE = "n60-easymesh-openssl-3.5.9"
REVIEW = "package/mtk/applications/easymesh-n60/tests/openssl-40-active-api-semantic-review.csv"
MATRIX = "package/mtk/applications/easymesh-n60/tests/openssl-40-api-regression-matrix.json"
MIGRATION_MAP = "package/mtk/applications/easymesh-n60/tests/openssl-111-to-359-migration-map.csv"
POLICY = "package/mtk/applications/easymesh-n60/tests/openssl-api-policy.json"
SCOPE_MANIFEST = "package/mtk/applications/easymesh-n60/tests/openssl-easymesh-scope.json"
REPO_INPUTS = [
    "package/mtk/vendor-sources.lock.json",
    REVIEW, MATRIX, MIGRATION_MAP, POLICY, SCOPE_MANIFEST,
    "package/mtk/applications/easymesh-n60/tests/test-openssl-api-migration-regressions.c",
    "package/mtk/applications/easymesh-n60/tests/test-openssl-api-migration-regression-matrix.py",
    "package/mtk/applications/easymesh-n60/scripts/run-openssl-provider-runtime.sh",
    "package/mtk/applications/easymesh-n60/scripts/enforce-openssl-target-api-gate.py",
    "package/mtk/applications/easymesh-n60/scripts/verify-openssl-api-migration-attestation.py",
]

def read_json(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))

def sha256(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()

def rows(path):
    with Path(path).open(encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f))

def git_sha(repo):
    p = subprocess.run(["git", "rev-parse", "HEAD"], cwd=repo, text=True,
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if p.returncode:
        raise ValueError("cannot resolve checked-out Git SHA")
    return p.stdout.strip()

def validate_ready(a):
    repo = a.repo_root.resolve()
    current_sha = git_sha(repo)
    if a.expected_git_sha and current_sha != a.expected_git_sha:
        raise ValueError("checkout Git SHA differs from GITHUB_SHA")
    run_id, attempt = int(a.run_id), int(a.run_attempt)
    if run_id <= 0 or attempt <= 0:
        raise ValueError("invalid workflow run/attempt identity")
    gate = read_json(a.gate_report)
    pre = read_json(a.preprocessor_summary)
    regression = read_json(a.regression_results)
    provider = read_json(a.provider_result)
    baseline = read_json(a.baseline_attestation)
    vendor = read_json(a.vendor_attestation)
    review = rows(repo / REVIEW)
    migration = rows(repo / MIGRATION_MAP)
    matrix = read_json(repo / MATRIX)
    policy = read_json(repo / POLICY)
    review_by = {str(x["api"]).strip().strip(chr(96)): x for x in review}
    matrix_by = {x["api"]: x for x in matrix.get("api_test_coverage", [])}
    migration_by = {x["api"]: x for x in migration}
    rules = policy.get("api_rules", {})
    failures = []
    if len(review) != 40 or len(review_by) != 40 or len(matrix_by) != 40:
        failures.append("40-item semantic review and regression matrix must each contain 40 unique APIs")
    if sum(int(x.get("active_call_sites", 0)) for x in review) != 348:
        failures.append("40-item baseline must retain exactly 348 active callsites")
    if set(review_by) != set(matrix_by):
        failures.append("regression matrix API set differs from the semantic-review baseline")
    if len(migration) != 68 or len(migration_by) != 68:
        failures.append("original 68-row traceability baseline is missing, duplicated or changed")
    if gate.get("schema_version") != 2 or gate.get("git_sha") != current_sha or gate.get("complete") is not True:
        failures.append("target API gate is incomplete or bound to a different Git SHA")
    if gate.get("firmware_compile_invoked") is not False or gate.get("unknown_fail_closed") != 0:
        failures.append("target API gate does not prove no firmware compile and zero UNKNOWN_FAIL_CLOSED")
    if gate.get("active_apis_unreviewed"):
        failures.append("target API gate still has unreviewed active deprecated APIs")
    subset = {x.get("api"): x for x in gate.get("easymesh_api_subset", [])}
    active = set(gate.get("target_active_apis", []))
    for api, row in review_by.items():
        mr = migration_by.get(api, {})
        item = subset.get(api, {})
        rule = rules.get(api, {})
        if mr.get("migration_status") != "APPROVED" or str(mr.get("approval", "")).lower() != "true":
            failures.append(api + ": migration-map approval is not complete")
        if str(row.get("approval", "")).lower() != "true" or row.get("review_status") not in {"IMPLEMENTED", "MIGRATED", "LEGACY_RETAINED"}:
            failures.append(api + ": semantic review is not approved after implementation")
        if not str(row.get("review_decision", "")).strip() or not str(row.get("semantic_invariants", "")).strip():
            failures.append(api + ": semantic decision or invariants are missing")
        if not isinstance(rule, dict) or rule.get("approved") is not True or rule.get("status") not in {"DIRECT_REPLACEMENT", "SEMANTIC_ADAPTATION", "LEGACY_RETAINED"} or not str(rule.get("reason", "")).strip():
            failures.append(api + ": detailed migration policy is missing or unapproved")
        ids = matrix_by.get(api, {}).get("test_ids", [])
        if not ids or not set(ids).issubset(set(regression.get("passed_test_ids", []))):
            failures.append(api + ": required regression tests did not all pass")
        if sorted(rule.get("regression_test_ids", [])) != sorted(ids):
            failures.append(api + ": migration policy regression_test_ids do not match the 40-API test matrix")
        if api in active:
            if rule.get("status") != "LEGACY_RETAINED" or row.get("review_status") != "LEGACY_RETAINED":
                failures.append(api + ": deprecated call remains active without an explicitly approved legacy-retention decision")
        elif item.get("scope_status") != "NO_LONGER_PRESENT_AFTER_PATCH":
            failures.append(api + ": migrated API lacks exact pristine-to-prepared removal evidence")
    if pre.get("git_sha") != current_sha or pre.get("complete") is not True or pre.get("firmware_compile_invoked") is not False:
        failures.append("target preprocessor evidence is incomplete or stale")
    if pre.get("callsite_counts", {}).get("UNKNOWN_FAIL_CLOSED", 0) != 0:
        failures.append("target preprocessor evidence retains UNKNOWN_FAIL_CLOSED callsites")
    if regression.get("scope_id") != SCOPE or regression.get("openssl_version") != "3.5.9" or regression.get("status") != "PASS" or regression.get("api_count") != 40:
        failures.append("40-API provider regression result is incomplete or not PASS")
    regression_inputs = regression.get("inputs", {})
    if regression_inputs.get("matrix_sha256") != sha256(repo / MATRIX):
        failures.append("40-API regression result was generated from a different test matrix")
    if regression_inputs.get("test_source_sha256") != sha256(repo / "package/mtk/applications/easymesh-n60/tests/test-openssl-api-migration-regressions.c"):
        failures.append("40-API regression result was generated from a different C test source")
    if not re.fullmatch(r"[0-9a-f]{64}", str(regression_inputs.get("test_log_sha256", ""))):
        failures.append("40-API regression test log hash is missing or invalid")
    if any(x.get("status") != "PASS" for x in regression.get("api_coverage", [])) or len(regression.get("api_coverage", [])) != 40:
        failures.append("not all 40 APIs have passing regression coverage")
    if provider.get("openssl_version") != "3.5.9" or provider.get("result") != "PASS":
        failures.append("Provider-native OpenSSL runtime regression did not pass")
    baseline_run = baseline.get("run", {})
    baseline_artifact = baseline.get("artifact", {})
    if baseline.get("status") != "VERIFIED" or baseline_run.get("git_sha") != current_sha:
        failures.append("exact-SHA OpenSSL header baseline attestation is invalid")
    if not re.fullmatch(r"[0-9a-f]{64}", str(baseline_artifact.get("sha256", ""))):
        failures.append("OpenSSL baseline artifact digest is missing or invalid")
    vendor_lock = repo / "package/mtk/vendor-sources.lock.json"
    vendor_files = vendor.get("files", {})
    if (vendor.get("status") != "passed" or vendor.get("commit_sha") != current_sha
        or vendor.get("run_id") != str(run_id) or vendor.get("run_attempt") != str(attempt)
        or vendor.get("lock_path") != "package/mtk/vendor-sources.lock.json"
        or vendor.get("lock_sha256") != sha256(vendor_lock)
        or vendor_files.get("package/mtk/vendor-sources.lock.json") != sha256(vendor_lock)):
        failures.append("same-run vendor audit credential or immutable vendor lock SHA256 is invalid")
    artifact_id = str(a.artifact_id)
    artifact_digest = str(a.artifact_digest).removeprefix("sha256:")
    if not artifact_id.isdigit() or not re.fullmatch(r"[0-9a-f]{64}", artifact_digest):
        failures.append("uploaded API evidence artifact ID/digest is missing or invalid")
    if failures:
        raise ValueError("API migration attestation blocked:\n- " + "\n- ".join(failures))
    evidence = {
        "gate_report": {"path": str(a.gate_report), "sha256": sha256(a.gate_report)},
        "preprocessor_summary": {"path": str(a.preprocessor_summary), "sha256": sha256(a.preprocessor_summary)},
        "regression_results": {"path": str(a.regression_results), "sha256": sha256(a.regression_results)},
        "provider_result": {"path": str(a.provider_result), "sha256": sha256(a.provider_result)},
        "baseline_attestation": {"path": str(a.baseline_attestation), "sha256": sha256(a.baseline_attestation)},
        "vendor_attestation": {"path": str(a.vendor_attestation), "sha256": sha256(a.vendor_attestation)},
    }
    return {
        "schema_version": 1, "status": "VERIFIED", "scope_id": SCOPE, "openssl_version": "3.5.9",
        "run": {"id": run_id, "attempt": attempt, "git_sha": current_sha, "ref": a.ref},
        "api_scope": {"original_candidate_count": 68, "required_api_count": 40, "baseline_active_callsites": 348,
                      "apis": sorted(review_by), "target_active_api_count": len(active)},
        "inputs": {p: sha256(repo / p) for p in REPO_INPUTS},
        "evidence": evidence,
        "artifact": {"name": "n60-openssl-3.5.9-api-and-provider-audit", "id": int(artifact_id), "sha256": artifact_digest},
        "vendor_lock_sha256": vendor.get("lock_sha256"),
        "result": {"api_gate": "PASS", "target_preprocessor": "PASS", "api_regressions": "PASS",
                   "provider_runtime": "PASS", "firmware_compile_invoked": False},
    }

def find_evidence(root, basename):
    matches = list(Path(root).rglob(basename))
    if len(matches) != 1:
        raise ValueError(f"expected one downloaded evidence file named {basename}; found {len(matches)}")
    return matches[0]

def verify(a):
    att = read_json(a.attestation)
    repo = a.repo_root.resolve()
    current_sha = git_sha(repo)
    if att.get("schema_version") != 1 or att.get("status") != "VERIFIED" or att.get("scope_id") != SCOPE:
        raise ValueError("OpenSSL API migration credential is missing, stale or invalid")
    run = att.get("run", {})
    if run.get("git_sha") != current_sha or run.get("id") != int(a.expected_run_id) or run.get("attempt") != int(a.expected_run_attempt):
        raise ValueError("OpenSSL API migration credential Git SHA/run/attempt mismatch")
    for path, digest in att.get("inputs", {}).items():
        if sha256(repo / path) != digest:
            raise ValueError("OpenSSL API migration input hash changed: " + path)
    evidence_map = {
        "gate_report": "openssl-target-api-gate.json",
        "preprocessor_summary": "openssl-target-preprocessor-summary.json",
        "regression_results": "openssl-api-regression-results.json",
        "provider_result": "provider-runtime-result.json",
        "baseline_attestation": "openssl-migration-baseline.attestation.json",
    }
    evidence_paths = {}
    for key, basename in evidence_map.items():
        item = att.get("evidence", {}).get(key, {})
        evidence_path = find_evidence(a.evidence_dir, basename)
        evidence_paths[key] = evidence_path
        if sha256(evidence_path) != item.get("sha256"):
            raise ValueError("downloaded OpenSSL evidence hash mismatch: " + basename)
    vendor_path = Path(a.vendor_attestation)
    vendor = read_json(vendor_path)
    lock_path = repo / "package/mtk/vendor-sources.lock.json"
    if sha256(vendor_path) != att.get("evidence", {}).get("vendor_attestation", {}).get("sha256"):
        raise ValueError("vendor source audit credential hash differs from the OpenSSL API credential")
    if (vendor.get("status") != "passed" or vendor.get("commit_sha") != current_sha
        or vendor.get("run_id") != str(a.expected_run_id) or vendor.get("run_attempt") != str(a.expected_run_attempt)
        or vendor.get("lock_sha256") != att.get("vendor_lock_sha256")
        or vendor.get("lock_sha256") != sha256(lock_path)
        or vendor.get("files", {}).get("package/mtk/vendor-sources.lock.json") != sha256(lock_path)):
        raise ValueError("same-run vendor lock SHA256 is not bound to the OpenSSL API credential")
    if a.verify_remote_artifact:
        remote = subprocess.run(
            ["gh", "api", f"repos/{a.repository}/actions/artifacts/{att['artifact']['id']}"],
            text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
        data = json.loads(remote.stdout)
        digest = str(data.get("digest", "")).removeprefix("sha256:")
        if data.get("name") != att["artifact"]["name"] or data.get("expired") is True:
            raise ValueError("OpenSSL API evidence artifact name/expiry validation failed")
        if data.get("workflow_run", {}).get("id") != int(a.expected_run_id) or digest != att["artifact"]["sha256"]:
            raise ValueError("OpenSSL API evidence artifact run ID or GitHub digest mismatch")
        if data.get("workflow_run", {}).get("head_sha") != current_sha:
            raise ValueError("OpenSSL API evidence artifact belongs to a different source revision")
        baseline = read_json(evidence_paths["baseline_attestation"])
        baseline_artifact = baseline.get("artifact", {})
        baseline_run = baseline.get("run", {})
        baseline_remote = subprocess.run(
            ["gh", "api", f"repos/{a.repository}/actions/artifacts/{baseline_artifact['id']}"],
            text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
        baseline_data = json.loads(baseline_remote.stdout)
        baseline_digest = str(baseline_data.get("digest", "")).removeprefix("sha256:")
        if baseline_data.get("name") != baseline_artifact.get("name") or baseline_data.get("expired") is True:
            raise ValueError("OpenSSL 1.1.1w-to-3.5.9 baseline artifact name/expiry validation failed")
        if baseline_data.get("workflow_run", {}).get("id") != baseline_run.get("id") or baseline_digest != baseline_artifact.get("sha256"):
            raise ValueError("OpenSSL baseline artifact run ID or GitHub digest mismatch")
        if baseline_data.get("workflow_run", {}).get("head_sha") != current_sha or baseline_run.get("git_sha") != current_sha:
            raise ValueError("OpenSSL baseline artifact belongs to a different source revision")
    print("PASS: OpenSSL 3.5.9 40-API migration credential, source hashes, run/attempt and both evidence artifact digests verified.")

def main():
    p = argparse.ArgumentParser()
    sub = p.add_subparsers(dest="command", required=True)
    c = sub.add_parser("create")
    for name in ("repo-root", "gate-report", "preprocessor-summary", "regression-results", "provider-result",
                 "baseline-attestation", "vendor-attestation", "output"):
        c.add_argument("--" + name, type=Path, required=True)
    for name in ("run-id", "run-attempt", "artifact-id", "artifact-digest"):
        c.add_argument("--" + name, required=True)
    c.add_argument("--expected-git-sha", required=True)
    c.add_argument("--ref", required=True)
    v = sub.add_parser("verify")
    for name in ("repo-root", "attestation", "evidence-dir", "vendor-attestation"):
        v.add_argument("--" + name, type=Path, required=True)
    for name in ("expected-run-id", "expected-run-attempt", "repository"):
        v.add_argument("--" + name, required=True)
    v.add_argument("--verify-remote-artifact", action="store_true")
    a = p.parse_args()
    if a.command == "create":
        result = validate_ready(a)
        a.output.parent.mkdir(parents=True, exist_ok=True)
        a.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
        print("PASS: immutable 40-API OpenSSL migration attestation created.")
    else:
        verify(a)

if __name__ == "__main__":
    try:
        main()
    except (ValueError, KeyError, OSError, json.JSONDecodeError, subprocess.CalledProcessError) as e:
        raise SystemExit("FAIL: " + str(e))
