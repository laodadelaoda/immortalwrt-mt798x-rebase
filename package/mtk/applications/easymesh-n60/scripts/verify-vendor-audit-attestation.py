#!/usr/bin/env python3
"""Create and verify immutable evidence that a vendor-source audit passed."""
from __future__ import annotations
import argparse
import hashlib
import json
import os
import subprocess
from pathlib import Path

LOCK = "package/mtk/vendor-sources.lock.json"
TRANSFORM = "package/mtk/applications/easymesh-n60/scripts/n60-vendor-source-transforms.py"
FIXED = [
    ".github/workflows/vendor-source-patch-audit.yml",
    ".github/workflows/main.yml",
    ".github/workflows/easymesh-quick.yml",
    ".github/workflows/wapp-source-audit.yml",
    ".github/workflows/conninfra-source-audit.yml",
    ".github/workflows/easymesh-wts-template-audit.yml",
    ".github/workflows/build-package.yml",
    ".github/workflows/quick-prepare-audit.yml",
    ".github/workflows/workflow-governance-audit.yml",
    ".github/scripts/audit-workflow-governance.py",
    ".github/scripts/check-package-dependency-closure.py",
    "package/mtk/applications/easymesh-n60/scripts/verify-vendor-audit-attestation.py",
    ".github/actions/easymesh-quick/action.yml",
    "target/linux/mediatek/Makefile",
    "include/version.mk",
    "feeds.conf.default",
    "scripts/feeds",
    "package/libs/openssl/Makefile",
    "package/libs/libnl-tiny/Makefile",
    "package/mtk/applications/datconf/Makefile",
    "package/kernel/mapfilter/Makefile",
    "package/mtk/drivers/mt_wifi/config.in",
    "package/mtk/drivers/mt_wifi/Makefile",
    "package/mtk/drivers/conninfra/Makefile",
    "package/mtk/drivers/warp/Makefile",
    "target/linux/mediatek/patches-6.12/999-zzz-5203-mtk-wifi_utility-add-universal-eeprom-read-write-backend.patch",
    "target/linux/mediatek/patches-6.12/999-mapfilter-add-kconfig.patch",
    "package/mtk/applications/easymesh-n60/Makefile",
    "Makefile",
    "rules.mk",
    "include/target.mk",
    "include/kernel-version.mk",
    "include/package-defaults.mk",
    "include/package.mk",
    "include/kernel.mk",
    "include/quilt.mk",
    "include/download.mk",
    "target/linux/mediatek/Makefile",
    "target/linux/mediatek/filogic/target.mk",
    "scripts/patch-kernel.sh",
    "config/n60pro-1001.config",
]
def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()

def inventory(root: Path) -> dict[str, str]:
    lock = json.loads((root / LOCK).read_text(encoding="utf-8"))
    paths = set(FIXED + [LOCK, TRANSFORM])
    for source in lock["sources"]:
        p = source.get("package_makefile")
        if p:
            paths.add(p)
    for patch_set in lock["patch_sets"]:
        directory = root / patch_set["directory"]
        if not directory.is_dir():
            raise SystemExit("FAIL: locked patch directory missing: " + str(directory))
        for p in directory.glob("*.patch"):
            if p.is_file():
                paths.add(p.relative_to(root).as_posix())
    for base in [
        "package/mtk/applications/easymesh-n60/tests",
        "package/mtk/applications/easymesh-n60/scripts",
        "package/mtk/applications/easymesh-n60/files",
        "package/mtk/applications/datconf/src",
    ]:
        folder = root / base
        if folder.is_dir():
            paths.update(p.relative_to(root).as_posix() for p in folder.rglob("*") if p.is_file())
    result = {}
    for name in sorted(paths):
        path = root / name
        if not path.is_file():
            raise SystemExit("FAIL: attested input missing: " + name)
        result[name] = sha(path)
    return result

def commit(root: Path) -> str:
    return subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=root, text=True
    ).strip()

def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=["create", "verify"])
    parser.add_argument("--repo", default=".")
    parser.add_argument("--attestation", default="vendor-audit-attestation.json")
    parser.add_argument("--expected-run-id")
    parser.add_argument("--expected-run-attempt")
    args = parser.parse_args()
    root = Path(args.repo).resolve()
    att_path = Path(args.attestation)
    if not att_path.is_absolute():
        att_path = root / att_path
    files = inventory(root)
    lock_hash = sha(root / LOCK)
    if args.mode == "create":
        data = {
            "schema_version": 1,
            "status": "passed",
            "commit_sha": commit(root),
            "branch": os.environ.get("GITHUB_REF_NAME", ""),
            "workflow": os.environ.get("GITHUB_WORKFLOW", ""),
            "workflow_ref": os.environ.get("GITHUB_WORKFLOW_REF", ""),
            "run_id": os.environ.get("GITHUB_RUN_ID", ""),
            "run_attempt": os.environ.get("GITHUB_RUN_ATTEMPT", ""),
            "lock_path": LOCK,
            "lock_sha256": lock_hash,
            "files": files,
        }
        if not data["run_id"] or not data["run_attempt"]:
            raise SystemExit("FAIL: GitHub run identity is unavailable; refusing to attest")
        att_path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print("PASS: audit attestation created for " + data["commit_sha"])
        print("PASS: locked files=" + str(len(files)) + " lock_sha256=" + lock_hash)
        return
    if not att_path.is_file():
        raise SystemExit("FAIL: successful vendor audit attestation artifact is missing")
    data = json.loads(att_path.read_text(encoding="utf-8"))
    checks = [
        (data.get("schema_version") == 1, "unsupported attestation schema"),
        (data.get("status") == "passed", "audit status is not passed"),
        (data.get("commit_sha") == commit(root), "checkout commit differs from audited commit"),
        (data.get("lock_path") == LOCK, "attestation lock path mismatch"),
        (data.get("lock_sha256") == lock_hash, "vendor lock SHA256 differs from audited version"),
        (data.get("files") == files, "patch/source/workflow inventory differs from audited version"),
    ]
    if args.expected_run_id is not None:
        checks.append((data.get("run_id") == args.expected_run_id, "attestation belongs to another workflow run"))
    if args.expected_run_attempt is not None:
        checks.append((data.get("run_attempt") == args.expected_run_attempt, "attestation belongs to another run attempt"))
    failed = [message for ok, message in checks if not ok]
    if failed:
        for message in failed:
            print("FAIL: " + message)
        raise SystemExit(1)
    print("PASS: audited commit=" + data["commit_sha"])
    print("PASS: audit run=" + data["run_id"] + " attempt=" + data["run_attempt"])
    print("PASS: lock SHA256=" + lock_hash + " | locked files=" + str(len(files)))
if __name__ == "__main__":
    main()
