#!/usr/bin/env python3
"""Exercise the optional patch wrapper's per-patch audit and non-truncating failure behavior."""
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

repo = Path(__file__).resolve().parents[4]
wrapper = Path(__file__).with_name("kernel-patch-audit-wrapper.sh")
scanner = Path(__file__).with_name("audit-kernel-source-structure.py")
tests_dir = Path(__file__).resolve().parent
patch_bin = shutil.which("patch")
if not patch_bin:
    raise SystemExit("FAIL: GNU patch is required for wrapper regression test")

with tempfile.TemporaryDirectory(prefix="kernel-patch-wrapper-") as tmp:
    root = Path(tmp)
    (root / "drivers").mkdir()
    (root / "Makefile").write_text("VERSION = 6\nPATCHLEVEL = 12\nSUBLEVEL = 112\n")
    source = root / "drivers/test.c"
    source.write_text("int clean_function(void) { return 0; }\n")
    reports = root / "reports"
    env = os.environ.copy()
    env.update({
        "REAL_PATCH_BIN": patch_bin,
        "PATCH_AUDIT_REPORT_DIR": str(reports),
        "PATCH_AUDIT_SCANNER": str(scanner),
        "PATCH_AUDIT_TESTS_DIR": str(tests_dir),
        "KERNEL_PATCH_AUDIT_PATCH": "fixture-0001.patch",
    })

    first_patch = """--- a/drivers/test.c
+++ b/drivers/test.c
@@ -1,1 +1,2 @@
 int clean_function(void) { return 0; }
+int second_function(void) { return 1; }
"""
    first = subprocess.run(
        ["bash", str(wrapper), "--fuzz=0", "-f", "-p1", "-d", str(root)],
        input=first_patch, text=True, capture_output=True, env=env,
    )
    if first.returncode:
        raise SystemExit("first wrapper fixture failed: " + first.stdout + first.stderr)
    if not (reports / "fixture-0001.patch.json").is_file():
        raise SystemExit("wrapper did not emit an intermediate report")

    env["KERNEL_PATCH_AUDIT_PATCH"] = "fixture-0002.patch"
    second_patch = """--- a/drivers/test.c
+++ b/drivers/test.c
@@ -1,2 +1,3 @@
 int clean_function(void) { return 0; }
 int second_function(void) { return 1; }
+int second_function(void) { return 2; }
"""
    second = subprocess.run(
        ["bash", str(wrapper), "--fuzz=0", "-f", "-p1", "-d", str(root)],
        input=second_patch, text=True, capture_output=True, env=env,
    )
    if second.returncode:
        raise SystemExit("wrapper stopped patch application after an audit finding: " +
                         second.stdout + second.stderr)
    if not (reports / "intermediate-failures").is_file():
        raise SystemExit("wrapper failed to record a blocking intermediate source finding")
    if not (reports / "fixture-0002.patch.json").is_file():
        raise SystemExit("wrapper did not preserve the failed intermediate report")

print("PASS: wrapper records per-patch reports and continues after source-audit findings")
