#!/usr/bin/env python3
"""Verify MT Wi-Fi patch 026 against the exact native OpenWrt Prepare tree."""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import subprocess
from pathlib import Path


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", type=Path, required=True)
    parser.add_argument("--evidence-dir", type=Path, required=True)
    args = parser.parse_args()
    repo = args.repo.resolve()
    evidence = args.evidence_dir
    evidence.mkdir(parents=True, exist_ok=True)
    report: list[str] = []
    failures: list[str] = []

    def check(condition: bool, message: str) -> None:
        report.append(("PASS: " if condition else "FAIL: ") + message)
        if not condition:
            failures.append(message)

    lock_path = repo / "package/mtk/vendor-sources.lock.json"
    patch_rel = Path("package/mtk/drivers/mt_wifi/patches-7673/026-since-v6.1-replace-deprecated-prandom_u32-usage.patch")
    patch_path = repo / patch_rel
    source_rel = Path("mt_wifi/embedded/common/rt_os_util.c")

    try:
        lock = json.loads(lock_path.read_text(encoding="utf-8"))
        item = next(x for x in lock["sources"] if x["id"] == "mtwifi")
        expected_build_dir = repo / item["expected_build_dir"]
        check(item["package_makefile"] == "package/mtk/drivers/mt_wifi/Makefile",
              "Lock maps mtwifi to the actual mt_wifi package Makefile")
        check(item["expected_patch_dir"] == "package/mtk/drivers/mt_wifi/patches-7673",
              "Lock selects the 7.6.7.3 PATCH_DIR containing patch 026")
        check(item["archive"] == "mt79xx_20250408-705eb4.tar.xz",
              "Lock pins the expected MT Wi-Fi 7.6.7.3 source archive")
        check(expected_build_dir.is_dir(),
              f"native PKG_BUILD_DIR exists at {expected_build_dir}")
    except Exception as exc:
        report.append(f"FAIL: unable to resolve mtwifi Lock entry: {exc}")
        failures.append("unable to resolve mtwifi Lock entry")
        expected_build_dir = repo / "build_dir/mtwifi-missing"

    check(patch_path.is_file(), f"patch 026 exists at {patch_rel.as_posix()}")
    check(patch_path.is_file() and "mt_wifi/embedded/common/rt_os_util.c" in patch_path.read_text(encoding="utf-8"),
          "patch 026 targets the vendor rt_os_util.c source path")

    source_path = expected_build_dir / source_rel
    candidates = sorted(repo.glob("build_dir/target-*/linux-*/mt_wifi/mt_wifi/embedded/common/rt_os_util.c"))
    check(len(candidates) == 1,
          f"exactly one prepared mt_wifi/embedded/common/rt_os_util.c exists (found {len(candidates)})")
    check(len(candidates) == 1 and candidates[0].resolve() == source_path.resolve(),
          "the discovered source path exactly matches Lock expected_build_dir plus archive source root")
    check(source_path.is_file(),
          f"real post-Prepare source exists at {source_path}")

    if patch_path.is_file() and expected_build_dir.is_dir():
        reverse = subprocess.run(
            ["patch", "--dry-run", "--batch", "--reverse", "--fuzz=0", "-p1", "-d", str(expected_build_dir)],
            input=patch_path.read_text(encoding="utf-8"),
            text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        )
        check(reverse.returncode == 0,
              "patch 026 reverse dry-run matches the prepared source with fuzz disabled (confirms the patch result)")
        reverse_offsets = re.findall(
            r"Hunk #[0-9]+ succeeded at .*\(offset [+-]?[1-9][0-9]* lines?\)",
            reverse.stdout,
        )
        check(not reverse_offsets,
              "patch 026 reverse dry-run has zero line offset")
        report.append("PATCH 026 reverse dry-run output:")
        report.extend("  " + line for line in reverse.stdout.splitlines())

    source_text = source_path.read_text(encoding="utf-8", errors="replace") if source_path.is_file() else ""
    check("#include <linux/random.h>" in source_text,
          "patched source includes linux/random.h for get_random_u32")
    marker = "UINT32 MtRandom32(VOID)"
    starts = [m.start() for m in re.finditer(re.escape(marker), source_text)]
    check(len(starts) == 1, f"exactly one MtRandom32(VOID) definition exists (found {len(starts)})")
    function = ""
    if len(starts) == 1:
        brace = source_text.find("{", starts[0])
        depth = 0
        end = -1
        for pos in range(brace, len(source_text)):
            if source_text[pos] == "{":
                depth += 1
            elif source_text[pos] == "}":
                depth -= 1
                if depth == 0:
                    end = pos + 1
                    break
        if brace >= 0 and end > brace:
            function = source_text[starts[0]:end]
    expected = re.compile(
        r"#if\s*\(\s*LINUX_VERSION_CODE\s*>=\s*KERNEL_VERSION\(6,\s*1,\s*0\)\s*\)\s*"
        r"return\s+get_random_u32\(\)\s*;\s*"
        r"#elif\s*\(\s*LINUX_VERSION_CODE\s*>=\s*KERNEL_VERSION\(3,\s*8,\s*0\)\s*\)\s*"
        r"return\s+prandom_u32\(\)\s*;\s*"
        r"#else[\s\S]*?return\s+random32\(\)\s*;",
        re.MULTILINE,
    )
    check(bool(function) and bool(expected.search(function)),
          "MtRandom32 uses get_random_u32 for Linux >= 6.1, retains prandom_u32 only for 3.8..6.0, and random32 for older kernels")
    report.append("Resolved source: " + str(source_path))
    if function:
        report.append("MtRandom32 final source:")
        report.extend("  " + line for line in function.splitlines())

    if source_path.is_file():
        shutil.copy2(source_path, evidence / "rt_os_util.c")
    if patch_path.is_file():
        shutil.copy2(patch_path, evidence / patch_path.name)
    if lock_path.is_file():
        shutil.copy2(lock_path, evidence / "vendor-sources.lock.json")
    (evidence / "RESULT.txt").write_text("\n".join(report) + "\n", encoding="utf-8")
    hash_targets = [p for p in (evidence / "rt_os_util.c", evidence / patch_path.name, evidence / "vendor-sources.lock.json") if p.is_file()]
    (evidence / "SHA256SUMS").write_text(
        "".join(f"{sha256(p)}  {p.name}\n" for p in hash_targets), encoding="utf-8"
    )
    print("\n".join(report))
    if failures:
        print("MT Wi-Fi 026 audit failures: " + "; ".join(failures))
        return 1
    print("PASS: MT Wi-Fi 026 exact source path, zero-fuzz reverse application, and MtRandom32 replacement.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
