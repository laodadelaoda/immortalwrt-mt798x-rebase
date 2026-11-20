#!/usr/bin/env python3
"""Focused preprocessor audit for active cred_len references in WAPP main.c.

This is conditional-preprocessing evidence, not a translation-unit compile.
Include directives are removed from a temporary copy so host cpp can evaluate
source-local #if/#ifdef branches without requiring the target sysroot.
"""
from __future__ import annotations
import argparse, hashlib, json, re, subprocess
from pathlib import Path

def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("source_root", type=Path)
    ap.add_argument("repo_root", type=Path)
    ap.add_argument("output_dir", type=Path)
    a = ap.parse_args()
    wapp = a.source_root / "wappd"
    src = wapp / "common/main.c"
    source = src.read_text(errors="replace")
    wapp_make = (wapp / "Makefile").read_text(errors="replace")
    wapp_config = (wapp / "wappd_config").read_text(errors="replace")
    package_make = (a.repo_root / "package/mtk/applications/easymesh-n60/Makefile").read_text(errors="replace")

    for macro in ("DPP_SUPPORT", "MAP_R3", "MAP_R3_RECONFIG"):
        if not re.search(rf"(?m)^CFLAGS\s*\+=\s*-D{macro}\s*$", wapp_make):
            raise SystemExit(f"FAIL: vendor WAPP Makefile no longer enables {macro}")
    if "ifeq ($(CONFIG_MAP_R3_SUPPORT), y)" not in wapp_config:
        raise SystemExit("FAIL: wappd_config no longer enables DPP from MAP_R3_SUPPORT")
    if "CONFIG_MAP_R3_SUPPORT=y" not in package_make:
        raise SystemExit("FAIL: package Build/Compile no longer passes CONFIG_MAP_R3_SUPPORT=y")

    # Preserve every source-local directive and code line, removing only include
    # directives (and their continuations) from the focused preprocessor input.
    kept, skipping = [], False
    for line in source.splitlines(keepends=True):
        if not skipping and re.match(r"^\s*#\s*include\b", line):
            skipping = line.rstrip("\r\n").endswith("\\")
            continue
        if skipping:
            skipping = line.rstrip("\r\n").endswith("\\")
            continue
        kept.append(line)

    a.output_dir.mkdir(parents=True, exist_ok=True)
    temp = a.output_dir / "main.c.without-includes.c"
    temp.write_text("".join(kept))
    profiles = {
        "map_r3_enabled": ["-DDPP_SUPPORT", "-DMAP_SUPPORT", "-DMAP_R2", "-DMAP_R3", "-DMAP_R3_RECONFIG", "-DMAP_R3_DPP_CONFIG", "-DOPENWRT_SUPPORT"],
        "map_r3_enabled_no_reconfig": ["-DDPP_SUPPORT", "-DMAP_SUPPORT", "-DMAP_R2", "-DMAP_R3", "-DMAP_R3_DPP_CONFIG", "-DOPENWRT_SUPPORT"],
        "map_r3_disabled": ["-DDPP_SUPPORT", "-DMAP_SUPPORT", "-DMAP_R2", "-DOPENWRT_SUPPORT"],
    }
    manifest = {
        "scope": "source-local conditional preprocessing; includes intentionally excluded; not a compile",
        "source": str(src),
        "source_sha256": digest(source.encode()),
        "wapp_makefile_sha256": digest(wapp_make.encode()),
        "package_makefile_sha256": digest(package_make.encode()),
        "raw_cred_len_line_numbers": [i for i, line in enumerate(source.splitlines(), 1) if re.search(r"\bcred_len\b", line)],
        "profiles": {}
    }
    for name, macros in profiles.items():
        out = a.output_dir / f"{name}.i"
        cmd = ["cc", "-E", "-P", "-x", "c", *macros, str(temp), "-o", str(out)]
        proc = subprocess.run(cmd, text=True, capture_output=True)
        if proc.returncode:
            raise SystemExit(f"FAIL: preprocessing {name}:\n{proc.stderr}")
        active = [i for i, line in enumerate(out.read_text(errors="replace").splitlines(), 1) if re.search(r"\bcred_len\b", line)]
        # Diagnostic only: the target compiler, not source-only preprocessing,
        # is authoritative for undeclared or invalid references.
        manifest["profiles"][name] = {
            "command": cmd, "output": out.name,
            "output_sha256": digest(out.read_bytes()), "active_cred_len_tokens": len(active),
            "active_cred_len_output_lines": active[:20]
        }
    (a.output_dir / "CRED-LEN-PREPROCESS-MANIFEST.json").write_text(json.dumps(manifest, indent=2) + "\n")
    report = [
        "Diagnostic only: active cred_len tokens are recorded per profile; Quick compilation is authoritative.",
        "Profiles: MAP_R3+MAP_R3_RECONFIG; MAP_R3 without MAP_R3_RECONFIG; MAP_R3 disabled.",
        "Raw-source and preprocessed occurrences are retained as evidence; this heuristic does not fail the audit.",
        "This is focused conditional preprocessing, not a full translation-unit compile.",
        "Commands and output SHA256 values: CRED-LEN-PREPROCESS-MANIFEST.json"
    ]
    (a.output_dir / "CRED-LEN-PREPROCESS-REPORT.txt").write_text("\n".join(report) + "\n")
    print("PASS: MAP_R3 cred_len conditional-preprocessor audit")

if __name__ == "__main__":
    main()
