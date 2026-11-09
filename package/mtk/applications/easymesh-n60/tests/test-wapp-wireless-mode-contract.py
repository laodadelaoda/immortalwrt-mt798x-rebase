#!/usr/bin/env python3
"""Verify WAPP 2.4/5 GHz mode helpers remain available without 6 GHz support."""
from __future__ import annotations
import re
import sys
from pathlib import Path


def fail(message: str) -> None:
    raise SystemExit("FAIL: " + message)


def main() -> None:
    if len(sys.argv) != 3:
        fail("usage: test-wapp-wireless-mode-contract.py <easymesh-build-dir> <topdir>")
    build_dir = Path(sys.argv[1])
    topdir = Path(sys.argv[2])
    header = build_dir / "wappd/include/wdev.h"
    makefile = build_dir / "wappd/Makefile"
    config = topdir / ".config"
    if not header.is_file():
        fail("patched WAPP wireless-mode header is missing: " + str(header))
    if not makefile.is_file():
        fail("WAPP Makefile is missing: " + str(makefile))
    if not config.is_file():
        fail("normalized N60 Pro .config is missing: " + str(config))

    source = header.read_text(encoding="utf-8")
    pattern = re.compile(
        r"#ifdef\s+MAP_6E_SUPPORT\s*\n"
        r"\s*#define\s+WMODE_CAP_6G\([^\n]+\n"
        r"#endif\s*\n"
        r"(?:/\*[^\n]*\*/\s*\n)?"
        r"\s*#define\s+WMODE_CAP_5G\([^\n]+\n"
        r"\s*#define\s+WMODE_CAP_2G\([^\n]+",
        re.MULTILINE,
    )
    if not pattern.search(source):
        fail("WMODE_CAP_5G/2G must be unconditional while WMODE_CAP_6G remains MAP_6E_SUPPORT-gated")

    build_make = makefile.read_text(encoding="utf-8")
    gate = re.search(
        r"ifeq\s*\(\$\(CONFIG_MTK_MAP_R2_6E_SUPPORT\),\s*y\)"
        r"(?:(?!^endif\s*$)[\s\S])*?CFLAGS\s*\+=\s*-DMAP_6E_SUPPORT",
        build_make,
        re.MULTILINE,
    )
    if not gate:
        fail("WAPP Makefile must keep MAP_6E_SUPPORT behind CONFIG_MTK_MAP_R2_6E_SUPPORT")

    config_text = config.read_text(encoding="utf-8")
    if re.search(r"^CONFIG_MTK_MAP_R2_6E_SUPPORT=y$", config_text, re.MULTILINE):
        fail("N60 Pro must not enable CONFIG_MTK_MAP_R2_6E_SUPPORT for this 2.4/5 GHz compatibility fix")

    print("PASS: WAPP WMODE_CAP_5G/2G are available without MAP_6E_SUPPORT; 6 GHz remains feature-gated and disabled in N60 Pro config.")


if __name__ == "__main__":
    main()
