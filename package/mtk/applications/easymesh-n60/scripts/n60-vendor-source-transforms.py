#!/usr/bin/env python3
"""Single source of truth for non-patch EasyMesh vendor source transformations.

The normalize phase is intentionally split out because two CRLF-normalized
files are patch preconditions for patches 006 and 001. The finalize phase runs
after the complete ordered patch series and mirrors the remaining Build/Prepare
mutations. This script is used directly by the production package Makefile.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit("FAIL: " + message)


def normalize(root: Path) -> None:
    files = (
        "1905daemon/ethernet/Makefile",
        "1905daemon/ethernet/mediatek_DSA/eth_ops_dsa.c",
    )
    for rel in files:
        path = root / rel
        require(path.is_file(), f"CRLF normalization input missing: {path}")
        data = path.read_bytes().replace(b"\r", b"")
        path.write_bytes(data)
        require(b"\r" not in data, f"CRLF normalization incomplete: {path}")
        print(f"TRANSFORM PASS: CRLF normalized: {rel}")


def finalize(root: Path) -> None:
    wapp = root / "wappd"

    # Packed attributes are removed only from these two in-memory list nodes.
    path = wapp / "include/map_1905.h"
    data = path.read_bytes()
    old1 = b"struct GNU_PACKED air_monitor_query_rsp{"
    old2 = b"struct GNU_PACKED bh_assoc_ctrl {"
    require(data.count(old1) == 1 and data.count(old2) == 1,
            "packed-list source precondition mismatch")
    data = data.replace(old1, b"struct air_monitor_query_rsp{", 1)
    data = data.replace(old2, b"struct bh_assoc_ctrl {", 1)
    path.write_bytes(data)
    require(b"GNU_PACKED air_monitor_query_rsp" not in data and
            b"GNU_PACKED bh_assoc_ctrl" not in data,
            "packed-list transformation verification failed")
    print("TRANSFORM PASS: two in-memory list structs no longer packed")

    # Six exact-length path-prefix copies; the vendor's explicit NUL writes remain.
    path = wapp / "common/ctrl_iface_unix.c"
    source = path.read_text(encoding="utf-8")
    pattern = re.compile(
        r"os_strncpy\(tmp_confname,\s*confname,\s*strlen\(confname\)"
        r"\s*-\s*strlen\(tmp_ptr\)\s*\)"
    )
    source, count = pattern.subn(
        "os_memcpy(tmp_confname, confname, strlen(confname) - strlen(tmp_ptr))",
        source,
    )
    require(count == 6, f"expected six path-prefix copies, found {count}")
    path.write_text(source, encoding="utf-8")
    require(not pattern.search(path.read_text(encoding="utf-8")),
            "path-prefix copy transformation left an old call")
    print("TRANSFORM PASS: six exact-length path-prefix copies")

    # Pass package EXTRA_CFLAGS into WAPP's actual compiler CFLAGS.
    path = wapp / "Makefile"
    source = path.read_text(encoding="utf-8")
    rules = [line.strip() for line in source.splitlines()
             if "$(CC)" in line and "$(CFLAGS)" in line]
    marker = "# N60 Pro: force package EXTRA_CFLAGS into WAPP compiler CFLAGS"
    require(bool(rules) and marker not in source,
            "WAPP CFLAGS bridge precondition mismatch")
    path.write_text(source.rstrip() + "\n\n" + marker +
                    "\noverride CFLAGS += $(EXTRA_CFLAGS)\n",
                    encoding="utf-8")
    require(marker in path.read_text(encoding="utf-8"),
            "WAPP CFLAGS bridge verification failed")
    print("TRANSFORM PASS: WAPP EXTRA_CFLAGS propagation")

    # musl-compatible inet_make_mask declaration.
    path = wapp / "include/rtmpiapp.h"
    source = path.read_text(encoding="utf-8")
    old = "__uint32_t inet_make_mask"
    require(source.count(old) == 1, "inet_make_mask declaration count mismatch")
    source = source.replace(old, "uint32_t inet_make_mask", 1)
    if "#include <stdint.h>" not in source:
        source = "#include <stdint.h>\n" + source
    path.write_text(source, encoding="utf-8")
    require("uint32_t inet_make_mask" in source and "#include <stdint.h>" in source,
            "inet_make_mask portability verification failed")
    print("TRANSFORM PASS: musl-portable inet_make_mask declaration")

    # libc string API portability in libmapd.
    path = root / "libmapd/include/os.h"
    source = path.read_text(encoding="utf-8")
    old = "os_memset(&now, 0, sizeof(now))"
    require(source.count(old) == 1, "libmapd os_memset call count mismatch")
    source = source.replace(old, "memset(&now, 0, sizeof(now))", 1)
    if "#include <string.h>" not in source:
        source = "#include <string.h>\n" + source
    path.write_text(source, encoding="utf-8")
    require("memset(&now, 0, sizeof(now))" in source and
            "#include <string.h>" in source,
            "libmapd memset portability verification failed")
    print("TRANSFORM PASS: libmapd libc memset portability")

    # Ensure P1905 ethernet compiler recipes propagate package EXTRA_CFLAGS.
    pattern = re.compile(
        re.escape("$(CC)") + r"\s+" + re.escape("$(CFLAGS)") +
        r"(?!\s+" + re.escape("$(EXTRA_CFLAGS)") + r")"
    )
    recipe = re.compile(re.escape("$(CC)") + r"\s+" + re.escape("$(CFLAGS)"))
    for rel in (
        "1905daemon/ethernet/Makefile",
        "1905daemon/ethernet/mediatek_DSA/libbridge/Makefile",
    ):
        path = root / rel
        source = path.read_text(encoding="utf-8")
        require("$(CC)" in source and "$(CFLAGS)" in source,
                f"P1905 compiler recipe missing: {rel}")
        source, count = pattern.subn(
            lambda match: match.group(0) + " $(EXTRA_CFLAGS)", source
        )
        path.write_text(source, encoding="utf-8")
        verified = path.read_text(encoding="utf-8")
        compiler_lines = [line for line in verified.splitlines() if recipe.search(line)]
        require(bool(compiler_lines) and
                all("$(EXTRA_CFLAGS)" in line for line in compiler_lines),
                f"P1905 EXTRA_CFLAGS propagation missing from one or more compiler recipes: {rel}")
        print(f"TRANSFORM PASS: P1905 compiler flags {rel} (updated={count}, recipes={len(compiler_lines)})")

    # Keep the fixed two-radio MBO profile; do not add 6 GHz.
    mbo = (
        "\n# MediaTek MBO parameters for N60 Pro\n"
        "mbo_ap_cdcp=1\n"
        "mbo_ap_assoc_disallow_reason=0\n"
        "mbo_ap_assoc_retry_delay=0\n"
        "mbo_ap_transition_reason_code=0\n"
        "mbo_ap_capability=64\n"
    )
    keys = (
        "mbo_ap_cdcp", "mbo_ap_assoc_disallow_reason",
        "mbo_ap_assoc_retry_delay", "mbo_ap_transition_reason_code",
        "mbo_ap_capability",
    )
    for band in ("ra0", "rax0"):
        path = wapp / f"config_and_icon_files/wapp_ap_{band}_default.conf"
        source = path.read_text(encoding="utf-8")
        require(source.count("interworking=1") == 1,
                f"interworking source precondition mismatch: {path}")
        source = source.replace("interworking=1", "interworking=0", 1)
        source = "\n".join(
            line for line in source.splitlines()
            if not any(line.startswith(key + "=") for key in keys)
        )
        source += mbo
        path.write_text(source, encoding="utf-8")
        verified = path.read_text(encoding="utf-8")
        require(verified.count("interworking=0") == 1,
                f"interworking verification failed: {path}")
        for key in keys:
            require(sum(line.startswith(key + "=")
                        for line in verified.splitlines()) == 1,
                    f"MBO key count mismatch: {key} in {path}")
        print(f"TRANSFORM PASS: two-band MBO profile {band}")

    path = wapp / "wapp_ap.conf"
    expected = "conf_list=/etc/wapp_ap_ra0.conf;/etc/wapp_ap_rax0.conf;\n"
    path.write_text(expected, encoding="utf-8")
    require(path.read_text(encoding="utf-8") == expected,
            "WAPP two-radio conf_list verification failed")
    require("6G" not in expected and "6g" not in expected,
            "unexpected 6 GHz WAPP config")
    print("TRANSFORM PASS: explicit 2.4/5 GHz WAPP conf_list; no 6 GHz")



def verify_lock(repo: Path, downloads: Path | None = None) -> None:
    """Check only the immutable inputs required by the production EasyMesh build."""
    import hashlib
    import json

    lock_path = repo / "package/mtk/vendor-sources.lock.json"
    require(lock_path.is_file(), f"canonical vendor source lock missing: {lock_path}")
    lock = json.loads(lock_path.read_text(encoding="utf-8"))
    require(lock.get("schema_version") == 1, "unsupported vendor source lock schema")

    sources = {item["id"]: item for item in lock.get("sources", [])}
    required_ids = {"wappd", "mapd", "1905daemon", "libmapd"}
    require(required_ids.issubset(sources), "vendor Lock is missing a required EasyMesh source")

    if downloads is not None:
        for source_id in sorted(required_ids):
            item = sources[source_id]
            archive = downloads / item["archive"]
            require(archive.is_file(), f"required vendor archive missing: {archive}")
            actual = hashlib.sha256(archive.read_bytes()).hexdigest()
            require(actual == item["sha256"],
                    f"{source_id} archive SHA256 mismatch: {actual} != {item['sha256']}")
            print(f"SOURCE OK: {source_id} ({item['archive']})")

    patch_sets = {item["id"]: item for item in lock.get("patch_sets", [])}
    require("easymesh" in patch_sets, "vendor Lock has no EasyMesh patch set")
    patch_set = patch_sets["easymesh"]
    patch_dir = repo / patch_set["directory"]
    require(patch_dir.is_dir(), f"EasyMesh patch directory missing: {patch_dir}")

    ordered = (patch_set.get("application_order", []) +
               patch_set.get("post_normalize_order", []))
    require(bool(ordered), "EasyMesh patch order is empty")
    require(len(ordered) == len(set(ordered)), "duplicate patch in EasyMesh Lock order")
    actual = sorted(p.name for p in patch_dir.glob("*.patch") if p.is_file())
    require(set(actual) == set(ordered),
            "EasyMesh patch inventory differs from Lock: "
            f"unlocked={sorted(set(actual)-set(ordered))}; "
            f"missing={sorted(set(ordered)-set(actual))}")
    for name in ordered:
        require((patch_dir / name).is_file(), f"locked EasyMesh patch missing: {name}")

    print(f"BUILD INPUTS OK: EasyMesh sources={len(required_ids)}, patches={len(ordered)}")

def main() -> None:
    if len(sys.argv) >= 2 and sys.argv[1] == "verify-lock":
        if len(sys.argv) not in (3, 5):
            raise SystemExit(
                "usage: n60-vendor-source-transforms.py verify-lock REPO_ROOT [--downloads DL_DIR]"
            )
        repo = Path(sys.argv[2])
        downloads = None
        if len(sys.argv) == 5:
            require(sys.argv[3] == "--downloads", "expected --downloads option")
            downloads = Path(sys.argv[4])
        require(repo.is_dir(), f"repository root does not exist: {repo}")
        verify_lock(repo, downloads)
        return
    if len(sys.argv) != 3 or sys.argv[1] not in ("normalize", "finalize"):
        raise SystemExit(
            "usage: n60-vendor-source-transforms.py {normalize|finalize|verify-lock} PATH"
        )
    phase, root_arg = sys.argv[1], sys.argv[2]
    root = Path(root_arg)
    require(root.is_dir(), f"source root does not exist: {root}")
    if phase == "normalize":
        normalize(root)
    else:
        finalize(root)
    print(f"PASS: shared non-patch source transformations phase={phase}")


if __name__ == "__main__":
    main()
