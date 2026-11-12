#!/usr/bin/env python3
"""Single source of truth for non-patch EasyMesh vendor source transformations.

The normalize phase is intentionally split out because two CRLF-normalized
files are patch preconditions for patches 006 and 001. The finalize phase runs
after the complete ordered patch series and mirrors the remaining Build/Prepare
mutations. This script is shared by the package Makefile and vendor audit.
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
    import hashlib
    import json

    lock_path = repo / "package/mtk/vendor-sources.lock.json"
    require(lock_path.is_file(), f"canonical vendor source lock missing: {lock_path}")
    lock = json.loads(lock_path.read_text(encoding="utf-8"))
    require(lock.get("schema_version") == 1, "unsupported vendor source lock schema")
    sources = lock.get("sources")
    patch_sets = lock.get("patch_sets")
    require(isinstance(sources, list) and sources, "vendor source lock has no sources")
    require(isinstance(patch_sets, list) and patch_sets, "vendor source lock has no patch sets")

    source_ids = set()
    for item in sources:
        source_id = item["id"]
        require(source_id not in source_ids, f"duplicate locked source id: {source_id}")
        source_ids.add(source_id)
        archive = item["archive"]
        digest = item["sha256"]
        require(len(digest) == 64 and all(c in "0123456789abcdef" for c in digest),
                f"invalid SHA256 for {source_id}")
        makefile_path = repo / item["package_makefile"]
        require(makefile_path.is_file(), f"{source_id} package Makefile missing: {makefile_path}")
        makefile = makefile_path.read_text(encoding="utf-8")
        workflow = (repo / ".github/workflows/vendor-source-patch-audit.yml").read_text(encoding="utf-8")
        scope = item.get("source_scope")
        require(scope in {"manual-package-prepare", "auxiliary-audit-only", "openwrt-package"},
                f"{source_id} has missing/invalid source_scope in canonical lock")
        require("package/mtk/vendor-sources.lock.json" in workflow and
                'fetch_archive "$name" "$url" "$sha"' in workflow,
                "vendor audit workflow does not fetch archives through the canonical lock")
        if item["package_makefile"].endswith("easymesh-n60/Makefile"):
            if source_id in {"bndstrg_plus", "fwdd"}:
                auxiliary = (repo / "package/mtk/applications/easymesh-n60/scripts/n60-auxiliary-source-audit.sh").read_text(encoding="utf-8")
                require(source_id in auxiliary and "vendor-sources.lock.json" in auxiliary,
                        f"{source_id} auxiliary audit does not consume the canonical source lock")
            else:
                require(archive in makefile,
                        f"{source_id} EasyMesh extraction declaration differs from canonical lock")
        else:
            source_var = item.get("source_var", "PKG_SOURCE")
            hash_var = item.get("hash_var", "PKG_HASH")
            if source_id == "datconf":
                require("PKG_NAME:=datconf" in makefile and
                        "PKG_REVISION:=757f9679" in makefile and
                        "PKG_SOURCE:=$(PKG_NAME)-$(PKG_REVISION).tar.bz2" in makefile,
                        "datconf derived source filename differs from canonical lock")
            else:
                require(re.search(rf"(?m)^{re.escape(source_var)}:=.*{re.escape(archive)}\s*$", makefile),
                        f"{source_id} {source_var} does not declare locked archive {archive}")
            require(re.search(rf"(?m)^{re.escape(hash_var)}:={re.escape(digest)}\s*$", makefile),
                    f"{source_id} {hash_var} does not match locked SHA256")
            url = item["url"]
            if item.get("source_url_var"):
                url_var = item["source_url_var"]
                require(re.search(rf"(?m)^{re.escape(url_var)}:=.*$", makefile),
                        f"{source_id} source URL variable {url_var} missing")
                require(url.rsplit("/", 1)[0] in makefile,
                        f"{source_id} source URL base differs from lock")
            else:
                require(url.rsplit("/", 1)[0] in makefile,
                        f"{source_id} source URL base differs from lock")
        if downloads is not None and source_id in {"wappd", "mapd", "1905daemon", "libmapd"}:
            archive_path = downloads / archive
            require(archive_path.is_file(), f"locked source archive missing from DL_DIR: {archive}")
            actual = hashlib.sha256(archive_path.read_bytes()).hexdigest()
            require(actual == digest,
                    f"{source_id} downloaded archive SHA256 mismatch: {actual} != {digest}")
        print(f"LOCK SOURCE PASS: {source_id} | {archive} | SHA256={digest}")

    patch_ids = set()
    for patch_set in patch_sets:
        patch_id = patch_set["id"]
        require(patch_id not in patch_ids, f"duplicate patch set id: {patch_id}")
        patch_ids.add(patch_id)
        directory = repo / patch_set["directory"]
        require(directory.is_dir(), f"locked patch directory missing: {directory}")
        require("n60-vendor-lock.py patch-order" in workflow and "apply_locked_series" in workflow,
                "vendor audit workflow does not consume Lock-driven patch ordering")
        expected = patch_set["application_order"] + patch_set.get("post_normalize_order", [])
        require(len(expected) == len(set(expected)),
                f"duplicate filename in locked patch order: {patch_id}")
        actual = sorted(p.name for p in directory.glob("*.patch") if p.is_file())
        expected_set = set(expected)
        require(set(actual) == expected_set,
                f"{patch_id} patch inventory differs from lock: "
                f"unlocked={sorted(set(actual)-expected_set)} "
                f"missing={sorted(expected_set-set(actual))}")
        for filename in expected:
            require((directory / filename).is_file(),
                    f"locked patch missing: {patch_id}/{filename}")
        if patch_id != "easymesh":
            require(expected == sorted(expected),
                    f"{patch_id} uses lexical patch application; lock order must be lexical")
        print(f"LOCK PATCH PASS: {patch_id} | patches={len(expected)} | {patch_set['directory']}")

    workflow_path = repo / ".github/workflows/vendor-source-patch-audit.yml"
    workflow = workflow_path.read_text(encoding="utf-8")
    helper_path = repo / "package/mtk/applications/easymesh-n60/scripts/n60-vendor-lock.py"
    helper = helper_path.read_text(encoding="utf-8")
    easy_makefile = (repo / "package/mtk/applications/easymesh-n60/Makefile").read_text(encoding="utf-8")
    require("def patch_set(repo,sid):" in helper and "def print_patch_order(repo,sid,phase):" in helper,
            "canonical Lock helper does not implement validated patch-order lookup")
    require('patch-order --repo "$GITHUB_WORKSPACE" --set "$set_id" --phase "$phase"' in workflow,
            "Vendor Audit does not obtain patch application order from Lock helper")
    require('patch-order --repo "$(TOPDIR)" --set easymesh --phase application' in easy_makefile and
            'patch-order --repo "$(TOPDIR)" --set easymesh --phase post_normalize' in easy_makefile,
            "EasyMesh Build/Prepare does not consume both Lock-defined patch phases")
    app_pos = easy_makefile.index('patch-order --repo "$(TOPDIR)" --set easymesh --phase application')
    normalize_call = 'n60-vendor-source-transforms.py normalize "$(PKG_BUILD_DIR)"'
    post_pos = easy_makefile.index('patch-order --repo "$(TOPDIR)" --set easymesh --phase post_normalize')
    finalize_call = 'n60-vendor-source-transforms.py finalize "$(PKG_BUILD_DIR)"'
    require(normalize_call in easy_makefile and finalize_call in easy_makefile,
            "EasyMesh Build/Prepare omits the shared normalize/finalize transformation phases")
    normalize_pos = easy_makefile.index(normalize_call)
    finalize_pos = easy_makefile.index(finalize_call)
    require(app_pos < normalize_pos < post_pos < finalize_pos,
            "EasyMesh Build/Prepare order differs from Vendor Audit: application -> normalize -> post-normalize -> finalize")
    easy_lock = next(p for p in patch_sets if p["id"] == "easymesh")
    require(easy_lock.get("application_order") and easy_lock.get("post_normalize_order"),
            "EasyMesh Lock must declare pre- and post-normalization patch phases")
    expected_application = {
        "002-dpp-parser-safety.patch",
        "003-wapp-gcc14-copy-semantics.patch",
        "004-libmapd-target-flags.patch",
        "005-wapp-hotspot-realloc-pointer-arithmetic.patch",
        "007-openssl3-use-native-evp-pkey-get0-ec-key.patch",
        "008-dpp-parser-bounds-and-secret-redaction.patch",
        "010-dpp-wdev-config-allocation-rollback.patch",
        "011-wapp-wts-security.patch",
    }
    expected_post = {
        "001-dsa-use-linux-mii-ioctl.patch",
        "006-p1905-libbridge-tool-propagation.patch",
    }
    require(expected_application.issubset(set(easy_lock["application_order"])),
            "EasyMesh Lock application phase omits a required WAPP/DPP/libmapd patch")
    require(expected_post.issubset(set(easy_lock["post_normalize_order"])),
            "EasyMesh Lock post-normalize phase omits a required P1905 patch")
    for filename in expected_application | expected_post:
        require(f'apply_patch_strict "./patches/{filename}"' not in easy_makefile,
                f"EasyMesh Makefile applies Lock-managed patch out of band: {filename}")
    wts_patch = "011-wapp-wts-security.patch"
    require(easy_lock["application_order"].count(wts_patch) == 1,
            "WTS security patch must appear exactly once in the canonical EasyMesh application order")
    require("WTS_SECURITY_PATCH=" not in easy_makefile and
            'apply_patch_strict "./patches/' + wts_patch + '"' not in easy_makefile,
            "EasyMesh Build/Prepare applies the Lock-managed WTS security patch out of band")

    print(f"PASS: canonical vendor lock verified | sources={len(sources)} patch_sets={len(patch_sets)}")



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
