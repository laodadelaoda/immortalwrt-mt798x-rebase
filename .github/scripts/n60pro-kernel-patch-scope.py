#!/usr/bin/env python3
"""Select kernel patches applicable to the N60 Pro (MT7986A).

A patch is excluded only when every changed target is either:
- a MediaTek DTS file belonging exclusively to a non-MT7986 SoC; or
- the MediaTek DTS Makefile, with every changed line adding/removing only
  non-MT7986 SoC-specific DTB/overlay entries or DTC_FLAGS.

Any shared source, driver, networking, mixed-purpose, or unrecognized change
keeps the entire patch in the N60 Pro patch set (fail closed).
"""
from __future__ import annotations

import argparse
import re
import shutil
from pathlib import Path

HEADER = re.compile(r"^(?:\+\+\+|---) [ab]/([^\t\n]+)", re.MULTILINE)
DTS_DIR = re.compile(r"^arch/arm(?:64)?/boot/dts/mediatek/")
SOC_PREFIX = re.compile(r"^(mt[0-9]+)", re.IGNORECASE)
N60PRO_SOC = "mt7986"
MEDIATEK_DTS_MAKEFILE = "arch/arm64/boot/dts/mediatek/Makefile"
SOC_MAKEFILE_ENTRY = re.compile(
    r"^[+-]\s*(?:dtb-\$\([^)]*\)\s*\+=\s*|DTC_FLAGS_)"
    r"(mt[0-9]+)[A-Za-z0-9_-]*(?:\.(?:dtb|dtbo))?(?:\s*:=\s*-@)?$",
    re.IGNORECASE,
)


KERNEL_ROOTS = {
    "arch", "block", "certs", "crypto", "Documentation", "drivers", "fs",
    "include", "init", "io_uring", "ipc", "kernel", "lib", "mm", "net",
    "rust", "samples", "scripts", "security", "sound", "tools", "usr", "virt",
}


def normalize_quilt_index_path(value: str) -> str:
    """Normalize OpenWrt Index paths to paths relative to the kernel tree."""
    path = value.strip()
    if path.startswith("kernel/"):
        return path[len("kernel/"):]
    first, separator, remainder = path.partition("/")
    if separator and first not in KERNEL_ROOTS:
        return remainder
    return path


def is_other_soc_dts_only(patch: Path) -> bool:
    text = patch.read_text(encoding="utf-8", errors="replace")
    paths = sorted(set(HEADER.findall(text)))
    if not paths:
        # Quilt Index paths may be rooted at kernel/, linux-6.12.xx/, or
        # linux-6.12.xx.orig/. Normalize the root component but retain every
        # indexed target, including non-DTS files, so mixed patches fail closed.
        quilt_index = re.findall(r"^Index:\s+(.+?)\s*$", text, re.MULTILINE)
        if quilt_index:
            paths = sorted(set(normalize_quilt_index_path(name) for name in quilt_index))
    if not paths:
        return False

    current_path = ""
    makefile_changes: list[str] = []
    has_other_soc_dts = False

    for line in text.splitlines():
        index_header = re.match(r"^Index:\s+(.+)$", line)
        if index_header:
            current_path = normalize_quilt_index_path(index_header.group(1))
            continue
        header = re.match(r"^\+\+\+ b/(.+)$", line)
        if header:
            current_path = header.group(1)
            continue
        if not ((line.startswith("+") or line.startswith("-"))
                and not line.startswith("+++")
                and not line.startswith("---")):
            continue

        if current_path == MEDIATEK_DTS_MAKEFILE:
            makefile_changes.append(line)
            continue

    for name in paths:
        if name == MEDIATEK_DTS_MAKEFILE:
            continue
        if not DTS_DIR.match(name):
            return False
        match = SOC_PREFIX.match(Path(name).name)
        if not match or match.group(1).lower() == N60PRO_SOC:
            return False
        has_other_soc_dts = True

    if not has_other_soc_dts:
        return False
    if makefile_changes:
        for line in makefile_changes:
            match = SOC_MAKEFILE_ENTRY.fullmatch(line)
            if not match or match.group(1).lower() == N60PRO_SOC:
                return False

    return True

def filter_mixed_soc_dts_patch(patch: Path, output: Path) -> tuple[bool, list[str]]:
    """Keep only MT7986 DTS file sections from an otherwise DTS-only patch.

    The source patch is never modified. Mixed non-DTS patches are preserved
    unchanged because their ownership/dependencies cannot be inferred safely.
    """
    text = patch.read_text(encoding="utf-8", errors="strict")
    lines = text.splitlines(keepends=True)
    starts = [i for i, line in enumerate(lines)
              if line.startswith("--- a/") and i + 1 < len(lines)
              and lines[i + 1].startswith("+++ b/")]
    if not starts:
        # Quilt patches use one Index: section per file instead of Git-style
        # --- a/... / +++ b/... headers. Filter only when every indexed target
        # is a MediaTek DTS file; unknown or shared targets remain untouched.
        index_starts = [i for i, line in enumerate(lines) if line.startswith("Index: ")]
        if not index_starts:
            return False, []
        preamble = lines[:index_starts[0]]
        sections = []
        for pos, start in enumerate(index_starts):
            end = index_starts[pos + 1] if pos + 1 < len(index_starts) else len(lines)
            section = lines[start:end]
            path = normalize_quilt_index_path(section[0].split(":", 1)[1])
            sections.append((path, section))

        if any(not DTS_DIR.match(path) or not SOC_PREFIX.match(Path(path).name)
               for path, _ in sections):
            return False, []
        if not any(SOC_PREFIX.match(Path(path).name).group(1).lower() == N60PRO_SOC
                   for path, _ in sections):
            return False, []

        kept = [(path, section) for path, section in sections
                if SOC_PREFIX.match(Path(path).name).group(1).lower() == N60PRO_SOC]
        if len(kept) == len(sections):
            return False, []

        rendered = list(preamble)
        for _, section in kept:
            rendered.extend(section)
        content = "".join(rendered)
        if not content.endswith("\n"):
            content += "\n"
        output.write_text(content, encoding="utf-8")
        return True, [path for path, _ in kept]

    preamble = lines[:starts[0]]
    sections = []
    for pos, start in enumerate(starts):
        end = starts[pos + 1] if pos + 1 < len(starts) else len(lines)
        section = lines[start:end]
        old_path = section[0][6:].strip().split("\t", 1)[0]
        new_path = section[1][6:].strip().split("\t", 1)[0]
        sections.append((old_path, new_path, section))

    # This transformation is permitted only when every file target is a
    # MediaTek DTS file. Never partially filter a patch touching shared code.
    if any(not DTS_DIR.match(new) or not SOC_PREFIX.match(Path(new).name)
           for _, new, _ in sections):
        return False, []
    if not any(SOC_PREFIX.match(Path(new).name).group(1).lower() == N60PRO_SOC
               for _, new, _ in sections):
        return False, []

    kept = [(old, new, section) for old, new, section in sections
            if SOC_PREFIX.match(Path(new).name).group(1).lower() == N60PRO_SOC]
    if len(kept) == len(sections):
        return False, []

    rendered = list(preamble)
    for _, _, section in kept:
        rendered.extend(section)
    # Ensure the temporary patch has a final newline; the source remains exact.
    content = "".join(rendered)
    if not content.endswith("\n"):
        content += "\n"
    output.write_text(content, encoding="utf-8")
    return True, [new for _, new, _ in kept]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    source = args.source.resolve()
    output = args.output.resolve()
    if not source.is_dir():
        raise SystemExit(f"kernel patch source directory missing: {source}")
    if output == source or source in output.parents:
        raise SystemExit("scoped output must be outside the source patch directory")

    shutil.rmtree(output, ignore_errors=True)
    output.mkdir(parents=True)
    import hashlib
    import json

    included = []
    excluded = []
    transformed = []
    for patch in sorted(source.iterdir()):
        if not patch.is_file() or patch.suffix != ".patch":
            continue
        source_sha = hashlib.sha256(patch.read_bytes()).hexdigest()
        if is_other_soc_dts_only(patch):
            excluded.append({"name": patch.name, "source_sha256": source_sha,
                "reason": "verified non-MT7986 MediaTek DTS-only change"})
            print(f"SKIP N60-IRRELEVANT OTHER-SOC DTS: {patch.name}")
            continue

        scoped_file = output / patch.name
        changed, retained_paths = filter_mixed_soc_dts_patch(patch, scoped_file)
        if changed:
            applied_sha = hashlib.sha256(scoped_file.read_bytes()).hexdigest()
            included.append({"name": patch.name, "source_sha256": source_sha,
                "applied_sha256": applied_sha, "action": "retain_mt7986_dts_sections",
                "retained_paths": retained_paths})
            transformed.append(patch.name)
            print(f"FILTER MIXED-SOC DTS TO MT7986 SECTIONS: {patch.name}")
        else:
            scoped_file.symlink_to(patch)
            included.append({"name": patch.name, "source_sha256": source_sha,
                "applied_sha256": source_sha, "action": "unchanged"})

    if not included:
        raise SystemExit("scoped kernel patch directory is empty; refusing to continue")

    manifest = {
        "schema": 1,
        "target": "mediatek/filogic netcore_n60-pro (MT7986A)",
        "kernel_patch_level": "6.12",
        "source_directory": "target/linux/mediatek/patches-6.12",
        "selection_policy": "fail-closed; classify git-style and OpenWrt/Quilt Index patches; exclude non-MT7986 DTS-only patches and narrow mixed DTS-only patches to MT7986 file sections",
        "included": included,
        "excluded": excluded,
        "transformed": transformed,
    }
    manifest_path = output / "scope-manifest.json"
    manifest_path.write_text(json.dumps(manifest, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    manifest_sha = hashlib.sha256(manifest_path.read_bytes()).hexdigest()
    (output / "scope-manifest.sha256").write_text(f"{manifest_sha}  scope-manifest.json\n", encoding="ascii")
    print(f"N60 Pro MT7986A kernel patch scope: kept={len(included)}, skipped_other_soc_dts={len(excluded)}")
    print(f"SCOPE_MANIFEST_SHA256={manifest_sha}")
    print(f"PATCH_DIR={output}")


if __name__ == "__main__":
    main()
