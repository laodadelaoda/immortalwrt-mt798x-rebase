#!/usr/bin/env python3
"""Inventory and attest the exact OpenWrt Linux 6.12.112 kernel source inputs."""
import argparse, csv, hashlib, json, re, subprocess, sys
from collections import defaultdict
from pathlib import Path

PATCH_DIRS = [
    "target/linux/generic/backport-6.12",
    "target/linux/generic/pending-6.12",
    "target/linux/generic/hack-6.12",
    "target/linux/mediatek/patches-6.12",
]
OVERLAY_DIRS = [
    "target/linux/generic/files",
    "target/linux/generic/files-6.12",
    "target/linux/mediatek/files",
    "target/linux/mediatek/files-6.12",
]
VERSION_FILE = "target/linux/generic/kernel-6.12"
SEMANTIC = [
    ("999-net-01-netdevice-add-macvlan-device-path-type.patch", "999-net-02-netdevice-add-dslite-device-path-type.patch", "DS-Lite enum context follows MACVLAN enum addition"),
    ("999-net-02-netdevice-add-dslite-device-path-type.patch", "999-net-03-netdevice-add-tnl-device-path-type.patch", "TNL enum context includes DS-Lite and 6RD entries"),
    ("999-net-02-netdevice-add-npu-device-path-type.patch", "999-net-03-netdevice-add-tnl-device-path-type.patch", "TNL enum hunk must preserve the NPU-added L2TP/PPTP entries after MTK_WDMA"),
    ("999-hnat-03-netfilter-nf_flow_table-support-hw-offload-through-v.patch", "999-hnat-04-net-8021q-support-hardware-flow-table-offload.patch", "VLAN ndo_flow_offload_check consumes flow_offload_hw_path introduced by HNAT base patch"),
    ("999-hnat-03-netfilter-nf_flow_table-support-hw-offload-through-v.patch", "999-hnat-05-net-bridge-support-hardware-flow-table-offload.patch", "Bridge ndo_flow_offload_check consumes flow_offload_hw_path introduced by HNAT base patch"),
    ("999-hnat-03-netfilter-nf_flow_table-support-hw-offload-through-v.patch", "999-hnat-06-net-pppoe-support-hardware-flow-table-offload.patch", "PPP/PPPoE flow-offload callbacks extend the HNAT base API"),
    ("999-hnat-03-netfilter-nf_flow_table-support-hw-offload-through-v.patch", "999-hnat-13-netdevice-add-ndo_flow_offload_stats64_add-for-offload-stats-correction.patch", "net_device_ops extension is based on ndo_flow_offload_check introduced by HNAT base patch"),
    ("999-hnat-13-netdevice-add-ndo_flow_offload_stats64_add-for-offload-stats-correction.patch", "999-hnat-14-net-vlan-add-ndo_flow_offload_stats64_add-for-offload-stats-correction.patch", "VLAN statistics callback initializes the ndo field introduced by net-04; source dependency is cross-file"),
    ("999-hnat-13-netdevice-add-ndo_flow_offload_stats64_add-for-offload-stats-correction.patch", "999-hnat-15-ppp-add-ndo_flow_offload_stats64_add-for-offload-stats-correction.patch", "PPP statistics callback initializes the ndo field introduced by net-04; source dependency is cross-file"),
    ("999-hnat-03-netfilter-nf_flow_table-support-hw-offload-through-v.patch", "999-tnl-01-mtk-tunnel-offload-support.patch", "Tunnel patch extends flow_offload_hw_path introduced by HNAT base patch"),
    ("999-net-03-netdevice-add-tnl-device-path-type.patch", "999-tnl-02-mtk-gre-offload-support.patch", "GRE callback sets BIT(DEV_PATH_TNL)"),
    ("999-tnl-01-mtk-tunnel-offload-support.patch", "999-tnl-02-mtk-gre-offload-support.patch", "GRE callback uses FLOW_OFFLOAD_TNL_GRETAP"),
    ("999-net-03-netdevice-add-tnl-device-path-type.patch", "999-tnl-04-mtk-vxlan-offload-support.patch", "VXLAN callback sets BIT(DEV_PATH_TNL)"),
    ("999-tnl-01-mtk-tunnel-offload-support.patch", "999-tnl-04-mtk-vxlan-offload-support.patch", "VXLAN callback uses FLOW_OFFLOAD_TNL_VXLAN"),
    ("999-hnat-06-net-pppoe-support-hardware-flow-table-offload.patch", "999-tnl-03-mtk-ppp-offload-support.patch", "PPP socket API patch extends ppp_generic and ppp_channel.h after HNAT PPP callbacks"),
    ("999-hnat-06-net-pppoe-support-hardware-flow-table-offload.patch", "999-tnl-90-mtk-l2tp-offload-support.patch", "L2TP PPP channel callback uses flow_offload_check member introduced by HNAT PPP patch"),
    ("999-hnat-06-net-pppoe-support-hardware-flow-table-offload.patch", "999-tnl-91-mtk-pptp-offload-support.patch", "PPTP PPP channel callback uses flow_offload_check member introduced by HNAT PPP patch"),
    ("999-dsa-02-add-mt7531-netlink-support.patch", "999-dsa-09-harden-mt7530-netlink-lifecycle-and-bounds.patch", "MT7530 hardening patch modifies Netlink files created by DSA base patch"),
    ("999-dsa-03-add-an8855-netlink-support.patch", "999-dsa-10-harden-an8855-netlink-and-procfs-lifecycle.patch", "AN8855 hardening patch modifies Netlink files created by DSA base patch"),
    ("622-v6.18-ppp-remove-rwlock-usage.patch", "999-hnat-06-net-pppoe-support-hardware-flow-table-offload.patch", "HNAT PPP callback traverses the PPP channel list after the v6.18 PPP locking backport"),
    ("622-v6.18-ppp-remove-rwlock-usage.patch", "999-tnl-03-mtk-ppp-offload-support.patch", "PPP socket lookup must follow the post-backport PPP channel list locking/lifetime model"),
    ("623-v6.18-pppoe-remove-rwlock-usage.patch", "999-hnat-06-net-pppoe-support-hardware-flow-table-offload.patch", "HNAT PPPoE callback is applied after PPPoE socket-locking backport"),
    ("624-v6.18-pppoe-drop-sock-reference-counting-on-fast-path.patch", "999-hnat-06-net-pppoe-support-hardware-flow-table-offload.patch", "HNAT PPPoE callback is applied after the PPPoE RCU fast-path backport"),
    ("611-pcie-mediatek-gen3-PERST-for-100ms.patch", "999-pcie-02-pcie-mediatek-gen3-Add-PCIe-IRQ-affinity-support.patch", "IRQ-affinity patch extends the PCIe startup path after PERST sequencing change"),
    ("966-pcie-mediatek-gen3-Add-WIFI-HW-reset-flow.patch", "999-pcie-02-pcie-mediatek-gen3-Add-PCIe-IRQ-affinity-support.patch", "IRQ-affinity patch extends the PCIe controller structure after WiFi reset fields"),
    ("999-pcie-01-pcie-mediatek-gen3-Add-PCIe-max-link-width-adjustment.patch", "999-pcie-02-pcie-mediatek-gen3-Add-PCIe-IRQ-affinity-support.patch", "IRQ-affinity patch applies after max-link-width controller field addition"),
    ("999-pcie-02-pcie-mediatek-gen3-Add-PCIe-IRQ-affinity-support.patch", "999-pcie-03-pcie-mediatek-gen3-adjust-WIFI-HW-reset-flow.patch", "WiFi reset revision consumes IRQ-affinity controller structure layout"),
    ("999-pcie-02-pcie-mediatek-gen3-Add-PCIe-IRQ-affinity-support.patch", "999-pcie-04-pcie-mediatek-gen3-Add-soft-off-and-soft-on-API.patch", "Soft off/on API consumes IRQ save/restore and MSI group state introduced by IRQ-affinity patch"),
    ("999-net-02-netdevice-add-npu-device-path-type.patch", "999-tnl-07-l2tp-add-fill-forward-path.patch", "L2TP callback uses DEV_PATH_L2TP and net_device_path.tunnel"),
    ("999-net-02-netdevice-add-npu-device-path-type.patch", "999-tnl-08-pptp-add-fill-forward-path.patch", "PPTP callback uses DEV_PATH_PPTP and net_device_path.tunnel"),
    ("999-net-02-netdevice-add-npu-device-path-type.patch", "999-ppe-41-nft_flow_offload-add-npu-offload-support.patch", "nft flow path consumes NPU tunnel path fields"),
    ("999-hnat-03-netfilter-nf_flow_table-support-hw-offload-through-v.patch", "999-tnl-90-mtk-l2tp-offload-support.patch", "L2TP flow_offload_check uses flow_offload_hw_path"),
    ("999-hnat-03-netfilter-nf_flow_table-support-hw-offload-through-v.patch", "999-tnl-91-mtk-pptp-offload-support.patch", "PPTP flow_offload_check uses flow_offload_hw_path"),
    ("999-net-03-netdevice-add-tnl-device-path-type.patch", "999-tnl-90-mtk-l2tp-offload-support.patch", "L2TP check sets BIT(DEV_PATH_TNL)"),
    ("999-net-03-netdevice-add-tnl-device-path-type.patch", "999-tnl-91-mtk-pptp-offload-support.patch", "PPTP check sets BIT(DEV_PATH_TNL)"),
    ("999-tnl-01-mtk-tunnel-offload-support.patch", "999-tnl-90-mtk-l2tp-offload-support.patch", "L2TP check uses FLOW_OFFLOAD_TNL_L2TP_V2"),
    ("999-tnl-01-mtk-tunnel-offload-support.patch", "999-tnl-91-mtk-pptp-offload-support.patch", "PPTP check uses FLOW_OFFLOAD_TNL_PPTP"),
    ("999-tnl-07-l2tp-add-fill-forward-path.patch", "999-tnl-90-mtk-l2tp-offload-support.patch", "Both extend net/l2tp/l2tp_ppp.c in this order"),
    ("999-tnl-08-pptp-add-fill-forward-path.patch", "999-tnl-91-mtk-pptp-offload-support.patch", "Both extend drivers/net/ppp/pptp.c in this order"),
    ("999-ppe-40-netfilter-add-npu-flow-offload-support.patch", "999-ppe-41-nft_flow_offload-add-npu-offload-support.patch", "nft patch populates NPU tuple fields introduced by flow-table patch"),
    ("999-ppe-40-netfilter-add-npu-flow-offload-support.patch", "999-ppe-42-mtk_ppe-add-npu-offload-support.patch", "PPE driver consumes NPU action and tuple fields"),
    ("999-ppe-41-nft_flow_offload-add-npu-offload-support.patch", "999-ppe-42-mtk_ppe-add-npu-offload-support.patch", "PPE driver consumes the NPU action data path"),
    ("999-eth-46-mtk_eth_soc-add-tnl-offload-support.patch", "999-ppe-42-mtk_ppe-add-npu-offload-support.patch", "PPE NPU path uses TPORT_NPU_* definitions"),
    ("736-04-net-ethernet-mediatek-fix-ppe-flow-accounting-for-L2.patch", "999-ppe-02-mtk_ppe-change-to-internal-ppe-debugfs.patch", "PPE debugfs patch extends the PPE implementation after generic L2 flow-accounting changes"),
    ("736-05-net-ethernet-mtk_eth_soc-zero-initialize-PPE-flow-ta.patch", "999-ppe-02-mtk_ppe-change-to-internal-ppe-debugfs.patch", "PPE debugfs implementation follows the generic PPE flow-table initialization change"),
    ("999-ppe-02-mtk_ppe-change-to-internal-ppe-debugfs.patch", "999-ppe-20-mtk_ppe-add-adaptive-PPPQ-mode.patch", "Adaptive PPPQ extends the QoS debugfs interface introduced by the base PPE debugfs patch"),
    ("999-ppe-04-mtk_ppe-change-to-internal-QoS-mode.patch", "999-ppe-20-mtk_ppe-add-adaptive-PPPQ-mode.patch", "Adaptive PPPQ consumes qos_toggle and QDMA shaper state introduced by the QoS patch"),
    ("999-ppe-11-mtk_ppe-dispatch-short-packets-a-high-priority.patch", "999-ppe-20-mtk_ppe-add-adaptive-PPPQ-mode.patch", "Adaptive PPPQ calls the queue getter exported by the short-packet priority patch"),
    ("999-ppe-14-mtk_ppe-add-PPE-cache-preserved-line-lock.patch", "999-ppe-20-mtk_ppe-add-adaptive-PPPQ-mode.patch", "Adaptive PPPQ refcount release uses the FOE state captured by the cache-preserved clear patch"),
]

def digest(data):
    return hashlib.sha256(data).hexdigest()

def head(repo):
    return subprocess.check_output(["git", "-C", str(repo), "rev-parse", "HEAD"], text=True).strip()

def targets(text):
    out = set()
    for line in text.splitlines():
        if line.startswith("diff --git "):
            m = re.match(r"diff --git a/(.+?) b/(.+)$", line)
            if m: out.update((m.group(1), m.group(2)))
        elif line.startswith("Index: "):
            # Quilt-style patches use Index: and versioned ---/+++ headers.
            value = line[len("Index: "):].strip()
            value = re.sub(r"^linux-[^/]+/", "", value)
            if value and value != "/dev/null": out.add(value)
        elif line.startswith(("--- ", "+++ ")):
            value = line[4:].split("\t", 1)[0].split(" ", 1)[0]
            if value.startswith(("a/", "b/")): out.add(value[2:])
            elif re.match(r"^linux-[^/]+(?:\.orig)?/", value):
                out.add(re.sub(r"^linux-[^/]+(?:\.orig)?/", "", value))
    return sorted(x for x in out if x and x != "/dev/null")

def hunk_metadata_errors(text):
    """Validate declared unified-diff old/new line counts before patching."""
    lines = text.splitlines()
    errors = []
    for index, header in enumerate(lines):
        if not header.startswith("@@"):
            continue
        match = re.match(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@", header)
        if not match:
            errors.append({"line": index + 1, "header": header, "error": "malformed unified-diff hunk header"})
            continue
        declared_old = int(match.group(2) or 1)
        declared_new = int(match.group(4) or 1)
        actual_old = actual_new = 0
        for body in lines[index + 1:]:
            if body == "-- " or body.startswith("@@") or body.startswith("diff --git ") or body.startswith("Index: ") or body.startswith(("--- a/", "--- /dev/null")):
                break
            if actual_old == declared_old and actual_new == declared_new:
                break
            if body == "":
                actual_old += 1
                actual_new += 1
            elif body.startswith(" "):
                actual_old += 1
                actual_new += 1
            elif body.startswith("-"):
                actual_old += 1
            elif body.startswith("+"):
                actual_new += 1
            elif body.startswith("\\"):
                continue
            else:
                errors.append({"line": index + 1, "header": header, "error": "invalid line inside unified-diff hunk", "content": body[:120]})
                break
        if (actual_old, actual_new) != (declared_old, declared_new):
            errors.append({
                "line": index + 1, "header": header,
                "declared_old": declared_old, "actual_old": actual_old,
                "declared_new": declared_new, "actual_new": actual_new,
                "error": "unified-diff hunk line-count mismatch",
            })
    return errors

def vendor_inventory(repo):
    """Inventory every active fixed-vendor patch from the canonical source Lock."""
    lock_path = repo / "package/mtk/vendor-sources.lock.json"
    lock_raw = lock_path.read_bytes()
    lock = json.loads(lock_raw)
    sources_by_set = defaultdict(list)
    for source in lock.get("sources", []):
        if source.get("patch_set"):
            sources_by_set[source["patch_set"]].append(source)

    patches = []
    patch_sets = []
    overlaps = defaultdict(list)
    for set_order, patch_set in enumerate(lock.get("patch_sets", []), 1):
        set_id = patch_set["id"]
        directory = patch_set["directory"]
        directory_path = repo / directory
        if not directory_path.is_dir():
            raise RuntimeError("Missing vendor patch directory: " + directory)
        phases = [
            ("application", patch_set.get("application_order", [])),
            ("post_normalize", patch_set.get("post_normalize_order", [])),
        ]
        ordered_names = [name for _, names in phases for name in names]
        actual_names = sorted(p.name for p in directory_path.iterdir()
                              if p.is_file() and p.suffix.lower() in (".patch", ".diff"))
        if sorted(ordered_names) != actual_names:
            raise RuntimeError(
                f"Vendor patch inventory differs from Lock for {set_id}: "
                f"unlisted={sorted(set(actual_names)-set(ordered_names))}; "
                f"missing={sorted(set(ordered_names)-set(actual_names))}"
            )

        set_sources = sources_by_set.get(set_id, [])
        if not set_sources:
            raise RuntimeError("Vendor patch set has no owning source declaration: " + set_id)
        owners = sorted({s["package_makefile"] for s in set_sources})
        if len(owners) != 1:
            raise RuntimeError("Vendor patch set maps to multiple package owners: " + set_id)

        sequence = 0
        for phase, names in phases:
            for name in names:
                sequence += 1
                patch_path = directory_path / name
                raw = patch_path.read_bytes()
                txt = raw.decode("utf-8", errors="replace")
                audit_only = all(s.get("source_scope") == "auxiliary-audit-only" for s in set_sources)
                root_suffix = ""
                if phase == "post_normalize":
                    roots = patch_set.get("post_normalize_root_suffixes", {})
                    if set(roots) != set(patch_set.get("post_normalize_order", [])):
                        raise RuntimeError("Post-normalize application roots are incomplete in vendor Lock: " + set_id)
                    root_suffix = roots[name]
                application_root = "audit-only" if audit_only else (
                    "PKG_BUILD_DIR" + ("/" + root_suffix if root_suffix else "")
                )
                target_files = targets(txt)
                target_records = []
                target_owners = []
                for target in target_files:
                    matched = None
                    if root_suffix:
                        matched = next((s for s in set_sources if s.get("extract_root") == root_suffix), None)
                    else:
                        matched = next((s for s in set_sources
                                        if target == s.get("extract_root")
                                        or target.startswith(str(s.get("extract_root", "")) + "/")), None)
                    if matched is None and len(set_sources) == 1:
                        matched = set_sources[0]
                    if matched is None and audit_only:
                        matched = next((s for s in set_sources
                                        if s["id"].split("_")[0] in name.lower()), None)
                    if matched is None:
                        raise RuntimeError(
                            f"Cannot resolve vendor patch target ownership: {patch_path.relative_to(repo)} -> {target}"
                        )
                    normalized = (root_suffix + "/" + target) if root_suffix else target
                    target_records.append(normalized)
                    target_owners.append({"target_file": normalized, "source_id": matched["id"]})
                    overlaps[(matched["id"], normalized)].append({
                        "path": patch_path.relative_to(repo).as_posix(),
                        "patch_set_id": set_id, "directory": directory,
                        "patch_set_order": set_order, "sequence": sequence, "phase": phase,
                    })
                source_ids = sorted({x["source_id"] for x in target_owners})
                item = {
                    "scope": "fixed-vendor-package",
                    "patch_set_id": set_id,
                    "patch_set_order": set_order,
                    "sequence": sequence,
                    "phase": phase,
                    "path": patch_path.relative_to(repo).as_posix(),
                    "name": name,
                    "sha256": digest(raw),
                    "bytes": len(raw),
                    "hunks": len(re.findall(r"^@@", txt, re.M)),
                    "hunk_metadata_errors": hunk_metadata_errors(txt),
                    "target_files": target_records,
                    "target_owners": target_owners,
                    "source_ids": source_ids,
                    "package_makefile": owners[0],
                    "source_archives": [
                        {"id": s["id"], "archive": s["archive"], "sha256": s["sha256"],
                         "source_scope": s.get("source_scope"),
                         "build_dir": s.get("expected_build_dir"),
                         "extract_root": s.get("extract_root")}
                        for s in set_sources if s["id"] in source_ids
                    ],
                    "application_root": application_root,
                    "application_mode": "audit-only" if audit_only else "native-Build-Prepare",
                }
                patches.append(item)
        patch_sets.append({
            "id": set_id, "directory": directory, "order": set_order,
            "package_makefile": owners[0],
            "source_ids": [s["id"] for s in set_sources],
            "application_order": patch_set.get("application_order", []),
            "post_normalize_order": patch_set.get("post_normalize_order", []),
            "post_normalize_root_suffixes": patch_set.get("post_normalize_root_suffixes", {}),
            "scope": patch_set.get("scope", ""),
        })

    overlap_matrix = {
        f"{source_id}:{target}": [x["path"] for x in sorted(items, key=lambda x: (x["patch_set_order"], x["sequence"]))]
        for (source_id, target), items in sorted(overlaps.items()) if len(items) > 1
    }
    overlap_edges = []
    cross_directory_edges = []
    cross_directory_matrix = {}
    for (source_id, target), items in sorted(overlaps.items()):
        ordered = sorted(items, key=lambda x: (x["patch_set_order"], x["sequence"]))
        if len({x["directory"] for x in ordered}) > 1:
            cross_directory_matrix[f"{source_id}:{target}"] = [x["path"] for x in ordered]
        for previous, following in zip(ordered, ordered[1:]):
            edge = {
                "source_id": source_id, "target_file": target,
                "previous_patch": previous["path"], "next_patch": following["path"],
                "previous_patch_set": previous["patch_set_id"], "next_patch_set": following["patch_set_id"],
                "previous_directory": previous["directory"], "next_directory": following["directory"],
                "previous_order": previous["sequence"], "next_order": following["sequence"],
                "dependency_basis": "same-source-same-file-application-order",
            }
            overlap_edges.append(edge)
            if previous["directory"] != following["directory"]:
                cross_directory_edges.append(edge)
    return {
        "release": lock.get("release"),
        "lock_path": lock_path.relative_to(repo).as_posix(),
        "lock_sha256": digest(lock_raw),
        "sources": lock.get("sources", []),
        "patch_sets": patch_sets,
        "patches": patches,
        "patch_count": len(patches),
        "patch_hunk_count": sum(p["hunks"] for p in patches),
        "patch_manifest_sha256": digest(json.dumps(patches, sort_keys=True, separators=(",", ":")).encode()),
        "file_overlap_matrix": overlap_matrix,
        "file_overlap_edges": overlap_edges,
        "cross_directory_overlap_matrix": cross_directory_matrix,
        "cross_directory_overlap_edges": cross_directory_edges,
        "duplicate_patch_content": [
            paths for paths in _groups([p["sha256"] for p in patches], [p["path"] for p in patches]).values()
            if len(paths) > 1
        ],
    }

def inventory(repo):
    patches = []
    for di, rel in enumerate(PATCH_DIRS, 1):
        d = repo / rel
        if not d.is_dir(): raise RuntimeError("Missing patch directory: " + rel)
        for p in sorted((x for x in d.iterdir() if x.is_file() and not x.name.startswith(".")), key=lambda x: x.name):
            raw = p.read_bytes()
            txt = raw.decode("utf-8", errors="replace")
            patches.append({
                "order": len(patches) + 1, "directory_order": di, "directory": rel,
                "name": p.name, "path": p.relative_to(repo).as_posix(),
                "sha256": digest(raw), "bytes": len(raw),
                "hunks": len(re.findall(r"^@@", txt, re.M)), "hunk_metadata_errors": hunk_metadata_errors(txt), "target_files": targets(txt),
                "line_endings": "mixed" if b"\r\n" in raw and re.search(rb"(?<!\r)\n", raw) else ("crlf" if b"\r\n" in raw else "lf"),
            })
    vendor = vendor_inventory(repo)
    overlays = []
    overlay_targets = defaultdict(list)
    for di, rel in enumerate(OVERLAY_DIRS, 1):
        d = repo / rel
        if not d.is_dir(): continue
        for p in sorted((x for x in d.rglob("*") if x.is_file()), key=lambda x: x.relative_to(d).as_posix()):
            item = {"directory_order": di, "directory": rel, "source_path": p.relative_to(repo).as_posix(),
                    "target_path": p.relative_to(d).as_posix(), "sha256": digest(p.read_bytes()), "bytes": p.stat().st_size}
            overlays.append(item); overlay_targets[item["target_path"]].append(item["source_path"])
    by_target = defaultdict(list)
    for p in patches:
        for target in p["target_files"]: by_target[target].append(p)
    overlap = {target: [p["path"] for p in ps] for target, ps in sorted(by_target.items()) if len(ps) > 1}
    edges = []
    cross_directory_edges = []
    cross_directory_matrix = {}
    for target, ps in sorted(by_target.items()):
        if len({p["directory"] for p in ps}) > 1:
            cross_directory_matrix[target] = [p["path"] for p in ps]
        for a, b in zip(ps, ps[1:]):
            edge = {"target_file": target, "previous_patch": a["path"], "next_patch": b["path"],
                    "previous_directory": a["directory"], "next_directory": b["directory"],
                    "previous_order": a["order"], "next_order": b["order"],
                    "dependency_basis": "same-kernel-source-same-file-application-order"}
            edges.append(edge)
            if a["directory"] != b["directory"]:
                cross_directory_edges.append(edge)
    empty_targets = [p["path"] for p in patches if not p["target_files"]]
    if empty_targets: raise RuntimeError("Patch target parser left files unclassified: " + ", ".join(empty_targets))
    name_groups = _groups([p["name"] for p in patches], [p["path"] for p in patches])
    duplicate_names = sorted(n for n, paths in name_groups.items() if len(paths) > 1)
    if duplicate_names: raise RuntimeError("Duplicate patch basenames make dependency references ambiguous: " + ", ".join(duplicate_names))
    names = {p["name"] for p in patches}
    order = {p["name"]: p["order"] for p in patches}
    semantic = [{"prerequisite": a, "consumer": b, "reason": why, "prerequisite_order": order[a], "consumer_order": order[b], "prerequisite_applied_before_consumer": order[a] < order[b]} for a, b, why in SEMANTIC if a in names and b in names]
    missing = [{"prerequisite": a, "consumer": b} for a, b, _ in SEMANTIC if a not in names or b not in names]
    version_text = (repo / VERSION_FILE).read_text()
    vm = re.search(r"LINUX_VERSION-6\.12\s*=\s*\.([0-9]+)", version_text)
    hm = re.search(r"LINUX_KERNEL_HASH-6\.12\.([0-9]+)\s*=\s*([0-9a-f]{64})", version_text)
    if not vm or not hm: raise RuntimeError("Cannot parse pinned kernel version/archive hash")
    if vm.group(1) != hm.group(1): raise RuntimeError("Kernel version and archive hash suffix differ")
    kernel = "6.12." + vm.group(1)
    patch_sha = digest(json.dumps(patches, sort_keys=True, separators=(",", ":")).encode())
    overlay_sha = digest(json.dumps(overlays, sort_keys=True, separators=(",", ":")).encode())
    core = {"kernel_version": kernel, "kernel_archive_sha256": hm.group(2),
            "patch_directories_in_application_order": PATCH_DIRS, "overlay_directories_in_application_order": OVERLAY_DIRS,
            "patches": patches, "vendor": vendor, "overlays": overlays,
            "file_overlap_matrix": overlap, "cross_directory_overlap_matrix": cross_directory_matrix,
            "vendor_cross_directory_overlap_matrix": vendor["cross_directory_overlap_matrix"],
            "semantic_dependencies": semantic}
    all_patch_records = patches + vendor["patches"]
    repository_duplicate_patch_content = [
        group for group in _groups([p["sha256"] for p in all_patch_records],
                                   [p["path"] for p in all_patch_records]).values()
        if len(group) > 1
    ]
    return {
        "schema_version": 1, "kernel_version": kernel, "kernel_archive_sha256": hm.group(2),
        "patch_directories_in_application_order": PATCH_DIRS, "overlay_directories_in_application_order": OVERLAY_DIRS,
        "patch_count": len(patches), "patch_hunk_count": sum(p["hunks"] for p in patches), "overlay_file_count": len(overlays), "patch_manifest_sha256": patch_sha,
        "overlay_manifest_sha256": overlay_sha, "input_manifest_sha256": digest(json.dumps(core, sort_keys=True, separators=(",", ":")).encode()),
        "patches": patches, "vendor": vendor, "repository_patch_count": len(patches) + vendor["patch_count"],
        "repository_patch_hunk_count": sum(p["hunks"] for p in patches) + vendor["patch_hunk_count"],
        "cross_directory_dependency_count": len(cross_directory_edges) + len(vendor["cross_directory_overlap_edges"]),
        "repository_duplicate_patch_content": repository_duplicate_patch_content,
        "repository_patch_manifest_sha256": digest(json.dumps({"kernel": patches, "vendor": vendor["patches"], "vendor_lock_sha256": vendor["lock_sha256"]}, sort_keys=True, separators=(",", ":")).encode()),
        "overlays": overlays, "file_overlap_matrix": overlap, "file_overlap_edges": edges,
        "cross_directory_overlap_matrix": cross_directory_matrix,
        "cross_directory_overlap_edges": cross_directory_edges,
        "overlay_collision_matrix": {k:v for k,v in sorted(overlay_targets.items()) if len(v)>1},
        "semantic_dependencies": semantic, "missing_semantic_dependencies": missing,
        "semantic_dependency_order_violations": [x for x in semantic if not x["prerequisite_applied_before_consumer"]],
        "duplicate_patch_content": [v for v in _groups([p["sha256"] for p in patches], [p["path"] for p in patches]).values() if len(v)>1],
    }

def validate_inventory(inv):
    """Fail closed on malformed hunk counts and missing/out-of-order prerequisites."""
    malformed = [(p["path"], e) for p in (inv["patches"] + inv.get("vendor", {}).get("patches", [])) for e in p.get("hunk_metadata_errors", [])]
    if malformed:
        details = "; ".join(f"{path}: line {err['line']}: {err['error']} ({err.get('header', '')})" for path, err in malformed[:20])
        raise RuntimeError("Unified-diff hunk metadata validation failed: " + details)
    missing = inv.get("missing_semantic_dependencies", [])
    violations = inv.get("semantic_dependency_order_violations", [])
    if missing:
        details = ", ".join(
            f"{x['prerequisite']} -> {x['consumer']}" for x in missing
        )
        raise RuntimeError("Missing curated semantic dependency patch(es): " + details)
    if violations:
        details = ", ".join(
            f"{x['prerequisite']} (order {x['prerequisite_order']}) -> "
            f"{x['consumer']} (order {x['consumer_order']})"
            for x in violations
        )
        raise RuntimeError("Semantic dependency order violation(s): " + details)

def _groups(keys, values):
    d = defaultdict(list)
    for k, v in zip(keys, values): d[k].append(v)
    return d

def write_inventory(inv, out):
    out.mkdir(parents=True, exist_ok=True)
    (out / "patch-inventory.json").write_text(json.dumps(inv, indent=2) + "\n")
    repository_manifest = {
        "schema_version": 1,
        "repository_head_sha": head(out.parent if out.name == "kernel-patch-audit" else out),
        "kernel": {
            "version": inv["kernel_version"], "archive_sha256": inv["kernel_archive_sha256"],
            "patch_directories_in_application_order": inv["patch_directories_in_application_order"],
            "patches": inv["patches"], "file_overlap_matrix": inv["file_overlap_matrix"],
            "same_file_dependency_edges": inv["file_overlap_edges"],
            "cross_directory_overlap_matrix": inv["cross_directory_overlap_matrix"],
            "cross_directory_dependency_edges": inv["cross_directory_overlap_edges"],
            "semantic_dependencies": inv["semantic_dependencies"],
        },
        "fixed_vendor": inv["vendor"],
        "cross_directory_dependency_count": inv["cross_directory_dependency_count"],
        "repository_duplicate_patch_content": inv["repository_duplicate_patch_content"],
        "overlays": inv["overlays"],
        "repository_patch_count": inv["repository_patch_count"],
        "repository_patch_hunk_count": inv["repository_patch_hunk_count"],
        "repository_patch_manifest_sha256": inv["repository_patch_manifest_sha256"],
        "input_manifest_sha256": inv["input_manifest_sha256"],
    }
    (out / "repository-patch-manifest.json").write_text(json.dumps(repository_manifest, indent=2) + "\n")
    for filename, rows, fields in [
        ("file-overlap-dependencies.csv", inv["file_overlap_edges"], ["target_file","previous_patch","next_patch","previous_order","next_order"]),
        ("vendor-file-overlap-dependencies.csv", inv["vendor"]["file_overlap_edges"], ["source_id","target_file","previous_patch","next_patch","previous_patch_set","next_patch_set","previous_directory","next_directory","previous_order","next_order","dependency_basis"]),
        ("cross-directory-dependencies.csv", inv["cross_directory_overlap_edges"], ["target_file","previous_patch","next_patch","previous_directory","next_directory","previous_order","next_order","dependency_basis"]),
        ("vendor-cross-directory-dependencies.csv", inv["vendor"]["cross_directory_overlap_edges"], ["source_id","target_file","previous_patch","next_patch","previous_patch_set","next_patch_set","previous_directory","next_directory","previous_order","next_order","dependency_basis"]),
        ("overlay-inventory.csv", inv["overlays"], ["directory_order","directory","source_path","target_path","sha256","bytes"]),
        ("semantic-dependencies.csv", inv["semantic_dependencies"], ["prerequisite","consumer","reason","prerequisite_order","consumer_order","prerequisite_applied_before_consumer"]),
    ]:
        with (out / filename).open("w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=fields); w.writeheader(); w.writerows(rows)
    (out / "README.md").write_text(
        "# Linux 6.12.112 patch-stack inventory\n\n"
        f"- Ordered Linux kernel patches: {inv['patch_count']} ({inv['patch_hunk_count']} hunks)\n"
        f"- Fixed vendor package patches: {inv['vendor']['patch_count']} ({inv['vendor']['patch_hunk_count']} hunks)\n"
        f"- Unified repository patch inputs: {inv['repository_patch_count']} ({inv['repository_patch_hunk_count']} hunks)\n"
        f"- Pre-patch overlay files: {inv['overlay_file_count']}\n"
        f"- Kernel same-file dependency edges: {len(inv['file_overlap_edges'])}\n"
        f"- Vendor same-file dependency edges: {len(inv['vendor']['file_overlap_edges'])}\n"
        f"- Cross-directory same-source dependency edges: {inv['cross_directory_dependency_count']}\n"
        f"- Exact duplicate patch-content groups: {len(inv['repository_duplicate_patch_content'])}\n"
        f"- Curated semantic dependency edges: {len(inv['semantic_dependencies'])}\n"
        f"- Patch manifest SHA256: {inv['patch_manifest_sha256']}\n"
        f"- Overlay manifest SHA256: {inv['overlay_manifest_sha256']}\n"
        f"- Combined input manifest SHA256: {inv['input_manifest_sha256']}\n\n"
        "Application order:\n" + "\n".join(f"{i}. {d}" for i,d in enumerate(PATCH_DIRS,1)) +
        "\n\nThe attestation is generated only after the actual OpenWrt target/linux/prepare succeeds with zero fuzz and no reject/original files.\n"
    )

def validate_patch_application_log(inv, log, repo):
    """Verify every locked patch was applied forward, without fuzz or skipped hunks."""
    matches = list(re.finditer(r"^Applying (.+?) using [^:]+:[ \t]*$", log, re.M))
    expected = [p["path"] for p in inv["patches"]]
    if len(matches) != len(expected):
        raise RuntimeError(
            f"Applied patch invocation count mismatch: expected {len(expected)}, observed {len(matches)}"
        )

    observed = []
    blocks = []
    for i, match in enumerate(matches):
        raw_path = match.group(1).strip()
        path = Path(raw_path)
        if not path.is_absolute():
            path = repo / path
        try:
            relative = path.resolve().relative_to(repo.resolve()).as_posix()
        except ValueError:
            raise RuntimeError("Patch invocation escapes repository: " + raw_path)
        observed.append(relative)
        end = matches[i + 1].start() if i + 1 < len(matches) else len(log)
        blocks.append(log[match.end():end])

    if observed != expected:
        for i, (got, want) in enumerate(zip(observed, expected), 1):
            if got != want:
                raise RuntimeError(
                    f"Applied patch path/order mismatch at {i}: observed {got}, expected {want}"
                )
        raise RuntimeError(
            f"Applied patch path/order mismatch: expected {len(expected)}, observed {len(observed)}"
        )

    total = 0
    for patch, block in zip(inv["patches"], blocks):
        name = patch["path"]
        if re.search(
            r"Skipping patch|Reversed \(or previously applied\)|Ignoring previously applied",
            block, re.I
        ):
            raise RuntimeError("Patch was skipped or treated as already applied: " + name)
        if re.search(r"Hunk #\d+ FAILED|malformed patch|can't find file to patch", block, re.I):
            raise RuntimeError("Patch contains a failed/malformed hunk: " + name)
        if re.search(r"with fuzz [1-9]|fuzz [1-9]", block, re.I):
            raise RuntimeError("Patch used non-zero fuzz: " + name)
        succeeded = re.findall(
            r"^Hunk #\d+ succeeded at \d+(?: .*)?\.?$",
            block, re.M
        )
        expected_hunks = patch["hunks"]
        if len(succeeded) != expected_hunks:
            raise RuntimeError(
                f"Patch hunk application count mismatch for {name}: "
                f"expected {expected_hunks}, observed {len(succeeded)}"
            )
        total += len(succeeded)
    return total


def attest(repo, out, kernel_src, log_path, archive, run_id, attempt):
    inv = json.loads((out / "patch-inventory.json").read_text())
    validate_inventory(inv)
    archive_sha = digest(archive.read_bytes())
    if archive_sha != inv["kernel_archive_sha256"]: raise RuntimeError("Downloaded kernel archive SHA256 differs from the repository pin")
    raw = log_path.read_bytes(); log = raw.decode("utf-8", errors="replace")
    applied_hunks = validate_patch_application_log(inv, log, repo)
    expected_hunks = sum(p["hunks"] for p in inv["patches"])
    if applied_hunks != expected_hunks:
        raise RuntimeError(f"Applied hunk total mismatch: expected {expected_hunks}, observed {applied_hunks}")
    mk = (kernel_src / "Makefile").read_text(errors="replace")
    for key, val in (("VERSION","6"),("PATCHLEVEL","12"),("SUBLEVEL","112")):
        if not re.search(rf"^{key}\s*=\s*{val}\s*$", mk, re.M): raise RuntimeError("Prepared kernel source is not Linux 6.12.112")
    rejects = list(kernel_src.rglob("*.rej")) + list(kernel_src.rglob("*.orig"))
    if rejects: raise RuntimeError("Reject/original files remain after patching: " + ", ".join(str(x) for x in rejects[:10]))
    paths = sorted({x for p in inv["patches"] for x in p["target_files"]} | {x["target_path"] for x in inv["overlays"]})
    state = []
    for rel in paths:
        p = kernel_src / rel
        state.append({"path":rel,"sha256":digest(p.read_bytes()) if p.is_file() else None,"state":"present" if p.is_file() else "absent"})
    att = {
        "schema_version":1,"repository_head_sha":head(repo),"github_run_id":str(run_id),"github_run_attempt":str(attempt),
        "kernel_version":inv["kernel_version"],"kernel_archive_sha256":archive_sha,
        "patch_directories_in_application_order":PATCH_DIRS,"overlay_directories_in_application_order":OVERLAY_DIRS,
        "patch_count":inv["patch_count"],"patch_hunk_count":expected_hunks,"applied_hunk_count":applied_hunks,"patch_manifest_sha256":inv["patch_manifest_sha256"],
        "vendor_lock_sha256":inv["vendor"]["lock_sha256"],"vendor_patch_count":inv["vendor"]["patch_count"],
        "vendor_patch_manifest_sha256":inv["vendor"]["patch_manifest_sha256"],
        "repository_patch_count":inv["repository_patch_count"],
        "repository_patch_manifest_sha256":inv["repository_patch_manifest_sha256"],
        "overlay_manifest_sha256":inv["overlay_manifest_sha256"],"input_manifest_sha256":inv["input_manifest_sha256"],
        "patch_log_sha256":digest(raw),"patched_paths_count":len(state),
        "patched_paths_state_sha256":digest(json.dumps(state,sort_keys=True,separators=(",",":")).encode()),
        "application_result":"PASS_ZERO_FUZZ_NO_SKIP_ALL_HUNKS_NO_REJECTS"
    }
    att["attestation_sha256"] = digest(json.dumps(att,sort_keys=True,separators=(",",":")).encode())
    (out / "kernel-patch-attestation.json").write_text(json.dumps(att,indent=2)+"\n")

def verify(repo, att_path, run_id, attempt):
    att = json.loads(att_path.read_text())
    if att.get("repository_head_sha") != head(repo): raise RuntimeError("Attestation HEAD differs from checked-out revision")
    if att.get("github_run_id") != str(run_id) or att.get("github_run_attempt") != str(attempt): raise RuntimeError("Attestation belongs to another workflow run/attempt")
    inv = inventory(repo)
    validate_inventory(inv)
    for key in ("kernel_version","kernel_archive_sha256","patch_manifest_sha256","overlay_manifest_sha256","input_manifest_sha256","patch_count","patch_hunk_count","vendor_lock_sha256","vendor_patch_count","vendor_patch_manifest_sha256","repository_patch_count","repository_patch_manifest_sha256"):
        if att.get(key) != inv.get(key): raise RuntimeError("Attested source input changed: " + key)
    if att.get("applied_hunk_count") != inv["patch_hunk_count"]:
        raise RuntimeError("Attested applied hunk count differs from the locked patch inventory")
    unsigned = dict(att); signature = unsigned.pop("attestation_sha256", None)
    if signature != digest(json.dumps(unsigned,sort_keys=True,separators=(",",":")).encode()): raise RuntimeError("Attestation digest is invalid")
    if att.get("application_result") != "PASS_ZERO_FUZZ_NO_SKIP_ALL_HUNKS_NO_REJECTS": raise RuntimeError("Kernel patch application was not attested as passing")
    print(f"PASS: Linux {att['kernel_version']}; {att['patch_count']} ordered patches / {att['applied_hunk_count']} hunks; attestation {signature}")

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("command", choices=["inventory","attest","verify"])
    ap.add_argument("--repo", type=Path, default=Path.cwd())
    ap.add_argument("--output-dir", type=Path, default=Path(".kernel-patch-audit"))
    ap.add_argument("--kernel-src", type=Path); ap.add_argument("--patch-log", type=Path)
    ap.add_argument("--kernel-archive", type=Path); ap.add_argument("--attestation", type=Path)
    ap.add_argument("--run-id", default=""); ap.add_argument("--run-attempt", default="")
    a = ap.parse_args(); repo = a.repo.resolve()
    out = a.output_dir if a.output_dir.is_absolute() else repo / a.output_dir
    try:
        if a.command == "inventory":
            inv = inventory(repo); validate_inventory(inv); write_inventory(inv,out)
            print(f"PASS: inventoried {inv['patch_count']} ordered patches and {inv['overlay_file_count']} overlays; input manifest {inv['input_manifest_sha256']}")
        elif a.command == "attest":
            if not all((a.kernel_src,a.patch_log,a.kernel_archive,a.run_id,a.run_attempt)): raise RuntimeError("attest requires kernel source, patch log, archive, run id and attempt")
            attest(repo,out,a.kernel_src.resolve(),a.patch_log.resolve(),a.kernel_archive.resolve(),a.run_id,a.run_attempt)
            print("PASS: immutable kernel patch-stack attestation created")
        else:
            if not all((a.attestation,a.run_id,a.run_attempt)): raise RuntimeError("verify requires attestation, run id and attempt")
            verify(repo,a.attestation.resolve(),a.run_id,a.run_attempt)
        return 0
    except Exception as e:
        print("ERROR: " + str(e), file=sys.stderr); return 1

if __name__ == "__main__":
    sys.exit(main())
