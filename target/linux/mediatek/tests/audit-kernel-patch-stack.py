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

def ordered_patch_files(directory):
    files = {p.name: p for p in directory.iterdir()
             if p.is_file() and p.name != "series" and not p.name.startswith(".")}
    series = directory / "series"
    if not series.is_file() or not series.stat().st_size:
        return [files[name] for name in sorted(files)]
    ordered = []
    for number, raw in enumerate(series.read_text(errors="replace").splitlines(), 1):
        entry = raw.split("#", 1)[0].strip()
        if not entry:
            continue
        for name in entry.split():
            if name not in files:
                raise RuntimeError(f"Patch series {series} line {number} references missing file: {name}")
            ordered.append(files[name])
    if not ordered:
        return [files[name] for name in sorted(files)]
    if len({p.name for p in ordered}) != len(ordered):
        raise RuntimeError("Patch series contains duplicate patch entries: " + str(series))
    return ordered

def inventory(repo):
    patches = []
    for di, rel in enumerate(PATCH_DIRS, 1):
        d = repo / rel
        if not d.is_dir(): raise RuntimeError("Missing patch directory: " + rel)
        for p in ordered_patch_files(d):
            raw = p.read_bytes()
            txt = raw.decode("utf-8", errors="replace")
            patches.append({
                "order": len(patches) + 1, "directory_order": di, "directory": rel,
                "name": p.name, "path": p.relative_to(repo).as_posix(),
                "sha256": digest(raw), "bytes": len(raw),
                "hunks": len(re.findall(r"^@@", txt, re.M)), "target_files": targets(txt),
                "line_endings": "mixed" if b"\r\n" in raw and re.search(rb"(?<!\r)\n", raw) else ("crlf" if b"\r\n" in raw else "lf"),
            })
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
    for target, ps in sorted(by_target.items()):
        for a, b in zip(ps, ps[1:]):
            edges.append({"target_file": target, "previous_patch": a["path"], "next_patch": b["path"],
                          "previous_order": a["order"], "next_order": b["order"]})
    empty_targets = [p["path"] for p in patches if not p["target_files"]]
    if empty_targets: raise RuntimeError("Patch target parser left files unclassified: " + ", ".join(empty_targets))
    name_groups = _groups([p["name"] for p in patches], [p["path"] for p in patches])
    duplicate_names = sorted(n for n, paths in name_groups.items() if len(paths) > 1)
    if duplicate_names: raise RuntimeError("Duplicate patch basenames make dependency references ambiguous: " + ", ".join(duplicate_names))
    names = {p["name"] for p in patches}
    order = {p["name"]: p["order"] for p in patches}
    semantic = [{"prerequisite": a, "consumer": b, "reason": why, "prerequisite_order": order[a], "consumer_order": order[b], "prerequisite_applied_before_consumer": order[a] < order[b]} for a, b, why in SEMANTIC if a in names and b in names]
    missing = [{"prerequisite": a, "consumer": b} for a, b, _ in SEMANTIC if a not in names or b not in names]
    order_violations = [x for x in semantic if not x["prerequisite_applied_before_consumer"]]
    duplicate_content = [v for v in _groups([p["sha256"] for p in patches], [p["path"] for p in patches]).values() if len(v) > 1]
    overlay_collisions = {k: v for k, v in sorted(overlay_targets.items()) if len(v) > 1}
    if missing:
        raise RuntimeError("Semantic dependency references missing patch inputs: " + json.dumps(missing, sort_keys=True))
    if order_violations:
        raise RuntimeError("Semantic dependency order violations: " + json.dumps(order_violations, sort_keys=True))
    if duplicate_content:
        raise RuntimeError("Byte-identical duplicate patch files: " + json.dumps(duplicate_content, sort_keys=True))
    if overlay_collisions:
        raise RuntimeError("Pre-patch overlay target collisions require explicit resolution: " + json.dumps(overlay_collisions, sort_keys=True))
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
            "patches": patches, "overlays": overlays, "file_overlap_matrix": overlap,
            "overlay_collision_matrix": overlay_collisions, "duplicate_patch_content": duplicate_content,
            "semantic_dependencies": semantic, "missing_semantic_dependencies": missing,
            "semantic_dependency_order_violations": order_violations}
    return {
        "schema_version": 2, "kernel_version": kernel, "kernel_archive_sha256": hm.group(2),
        "patch_directories_in_application_order": PATCH_DIRS, "overlay_directories_in_application_order": OVERLAY_DIRS,
        "patch_count": len(patches), "overlay_file_count": len(overlays), "patch_manifest_sha256": patch_sha,
        "overlay_manifest_sha256": overlay_sha, "input_manifest_sha256": digest(json.dumps(core, sort_keys=True, separators=(",", ":")).encode()),
        "patches": patches, "overlays": overlays, "file_overlap_matrix": overlap, "file_overlap_edges": edges,
        "overlay_collision_matrix": overlay_collisions,
        "semantic_dependencies": semantic, "missing_semantic_dependencies": missing,
        "semantic_dependency_order_violations": order_violations,
        "duplicate_patch_content": duplicate_content,
    }

def _groups(keys, values):
    d = defaultdict(list)
    for k, v in zip(keys, values): d[k].append(v)
    return d

def write_inventory(inv, out):
    out.mkdir(parents=True, exist_ok=True)
    (out / "patch-inventory.json").write_text(json.dumps(inv, indent=2) + "\n")
    for filename, rows, fields in [
        ("file-overlap-dependencies.csv", inv["file_overlap_edges"], ["target_file","previous_patch","next_patch","previous_order","next_order"]),
        ("overlay-inventory.csv", inv["overlays"], ["directory_order","directory","source_path","target_path","sha256","bytes"]),
        ("semantic-dependencies.csv", inv["semantic_dependencies"], ["prerequisite","consumer","reason","prerequisite_order","consumer_order","prerequisite_applied_before_consumer"]),
    ]:
        with (out / filename).open("w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=fields); w.writeheader(); w.writerows(rows)
    (out / "README.md").write_text(
        "# Linux 6.12.112 patch-stack inventory\n\n"
        f"- Ordered patch inputs: {inv['patch_count']}\n- Pre-patch overlay files: {inv['overlay_file_count']}\n"
        f"- Same-file dependency edges: {len(inv['file_overlap_edges'])}\n"
        f"- Curated semantic dependency edges: {len(inv['semantic_dependencies'])}\n"
        f"- Patch manifest SHA256: {inv['patch_manifest_sha256']}\n"
        f"- Overlay manifest SHA256: {inv['overlay_manifest_sha256']}\n"
        f"- Combined input manifest SHA256: {inv['input_manifest_sha256']}\n\n"
        "Application order:\n" + "\n".join(f"{i}. {d}" for i,d in enumerate(PATCH_DIRS,1)) +
        "\n\nThe attestation is generated only after the actual OpenWrt target/linux/prepare succeeds with zero fuzz and no reject/original files.\n"
        "Inventory follows each patch directory series file when present; otherwise it follows native sorted patch order.\n"
        "Every patch is source-scanned immediately after application; DSA and PCIe lifecycle contracts run at their final dependent patches.\n"
        "The final attestation reruns the whole-tree C/header/Kconfig/Makefile/DTS scan and all DSA/PCIe lifecycle contracts.\n"
        "Review-severity candidates are recorded for inspection; unambiguous same-file duplicate function definitions, prototypes, and tagged type definitions block attestation.\n"
    )

def attest(repo, out, kernel_src, log_path, archive, run_id, attempt):
    inv = json.loads((out / "patch-inventory.json").read_text())
    archive_sha = digest(archive.read_bytes())
    if archive_sha != inv["kernel_archive_sha256"]: raise RuntimeError("Downloaded kernel archive SHA256 differs from the repository pin")
    raw = log_path.read_bytes(); log = raw.decode("utf-8", errors="replace")
    applied = [Path(x).name for x in re.findall(r"^Applying (.+?) using [^:]+:", log, re.M)]
    expected = [p["name"] for p in inv["patches"]]
    if applied != expected: raise RuntimeError(f"Applied patch sequence mismatch: expected {len(expected)}, observed {len(applied)}")
    if re.search(r"Patch failed!|FAILED at|with fuzz [1-9]|fuzz [1-9]", log, re.I): raise RuntimeError("Patch log contains failure or non-zero fuzz")
    mk = (kernel_src / "Makefile").read_text(errors="replace")
    for key, val in (("VERSION","6"),("PATCHLEVEL","12"),("SUBLEVEL","112")):
        if not re.search(rf"^{key}\s*=\s*{val}\s*$", mk, re.M): raise RuntimeError("Prepared kernel source is not Linux 6.12.112")
    rejects = list(kernel_src.rglob("*.rej")) + list(kernel_src.rglob("*.orig"))
    if rejects: raise RuntimeError("Reject/original files remain after patching: " + ", ".join(str(x) for x in rejects[:10]))

    audit_failures = []
    intermediate_dir = out / "intermediate"
    intermediate_reports = sorted(intermediate_dir.glob("*.json")) if intermediate_dir.is_dir() else []
    if (intermediate_dir / "intermediate-failures").exists():
        audit_failures.append("one or more intermediate patch-level source/lifecycle checks failed")
    if len(intermediate_reports) != inv["patch_count"]:
        audit_failures.append(f"expected {inv['patch_count']} per-patch audit reports, found {len(intermediate_reports)}")
    intermediate_state = []
    intermediate_review_count = 0
    for report in intermediate_reports:
        try:
            data = json.loads(report.read_text())
            if data.get("error_count", 0):
                audit_failures.append("intermediate source errors in " + report.name)
            intermediate_review_count += data.get("review_count", 0)
            intermediate_state.append({"name":report.name,"sha256":digest(report.read_bytes())})
        except Exception as exc:
            audit_failures.append("invalid intermediate report " + report.name + ": " + str(exc))
    intermediate_sha = digest(json.dumps(intermediate_state,sort_keys=True,separators=(",",":")).encode())

    # Run every final-tree gate even when an earlier intermediate gate failed,
    # so one prepare produces a complete diagnostic set rather than stopping
    # at the first finding. Any failure blocks attestation issuance.
    source_report = out / "source-structure-audit.json"
    tests_dir = repo / "target/linux/mediatek/tests"
    scanner = tests_dir / "audit-kernel-source-structure.py"
    gates = [
        ("source scanner regression", [sys.executable, str(tests_dir / "test-kernel-source-structure.py")]),
        ("patch wrapper regression", [sys.executable, str(tests_dir / "test-kernel-patch-audit-wrapper.py")]),
        ("whole-tree source structure", [sys.executable, str(scanner), "--kernel-src", str(kernel_src),
                                         "--output", str(source_report)]),
        ("MT7530 Netlink lifecycle", [sys.executable, str(tests_dir / "test-dsa-mt7530-netlink.py"), str(kernel_src)]),
        ("AN8855 Netlink/procfs lifecycle", [sys.executable, str(tests_dir / "test-dsa-an8855-netlink.py"), str(kernel_src)]),
        ("PCIe Gen3 IRQ lifecycle", [sys.executable, str(tests_dir / "test-pcie-gen3-irq-lifecycle.py"), str(kernel_src)]),
        ("Ethernet/HNAT/PPE/NPU/TNL API and ownership", [sys.executable, str(tests_dir / "test-network-offload-api.py"), str(kernel_src)]),
        ("PHY/WED API and lifecycle", [sys.executable, str(tests_dir / "test-phy-wed-api.py"), str(kernel_src)]),
    ]
    for label, command in gates:
        result = subprocess.run(command, check=False)
        if result.returncode:
            audit_failures.append(label + " failed with exit code " + str(result.returncode))
    if not source_report.is_file():
        audit_failures.append("whole-tree source structure report was not produced")
        source_report_data = {"error_count": -1, "review_count": -1}
        source_report_sha = ""
    else:
        source_report_data = json.loads(source_report.read_text())
        source_report_sha = digest(source_report.read_bytes())
        if source_report_data.get("error_count", 0):
            audit_failures.append("whole-tree source structure audit contains blocking errors")
    if audit_failures:
        raise RuntimeError("Audit gates failed: " + "; ".join(audit_failures))

    paths = sorted({x for p in inv["patches"] for x in p["target_files"]} | {x["target_path"] for x in inv["overlays"]})
    state = []
    for rel in paths:
        p = kernel_src / rel
        state.append({"path":rel,"sha256":digest(p.read_bytes()) if p.is_file() else None,"state":"present" if p.is_file() else "absent"})
    att = {
        "schema_version":3,"repository_head_sha":head(repo),"github_run_id":str(run_id),"github_run_attempt":str(attempt),
        "kernel_version":inv["kernel_version"],"kernel_archive_sha256":archive_sha,
        "patch_directories_in_application_order":PATCH_DIRS,"overlay_directories_in_application_order":OVERLAY_DIRS,
        "patch_count":inv["patch_count"],"patch_manifest_sha256":inv["patch_manifest_sha256"],
        "overlay_manifest_sha256":inv["overlay_manifest_sha256"],"input_manifest_sha256":inv["input_manifest_sha256"],
        "patch_log_sha256":digest(raw),"source_structure_audit_sha256":source_report_sha,
        "source_structure_error_count":source_report_data["error_count"],
        "source_structure_review_count":source_report_data["review_count"],
        "intermediate_patch_audit_count":len(intermediate_reports),"intermediate_patch_audit_review_count":intermediate_review_count,"intermediate_patch_audit_sha256":intermediate_sha,
        "patched_paths_count":len(state),
        "patched_paths_state_sha256":digest(json.dumps(state,sort_keys=True,separators=(",",":")).encode()),
        "application_result":"PASS_ZERO_FUZZ_NO_REJECTS"
    }
    att["attestation_sha256"] = digest(json.dumps(att,sort_keys=True,separators=(",",":")).encode())
    (out / "kernel-patch-attestation.json").write_text(json.dumps(att,indent=2)+"\n")

def verify(repo, att_path, run_id, attempt, source_report, intermediate_dir):
    att = json.loads(att_path.read_text())
    if att.get("schema_version") != 3:
        raise RuntimeError("Unsupported or obsolete kernel patch attestation schema (expected v3)")
    if not source_report or not source_report.is_file():
        raise RuntimeError("The attested source-structure audit report is missing")
    source_report_data = json.loads(source_report.read_text())
    if digest(source_report.read_bytes()) != att.get("source_structure_audit_sha256"):
        raise RuntimeError("Source-structure audit report does not match the immutable attestation")
    if source_report_data.get("error_count", 0) or source_report_data.get("error_count") != att.get("source_structure_error_count") or source_report_data.get("review_count") != att.get("source_structure_review_count"):
        raise RuntimeError("Source-structure audit summary differs from the immutable attestation")
    if not intermediate_dir or not intermediate_dir.is_dir() or (intermediate_dir / "intermediate-failures").exists():
        raise RuntimeError("Per-patch audit reports are missing or include failures")
    reports = sorted(intermediate_dir.glob("*.json"))
    state = []
    review_count = 0
    for report in reports:
        data = json.loads(report.read_text())
        if data.get("error_count", 0):
            raise RuntimeError("Per-patch audit report contains errors: " + report.name)
        review_count += data.get("review_count", 0)
        state.append({"name":report.name,"sha256":digest(report.read_bytes())})
    intermediate_sha = digest(json.dumps(state,sort_keys=True,separators=(",",":")).encode())
    if len(reports) != att.get("intermediate_patch_audit_count") or len(reports) != att.get("patch_count") or review_count != att.get("intermediate_patch_audit_review_count") or intermediate_sha != att.get("intermediate_patch_audit_sha256"):
        raise RuntimeError("Per-patch audit reports do not match the immutable attestation")
    if att.get("repository_head_sha") != head(repo): raise RuntimeError("Attestation HEAD differs from checked-out revision")
    if att.get("github_run_id") != str(run_id) or att.get("github_run_attempt") != str(attempt): raise RuntimeError("Attestation belongs to another workflow run/attempt")
    inv = inventory(repo)
    for key in ("kernel_version","kernel_archive_sha256","patch_manifest_sha256","overlay_manifest_sha256","input_manifest_sha256","patch_count"):
        if att.get(key) != inv.get(key): raise RuntimeError("Attested source input changed: " + key)
    unsigned = dict(att); signature = unsigned.pop("attestation_sha256", None)
    if signature != digest(json.dumps(unsigned,sort_keys=True,separators=(",",":")).encode()): raise RuntimeError("Attestation digest is invalid")
    if att.get("application_result") != "PASS_ZERO_FUZZ_NO_REJECTS": raise RuntimeError("Kernel patch application was not attested as passing")
    print(f"PASS: Linux {att['kernel_version']}; {att['patch_count']} ordered patches; attestation {signature}")

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("command", choices=["inventory","attest","verify"])
    ap.add_argument("--repo", type=Path, default=Path.cwd())
    ap.add_argument("--output-dir", type=Path, default=Path(".kernel-patch-audit"))
    ap.add_argument("--kernel-src", type=Path); ap.add_argument("--patch-log", type=Path)
    ap.add_argument("--kernel-archive", type=Path); ap.add_argument("--attestation", type=Path)
    ap.add_argument("--source-audit-report", type=Path); ap.add_argument("--intermediate-audit-dir", type=Path)
    ap.add_argument("--run-id", default=""); ap.add_argument("--run-attempt", default="")
    a = ap.parse_args(); repo = a.repo.resolve()
    out = a.output_dir if a.output_dir.is_absolute() else repo / a.output_dir
    try:
        if a.command == "inventory":
            inv = inventory(repo); write_inventory(inv,out)
            print(f"PASS: inventoried {inv['patch_count']} ordered patches and {inv['overlay_file_count']} overlays; input manifest {inv['input_manifest_sha256']}")
        elif a.command == "attest":
            if not all((a.kernel_src,a.patch_log,a.kernel_archive,a.run_id,a.run_attempt)): raise RuntimeError("attest requires kernel source, patch log, archive, run id and attempt")
            attest(repo,out,a.kernel_src.resolve(),a.patch_log.resolve(),a.kernel_archive.resolve(),a.run_id,a.run_attempt)
            print("PASS: immutable kernel patch-stack attestation created")
        else:
            if not all((a.attestation,a.source_audit_report,a.intermediate_audit_dir,a.run_id,a.run_attempt)): raise RuntimeError("verify requires attestation, source audit report, intermediate audit directory, run id and attempt")
            verify(repo,a.attestation.resolve(),a.run_id,a.run_attempt,a.source_audit_report.resolve(),a.intermediate_audit_dir.resolve())
        return 0
    except Exception as e:
        print("ERROR: " + str(e), file=sys.stderr); return 1

if __name__ == "__main__":
    sys.exit(main())
