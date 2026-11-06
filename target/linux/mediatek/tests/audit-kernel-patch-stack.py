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
    ("999-hnat-03-netfilter-nf_flow_table-support-hw-offload-through-v.patch", "999-net-04-netdevice-add-ndo_flow_offload_stats64_add-for-offload-stats-correction.patch", "net_device_ops extension is based on ndo_flow_offload_check introduced by HNAT base patch"),
    ("999-net-04-netdevice-add-ndo_flow_offload_stats64_add-for-offload-stats-correction.patch", "999-hnat-14-net-vlan-add-ndo_flow_offload_stats64_add-for-offload-stats-correction.patch", "VLAN statistics callback initializes the ndo field introduced by net-04; source dependency is cross-file"),
    ("999-net-04-netdevice-add-ndo_flow_offload_stats64_add-for-offload-stats-correction.patch", "999-hnat-15-ppp-add-ndo_flow_offload_stats64_add-for-offload-stats-correction.patch", "PPP statistics callback initializes the ndo field introduced by net-04; source dependency is cross-file"),
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
        elif line.startswith(("--- ", "+++ ")):
            value = line[4:].split("\t", 1)[0].split(" ", 1)[0]
            if value.startswith(("a/", "b/")): out.add(value[2:])
    return sorted(x for x in out if x and x != "/dev/null")

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
            "patches": patches, "overlays": overlays, "file_overlap_matrix": overlap, "semantic_dependencies": semantic}
    return {
        "schema_version": 1, "kernel_version": kernel, "kernel_archive_sha256": hm.group(2),
        "patch_directories_in_application_order": PATCH_DIRS, "overlay_directories_in_application_order": OVERLAY_DIRS,
        "patch_count": len(patches), "overlay_file_count": len(overlays), "patch_manifest_sha256": patch_sha,
        "overlay_manifest_sha256": overlay_sha, "input_manifest_sha256": digest(json.dumps(core, sort_keys=True, separators=(",", ":")).encode()),
        "patches": patches, "overlays": overlays, "file_overlap_matrix": overlap, "file_overlap_edges": edges,
        "overlay_collision_matrix": {k:v for k,v in sorted(overlay_targets.items()) if len(v)>1},
        "semantic_dependencies": semantic, "missing_semantic_dependencies": missing,
        "duplicate_patch_content": [v for v in _groups([p["sha256"] for p in patches], [p["path"] for p in patches]).values() if len(v)>1],
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
    paths = sorted({x for p in inv["patches"] for x in p["target_files"]} | {x["target_path"] for x in inv["overlays"]})
    state = []
    for rel in paths:
        p = kernel_src / rel
        state.append({"path":rel,"sha256":digest(p.read_bytes()) if p.is_file() else None,"state":"present" if p.is_file() else "absent"})
    att = {
        "schema_version":1,"repository_head_sha":head(repo),"github_run_id":str(run_id),"github_run_attempt":str(attempt),
        "kernel_version":inv["kernel_version"],"kernel_archive_sha256":archive_sha,
        "patch_directories_in_application_order":PATCH_DIRS,"overlay_directories_in_application_order":OVERLAY_DIRS,
        "patch_count":inv["patch_count"],"patch_manifest_sha256":inv["patch_manifest_sha256"],
        "overlay_manifest_sha256":inv["overlay_manifest_sha256"],"input_manifest_sha256":inv["input_manifest_sha256"],
        "patch_log_sha256":digest(raw),"patched_paths_count":len(state),
        "patched_paths_state_sha256":digest(json.dumps(state,sort_keys=True,separators=(",",":")).encode()),
        "application_result":"PASS_ZERO_FUZZ_NO_REJECTS"
    }
    att["attestation_sha256"] = digest(json.dumps(att,sort_keys=True,separators=(",",":")).encode())
    (out / "kernel-patch-attestation.json").write_text(json.dumps(att,indent=2)+"\n")

def verify(repo, att_path, run_id, attempt):
    att = json.loads(att_path.read_text())
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
            if not all((a.attestation,a.run_id,a.run_attempt)): raise RuntimeError("verify requires attestation, run id and attempt")
            verify(repo,a.attestation.resolve(),a.run_id,a.run_attempt)
        return 0
    except Exception as e:
        print("ERROR: " + str(e), file=sys.stderr); return 1

if __name__ == "__main__":
    sys.exit(main())
