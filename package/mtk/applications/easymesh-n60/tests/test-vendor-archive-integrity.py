#!/usr/bin/env python3
"""Verify pinned vendor archive members, patch deltas, and kernel package build edges."""
from pathlib import Path, PurePosixPath
import hashlib, posixpath, re, sys, tarfile

def need(ok, msg):
    if not ok:
        raise SystemExit("FAIL: " + msg)

if len(sys.argv) != 5:
    raise SystemExit("usage: test-vendor-archive-integrity.py <input> <source> <pristine> <repo>")
inp, src, pristine, repo = map(Path, sys.argv[1:])
def inventory(root):
    return {p.relative_to(root).as_posix(): p for p in root.rglob("*") if p.is_file()}
def sha(path):
    h=hashlib.sha256()
    with path.open("rb") as f:
        for b in iter(lambda:f.read(1024*1024),b""): h.update(b)
    return h.hexdigest()
def patch_targets(directory):
    result=set()
    patches=sorted(directory.glob("*.patch"))
    need(bool(patches),f"no patch series: {directory}")
    for patch in patches:
        if patch.stat().st_size == 0: continue
        for line in patch.read_text(encoding="utf-8",errors="replace").splitlines():
            if not (line.startswith("--- ") or line.startswith("+++ ")): continue
            raw=line[4:].split("\t",1)[0].split(" ",1)[0]
            if raw == "/dev/null": continue
            if raw.startswith(("a/","b/")): raw=raw[2:]
            rel=PurePosixPath(posixpath.normpath(raw)).as_posix()
            need(rel not in ("", ".", "..") and not rel.startswith("../"),
                 f"bad -p1 path in {patch}: {raw}")
            # Removing the a/ or b/ prefix above is exactly GNU patch -p1.
            result.add(rel)
    return result

specs=[
 ("mtwifi","mt79xx_20250408-705eb4.tar.xz","",src/"mtwifi",pristine/"mtwifi",repo/"package/mtk/drivers/mt_wifi/patches-7673"),
 ("conninfra","mt79xx_conninfra_20250408-f2fa25.tar.xz","conninfra/",src/"conninfra/conninfra",pristine/"conninfra",repo/"package/mtk/drivers/conninfra/patches"),
 ("warp","warp_20250408-5f71ec.tar.xz","warp/",src/"warp/warp",pristine/"warp",repo/"package/mtk/drivers/warp/patches"),
 ("datconf","datconf-757f9679.tar.bz2","datconf/",src/"datconf/datconf",pristine/"datconf",repo/"package/mtk/applications/datconf/patches"),
 ("mapfilter","mapfilter-96f2afed.tar.bz2","mapfilter/",src/"mapfilter/mapfilter",pristine/"mapfilter",repo/"package/kernel/mapfilter/patches"),
]
for name,archive_name,prefix,root,base,patch_dir in specs:
    archive_path=inp/archive_name
    need(archive_path.is_file() and root.is_dir() and base.is_dir(),f"{name} archive/source/pristine missing")
    with tarfile.open(archive_path,"r:*") as tar:
        members={}
        for m in tar.getmembers():
            if not m.isfile(): continue
            path=m.name
            if prefix:
                need(path.startswith(prefix),f"{name} unexpected archive root: {path}")
                path=path[len(prefix):]
            need(path and path not in members,f"{name} duplicate archive member: {path}")
            members[path]=m
        original=inventory(base)
        need(set(original)==set(members),
             f"{name} archive manifest mismatch: missing={sorted(set(members)-set(original))} extra={sorted(set(original)-set(members))}")
        for path,m in members.items():
            stream=tar.extractfile(m)
            need(stream is not None and hashlib.sha256(stream.read()).hexdigest()==sha(original[path]),
                 f"{name} extracted file differs from pinned archive: {path}")
    targets=patch_targets(patch_dir)
    if name == "datconf":
        # OpenWrt Build/Prepare copies package ./src over the extracted tree
        # before applying patches. These three files are expected overlay inputs,
        # not unexplained vendor-archive patch deltas.
        targets.update({
            "datconf/ucode/CMakeLists.txt",
            "datconf/ucode/datconf.c",
            "datconf/ucode/example/example.uc",
        })
    before,after=inventory(base),inventory(root)
    reject=[p.relative_to(root).as_posix() for p in root.rglob("*.rej") if p.is_file()]
    need(not reject,f"{name} has rejected patch files: {reject}")
    backups=[p.relative_to(root).as_posix() for p in root.rglob("*.orig") if p.is_file()]
    for backup in backups:
        rel=backup[:-5]
        need(rel in targets and rel in before and (root/backup).stat().st_size>0,
             f"{name} unexpected/empty patch backup: {backup}")
    changed=set()
    for rel in set(before)|set(after):
        if rel.endswith(".orig"): continue
        if rel not in before or rel not in after or sha(before[rel])!=sha(after[rel]): changed.add(rel)
    need(bool(changed),f"{name} patch series made no source changes")
    need(not (changed-targets),f"{name} changed files outside patch targets: {sorted(changed-targets)}")
    print(f"ARCHIVE/PATCH PASS: {name}: archive_files={len(members)} changed={len(changed)} targets={len(targets)} backups={len(backups)}")

# Conninfra Kbuild references must resolve against the exact MT7986 source archive.
conn_pkg=(repo/"package/mtk/drivers/conninfra/Makefile").read_text()
conn_src=(src/"conninfra/conninfra/Makefile").read_text()
need("PKG_BUILD_DIR:=$(KERNEL_BUILD_DIR)/$(PKG_NAME)" in conn_pkg and
     "FILES:=$(PKG_BUILD_DIR)/conninfra.ko" in conn_pkg and
     '$(MAKE) -C "$(LINUX_DIR)"' in conn_pkg and "modules" in conn_pkg,
     "Conninfra package build/output mapping incomplete")
need("MTK_CONNINFRA_APSOC_MT7986" in conn_pkg and "obj-m += $(MODULE_NAME).o" in conn_src and
     re.search(r"(?m)^ccflags-y\s*\+=\s*-Werror\s*$", conn_src) is not None and
     re.search(r"(?m)^\s*KBUILD_MODPOST_(?:WARN|FAIL_ON_WARNINGS)\s*[:+?]?=", conn_src) is None and
     "Keep upstream Linux 6.12 modpost defaults" in conn_src,
     "Conninfra MT7986/Werror/upstream-modpost contract missing")
conn_objects=re.findall(r"^\$\(MODULE_NAME\)-objs\s*\+=\s*(\S+)",conn_src,re.M)
conn_files=inventory(src/"conninfra/conninfra")
for obj in conn_objects:
    rel=posixpath.splitext(obj)[0]+".c"
    need(rel in conn_files,f"Conninfra Kbuild object source missing: {rel}")
need(any(x.startswith("platform/mt7986/") for x in conn_objects),"Conninfra MT7986 object set absent")
print(f"BUILD RULES PASS: conninfra MT7986 object references={len(conn_objects)}")

# WARP MT7986 uses HW version 2 and both 7986 WO firmware images.
warp_pkg=(repo/"package/mtk/drivers/warp/Makefile").read_text()
warp_cfg=(repo/"package/mtk/drivers/warp/config.in").read_text()
warp_src=(src/"warp/warp/Makefile").read_text()
warp_files=inventory(src/"warp/warp")
need("FILES:=$(PKG_BUILD_DIR)/mtk_warp.ko" in warp_pkg and 'M="$(PKG_BUILD_DIR)"' in warp_pkg and
     "modules" in warp_pkg and "default 2 if TARGET_mediatek_mt7986" in warp_cfg and
     "obj-m += $(MODULE_NAME).o" in warp_src and "$(MODULE_NAME)-objs += $(OBJS)" in warp_src,
     "WARP package/Kbuild MT7986 contract incomplete")
warp_objects=["warp_main.c","warp_utility.c","wed.c","wdma.c","warp_proc.c","warp_wifi.c","warp_bus.c","warp_ser.c",
 "mcu/warp_msg.c","mcu/warp_evt.c","regs/reg_v2/warp_hw_v2.c","regs/reg_v2/warp_hw_ccif.c",
 "mcu/warp_ccif.c","mcu/warp_cmd.c","mcu/warp_fwdl.c","mcu/warp_woif.c","mcu/warp_wo.c",
 "mcu/warp_woctrl.c","regs/reg_v2/warp_mt7986.c","warp_bm_v2.c"]
for rel in warp_objects: need(rel in warp_files,f"WARP MT7986 v2 source missing: {rel}")
for rel in ("bin/7986_WOCPU0_RAM_CODE_release.bin","bin/7986_WOCPU1_RAM_CODE_release.bin"):
    need(rel in warp_files,f"WARP firmware missing: {rel}")
print(f"BUILD RULES PASS: warp MT7986 v2 source objects={len(warp_objects)} firmware_images=2")

datconf_pkg=(repo/"package/mtk/applications/datconf/Makefile").read_text()
# package-defaults.mk copies package-local ./src into PKG_BUILD_DIR after
# archive extraction. Keep that overlay explicit and independently audited
# before Quick; it is not part of the vendor tarball.
datconf_overlay_root = repo/"package/mtk/applications/datconf/src"
need(datconf_overlay_root.is_dir(), "datconf repository overlay directory missing")
datconf_overlay = {
    p.relative_to(datconf_overlay_root).as_posix(): p
    for p in datconf_overlay_root.rglob("*") if p.is_file()
}
expected_datconf_overlay = {
    "datconf/ucode/CMakeLists.txt",
    "datconf/ucode/datconf.c",
    "datconf/ucode/example/example.uc",
}
need(set(datconf_overlay) == expected_datconf_overlay,
     "datconf overlay manifest changed: "
     f"unexpected={sorted(set(datconf_overlay)-expected_datconf_overlay)} "
     f"missing={sorted(expected_datconf_overlay-set(datconf_overlay))}")
package_defaults = (repo/"include/package-defaults.mk").read_text()
need("[ ! -d ./src/ ] || $(CP) ./src/. $(PKG_BUILD_DIR)" in package_defaults,
     "OpenWrt local-src overlay copy semantics changed; update the inventory model")
need("include $(INCLUDE_DIR)/package.mk" in datconf_pkg and
     not re.search(r"(?m)^define Build/Prepare(?:/|$)", datconf_pkg),
     "datconf no longer uses the audited default Build/Prepare overlay path")
for rel, source_path in sorted(datconf_overlay.items()):
    need(source_path.stat().st_size > 0, f"datconf overlay file is empty: {rel}")
    print(f"DATCONF OVERLAY: {rel} | SHA256={sha(source_path)}")
print(f"PASS: datconf local overlay manifest contains {len(datconf_overlay)} exact files and uses OpenWrt Build/Prepare/Default copy semantics.")
datconf_files=inventory(src/"datconf/datconf")
need("include $(INCLUDE_DIR)/cmake.mk" in datconf_pkg and
     "PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)" in datconf_pkg,
     "datconf CMake package rules incomplete")
for rel in ("CMakeLists.txt","datconf/CMakeLists.txt","datconf/datconf.c","datconf/libdatconf.c",
            "kvcutil/CMakeLists.txt","kvcutil/libkvcutil.c"):
    need(rel in datconf_files,f"datconf CMake/source input missing: {rel}")
mtwifi_pkg=(repo/"package/mtk/drivers/mt_wifi/Makefile").read_text()
need("PKG_BUILD_DEPENDS:=warp conninfra" in mtwifi_pkg and
     'KBUILD_EXTRA_SYMBOLS="$(KERNEL_BUILD_DIR)/conninfra/Module.symvers"' in mtwifi_pkg,
     "mt_wifi Conninfra/WARP dependency or modpost edge missing")
need('M="$(PKG_BUILD_DIR)/mt_wifi_ap"' in mtwifi_pkg and
     (src/"mtwifi/mt_wifi_ap/Makefile").is_file(),
     "mt_wifi_ap Kbuild entrypoint referenced by Build/Compile is missing")
need((src/"mtwifi/mt_wifi/embedded/plug_in/warp_proxy/Makefile").is_file(),
     "mt_wifi WARP proxy Kbuild entrypoint is missing")
mapfilter_pkg=(repo/"package/kernel/mapfilter/Makefile").read_text()
need((src/"mapfilter/mapfilter/Makefile").is_file() and "Build/Compile" in mapfilter_pkg,
     "MAPFILTER source/build rule missing")

# Audit the remaining EasyMesh and auxiliary archives against their pristine
# extracts, then prove every changed source file is named by the applied patch
# series. The DSA patch is applied one directory lower than the other patches.
def verify_component(name, archive_name, prefix, root, base, allowed):
    archive_path=inp/archive_name
    need(archive_path.is_file() and root.is_dir() and base.is_dir(),
         f"{name} archive/source/pristine missing")
    with tarfile.open(archive_path,"r:*") as tar:
        members={}
        for m in tar.getmembers():
            if not m.isfile(): continue
            path=m.name
            if prefix:
                need(path.startswith(prefix),f"{name} unexpected archive root: {path}")
                path=path[len(prefix):]
            need(path and path not in members,f"{name} duplicate archive member: {path}")
            members[path]=m
        original=inventory(base)
        need(set(original)==set(members),
             f"{name} archive manifest mismatch: missing={sorted(set(members)-set(original))} extra={sorted(set(original)-set(members))}")
        for path,m in members.items():
            stream=tar.extractfile(m)
            need(stream is not None and hashlib.sha256(stream.read()).hexdigest()==sha(original[path]),
                 f"{name} pristine file differs from pinned archive: {path}")
    before,after=inventory(base),inventory(root)
    reject=[p.relative_to(root).as_posix() for p in root.rglob("*.rej") if p.is_file()]
    need(not reject,f"{name} rejected patch files remain: {reject}")
    backups=[p.relative_to(root).as_posix() for p in root.rglob("*.orig") if p.is_file()]
    for backup in backups:
        rel=backup[:-5]
        need(rel in allowed and rel in before and (root/backup).stat().st_size>0,
             f"{name} unexpected/empty patch backup: {backup}")
    changed=set()
    for rel in set(before)|set(after):
        if rel.endswith(".orig"): continue
        if rel not in before or rel not in after or sha(before[rel])!=sha(after[rel]):
            changed.add(rel)
    need(not (changed-allowed),
         f"{name} changed outside declared patch targets: {sorted(changed-allowed)}")
    print(f"ARCHIVE/PATCH PASS: {name}: archive_files={len(members)} changed={len(changed)} targets={len(allowed)} backups={len(backups)}")

easy_targets=patch_targets(repo/"package/mtk/applications/easymesh-n60/patches")
easy_specs=[
 ("wappd","wappd-80ca5724.tar.bz2","wappd/",src/"easymesh/wappd",pristine/"wappd","wappd/"),
 ("mapd","mapd-6eca4331.tar.bz2","mapd/",src/"easymesh/mapd",pristine/"mapd","mapd/"),
 ("1905daemon","1905daemon-35234223.tar.bz2","1905daemon/",src/"easymesh/1905daemon",pristine/"1905daemon","1905daemon/"),
 ("libmapd","libmapd-0132d199.tar.bz2","libmapd/",src/"easymesh/libmapd",pristine/"libmapd","libmapd/"),
]
for name,archive_name,prefix,root,base,patch_prefix in easy_specs:
    allowed={p[len(patch_prefix):] for p in easy_targets if p.startswith(patch_prefix)}
    if name=="1905daemon":
        # 001-dsa-use-linux-mii-ioctl.patch is applied with -d 1905daemon.
        allowed.update(p for p in easy_targets if p.startswith("ethernet/"))
    verify_component(name,archive_name,prefix,root,base,allowed)

aux_targets=patch_targets(repo/"package/mtk/applications/easymesh-n60/auxiliary-patches")
verify_component("bndstrg_plus","bndstrg_plus-8350508d.tar.bz2","bndstrg_plus/",
                 src/"bndstrg/bndstrg_plus",pristine/"bndstrg_plus",
                 {p[len("bndstrg_plus/"):] for p in aux_targets if p.startswith("bndstrg_plus/")})
verify_component("fwdd","fwdd-bcbae0e4.tar.bz2","fwdd/",
                 src/"fwdd/fwdd",pristine/"fwdd",
                 {p[len("fwdd/"):] for p in aux_targets if p.startswith("fwdd/")})

print("BUILD RULES PASS: datconf CMake, mt_wifi->Conninfra/WARP, MAPFILTER source/module mapping")
print("PASS: archive hashes/manifests, patch-only source deltas, and kernel package build references.")
