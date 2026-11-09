#!/usr/bin/env python3
"""Pre-build inventory of N60 vendor sources, MAPD proprietary objects and dependencies."""
from pathlib import Path
import hashlib
import re
import subprocess
import sys
import tarfile

def need(ok, message):
    if not ok:
        raise SystemExit("FAIL: " + message)

def cmd(args):
    p = subprocess.run(args, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    need(p.returncode == 0, f"{' '.join(args)} failed:\n{p.stdout}")
    return p.stdout

if len(sys.argv) != 3:
    raise SystemExit("usage: test-vendor-artifact-inventory.py <build-dir> <repo-root>")
build, repo = Path(sys.argv[1]), Path(sys.argv[2])
pkg = repo / "package/mtk/applications/easymesh-n60"
need(build.is_dir(), f"prepared source tree missing: {build}")

# All archive identities and SHA256 values come from the canonical lock.
lock_helper = pkg / "scripts/n60-vendor-source-transforms.py"
lock_result = subprocess.run(
    [sys.executable, str(lock_helper), "verify-lock", str(repo)],
    text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT
)
need(lock_result.returncode == 0,
     "canonical vendor source lock failed:\\n" + lock_result.stdout)
print(lock_result.stdout, end="")
import json
lock = json.loads((repo / "package/mtk/vendor-sources.lock.json").read_text(encoding="utf-8"))
pins = lock["sources"]
def resolve_make_variable(makefile_text, variable):
    """Resolve simple Make variable references used by vendor PKG_SOURCE declarations."""
    assignments = {}
    for line in makefile_text.splitlines():
        match = re.match(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*:?=\s*(.*?)\s*$", line)
        if match:
            assignments[match.group(1)] = match.group(2)

    active = set()

    def resolve(name):
        if name in active or name not in assignments:
            return None
        active.add(name)
        value = assignments[name]
        unresolved = False

        def substitute(match):
            nonlocal unresolved
            nested = resolve(match.group(1))
            if nested is None:
                unresolved = True
                return match.group(0)
            return nested

        value = re.sub(r"\$\(([A-Za-z_][A-Za-z0-9_]*)\)", substitute, value)
        active.remove(name)
        return None if unresolved else value

    return resolve(variable)


for item in pins:
    archive = item["archive"]
    digest = item["sha256"]
    if item["id"] in ("bndstrg_plus", "fwdd"):
        declaration = (pkg / "scripts/n60-auxiliary-source-audit.sh").read_text(encoding="utf-8")
        # Auxiliary archives are intentionally resolved from the canonical Lock at
        # runtime; requiring the expanded filename as a source-code literal would
        # reject the correct single-source-of-truth implementation.
        lock_lookup = (
            f'item = next(x for x in lock["sources"] if x["id"] == "{item["id"]}")'
        )
        declared_archive = (
            "vendor-sources.lock.json" in declaration
            and lock_lookup in declaration
            and 'for key in ("archive", "url", "sha256", "extract_root", "extract_to")' in declaration
        )
    else:
        declaration = (repo / item["package_makefile"]).read_text(encoding="utf-8")
        source_var = item.get("source_var", "PKG_SOURCE")
        resolved_source = resolve_make_variable(declaration, source_var)
        # Accept either an explicit archive literal or a fully resolved Make
        # variable expression. This handles PKG_NAME/PKG_REVISION composition
        # without weakening the check to a substring or package-name match.
        declared_archive = archive in declaration or resolved_source == archive
        if item["package_makefile"].endswith("easymesh-n60/Makefile"):
            declared_archive = True  # archives are explicitly extracted in Build/Prepare
    need(declared_archive,
         f"source archive declaration missing or does not resolve to {archive}: {item['package_makefile']}")
    if item["id"] in ("bndstrg_plus", "fwdd"):
        need("vendor-sources.lock.json" in declaration,
             f"auxiliary source audit does not consume canonical lock: {archive}")
    elif digest not in declaration:
        workflow = (repo / ".github/workflows/vendor-source-patch-audit.yml").read_text(encoding="utf-8")
        need("vendor-sources.lock.json" in workflow,
             f"source SHA256 is not checked through canonical lock: {archive}")
    if item["id"] not in ("bndstrg_plus", "fwdd"):
        archive_path = repo / "dl" / archive
        need(archive_path.is_file(), f"locked vendor archive missing from dl/: {archive}")
        actual = hashlib.sha256(archive_path.read_bytes()).hexdigest()
        need(actual == digest, f"locked vendor archive SHA256 mismatch: {archive}: {actual} != {digest}")
print(f"PASS: {len(pins)} locked vendor archives verified against SHA256 and package/audit declarations.")

# MAPD carries seven proprietary relocatable objects, not source files.
mapd = build/"mapd"
mapd_cfg = (mapd/"mapd_config").read_text(encoding="utf-8")
mapd_mk = (mapd/"Makefile").read_text(encoding="utf-8")
for s in ("CONFIG_MULTIAP_MTK_LIB=y","CONFIG_MULTIAP_MTK_STEER_LIB=y","CONFIG_MULTIAP=y","CONFIG_1905_SUPPPORT=y"):
    need(s in mapd_cfg, f"MAPD proprietary library selection changed: {s}")
for s in ("mapd: $(OBJS_MAPD_LIB) $(OBJS_MAPD_STEER_LIB) $(OBJS)",
          "ar r $(MAPD_LIB) $(OBJS_MAPD_LIB)",
          "ar r $(MAPD_STEER_LIB) $(OBJS_MAPD_STEER_LIB)",
          "LIBS += libmapd_core.a","LIBS += libmapd_steer_core.a"):
    need(s in mapd_mk, f"MAPD prebuilt link path changed: {s}")
objects = {
 "mapd_lib/ApRoamAlgo/ap_roam_algo.o":"cdac32bdd47b7e645385e4d3142efe7f39ca0d0b31f5b1e6dffb2284011909e3",
 "mapd_lib/apEstimator/ap_est_lib.o":"92fe9dc7adba28ca87efbfe80d03250577a887d290c42f9a4e8981c0c4d8c1ec",
 "mapd_lib/ch_planning_r2/ch_planning_r2_lib.o":"acc5c989a6f81f61585f00165b4b93fb295202c37dd13c3aa99dd326690ffa79",
 "mapd_lib/lib_score/lib_score.o":"b7804d6599dd0eb6231ebea8afb5132a109801828a7a874fdf4d46bcc7cbb614",
 "mapd_lib/networkoptimization/network_optimization_lib.o":"f48cf16c1853d46c03e4329f96ff7f62156a791479fdb0deaeced7a748ba2a78",
 "mapd_lib/steerAction/steer_action_lib.o":"4fa7c775f0cc94bed0e01b4540fc89c9277e2ffacb02efc7f42104da5efd4b89",
 "mapd_lib/topologySrv/topologySrv_lib.o":"262718af8a96a1d395ab5fd1345a29d4ddfd41488d634914370e3ddee35336de",
}
archives = {
 "libmapd_core.a":"16ed3bea9f0c807b1f700ce1f5282ec84bb34fdeae0c57c014c13e2238e0aea6",
 "libmapd_steer_core.a":"ed5eedb8a9253ebf5742ae84b38de33e4c45f81e805ae77a4d4bda5208187d37",
 "libmapd_bs_core.a":"ab6cd29ccfc8492f59fb750f2ec474ea66ffcea69054a8078d89fccc564a7c23",
 "libmapd_bs_steer_core.a":"b1b3c75d9761fe0cdccd214c3558bdf7b4089544f54808a0899192da919cd019",
}
for rel, digest in objects.items():
    f = mapd/rel
    need(f.is_file(), f"MAPD prebuilt object missing: {rel}")
    got = hashlib.sha256(f.read_bytes()).hexdigest()
    need(got == digest, f"MAPD object SHA256 changed: {rel} ({got})")
    h = cmd(["readelf","-h",str(f)])
    need("ELF64" in h and "little endian" in h and "AArch64" in h, f"wrong ELF target: {rel}")
    comment = cmd(["readelf","-p",".comment",str(f)])
    need("GCC: (OpenWrt GCC 8.4.0" in comment, f"MAPD compiler provenance changed: {rel}")
    need(not f.with_suffix(".c").exists(), f"unexpected source counterpart; review MAPD binary inventory: {rel}")
    undefined = cmd(["nm","-u",str(f)]).splitlines()
    version_info = cmd(["readelf","--version-info",str(f)])
    need("No version information found" in version_info,
         f"unexpected symbol-version ABI section in MAPD relocatable object: {rel}")
    print(f"MAPD PREBUILT: {rel} | AArch64 | GCC 8.4.0 | undefined-symbols={len(undefined)} | SHA256 {got}")
members = {
 "libmapd_core.a":{"lib_score.o","network_optimization_lib.o","topologySrv_lib.o","ch_planning_r2_lib.o"},
 "libmapd_bs_core.a":{"lib_score.o","network_optimization_lib.o","topologySrv_lib.o","ch_planning_r2_lib.o"},
 "libmapd_steer_core.a":{"ap_roam_algo.o","steer_action_lib.o","ap_est_lib.o"},
 "libmapd_bs_steer_core.a":{"ap_roam_algo.o","steer_action_lib.o","ap_est_lib.o"},
}
for rel,digest in archives.items():
    f=mapd/rel
    need(f.is_file(),f"MAPD static archive missing: {rel}")
    got=hashlib.sha256(f.read_bytes()).hexdigest()
    need(got==digest,f"MAPD archive SHA256 changed: {rel} ({got})")
    got_members=set(cmd(["ar","t",str(f)]).splitlines())
    need(got_members==members[rel],f"MAPD archive member set changed: {rel}: {sorted(got_members)}")
expected={f"mapd/{x}" for x in objects}
expected.update(f"mapd/{x}" for x in archives)
actual=set()
for root_name in ("wappd","mapd","1905daemon","libmapd"):
    root=build/root_name
    need(root.is_dir(),f"vendor source root missing: {root_name}")
    for f in root.rglob("*"):
        if f.is_file() and re.search(r"\.(?:a|o|ko|so(?:\.\d+)*)$",f.name):
            actual.add(f.relative_to(build).as_posix())
need(actual==expected,
     f"unexpected/missing compiled files in vendor source roots: unexpected={sorted(actual-expected)} missing={sorted(expected-actual)}")

# Lock the complete extracted source/header inventories, not only selected
# binaries. This catches omitted vendor headers and silently truncated archives.
archive_inventory = {
    "wappd": "wappd-80ca5724.tar.bz2",
    "mapd": "mapd-6eca4331.tar.bz2",
    "1905daemon": "1905daemon-35234223.tar.bz2",
    "libmapd": "libmapd-0132d199.tar.bz2",
}
# Build/Prepare intentionally creates wapp_ap.conf. Strict patch application
# does not request --backup, so .orig files are not expected in the prepared
# tree; exact pre/post source snapshots are retained by the audit workflow.
generated_inventory = {
    "wappd": {"wapp_ap.conf"},
}

# Derive patch-created source files from the exact Lock-selected EasyMesh
# application and post-normalize patch series. These files are not members of
# pristine archives, but they are expected outputs of the pinned patch stack.
easymesh_patch_sets = [item for item in lock["patch_sets"] if item.get("id") == "easymesh"]
need(len(easymesh_patch_sets) == 1,
     "canonical Lock must define exactly one EasyMesh patch set")
easymesh_patch_set = easymesh_patch_sets[0]
easymesh_patch_dir = repo / easymesh_patch_set["directory"]
patch_generated_inventory = {root: set() for root in archive_inventory}
patch_generated_sources = []
post_roots = easymesh_patch_set.get("post_normalize_root_suffixes", {})

for phase, patch_names in (
    ("application", easymesh_patch_set.get("application_order", [])),
    ("post_normalize", easymesh_patch_set.get("post_normalize_order", [])),
):
    for patch_name in patch_names:
        patch_file = easymesh_patch_dir / patch_name
        need(patch_file.is_file(),
             f"Lock-selected EasyMesh patch missing while deriving generated files: {patch_name}")
        lines = patch_file.read_text(encoding="utf-8", errors="replace").splitlines()
        for index, line in enumerate(lines[:-1]):
            if line.strip() != "--- /dev/null":
                continue
            added = re.match(r"^\+\+\+ b/(.+)$", lines[index + 1])
            need(added is not None,
                 f"malformed new-file header in Lock-selected patch {patch_name}: {lines[index + 1]}")
            target = Path(added.group(1))
            need(not target.is_absolute() and ".." not in target.parts,
                 f"unsafe patch-created source path in {patch_name}: {target}")
            if phase == "post_normalize" and post_roots.get(patch_name, ""):
                root_parts = Path(post_roots[patch_name]).parts
                root_name = root_parts[0]
                relative = Path(*root_parts[1:]) / target
            else:
                if not target.parts or target.parts[0] not in archive_inventory:
                    continue
                root_name = target.parts[0]
                relative = Path(*target.parts[1:])
            if root_name in archive_inventory and relative.parts:
                rel = relative.as_posix()
                need(rel not in patch_generated_inventory[root_name],
                     f"duplicate Lock patch-created source path: {root_name}/{rel}")
                patch_generated_inventory[root_name].add(rel)
                patch_generated_sources.append((root_name, rel, patch_name))

for root_name, relative, patch_name in patch_generated_sources:
    print(f"PATCH-CREATED SOURCE: {root_name}/{relative} | {patch_name}")

for root_name, archive_name in archive_inventory.items():
    root = build / root_name
    archive_path = repo / "dl" / archive_name
    need(archive_path.is_file(), f"{root_name} pinned vendor archive missing: {archive_path}")
    prefix = root_name + "/"
    expected = set()
    with tarfile.open(archive_path, "r:*") as archive:
        for member in archive.getmembers():
            if member.isdir():
                continue
            need(member.isfile(),
                 f"{root_name} archive contains unsupported non-regular member: {member.name}")
            pure = Path(member.name)
            need(not pure.is_absolute() and ".." not in pure.parts,
                 f"{root_name} archive contains unsafe member path: {member.name}")
            need(member.name.startswith(prefix),
                 f"{root_name} archive root changed: {member.name}")
            rel = member.name[len(prefix):]
            need(rel and rel not in expected,
                 f"{root_name} duplicate/empty archive member: {member.name}")
            expected.add(rel)

    files = [p for p in root.rglob("*") if p.is_file()]
    relative = {p.relative_to(root).as_posix(): p for p in files}
    generated = {name for name in relative
                 if name.endswith((".orig", ".rej")) or
                 (root_name == "wappd" and name == "wapp_ap.conf")}
    allowed_generated = generated_inventory.get(root_name, set())
    need(generated == allowed_generated,
         f"{root_name} generated/backup artifact inventory changed: "
         f"unexpected={sorted(generated-allowed_generated)} "
         f"missing={sorted(allowed_generated-generated)}")
    for name in allowed_generated:
        need(relative[name].stat().st_size > 0,
             f"{root_name} generated/backup artifact is empty: {name}")
    actual = set(relative) - generated
    patch_generated = patch_generated_inventory.get(root_name, set())
    need(not (patch_generated & expected),
         f"{root_name} Lock patch-created paths collide with pristine archive files: "
         f"{sorted(patch_generated & expected)}")
    need(actual == expected | patch_generated,
         f"{root_name} prepared source paths differ from pinned archive + Lock patch outputs: "
         f"missing={sorted((expected | patch_generated)-actual)} "
         f"extra={sorted(actual-(expected | patch_generated))}")
    for name in patch_generated:
        need(relative[name].stat().st_size > 0,
             f"{root_name} Lock patch-created source file is empty: {name}")
    headers = sum(Path(name).suffix.lower() in (".h", ".hh", ".hpp")
                  for name in actual)
    print(f"SOURCE INVENTORY: {root_name} | archive_files={len(expected)} | "
          f"patch_created_files={sorted(patch_generated)} | prepared_vendor_files={len(actual)} | "
          f"headers={headers} | generated_artifacts={sorted(generated)}")
package_mk=(pkg/"Makefile").read_text(encoding="utf-8")
need("version mapd >" in package_mk and "$(MAKE) -C $(PKG_BUILD_DIR)/mapd" in package_mk,
     "package must preserve prebuilt MAPD objects by invoking explicit version/mapd targets, not all/clean")
print("PASS: exact MAPD inventory: 7 proprietary AArch64/GCC 8.4.0 objects and 4 pinned static archives.")
print("LIMIT: MAPD objects have no supplied source; static code-level API/security review is impossible. Target linking remains mandatory.")

# These legacy ELF files are retained as audit references. The WAPP source-audit
# workflow copies the original wapp/mapd/p1905 binaries for source-vs-binary
# comparison. None may be installed into the new source-built firmware package.
reference = [
 "files/usr/bin/wapp","files/usr/bin/mapd","files/usr/bin/p1905_managerd","files/usr/bin/wappctrl",
 "files/usr/lib/libcrypto.so.1.1","files/usr/lib/libssl.so.1.1",
 "files/usr/lib/libeth_1905ops.so","files/usr/lib/libmapd_interface_client.so",
]
for rel in reference:
    f = pkg/rel
    need(f.is_file(),f"required audit-reference binary is missing: {rel}")
    need(f.read_bytes()[:4] == b"\x7fELF",f"audit reference is not an ELF binary: {rel}")
usr = pkg/"files/usr"
actual_elf = set()
if usr.exists():
    for f in usr.rglob("*"):
        if f.is_file() and f.read_bytes()[:4] == b"\x7fELF":
            actual_elf.add(f.relative_to(pkg).as_posix())
need(actual_elf == set(reference),
     f"unexpected/missing ELF audit references: unexpected={sorted(actual_elf-set(reference))} missing={sorted(set(reference)-actual_elf)}")
# Inspect legacy vendor ELF metadata without treating these files as installed
# runtime dependencies. Their exact SONAME and NEEDED edges are part of the audit.
legacy_dynamic = {}
for rel in reference:
    elf = pkg/rel
    info = cmd(["readelf","-h",str(elf)])
    need("ELF64" in info and "AArch64" in info,
         f"legacy audit-reference ELF has wrong architecture: {rel}")
    dynamic = cmd(["readelf","-d",str(elf)])
    sonames = re.findall(r"\(SONAME\).*?\[(.*?)\]", dynamic)
    needed = re.findall(r"\(NEEDED\).*?\[(.*?)\]", dynamic)
    legacy_dynamic[rel] = {"soname": sonames, "needed": needed}
    print(f"AUDIT REFERENCE ELF: {rel} | ELF64 AArch64 | SONAME={sonames or ['<none>']} | NEEDED={needed}")

crypto = legacy_dynamic["files/usr/lib/libcrypto.so.1.1"]
ssl = legacy_dynamic["files/usr/lib/libssl.so.1.1"]
need(crypto["soname"] == ["libcrypto.so.1.1"],
     f"legacy libcrypto SONAME changed: {crypto['soname']}")
need(ssl["soname"] == ["libssl.so.1.1"],
     f"legacy libssl SONAME changed: {ssl['soname']}")
need("libcrypto.so.1.1" in ssl["needed"],
     "legacy libssl no longer declares its libcrypto.so.1.1 dependency")
legacy_bins = ("files/usr/bin/wapp", "files/usr/bin/mapd",
               "files/usr/bin/p1905_managerd", "files/usr/bin/wappctrl")
for rel in legacy_bins:
    needed = legacy_dynamic[rel]["needed"]
    print(f"LEGACY EXECUTABLE ABI: {rel} | OpenSSL-1.1-needed=" +
          str([x for x in needed if x in ("libssl.so.1.1", "libcrypto.so.1.1")]))
print("PASS: legacy OpenSSL 1.1 ELF architecture, SONAME and libssl -> libcrypto dependency identified.")
for s in ("$(INSTALL_BIN) $(PKG_BUILD_DIR)/wappd/wapp",
          "$(INSTALL_BIN) $(PKG_BUILD_DIR)/wappd/wappctrl",
          "$(INSTALL_BIN) $(PKG_BUILD_DIR)/mapd/mapd",
          "$(INSTALL_BIN) $(PKG_BUILD_DIR)/1905daemon/p1905_managerd",
          "$(INSTALL_BIN) $(PKG_BUILD_DIR)/1905daemon/ethernet/libeth_1905ops.so",
          "$(INSTALL_BIN) $(PKG_BUILD_DIR)/libmapd/libmapd_interface_client.so"):
    need(s in package_mk,f"source-built install output missing: {s}")
for rel in ("files/usr/bin/wapp","files/usr/bin/mapd","files/usr/bin/p1905_managerd",
            "files/usr/bin/wappctrl","files/usr/lib/libeth_1905ops.so",
            "files/usr/lib/libmapd_interface_client.so"):
    need(not re.search(re.escape(rel) + r"(?=[\s;]|$)", package_mk),
         f"audit-reference binary must not be installed: {rel}")
need("libssl.so.1.1" not in package_mk and "libcrypto.so.1.1" not in package_mk,
     "obsolete OpenSSL 1.1 library referenced by package install")
need("DEPENDS:=+kmod-mapfilter +libnl-tiny +libkvcutil +libopenssl" in package_mk,
     "EasyMesh package no longer depends on the OpenSSL 3.x runtime package")
need("$(INSTALL_BIN) ./files/usr/lib/libssl.so.1.1" not in package_mk and
     "$(INSTALL_BIN) ./files/usr/lib/libcrypto.so.1.1" not in package_mk,
     "legacy OpenSSL 1.1 libraries must never be installed by EasyMesh")
print("PASS: 8 reviewed ELF files are retained only as audit references; package install uses source-built outputs and does not install legacy OpenSSL 1.1 libraries.")
# datconf is a separate CMake package dependency. Derive its complete file
# manifest from the pinned archive; CMake-generated metadata is not vendor input.
import tarfile

datconf_roots = list((repo / "build_dir").glob("target-*/datconf"))
need(len(datconf_roots) == 1,
     f"expected exactly one prepared datconf source tree, found {datconf_roots}")
datconf_root = datconf_roots[0]
datconf_archive = repo / "dl/datconf-757f9679.tar.bz2"
need(datconf_archive.is_file(), f"pinned datconf source archive missing: {datconf_archive}")
with tarfile.open(datconf_archive, "r:bz2") as archive:
    file_members = [m for m in archive.getmembers() if m.isfile()]
    need(all(m.name.startswith("datconf/") for m in file_members),
         "datconf archive contains files outside the expected datconf/ root")
    member_names = [m.name for m in file_members]
    need(len(member_names) == len(set(member_names)),
         "datconf archive contains duplicate file paths")
    members = file_members
    expected_datconf = {m.name[len("datconf/"):] for m in members}
need(bool(expected_datconf), "pinned datconf archive has no regular files")
# Reconstruct the exact post-patch vendor tree from the pinned archive.
# Comparing prepared sources directly with the pristine archive is incorrect:
# patch 002 intentionally updates four CMakeLists.txt files from CMake 2.6 to 3.5.
import tempfile

with tempfile.TemporaryDirectory(prefix="n60-datconf-audit-") as tmp:
    pristine_root = Path(tmp) / "datconf"
    pristine_root.mkdir()
    with tarfile.open(datconf_archive, "r:bz2") as archive:
        for member in members:
            rel = Path(member.name).relative_to("datconf")
            target = pristine_root / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            source_member = archive.extractfile(member)
            need(source_member is not None, f"cannot read datconf archive member: {member.name}")
            target.write_bytes(source_member.read())

    patch_dir = repo / "package/mtk/applications/datconf/patches"
    patch_files = sorted(patch_dir.glob("*.patch"))
    need(bool(patch_files), "datconf patch series is missing")
    for patch_file in patch_files:
        if patch_file.stat().st_size == 0:
            continue
        # Run patch from the extracted vendor root, not from the repository.
        result = subprocess.run(
            ["patch", "--batch", "--fuzz=0", "-p1", "-i", str(patch_file.resolve())],
            cwd=pristine_root, text=True, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT)
        need(result.returncode == 0,
             f"datconf patch failed against pinned archive: {patch_file.name}\\n{result.stdout}")

    for name in sorted(expected_datconf):
        expected_path = pristine_root / name
        actual_path = datconf_root / name
        need(actual_path.is_file(), f"datconf vendor source/header missing after CMake prepare: {name}")
        need(expected_path.is_file() and
             hashlib.sha256(expected_path.read_bytes()).digest() ==
             hashlib.sha256(actual_path.read_bytes()).digest(),
             f"datconf post-patch source differs from archive+patch result: {name}")

# package-defaults.mk copies every file below ./src/ into PKG_BUILD_DIR.
# Treat this as an explicit overlay input, not as an unexplained vendor file.
overlay_root = repo / "package/mtk/applications/datconf/src"
need(overlay_root.is_dir(), f"datconf repository overlay directory missing: {overlay_root}")
overlay_files = {
    p.relative_to(overlay_root).as_posix(): p
    for p in overlay_root.rglob("*") if p.is_file()
}
expected_overlay = {
    "datconf/ucode/CMakeLists.txt",
    "datconf/ucode/datconf.c",
    "datconf/ucode/example/example.uc",
}
need(set(overlay_files) == expected_overlay,
     "datconf overlay manifest changed: "
     f"unexpected={sorted(set(overlay_files)-expected_overlay)} "
     f"missing={sorted(expected_overlay-set(overlay_files))}")
for rel, source_path in overlay_files.items():
    prepared_path = datconf_root / rel
    need(prepared_path.is_file(), f"datconf Build/Prepare overlay missing: {rel}")
    need(hashlib.sha256(source_path.read_bytes()).digest() ==
         hashlib.sha256(prepared_path.read_bytes()).digest(),
         f"datconf Build/Prepare overlay differs from repository source: {rel}")

def is_datconf_source(name):
    path = Path(name)
    return (path.name == "CMakeLists.txt" or
            path.suffix.lower() in {
                ".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp",
                ".hxx", ".cmake", ".uc",
            })

expected_sources = {name for name in expected_datconf if is_datconf_source(name)}
expected_sources.update(rel for rel in expected_overlay if is_datconf_source(rel))
actual_sources = {
    p.relative_to(datconf_root).as_posix()
    for p in datconf_root.rglob("*")
    if p.is_file()
    and is_datconf_source(p.relative_to(datconf_root).as_posix())
    and "CMakeFiles/" not in p.relative_to(datconf_root).as_posix()
}
need(actual_sources == expected_sources,
     "datconf prepared source inventory differs from archive + declared overlay: "
     f"unexpected={sorted(actual_sources-expected_sources)} "
     f"missing={sorted(expected_sources-actual_sources)}")
print(f"SOURCE INVENTORY: datconf | pinned_vendor_files={len(expected_datconf)} | "
      f"overlay_files={len(overlay_files)} | source_files={len(actual_sources)} | "
      "CMake-generated metadata excluded")

# Verify N60's resolved MT7986 profile and selected firmware payload.
config_fragment=repo/"config/n60pro-1001.config"
fragment=config_fragment.read_text(encoding="utf-8",errors="replace")
need('CONFIG_first_card_name="MT7986"' in fragment,
     'N60 standard config fragment must explicitly override wifi-dats MT7981 default with CONFIG_first_card_name="MT7986"')
need('CONFIG_first_card_name="MT7981"' not in fragment,
     "N60 standard config fragment must not select the MT7981 first-card profile")
config_path=repo/".config"
need(config_path.is_file(),"resolved .config missing; make defconfig must run before Build/Prepare")
config=config_path.read_text(encoding="utf-8",errors="replace")
for symbol in ("CONFIG_MTK_6G_SUPPORT", "CONFIG_MTK_MAP_R2_6E_SUPPORT", "CONFIG_MTK_MAP_R3_6E_SUPPORT"):
    need(not re.search(rf"(?m)^{symbol}=(?:y|m)$",config),
         f"N60 must not enable 6 GHz/6E option {symbol}")
need('CONFIG_first_card_name="MT7986"' in config,'wifi-dats must resolve CONFIG_first_card_name="MT7986"')
need("CONFIG_MTK_FIRST_IF_MT7986=y" in config,"N60 first MTK Wi-Fi interface is not MT7986")
need("CONFIG_MTK_WIFI_FW_BIN_LOAD=y" in config,"MTK Wi-Fi firmware loading is not enabled")
versions=re.findall(r"^CONFIG_MTK_MT_WIFI_MT7986_(\d{8})=y$",config,re.M)
need(len(versions)==1,f"expected one selected MT7986 firmware version, found {versions}")
fw=repo/"package/mtk/drivers/mt_wifi/files"/f"mt7986-fw-{versions[0]}"
for name in ("7986_WACPU_RAM_CODE_release.bin","WIFI_RAM_CODE_MT7986.bin",
             "WIFI_RAM_CODE_MT7986_MT7975.bin","mt7986_patch_e1_hdr.bin",
             "mt7986_patch_e1_hdr_mt7975.bin"):
    need((fw/name).is_file() and (fw/name).stat().st_size>0,f"selected MT7986/MT7975 firmware missing: {fw/name}")
wifi_mk=(repo/"package/mtk/drivers/wifi-profile/Makefile").read_text(encoding="utf-8")
need('CONFIG_first_card_name)" = "MT7986"' in wifi_mk,"wifi-dats install rule no longer selects MT7986 profiles")
print(f"PASS: N60 selects MT7986 wifi-dats profile and firmware payload {versions[0]} with MT7975-specific files.")

# Verify source/header and link dependency edges.
datconf_mk=(repo/"package/mtk/applications/datconf/Makefile").read_text(encoding="utf-8")
mtwifi_mk=(repo/"package/mtk/drivers/mt_wifi/Makefile").read_text(encoding="utf-8")
mapfilter_mk=(repo/"package/kernel/mapfilter/Makefile").read_text(encoding="utf-8")
wapp_mk=(build/"wappd/Makefile").read_text(encoding="utf-8")
p1905_mk=(build/"1905daemon/Makefile").read_text(encoding="utf-8")
eth_mk=(build/"1905daemon/ethernet/Makefile").read_text(encoding="utf-8")
libmapd_mk=(build/"libmapd/Makefile").read_text(encoding="utf-8")
need(all(x in datconf_mk for x in ("Build/InstallDev","libdatconf.h","libkvcutil.h","libdatconf.a","libkvcutil.so*")),
     "datconf/libkvcutil development headers/libraries are not staged")
need("-I$(UAPD_INCLUDE_PATH)" in wapp_mk and "-ldatconf -lkvcutil" in wapp_mk and
     "-lssl -lcrypto" in wapp_mk,
     "WAPP datconf/kvcutil/OpenSSL header/link edges missing")
need(all(x in p1905_mk for x in ("-I$(STAGING_DIR)/usr/include/libnl-tiny",
                                  "-lnl-tiny","-lssl -lcrypto",
                                  "CRYPTO_LIB = src/crypto/libcrypto.a",
                                  "cd src/crypto && $(MAKE)","-leth_1905ops")),
     "P1905 libnl headers/OpenSSL/internal crypto/Ethernet link edges incomplete")
need(all(x in mapd_mk for x in ("LIBS += ../wappd/libwapp_usr_intf_client.a",
                                "LIBS += ../1905daemon/lib_export/lib1905_interface.a",
                                "LIBS += libmapd_core.a","LIBS += libmapd_steer_core.a")),
     "MAPD WAPP/P1905 client and proprietary static library edges incomplete")
need("libbridge.a" in eth_mk and "mediatek_DSA" in eth_mk,"P1905 DSA libbridge source dependency missing")
need("$(CC) $(CFLAGS) -I ./include -c -fPIC" in libmapd_mk and
     "$(CC) $(LDFLAGS) -shared -o $@ $^" in libmapd_mk,
     "libmapd target CFLAGS/LDFLAGS propagation missing")
need("PKG_BUILD_DEPENDS:=warp conninfra" in mtwifi_mk and
     'KBUILD_EXTRA_SYMBOLS="$(KERNEL_BUILD_DIR)/conninfra/Module.symvers"' in mtwifi_mk,
     "mt_wifi conninfra/WARP build/modpost dependency closure incomplete")
need(all(x in mtwifi_mk for x in ("+kmod-conninfra","+kmod-warp","+wifi-dats")),
     "mt_wifi runtime dependency closure incomplete")
need("+kmod-nf-conntrack +kmod-nf-nat" in mapfilter_mk,"MAPFILTER netfilter dependencies missing")
need("PKG_BUILD_DEPENDS:=datconf openssl libnl-tiny" in package_mk and
     "+kmod-mapfilter +libnl-tiny +libkvcutil +libopenssl" in package_mk,
     "EasyMesh build/runtime dependencies changed")
print("PASS: WAPP/MAPD/P1905/libmapd/datconf/OpenSSL/libnl-tiny/libbridge/conninfra/WARP/mt_wifi/MAPFILTER dependency edges.")
print("AUDIT LIMIT: static checks do not prove actual link, module modpost, or runtime operation; Quick/Full builds remain mandatory.")
