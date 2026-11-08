#!/usr/bin/env python3
"""Canonical vendor lock: downloads, real GNU Make evaluation and patch order."""
from __future__ import annotations
import argparse, hashlib, json, subprocess, time, urllib.error, urllib.request
from pathlib import Path
LOCK="package/mtk/vendor-sources.lock.json"

def fail(message): raise SystemExit("FAIL: "+message)
def load(repo): return json.loads((repo/LOCK).read_text(encoding="utf-8"))

def download(repo, dl_dir, ids):
    sources={x["id"]:x for x in load(repo)["sources"]}
    missing=set(ids)-sources.keys()
    if missing: fail("unknown lock source id(s): "+", ".join(sorted(missing)))
    dl_dir.mkdir(parents=True,exist_ok=True)
    for sid in ids:
        item=sources[sid]; target=dl_dir/item["archive"]
        if not target.is_file():
            req=urllib.request.Request(item["url"],headers={"User-Agent":"N60-vendor-lock/2"})
            partial=target.with_name(target.name+".part")
            last_error=None
            for attempt in range(1,5):
                partial.unlink(missing_ok=True)
                try:
                    with urllib.request.urlopen(req,timeout=180) as src,partial.open("wb") as dst:
                        while True:
                            block=src.read(1024*1024)
                            if not block: break
                            dst.write(block)
                    partial.replace(target)
                    last_error=None
                    break
                except urllib.error.HTTPError as exc:
                    partial.unlink(missing_ok=True)
                    if exc.code not in (408,425,429) and exc.code < 500:
                        fail(f"{sid} download returned non-retryable HTTP {exc.code}: {exc.reason}")
                    last_error=exc
                except (TimeoutError,ConnectionError,urllib.error.URLError) as exc:
                    partial.unlink(missing_ok=True)
                    last_error=exc
                if attempt < 4:
                    delay=5*(2**(attempt-1))
                    print(f"LOCK DOWNLOAD RETRY: {sid} attempt={attempt}/4 error={last_error!r}; retrying in {delay}s",flush=True)
                    time.sleep(delay)
            if last_error is not None:
                fail(f"{sid} download failed after 4 attempts: {last_error!r}")
        digest=hashlib.sha256(target.read_bytes()).hexdigest()
        if digest!=item["sha256"]:
            target.unlink(missing_ok=True); fail(f"{sid} SHA256 mismatch: {digest} != {item['sha256']}")
        print(f"LOCK DOWNLOAD PASS: {sid} {item['archive']} sha256={digest}")

def verify_downloads(repo, dl_dir, ids):
    sources={x["id"]:x for x in load(repo)["sources"]}
    missing=set(ids)-sources.keys()
    if missing: fail("unknown lock source id(s): "+", ".join(sorted(missing)))
    if not dl_dir.is_dir(): fail("download directory missing: "+str(dl_dir))
    for sid in ids:
        item=sources[sid]; target=dl_dir/item["archive"]
        if not target.is_file(): fail(sid+" native Package download missing: "+str(target))
        digest=hashlib.sha256(target.read_bytes()).hexdigest()
        if digest!=item["sha256"]: fail(sid+" native Package download SHA256 mismatch: "+digest+" != "+item["sha256"])
        print(f"NATIVE PACKAGE DOWNLOAD PASS: {sid} {item['archive']} sha256={digest}")

def make_values(repo,item):
    package_makefile=item["package_makefile"]
    package_dir=(repo/package_makefile).parent
    config=repo/".config"
    if not config.is_file():
        fail("N60 Pro normalized .config is missing; run cp config/n60pro-1001.config .config && make defconfig first")
    probe="""# Match native Package evaluation: CURDIR is the Package directory.
-include $(TOPDIR)/.config
include Makefile
.PHONY: __n60_vendor_dump
__n60_vendor_dump:
\t@printf '%s\\n' 'PKG_NAME=$(PKG_NAME)' 'PKG_VERSION=$(PKG_VERSION)' 'PKG_SOURCE=$(PKG_SOURCE)' 'PKG_SOURCE_URL=$(PKG_SOURCE_URL)' 'PKG_HASH=$(PKG_HASH)' 'PKG_BUILD_DIR=$(PKG_BUILD_DIR)' 'PATCH_DIR=$(PATCH_DIR)' 'BUILD_DIR=$(BUILD_DIR)' 'KERNEL_BUILD_DIR=$(KERNEL_BUILD_DIR)' 'REPO_URL=$(REPO_URL)' 'CONFIG_MTK_MT_WIFI_DRIVER_VERSION_7673=$(CONFIG_MTK_MT_WIFI_DRIVER_VERSION_7673)' 'CURDIR=$(CURDIR)'
"""
    cmd=["make","--no-print-directory","--silent","-C",str(package_dir),"-f","-","TOPDIR="+str(repo),"__n60_vendor_dump"]
    proc=subprocess.run(cmd,input=probe,text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,cwd=repo)
    if proc.returncode: fail(item["id"]+" GNU Make evaluation failed:\\n"+proc.stdout)
    values={}
    for line in proc.stdout.splitlines():
        if "=" in line:
            k,v=line.split("=",1); values[k]=v.strip()
    for key in ("PKG_BUILD_DIR","PATCH_DIR"):
        if not values.get(key): fail(item["id"]+" GNU Make returned empty "+key+": "+proc.stdout)
    for key in ("PKG_SOURCE","PKG_SOURCE_URL","PKG_HASH","REPO_URL","PKG_VERSION"):
        values.setdefault(key,"")
    if item["id"]=="mtwifi":
        if values.get("CONFIG_MTK_MT_WIFI_DRIVER_VERSION_7673")!="y":
            fail("N60 Pro config must select CONFIG_MTK_MT_WIFI_DRIVER_VERSION_7673=y; got "+repr(values.get("CONFIG_MTK_MT_WIFI_DRIVER_VERSION_7673")))
        if values.get("PKG_VERSION")!="7.6.7.3":
            fail("N60 Pro MT Wi-Fi package version must resolve to 7.6.7.3; got "+repr(values.get("PKG_VERSION")))
    return values

def relative(repo,package_dir,value,label,sid):
    p=Path(value); p=p if p.is_absolute() else package_dir/p
    try: return p.resolve().relative_to(repo.resolve()).as_posix()
    except ValueError: fail(sid+" "+label+" escapes repository: "+value)

def verify_packages(repo):
    lock=load(repo); seen=set()
    for item in lock["sources"]:
        sid=item["id"]; scope=item.get("source_scope")
        if sid in seen: fail("duplicate source id: "+sid)
        seen.add(sid)
        if scope not in ("manual-package-prepare","auxiliary-audit-only","openwrt-package"):
            fail(sid+" missing/invalid source_scope")
        if scope=="auxiliary-audit-only":
            if item.get("expected_build_dir") is not None or item.get("expected_patch_dir") is not None:
                fail(sid+" auxiliary source must not declare Package build/patch paths")
            print("PACKAGE SCOPE PASS: "+sid+" auxiliary-audit-only"); continue
        if not item.get("expected_build_dir") or not item.get("expected_patch_dir"):
            fail(sid+" Lock requires expected_build_dir and expected_patch_dir")
        package_dir=(repo/item["package_makefile"]).parent
        if not (repo/item["package_makefile"]).is_file(): fail(sid+" Package Makefile missing")
        values=make_values(repo,item)
        build=relative(repo,package_dir,values["PKG_BUILD_DIR"],"PKG_BUILD_DIR",sid)
        patch=relative(repo,package_dir,values["PATCH_DIR"],"PATCH_DIR",sid)
        if build!=item["expected_build_dir"]: fail(sid+" GNU Make PKG_BUILD_DIR mismatch: "+build+" != "+item["expected_build_dir"])
        if patch!=item["expected_patch_dir"]: fail(sid+" GNU Make PATCH_DIR mismatch: "+patch+" != "+item["expected_patch_dir"])
        if scope=="openwrt-package":
            source_var=item.get("source_var","PKG_SOURCE")
            hash_var=item.get("hash_var","PKG_HASH")
            source_url_var=item.get("source_url_var","PKG_SOURCE_URL")
            expected_base=item["url"].rsplit("/",1)[0]
            expected={source_var:item["archive"],hash_var:item["sha256"],
                      "PKG_SOURCE_URL":expected_base,source_url_var:expected_base}
            for key,value in expected.items():
                if values.get(key)!=value:
                    fail(sid+" GNU Make "+key+" mismatch: "+repr(values.get(key))+" != "+repr(value))
            if item["url"] != expected_base + "/" + values[source_var]:
                fail(sid+" Lock URL does not resolve from evaluated Package source URL and filename")
        else:
            if any(values.get(k) for k in ("PKG_SOURCE","PKG_SOURCE_URL","PKG_HASH")):
                fail(sid+" manual Package unexpectedly defines native source download variables")
        print("GNU MAKE PACKAGE VARS PASS: "+sid+" scope="+scope+" PKG_SOURCE="+values["PKG_SOURCE"]+" PKG_SOURCE_URL="+values["PKG_SOURCE_URL"]+" PKG_HASH="+values["PKG_HASH"]+" PKG_BUILD_DIR="+build+" PATCH_DIR="+patch)

def patch_set(repo,sid):
    matches=[p for p in load(repo)["patch_sets"] if p.get("id")==sid]
    if len(matches)!=1: fail("Lock patch set missing/duplicated: "+sid)
    entry=matches[0]; directory=repo/entry["directory"]
    if not directory.is_dir(): fail("locked patch directory missing: "+entry["directory"])
    order=list(entry.get("application_order",[]))+list(entry.get("post_normalize_order",[]))
    if len(order)!=len(set(order)): fail(sid+" Lock has duplicate patch entries")
    post_order=list(entry.get("post_normalize_order",[]))
    root_suffixes=entry.get("post_normalize_root_suffixes",{})
    if post_order and (not isinstance(root_suffixes,dict) or set(root_suffixes)!=set(post_order)):
        fail(sid+" Lock must declare exactly one post_normalize_root_suffixes entry per post-normalize patch")
    if not post_order and root_suffixes:
        fail(sid+" declares post-normalize roots without post-normalize patches")
    for patch_name,suffix in root_suffixes.items():
        if not isinstance(suffix,str) or suffix.startswith("/") or ".." in Path(suffix).parts:
            fail(sid+" has unsafe post-normalize root suffix for "+patch_name)
    actual=sorted(p.name for p in directory.glob("*.patch"))
    if sorted(order)!=actual:
        fail(sid+" Lock inventory mismatch; missing="+repr(sorted(set(order)-set(actual)))+" unlisted="+repr(sorted(set(actual)-set(order))))
    # OpenWrt's native PatchDir sorts filenames (or follows series under Quilt).
    # Require the canonical Lock order to be identical to that real native order.
    if sid in {"mtwifi-7673","conninfra","warp","datconf","mapfilter"}:
        native_order=list(entry.get("application_order",[]))
        if native_order != actual:
            fail(sid+" Lock order differs from OpenWrt native lexical patch order")
        series=directory/"series"
        if series.is_file():
            declared=[line.strip() for line in series.read_text(encoding="utf-8").splitlines()
                      if line.strip() and not line.lstrip().startswith("#")]
            if declared != native_order:
                fail(sid+" Quilt series differs from canonical Lock order")
    return entry

def print_patch_order(repo,sid,phase):
    entry=patch_set(repo,sid)
    names=entry.get("application_order",[]) if phase=="application" else entry.get("post_normalize_order",[]) if phase=="post_normalize" else entry.get("application_order",[])+entry.get("post_normalize_order",[])
    if not names: fail(sid+" has no patches in phase "+phase)
    for name in names: print(name)

def print_patch_root(repo,sid,phase,name):
    if phase!="post_normalize": fail("patch-root is only valid for post_normalize")
    entry=patch_set(repo,sid)
    if name not in entry.get("post_normalize_order",[]):
        fail(sid+" patch is not in post_normalize order: "+name)
    roots=entry.get("post_normalize_root_suffixes",{})
    if set(roots)!=set(entry.get("post_normalize_order",[])):
        fail(sid+" post-normalize root mapping is incomplete")
    print(roots[name])

def main():
    p=argparse.ArgumentParser(); sub=p.add_subparsers(dest="cmd",required=True)
    d=sub.add_parser("download"); d.add_argument("--repo",required=True,type=Path); d.add_argument("--dl-dir",required=True,type=Path); d.add_argument("--ids",nargs="+",required=True)
    v=sub.add_parser("verify-packages"); v.add_argument("--repo",required=True,type=Path)
    x=sub.add_parser("verify-downloads"); x.add_argument("--repo",required=True,type=Path); x.add_argument("--dl-dir",required=True,type=Path); x.add_argument("--ids",nargs="+",required=True)
    q=sub.add_parser("patch-order"); q.add_argument("--repo",required=True,type=Path); q.add_argument("--set",required=True); q.add_argument("--phase",choices=("application","post_normalize","all"),default="all")
    r=sub.add_parser("patch-root"); r.add_argument("--repo",required=True,type=Path); r.add_argument("--set",required=True); r.add_argument("--phase",choices=("post_normalize",),required=True); r.add_argument("--name",required=True)
    a=p.parse_args()
    if a.cmd=="download": download(a.repo,a.dl_dir,a.ids)
    elif a.cmd=="verify-packages": verify_packages(a.repo)
    elif a.cmd=="verify-downloads": verify_downloads(a.repo,a.dl_dir,a.ids)
    elif a.cmd=="patch-root": print_patch_root(a.repo,a.set,a.phase,a.name)
    else: print_patch_order(a.repo,a.set,a.phase)
if __name__=="__main__": main()
