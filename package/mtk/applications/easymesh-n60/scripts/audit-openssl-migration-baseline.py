#!/usr/bin/env python3
"""Compare pinned OpenSSL 1.1.1w and 3.5.9 public-header inventories without modifying sources."""
import argparse
import csv
import hashlib
import importlib.util
import json
import re
from pathlib import Path

def sha256(path):
    h=hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda:f.read(1024*1024),b""):
            h.update(chunk)
    return h.hexdigest()

def header_files(root):
    base=root/"include/openssl"
    if not base.is_dir():
        raise SystemExit("missing OpenSSL public header directory: "+str(base))
    return sorted(base.rglob("*.h"))

def token_present(files, api):
    rx=re.compile(r"\b"+re.escape(api)+r"\b")
    return any(rx.search(p.read_text(encoding="utf-8",errors="replace")) for p in files)

def header_digest(files):
    h=hashlib.sha256()
    for p in files:
        rel=p.as_posix().split("/include/openssl/",1)[-1]
        h.update(rel.encode()); h.update(b"\0"); h.update(bytes.fromhex(sha256(p))); h.update(b"\n")
    return h.hexdigest()

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--repo-root",type=Path,required=True)
    ap.add_argument("--openssl-1111-source",type=Path,required=True)
    ap.add_argument("--openssl-359-source",type=Path,required=True)
    ap.add_argument("--archive-1111",type=Path,required=True)
    ap.add_argument("--archive-359",type=Path,required=True)
    ap.add_argument("--output-dir",type=Path,required=True)
    a=ap.parse_args()

    lock_path=a.repo_root/"package/mtk/applications/easymesh-n60/tests/openssl-migration-baseline.lock.json"
    map_path=a.repo_root/"package/mtk/applications/easymesh-n60/tests/openssl-111-to-359-migration-map.csv"
    makefile=a.repo_root/"package/libs/openssl/Makefile"
    lock=json.loads(lock_path.read_text())
    mk=makefile.read_text()
    version=re.search(r"(?m)^PKG_VERSION:=([^\s#]+)",mk)
    pkg_hash=re.search(r"(?m)^PKG_HASH:=([0-9a-f]{64})",mk)
    if not version or version.group(1)!="3.5.9" or not pkg_hash:
        raise SystemExit("OpenWrt OpenSSL package is not pinned to the expected 3.5.9 baseline")
    if pkg_hash.group(1)!=lock["to"]["sha256"]:
        raise SystemExit("OpenSSL 3.5.9 package PKG_HASH differs from migration lock")
    h1111=sha256(a.archive_1111); h359=sha256(a.archive_359)
    if h1111!=lock["from"]["sha256"]:
        raise SystemExit("OpenSSL 1.1.1w archive SHA256 mismatch: "+h1111)
    if h359!=lock["to"]["sha256"]:
        raise SystemExit("OpenSSL 3.5.9 archive SHA256 mismatch: "+h359)

    spec=importlib.util.spec_from_file_location("openssl_inventory",a.repo_root/"package/mtk/applications/easymesh-n60/tests/test-openssl-api-inventory.py")
    mod=importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)
    names1111,depr1111=mod.catalog(a.openssl_1111_source)
    names359,depr359=mod.catalog(a.openssl_359_source)
    files1111=header_files(a.openssl_1111_source); files359=header_files(a.openssl_359_source)
    with map_path.open(encoding="utf-8",newline="") as f:
        mapping=list(csv.DictReader(f))
    if len(mapping)!=64 or len({r["api"] for r in mapping})!=64:
        raise SystemExit("migration map must contain exactly 64 unique API rows; found "+str(len(mapping)))

    rows=[]; failures=[]
    for item in mapping:
        api=item["api"]
        present1111=token_present(files1111,api)
        present359=token_present(files359,api)
        deprecated359=api in depr359
        deprecated1111=api in depr1111
        if not present359 or not deprecated359:
            failures.append("API not found as deprecated in OpenSSL 3.5.9 headers: "+api)
        rows.append({
            "api":api,
            "observed_calls_run_42724660705":item["observed_calls_run_42724660705"],
            "observed_components":item["observed_components"],
            "present_in_1_1_1w_headers":str(present1111).lower(),
            "deprecated_in_1_1_1w_headers":str(deprecated1111).lower(),
            "present_in_3_5_9_headers":str(present359).lower(),
            "deprecated_in_3_5_9_headers":str(deprecated359).lower(),
            "deprecation_macro_3_5_9":depr359.get(api,""),
            "migration_status":item["migration_status"],
            "approval":item["approval"],
            "candidate_replacement":item["proposed_replacement"],
            "official_target_manual_url":item["official_target_manual_url"],
            "semantic_review_requirements":item["semantic_review_requirements"]
        })

    a.output_dir.mkdir(parents=True,exist_ok=True)
    fields=list(rows[0])
    with (a.output_dir/"openssl-1111-to-359-header-delta.csv").open("w",encoding="utf-8",newline="") as f:
        w=csv.DictWriter(f,fieldnames=fields); w.writeheader(); w.writerows(rows)
    summary={
        "baseline_id":lock["baseline_id"],
        "from_version":lock["from"]["version"],
        "to_version":lock["to"]["version"],
        "archive_sha256":{"1.1.1w":h1111,"3.5.9":h359},
        "header_tree_sha256":{"1.1.1w":header_digest(files1111),"3.5.9":header_digest(files359)},
        "header_api_names":{"1.1.1w":len(names1111),"3.5.9":len(names359)},
        "deprecated_api_declarations":{"1.1.1w":len(depr1111),"3.5.9":len(depr359)},
        "migration_map_rows":len(mapping),
        "migration_map_apis_present_and_deprecated_in_3_5_9":sum(1 for r in rows if r["present_in_3_5_9_headers"]=="true" and r["deprecated_in_3_5_9_headers"]=="true"),
        "api_presence_in_1_1_1w":sum(1 for r in rows if r["present_in_1_1_1w_headers"]=="true"),
        "failures":failures,
        "limitations":["header symbol presence is not proof of source-level call reachability or semantic equivalence","the 1.1.1w deprecation parser is informational; API-specific migration decisions require official manual review"]
    }
    (a.output_dir/"openssl-migration-baseline.json").write_text(json.dumps(summary,indent=2)+"\n")
    print(json.dumps(summary,indent=2))
    return 1 if failures else 0

if __name__=="__main__":
    raise SystemExit(main())
