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
    return sorted(p for p in base.rglob("*") if p.is_file() and (p.name.endswith(".h") or p.name.endswith(".h.in")))

def header_status_359(present,deprecated):
    if not present: return "NOT_PRESENT"
    return "PRESENT_DEPRECATED" if deprecated else "PRESENT_NOT_DEPRECATED"

def token_present(files, api):
    rx=re.compile(r"\b"+re.escape(api)+r"\b")
    return any(rx.search(p.read_text(encoding="utf-8",errors="replace")) for p in files)

def deprecation_annotation(files, api):
    rx=re.compile(r"((?:OSSL_)?DEPRECATEDIN_[A-Za-z0-9_]+)[^;{}]{0,700}?\b"+re.escape(api)+r"\s*\(")
    for p in files:
        m=rx.search(p.read_text(encoding="utf-8",errors="replace"))
        if m:
            return m.group(1)
    return ""

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
    ap.add_argument("--git-sha",required=True)
    ap.add_argument("--run-id",required=True)
    ap.add_argument("--run-attempt",required=True)
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
    v1111=(a.openssl_1111_source/"include/openssl/opensslv.h").read_text(encoding="utf-8",errors="replace")
    if "OpenSSL 1.1.1w" not in v1111:
        raise SystemExit("OpenSSL source tree is not the pinned 1.1.1w release")
    v359=(a.openssl_359_source/"VERSION.dat").read_text(encoding="utf-8",errors="replace")
    version_fields={}
    for line in v359.splitlines():
        if "=" in line:
            k,v=line.split("=",1); version_fields[k.strip()]=v.strip().strip('"')
    if tuple(version_fields.get(k) for k in ("MAJOR","MINOR","PATCH")) != ("3","5","9"):
        raise SystemExit("OpenSSL source tree is not the pinned 3.5.9 release")
    names1111,depr1111=mod.catalog(a.openssl_1111_source)
    names359,depr359=mod.catalog(a.openssl_359_source)
    files1111=header_files(a.openssl_1111_source); files359=header_files(a.openssl_359_source)
    with map_path.open(encoding="utf-8",newline="") as f:
        mapping=list(csv.DictReader(f))
    if len(mapping)!=68 or len({r["api"] for r in mapping})!=68:
        raise SystemExit("migration map must contain exactly 68 unique API rows; found "+str(len(mapping)))

    rows=[]; failures=[]
    for item in mapping:
        api=item["api"]
        present1111=token_present(files1111,api)
        present359=token_present(files359,api)
        deprecated359=api in depr359
        deprecated1111=deprecation_annotation(files1111,api)
        if not present1111:
            failures.append("API not found in OpenSSL 1.1.1w headers: "+api)
        # OpenSSL 3.x deprecation is not a migration verdict. Keep every
        # 1.1.1w source candidate in the traceability report and record its
        # actual 3.5.9 header/deprecation state without failing the baseline.
        rows.append({
            "api":api,
            "observed_lexical_occurrences":item["observed_lexical_occurrences"],
            "observed_components":item["observed_components"],
            "source_reachability_status":item["source_reachability_status"],
            "source_reachability_evidence":item["source_reachability_evidence"],
            "present_in_1_1_1w_headers":str(present1111).lower(),
            "deprecation_annotation_1_1_1w":deprecated1111,
            "present_in_3_5_9_headers":str(present359).lower(),
            "deprecated_in_3_5_9_headers":str(deprecated359).lower(),
            "header_status_3_5_9":header_status_359(present359,deprecated359),
            "deprecation_macro_3_5_9":depr359.get(api,""),
            "migration_status":item["migration_status"],
            "approval":item["approval"],
            "candidate_replacement":item["proposed_replacement"],
            "official_mapping_kind":item["official_mapping_kind"],
            "official_mapping_section":item["official_mapping_section"],
            "official_target_manual_url":item["official_target_manual_url"],
            "semantic_review_requirements":item["semantic_review_requirements"]
        })

    a.output_dir.mkdir(parents=True,exist_ok=True)
    fields=list(rows[0])
    with (a.output_dir/"openssl-1111-to-359-header-delta.csv").open("w",encoding="utf-8",newline="") as f:
        w=csv.DictWriter(f,fieldnames=fields); w.writeheader(); w.writerows(rows)
    summary={
        "schema_version":2,
        "baseline_id":lock["baseline_id"],
        "git_sha":a.git_sha,
        "run_id":int(a.run_id),
        "run_attempt":int(a.run_attempt),
        "input_sha256":{
            "migration_lock":sha256(lock_path),
            "migration_map":sha256(map_path),
            "openssl_package_makefile":sha256(makefile),
            "api_inventory_script":sha256(a.repo_root/"package/mtk/applications/easymesh-n60/tests/test-openssl-api-inventory.py"),
            "api_inventory_selftest":sha256(a.repo_root/"package/mtk/applications/easymesh-n60/tests/test-openssl-api-inventory-selftest.py"),
            "baseline_auditor_script":sha256(a.repo_root/"package/mtk/applications/easymesh-n60/scripts/audit-openssl-migration-baseline.py"),
            "baseline_auditor_selftest":sha256(a.repo_root/"package/mtk/applications/easymesh-n60/tests/test-openssl-migration-baseline-selftest.py"),
            "api_policy":sha256(a.repo_root/"package/mtk/applications/easymesh-n60/tests/openssl-api-policy.json")
        },
        "from_version":lock["from"]["version"],
        "to_version":lock["to"]["version"],
        "archive_sha256":{"1.1.1w":h1111,"3.5.9":h359},
        "header_tree_sha256":{"1.1.1w":header_digest(files1111),"3.5.9":header_digest(files359)},
        "header_api_names":{"1.1.1w":len(names1111),"3.5.9":len(names359)},
        "deprecated_api_declarations":{"3.5.9":len(depr359)},
        "migration_map_rows":len(mapping),
        "migration_map_apis_present_in_1_1_1w":sum(1 for r in rows if r["present_in_1_1_1w_headers"]=="true"),
        "migration_map_apis_deprecated_in_3_5_9":sum(1 for r in rows if r["present_in_3_5_9_headers"]=="true" and r["deprecated_in_3_5_9_headers"]=="true"),
        "migration_map_apis_present_and_deprecated_in_3_5_9":sum(1 for r in rows if r["present_in_3_5_9_headers"]=="true" and r["deprecated_in_3_5_9_headers"]=="true"),
        "migration_map_apis_with_1_1_1w_deprecation_annotation":sum(1 for r in rows if r["deprecation_annotation_1_1_1w"]),
        "api_presence_in_1_1_1w":sum(1 for r in rows if r["present_in_1_1_1w_headers"]=="true"),
        "failures":failures,
        "limitations":["header symbol presence is not proof of source-level call reachability or semantic equivalence","the 1.1.1w deprecation parser is informational; API-specific migration decisions require official manual review"]
    }
    (a.output_dir/"openssl-migration-baseline.json").write_text(json.dumps(summary,indent=2)+"\n")
    print(json.dumps(summary,indent=2))
    return 1 if failures else 0

if __name__=="__main__":
    raise SystemExit(main())
