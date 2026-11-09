#!/usr/bin/env python3
"""Map upstream changes to vendor components and required compatibility evidence."""
import argparse, fnmatch, hashlib, json, subprocess
from pathlib import Path
def git(root,*args):
    return subprocess.check_output(["git","-C",str(root),*args],text=True).strip()
def main():
    p=argparse.ArgumentParser()
    p.add_argument("--repo",default="."); p.add_argument("--base-sha",required=True); p.add_argument("--target-sha",required=True); p.add_argument("--out",default="upstream-compatibility-report")
    a=p.parse_args(); root=Path(a.repo).resolve(); base=a.base_sha; target=a.target_sha
    git(root,"cat-file","-e",base+"^{commit}"); git(root,"cat-file","-e",target+"^{commit}")
    subprocess.run(["git","-C",str(root),"merge-base","--is-ancestor",base,target],check=True)
    raw=git(root,"diff","--name-status","-M",base,target)
    changes=[]
    for line in raw.splitlines():
        f=line.split("\t"); status=f[0]
        for path in (f[1:] if status.startswith(("R","C")) else f[1:2]): changes.append({"status":status,"path":path})
    lock=json.loads((root/"package/mtk/upstream-compatibility.lock.json").read_text())
    m=json.loads((root/"package/mtk/upstream-compatibility-matrix.json").read_text())
    components=set(); risks=set(); unmapped=[]; out_changes=[]
    for item in changes:
        matches=[r for r in m["path_rules"] if fnmatch.fnmatchcase(item["path"],r["pattern"])]
        if matches:
            item["classification"]="mapped"; item["rules"]=[r["pattern"] for r in matches]
            item["risks"]=sorted({x for r in matches for x in r["risks"]})
            item["components"]=sorted({x for r in matches for x in r["components"]})
            risks.update(item["risks"]); components.update(item["components"])
        else:
            item["classification"]="unmapped-protected" if any(item["path"].startswith(x) for x in m["protected_roots"]) else "non-build-or-documentation"
            if item["classification"]=="unmapped-protected": unmapped.append(item["path"])
        out_changes.append(item)
    impacted=[]; evidence=set()
    for name in sorted(components):
        c=m["components"][name]; impacted.append({"component":name,"locked_sources":c["sources"],"risks":c["risks"],"required_evidence":c["evidence"]}); evidence.update(c["evidence"])
    verdict="BLOCKED_UNMAPPED_SOURCE_CHANGE" if unmapped else "NO_UPSTREAM_DELTA" if not changes else "REVIEW_REQUIRED_COMPATIBILITY_NOT_YET_PROVEN" if components or risks else "DOCUMENTATION_OR_NONBUILD_DELTA"
    sha=lambda x:hashlib.sha256(x.read_bytes()).hexdigest()
    report={"schema_version":1,"upstream_repository":lock["upstream_repository"],"upstream_branch":lock["upstream_branch"],"last_integrated_upstream_sha":base,"observed_upstream_sha":target,"compare_range":base+".."+target,"changed_file_count":len(changes),"changes":out_changes,"risk_domains":sorted(risks),"impacted_components":impacted,"required_compatibility_evidence":sorted(evidence),"vendor_lock_sha256":sha(root/"package/mtk/vendor-sources.lock.json"),"upstream_lock_sha256":sha(root/"package/mtk/upstream-compatibility.lock.json"),"compatibility_matrix_sha256":sha(root/"package/mtk/upstream-compatibility-matrix.json"),"verdict":verdict,"policy":"Impact mapping is not ABI/runtime proof. Relevant upstream changes remain unapproved until all required build, link, module and device evidence is attached and reviewed."}
    dest=root/a.out; dest.mkdir(parents=True,exist_ok=True)
    (dest/"upstream-compatibility-report.json").write_text(json.dumps(report,indent=2,sort_keys=True)+"\n")
    lines=["# N60 Pro upstream compatibility impact report","", "Upstream: "+lock["upstream_repository"]+" @ "+lock["upstream_branch"],"Baseline: "+base,"Observed: "+target,"Changed files: "+str(len(changes)),"Verdict: "+verdict,"","## Risk domains"]+["- "+x for x in sorted(risks)]+["","## Impacted components"]
    lines += ["- "+c["component"]+"; sources="+", ".join(c["locked_sources"])+"; evidence="+", ".join(c["required_evidence"]) for c in impacted]
    lines += ["","## Changed paths"]+["- "+x["status"]+" "+x["path"]+" ["+x["classification"]+"]" for x in out_changes]+["","## Gate policy",report["policy"],""]
    (dest/"upstream-compatibility-report.md").write_text("\n".join(lines))
    print("UPSTREAM_IMPACT_VERDICT="+verdict)
    if unmapped: raise SystemExit("FAIL: unmapped protected paths: "+", ".join(unmapped))
if __name__=="__main__": main()
