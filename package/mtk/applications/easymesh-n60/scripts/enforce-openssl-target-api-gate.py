#!/usr/bin/env python3
"""Enforce OpenSSL migration policy only for exact, active N60 target call sites."""
import argparse,csv,hashlib,json,re,subprocess,sys
from collections import Counter
from pathlib import Path

ALLOWED={"DIRECT_REPLACEMENT","SEMANTIC_ADAPTATION","LEGACY_RETAINED","REQUIRES_REDESIGN","BLOCKED"}
REACH={"ACTIVE","EXCLUDED_WITH_EVIDENCE","UNKNOWN_FAIL_CLOSED"}

def sha256(path):
 h=hashlib.sha256()
 with Path(path).open("rb") as f:
  for chunk in iter(lambda:f.read(1024*1024),b""): h.update(chunk)
 return h.hexdigest()

def load_json(path):
 return json.loads(Path(path).read_text(encoding="utf-8"))

def key(row):
 return (row.get("component"),row.get("path"),int(row.get("line",0)),row.get("api"))

def observe_preprocessed_output(path,source_path,line_number,api):
 marker=re.compile(r'^#\s*(\d+)\s+"([^"]+)"')
 call=re.compile(r"\b"+re.escape(api)+r"\s*\(")
 current=None; lineno=1; emitted=False; hit=False
 for text in Path(path).read_text(encoding="utf-8",errors="replace").splitlines():
  m=marker.match(text)
  if m:
   current=Path(m.group(2)).resolve(); lineno=int(m.group(1)); continue
  if text.lstrip().startswith("#"): continue
  if current==source_path and lineno==line_number:
   emitted=True
   if call.search(text): hit=True
  if current: lineno+=1
 return emitted,hit


REQUIRED_EASYMESH_COMPONENTS={"wappd","mapd","1905daemon","libmapd"}

def build_easymesh_api_subset(inventory_rows,callsites,noncalls,macro_rows,migration_map,delta_rows=None):
 """Retain every original EasyMesh API candidate; isolate target-ACTIVE calls for migration."""
 delta_by_api={r.get("api"):r for r in (delta_rows or []) if r.get("api")}
 rows={}
 def item(api):
  if api not in rows:
   mr=migration_map.get(api,{})
   try: baseline_count=int(mr.get("observed_lexical_occurrences") or 0)
   except (TypeError,ValueError): baseline_count=0
   rows[api]={"api":api,"components":set(x for x in mr.get("observed_components","").split(";") if x),
    "baseline_lexical_occurrences":baseline_count,"pristine_call_count":None,"prepared_call_count":None,
    "source_reference_count":0,"active_call_sites":0,"excluded_call_sites":0,"unknown_call_sites":0,
    "declaration_references":0,"other_non_call_references":0,
    "macro_references":0,"macro_active":0,"macro_excluded":0,"macro_unknown":0,"source_locations":[]}
  return rows[api]
 for api in migration_map: item(api)
 for r in inventory_rows:
  if not r.get("deprecated_macro"): continue
  x=item(r["api"]); x["components"].add(r["component"]); x["source_reference_count"]+=1
  x["source_locations"].append({"component":r["component"],"path":r["path"],"line":int(r["line"]),"kind":"LEXICAL_REFERENCE"})
 for r in callsites:
  x=item(r["api"]); x["components"].add(r["component"]); status=r.get("reachability_status")
  if status=="ACTIVE": x["active_call_sites"]+=1
  elif status=="EXCLUDED_WITH_EVIDENCE": x["excluded_call_sites"]+=1
  else: x["unknown_call_sites"]+=1
  x["source_locations"].append({"component":r["component"],"path":r["path"],"line":int(r["line"]),
   "kind":"CALL_SITE","reachability_status":status,"reference_kind":r.get("reference_kind")})
 for r in noncalls:
  x=item(r["api"]); x["components"].add(r["component"])
  if r.get("reference_kind")=="DECLARATION_OR_DEFINITION": x["declaration_references"]+=1
  else: x["other_non_call_references"]+=1
  x["source_locations"].append({"component":r["component"],"path":r["path"],"line":int(r["line"]),
   "kind":"NON_CALL_REFERENCE","reachability_status":r.get("reachability_status"),"reference_kind":r.get("reference_kind")})
 for r in macro_rows:
  x=item(r["api"]); x["components"].add(r["component"]); x["macro_references"]+=1
  status=r.get("reachability_status")
  if status=="ACTIVE": x["macro_active"]+=1
  elif status=="EXCLUDED_WITH_EVIDENCE": x["macro_excluded"]+=1
  else: x["macro_unknown"]+=1
  x["source_locations"].append({"component":r["component"],"path":r["path"],"line":int(r["line"]),
   "kind":"MACRO_REFERENCE","macro":r.get("macro"),"reachability_status":status})
 out=[]
 for api,x in sorted(rows.items()):
  mr=migration_map.get(api,{})
  delta=delta_by_api.get(api)
  if delta:
   try:
    x["pristine_call_count"]=int(delta["pristine_calls"])
    x["prepared_call_count"]=int(delta["prepared_calls"])
   except (KeyError,TypeError,ValueError):
    x["pristine_call_count"]=None; x["prepared_call_count"]=None
  elif x["source_reference_count"]:
   x["pristine_call_count"]=x["baseline_lexical_occurrences"] or x["source_reference_count"]
   x["prepared_call_count"]=x["source_reference_count"]
  else:
   x["pristine_call_count"]=x["baseline_lexical_occurrences"] or None
   x["prepared_call_count"]=0
  if x["unknown_call_sites"] or x["macro_unknown"]: status="UNKNOWN_FAIL_CLOSED"
  elif x["active_call_sites"] or x["macro_active"]: status="ACTIVE"
  elif x["prepared_call_count"]==0 and (x["pristine_call_count"] or 0)>0 and delta:
   status="NO_LONGER_PRESENT_AFTER_PATCH"
  elif x["prepared_call_count"] and (x["excluded_call_sites"] or x["macro_excluded"] or x["declaration_references"] or x["other_non_call_references"]):
   status="EXCLUDED_WITH_EVIDENCE"
  else: status="UNKNOWN_FAIL_CLOSED"
  x.update({"components":sorted(x["components"]),"scope_status":status,
   "needs_migration_review":x["active_call_sites"]>0,
   "requires_patch_semantic_review":status=="NO_LONGER_PRESENT_AFTER_PATCH",
   "migration_status":mr.get("migration_status","MISSING_FROM_GLOBAL_BASELINE"),
   "approval":mr.get("approval","false"),"global_baseline_candidate":api in migration_map,
   "source_locations":sorted(x["source_locations"],key=lambda z:(z["component"],z["path"],z["line"],z["kind"]))})
  out.append(x)
 return out

def validate_scope_manifest(scope,summary,migration_map):
 failures=[]
 if scope.get("schema_version")!=1 or scope.get("scope_id")!="n60-easymesh-openssl-3.5.9":
  failures.append("invalid EasyMesh OpenSSL scope manifest identity/schema")
 if scope.get("openssl_version")!="3.5.9": failures.append("EasyMesh OpenSSL scope manifest version is not 3.5.9")
 if set(scope.get("primary_components",[]))!=REQUIRED_EASYMESH_COMPONENTS:
  failures.append("EasyMesh scope manifest primary component set differs from the audited DPP/WAPP/MAPD/1905 source set")
 if set(summary.get("components",{}))!=REQUIRED_EASYMESH_COMPONENTS:
  failures.append("target preprocessor component set does not cover the complete EasyMesh OpenSSL scope")
 baseline=scope.get("global_baseline",{})
 if baseline.get("expected_rows")!=68 or len(migration_map)!=68 or baseline.get("role")!="TRACEABILITY_ONLY" or baseline.get("is_migration_approval") is not False:
  failures.append("68-row global reference baseline was changed, mis-scoped or treated as migration approval")
 supporting={x.get("name") for x in scope.get("supporting_dependencies",[]) if isinstance(x,dict)}
 if supporting!={"datconf","libnl-tiny"}:
  failures.append("EasyMesh supporting dependency boundary list must explicitly retain datconf/libkvcutil and libnl-tiny")
 return failures

def evaluate(inventory_rows,callsites,noncalls,summary,macro_rows,migration_map,policy,source_root,expected_git_sha,delta_rows=None):
 failures=[]
 if summary.get("git_sha")!=expected_git_sha: failures.append("target preprocessor evidence Git SHA mismatch")
 if summary.get("firmware_compile_invoked") is not False: failures.append("firmware compilation was invoked or not disproven")
 if summary.get("complete") is not True or summary.get("source_reachability_complete") is not True:
  failures.append("target preprocessor evidence is incomplete; fail closed")
 for field in ("callsite_counts","non_call_reference_counts","macro_reference_counts"):
  counts=summary.get(field,{})
  if counts.get("UNKNOWN_FAIL_CLOSED",0)!=0: failures.append(field+" retains UNKNOWN_FAIL_CLOSED references")
  if counts.get("total") is None: failures.append("missing "+field+" total")
 if summary.get("callsite_counts",{}).get("total")!=len(callsites): failures.append("callsite evidence count mismatch")
 if summary.get("non_call_reference_counts",{}).get("total")!=len(noncalls): failures.append("non-call evidence count mismatch")
 if summary.get("macro_reference_counts",{}).get("total")!=len(macro_rows): failures.append("macro evidence count mismatch")
 if any(x.get("reachability_status")=="UNKNOWN_FAIL_CLOSED" for x in macro_rows):
  failures.append("macro reachability retains UNKNOWN_FAIL_CLOSED references")
 active_component_api_hits={
  (x.get("component"),x.get("api")) for x in callsites
  if x.get("reachability_status")=="ACTIVE" and x.get("reference_kind") not in
     {"DECLARATION_OR_DEFINITION","UNKNOWN_REFERENCE_KIND"}
 }
 for row in macro_rows:
  if row.get("reachability_status")=="EXCLUDED_WITH_EVIDENCE":
   if (row.get("component"),row.get("api")) in active_component_api_hits:
    failures.append("macro exclusion contradicts an active target-preprocessor API hit in the same component: "+repr(key(row)))
   component=summary.get("components",{}).get(row.get("component"),{})
   source=(Path(source_root).resolve()/str(row.get("path",""))).resolve()
   valid=(row.get("reachability")=="UNREFERENCED_MACRO_DEFINITION" and
          row.get("reason")=="macro definition is lexically unreferenced and no target-preprocessed API call exists in the component" and
          component.get("source_reachability_complete") is True and
          source.is_relative_to(Path(source_root).resolve()) and source.is_file() and
          sha256(source)==row.get("source_sha256"))
   if not valid: failures.append("macro EXCLUDED_WITH_EVIDENCE lacks matching lexical/source proof: "+repr(key(row)))

 evidence={}
 for group in (callsites,noncalls):
  for row in group:
   k=key(row)
   if not all(k) or k in evidence:
    failures.append("empty or duplicate target reference key: "+repr(k)); continue
   status=row.get("reachability_status")
   if status not in REACH: failures.append("invalid target reachability status: "+repr(k))
   root=Path(source_root).resolve()
   source=(root/str(row.get("path",""))).resolve()
   if not source.is_relative_to(root):
    failures.append("target source path escapes the prepared component tree: "+repr(k))
   elif not source.is_file() or sha256(source)!=row.get("source_sha256"):
    failures.append("target source SHA256 mismatch: "+repr(k))
   if status=="EXCLUDED_WITH_EVIDENCE":
    proof=row.get("preprocessor_negative_evidence")
    component=summary.get("components",{}).get(k[0],{})
    compiled=[x for x in component.get("translation_units",[]) if x.get("returncode")==0 and x.get("preprocessed_sha256")]
    source_text=str(source)
    matching=[x for x in compiled if str(Path(x.get("source","")).resolve())==source_text]
    expected_hashes=sorted(x["preprocessed_sha256"] for x in matching)
    evidence_root=Path(summary.get("evidence_output_dir","")).resolve()
    observed=[]
    for tu in matching:
     output=Path(tu.get("preprocessed_output","")).resolve()
     if not output.is_relative_to(evidence_root) or not output.is_file() or sha256(output)!=tu.get("preprocessed_sha256"):
      failures.append("excluded API has missing, escaped or hash-mismatched preprocessor output: "+repr(k))
      continue
     emitted,hit=observe_preprocessed_output(output,source,int(k[2]),str(k[3]))
     observed.append((not emitted,not hit))
    independently_absent=bool(observed) and all(x==(True,True) for x in observed)
    valid=(component.get("source_reachability_complete") is True and bool(matching) and
      isinstance(proof,dict) and proof.get("source_translation_unit") is True and
      proof.get("component_complete") is True and proof.get("api_hit_absent") is True and
      proof.get("source_line_absent") is True and independently_absent and
      proof.get("preprocessed_sha256")==expected_hashes and
      proof.get("target_compiler_sha256")==summary.get("target_compiler_sha256") and
      proof.get("target_config_sha256")==summary.get("target_config_sha256") and
      proof.get("source_sha256")==row.get("source_sha256") and
      proof.get("conditional_branch_path")==row.get("conditional_branch_path"))
    if not valid: failures.append("EXCLUDED_WITH_EVIDENCE lacks matching negative target-preprocessor proof: "+repr(k))
   evidence[k]=row

 inventory={}
 for row in inventory_rows:
  if not row.get("deprecated_macro"): continue
  k=key(row)
  if not all(k) or k in inventory: failures.append("empty or duplicate deprecated inventory key: "+repr(k))
  inventory[k]=row
 if set(inventory)!=set(evidence):
  missing=sorted(set(inventory)-set(evidence))
  extra=sorted(set(evidence)-set(inventory))
  if missing: failures.append("deprecated source references lack exact target evidence: "+repr(missing[:20]))
  if extra: failures.append("target evidence has no matching deprecated API inventory row: "+repr(extra[:20]))

 active=[]; excluded=0; declarations=0; unknown=0
 for k,row in inventory.items():
  ev=evidence.get(k)
  if ev is None: continue
  kind=ev.get("reference_kind")
  status=ev.get("reachability_status")
  if kind=="DECLARATION_OR_DEFINITION":
   declarations+=1
   continue
  if status=="UNKNOWN_FAIL_CLOSED" or kind=="UNKNOWN_REFERENCE_KIND":
   unknown+=1
   failures.append("unresolved target API reference: "+str(k))
   continue
  if status=="EXCLUDED_WITH_EVIDENCE":
   excluded+=1
   continue
  if status!="ACTIVE":
   failures.append("invalid active-callsite classification: "+str(k))
   continue
  active.append({"component":k[0],"path":k[1],"line":k[2],"api":k[3]})

 active_apis=sorted({x["api"] for x in active})
 for api in active_apis:
  mr=migration_map.get(api)
  if mr is None:
   failures.append("active deprecated API is missing from the migration map: "+api)
   continue
  if mr.get("source_reachability_status") in {"UNREFERENCED_MACRO_DEFINITION","OPENSSL_NO_ENGINE_GUARD_REQUIRES_PREPROCESSOR"}:
   failures.append("target preprocessor contradicts the migration map's exclusion claim: "+api)
  if mr.get("migration_status")!="APPROVED" or str(mr.get("approval","")).lower()!="true":
   failures.append("active deprecated API has no completed semantic review/approval: "+api)
   continue
  rule=policy.get("api_rules",{}).get(api)
  if not isinstance(rule,dict):
   failures.append("approved active API has no detailed policy: "+api)
   continue
  status=rule.get("status"); reason=rule.get("reason","")
  if status not in ALLOWED or not isinstance(reason,str) or not reason.strip() or rule.get("approved") is not True:
   failures.append("active API policy is incomplete or unapproved: "+api)
  elif status in {"DIRECT_REPLACEMENT","SEMANTIC_ADAPTATION"}:
   failures.append("migration mapping exists but deprecated API calls are still active in target source: "+api)
  elif status in {"REQUIRES_REDESIGN","BLOCKED"}:
   failures.append("active deprecated API remains blocked pending redesign: "+api)
  elif status=="LEGACY_RETAINED" and not any(token in reason.lower() for token in ("compatibility","interoperability","hardware","provider limitation","upstream")):
   failures.append("legacy-retained API lacks a concrete compatibility/interoperability justification: "+api)

 counts=Counter(x["api"] for x in active)
 subset=build_easymesh_api_subset(inventory_rows,callsites,noncalls,macro_rows,migration_map,delta_rows)
 active_subset=[x["api"] for x in subset if x["needs_migration_review"]]
 return {
  "schema_version":2,"git_sha":expected_git_sha,"firmware_compile_invoked":False,
  "inventory_deprecated_references":len(inventory),"target_active_call_sites":len(active),
  "target_active_apis":active_apis,"target_active_api_counts":dict(sorted(counts.items())),
  "excluded_with_evidence":excluded,"declarations_or_definitions":declarations,
  "unknown_fail_closed":unknown,"macro_reference_count":len(macro_rows),
  "migration_map_rows":len(migration_map),
  "easymesh_api_candidate_count":len(subset),
  "easymesh_api_migration_required_count":len(active_subset),
  "easymesh_api_migration_required":active_subset,"easymesh_api_subset":subset,\n  "easymesh_api_removed_by_patch":[x["api"] for x in subset if x["requires_patch_semantic_review"]],
  "active_apis_unreviewed":[api for api in active_apis if api not in migration_map or migration_map[api].get("migration_status")!="APPROVED" or str(migration_map[api].get("approval","")).lower()!="true"],
  "failures":failures,"complete":not failures
 }

def main():
 ap=argparse.ArgumentParser()
 for name in ("inventory","callsites","noncalls","summary","macros","migration-map","delta","policy","source-root","repo-root","output","scope-manifest"):
  ap.add_argument("--"+name,type=Path,required=True)
 a=ap.parse_args()
 repo=a.repo_root.resolve()
 git=subprocess.run(["git","rev-parse","HEAD"],cwd=repo,text=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
 if git.returncode: raise SystemExit("cannot resolve API audit checkout Git SHA")
 with a.inventory.open(encoding="utf-8",newline="") as f: inventory=list(csv.DictReader(f))
 with a.migration_map.open(encoding="utf-8",newline="") as f: migration_rows=list(csv.DictReader(f))
 migration_map={x["api"]:x for x in migration_rows}
 summary=load_json(a.summary)
 scope=load_json(a.scope_manifest)
 with a.delta.open(encoding="utf-8",newline="") as f: delta_rows=list(csv.DictReader(f))\n report=evaluate(inventory,load_json(a.callsites),load_json(a.noncalls),summary,
                 load_json(a.macros),migration_map,load_json(a.policy),a.source_root,git.stdout.strip(),delta_rows)
 report["failures"].extend(validate_scope_manifest(scope,summary,migration_map))
 report["scope"]={"scope_id":scope.get("scope_id"),"openssl_version":scope.get("openssl_version"),
  "primary_components":scope.get("primary_components"),"supporting_dependencies":scope.get("supporting_dependencies"),
  "global_baseline":{"path":scope.get("global_baseline",{}).get("path"),"rows":len(migration_rows),
   "sha256":sha256_file(a.migration_map),"role":"TRACEABILITY_ONLY"}}
 report["complete"]=not report["failures"]
 a.output.parent.mkdir(parents=True,exist_ok=True)
 a.output.write_text(json.dumps(report,indent=2)+"\n",encoding="utf-8")
 subset={"schema_version":1,"scope_id":scope.get("scope_id"),"openssl_version":scope.get("openssl_version"),
  "git_sha":git.stdout.strip(),"scope_components":scope.get("primary_components"),
  "global_baseline":report["scope"]["global_baseline"],
  "candidate_api_count":report["easymesh_api_candidate_count"],\n  "original_68_candidate_set_preserved":len(migration_map)==68,
  "migration_required_api_count":report["easymesh_api_migration_required_count"],
  "migration_required_apis":report["easymesh_api_migration_required"],\n  "removed_by_patch_requiring_semantic_review":report["easymesh_api_removed_by_patch"],
  "apis":report["easymesh_api_subset"],"dependency_boundary_policy":scope.get("supporting_dependencies")}
 (a.output.parent/"easymesh-openssl-api-subset.json").write_text(json.dumps(subset,indent=2)+"\n",encoding="utf-8")
 fields=["api","components","source_reference_count","active_call_sites","excluded_call_sites","unknown_call_sites",
  "declaration_references","other_non_call_references","macro_references","macro_active","macro_excluded",
  "macro_unknown","scope_status","needs_migration_review","migration_status","approval","global_baseline_candidate"]
 with (a.output.parent/"easymesh-openssl-api-subset.csv").open("w",encoding="utf-8",newline="") as f:
  writer=csv.DictWriter(f,fieldnames=fields); writer.writeheader()
  for row in report["easymesh_api_subset"]:
   writer.writerow({k:(";".join(row[k]) if k=="components" else row[k]) for k in fields})
 print(json.dumps({k:report[k] for k in ("target_active_call_sites","target_active_apis","easymesh_api_candidate_count","easymesh_api_migration_required","easymesh_api_removed_by_patch","excluded_with_evidence","declarations_or_definitions","unknown_fail_closed","complete","failures")},indent=2))
 return 0 if report["complete"] else 1

if __name__=="__main__": raise SystemExit(main())
