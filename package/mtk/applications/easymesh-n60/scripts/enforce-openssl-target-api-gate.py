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

def evaluate(inventory_rows,callsites,noncalls,summary,macro_rows,migration_map,policy,source_root,expected_git_sha):
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
 return {
  "schema_version":1,"git_sha":expected_git_sha,"firmware_compile_invoked":False,
  "inventory_deprecated_references":len(inventory),"target_active_call_sites":len(active),
  "target_active_apis":active_apis,"target_active_api_counts":dict(sorted(counts.items())),
  "excluded_with_evidence":excluded,"declarations_or_definitions":declarations,
  "unknown_fail_closed":unknown,"macro_reference_count":len(macro_rows),
  "migration_map_rows":len(migration_map),
  "active_apis_unreviewed":[api for api in active_apis if api not in migration_map or migration_map[api].get("migration_status")!="APPROVED" or str(migration_map[api].get("approval","")).lower()!="true"],
  "failures":failures,"complete":not failures
 }

def main():
 ap=argparse.ArgumentParser()
 for name in ("inventory","callsites","noncalls","summary","macros","migration-map","policy","source-root","repo-root","output"):
  ap.add_argument("--"+name,type=Path,required=True)
 a=ap.parse_args()
 repo=a.repo_root.resolve()
 git=subprocess.run(["git","rev-parse","HEAD"],cwd=repo,text=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
 if git.returncode: raise SystemExit("cannot resolve API audit checkout Git SHA")
 with a.inventory.open(encoding="utf-8",newline="") as f: inventory=list(csv.DictReader(f))
 with a.migration_map.open(encoding="utf-8",newline="") as f: migration_rows=list(csv.DictReader(f))
 migration_map={x["api"]:x for x in migration_rows}
 report=evaluate(inventory,load_json(a.callsites),load_json(a.noncalls),load_json(a.summary),
                 load_json(a.macros),migration_map,load_json(a.policy),a.source_root,git.stdout.strip())
 a.output.parent.mkdir(parents=True,exist_ok=True)
 a.output.write_text(json.dumps(report,indent=2)+"\n",encoding="utf-8")
 print(json.dumps({k:report[k] for k in ("target_active_call_sites","target_active_apis","excluded_with_evidence","declarations_or_definitions","unknown_fail_closed","complete","failures")},indent=2))
 return 0 if report["complete"] else 1

if __name__=="__main__": raise SystemExit(main())
