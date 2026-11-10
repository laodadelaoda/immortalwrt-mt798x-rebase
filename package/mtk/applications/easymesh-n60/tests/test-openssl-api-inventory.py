#!/usr/bin/env python3
"""Fail-closed source-call inventory against the pinned OpenSSL 3.5.9 headers."""
import argparse,csv,hashlib,json,re
from collections import Counter
from pathlib import Path
COMP=("wappd","mapd","1905daemon","libmapd")
EXT={".c",".h",".cc",".cpp",".cxx",".inc"}
# DECL is a deliberately lightweight header lexer. Exclude C type keywords
# so function-pointer declarators such as "int (*callback)(void)" cannot be
# misreported as an OpenSSL API named "int".
C_KEYWORDS={"auto","break","case","char","const","continue","default","do","double","else","enum","extern","float","for","goto","if","inline","int","long","register","restrict","return","short","signed","sizeof","static","struct","switch","typedef","union","unsigned","void","volatile","while","_Bool","_Complex","_Imaginary"}
MASK=re.compile(r'//[^\n]*|/\*.*?\*/|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'',re.S)
DECL=re.compile(r"\b([A-Za-z_]\w*)\s*\([^;{}]*\)\s*;",re.S)
DEPR=re.compile(r"(OSSL_DEPRECATEDIN_[A-Za-z0-9_]+)[\s\S]{0,700}?;",re.S)
def clean(s): return MASK.sub(lambda m:"".join("\n" if c=="\n" else " " for c in m.group()),s)
def mask_define_directives(s):
 lines=s.splitlines(keepends=True); out=[]; i=0
 while i<len(lines):
  if re.match(r"^[ \t]*#[ \t]*define\b",lines[i]):
   cont=True
   while cont and i<len(lines):
    line=lines[i]; out.append(re.sub(r"[^\n]"," ",line))
    cont=line.rstrip("\r\n").endswith("\\"); i+=1
  else:
   out.append(lines[i]); i+=1
 return "".join(out)
def sha256_file(path):
 h=hashlib.sha256()
 with path.open("rb") as f:
  for chunk in iter(lambda:f.read(1024*1024),b""): h.update(chunk)
 return h.hexdigest()
def verify_baseline_attestation(repo_root,lock):
 tests=repo_root/"package/mtk/applications/easymesh-n60/tests"
 att_path=tests/"openssl-migration-baseline.attestation.json"
 att=json.loads(att_path.read_text(encoding="utf-8"))
 if att.get("schema_version")!=2 or att.get("status")!="VERIFIED" or att.get("baseline_id")!=lock.get("baseline_id"):
  raise ValueError("missing, stale or invalid OpenSSL migration baseline attestation")
 run=att.get("run",{}); artifact=att.get("artifact",{}); source=att.get("source",{}); results=att.get("results",{})
 if not re.fullmatch(r"[0-9a-f]{40}",run.get("git_sha","")) or int(run.get("id",0))<=0 or int(run.get("attempt",0))<=0:
  raise ValueError("OpenSSL baseline attestation has no valid run identity")
 if not re.fullmatch(r"[0-9a-f]{64}",artifact.get("sha256","")) or not artifact.get("id"):
  raise ValueError("OpenSSL baseline attestation has no artifact integrity identity")
 if source.get("archive_sha256",{}).get("1.1.1w")!=lock["from"]["sha256"] or source.get("archive_sha256",{}).get("3.5.9")!=lock["to"]["sha256"]:
  raise ValueError("OpenSSL baseline attestation archive hashes do not match the immutable lock")
 if results.get("failures")!=[] or results.get("migration_map_rows")!=68 or results.get("migration_map_apis_present_in_1_1_1w")!=68 or results.get("migration_map_apis_deprecated_in_3_5_9")!=68:
  raise ValueError("OpenSSL baseline attestation does not prove complete 68-API header coverage")
 paths={
  "migration_lock":tests/"openssl-migration-baseline.lock.json",
  "migration_map":tests/"openssl-111-to-359-migration-map.csv",
  "openssl_package_makefile":repo_root/"package/libs/openssl/Makefile",
  "api_inventory_script":tests/"test-openssl-api-inventory.py",
  "api_inventory_selftest":tests/"test-openssl-api-inventory-selftest.py",
  "baseline_auditor_script":repo_root/"package/mtk/applications/easymesh-n60/scripts/audit-openssl-migration-baseline.py",
  "baseline_auditor_selftest":tests/"test-openssl-migration-baseline-selftest.py",
  "api_policy":tests/"openssl-api-policy.json"
 }
 for name,path in paths.items():
  expected=att.get("input_sha256",{}).get(name)
  if not expected or sha256_file(path)!=expected:
   raise ValueError("OpenSSL baseline attestation input hash mismatch: "+name)
 return att
def validate_openssl_source(root,repo_root):
 inc=root/"include/openssl"
 # The release archive contains a Perl template, not numeric version macros.
 if not (inc/"opensslv.h.in").is_file(): raise FileNotFoundError("missing OpenSSL opensslv.h.in: "+str(inc))
 mk=repo_root/"package/libs/openssl/Makefile"
 text=mk.read_text(encoding="utf-8")
 m=re.search(r"(?m)^PKG_VERSION\s*:=\s*([^\s#]+)",text)
 h=re.search(r"(?m)^PKG_HASH:=([0-9a-f]{64})",text)
 if not m or m.group(1)!="3.5.9" or not h: raise ValueError("repository OpenSSL package is not pinned to the expected 3.5.9 version/hash")
 lock_path=repo_root/"package/mtk/applications/easymesh-n60/tests/openssl-migration-baseline.lock.json"
 lock=json.loads(lock_path.read_text(encoding="utf-8"))
 if lock.get("schema_version")!=1 or lock.get("from",{}).get("version")!="1.1.1w" or lock.get("to",{}).get("version")!="3.5.9": raise ValueError("invalid OpenSSL 1.1.1w-to-3.5.9 migration baseline lock")
 if lock["to"].get("sha256")!=h.group(1) or not re.fullmatch(r"[0-9a-f]{64}",lock["from"].get("sha256","")): raise ValueError("OpenSSL package hash does not match immutable migration baseline lock")
 verify_baseline_attestation(repo_root,lock)
 generated=inc/"opensslv.h"
 if generated.is_file():
  vh=generated.read_text(encoding="utf-8")
  for macro,v in (("OPENSSL_VERSION_MAJOR","3"),("OPENSSL_VERSION_MINOR","5"),("OPENSSL_VERSION_PATCH","9")):
   if not re.search(r"(?m)^\s*#\s*define\s+"+macro+r"\s+"+v+r"(?:\s|$)",vh): raise ValueError("generated OpenSSL version header mismatch: "+macro)
 return "3.5.9"
def catalog(root):
 inc=root/"include/openssl"
 if not inc.is_dir(): raise ValueError("missing OpenSSL public headers: "+str(inc))
 names=set(); deprecated={}
 for p in sorted(x for x in inc.rglob("*") if x.is_file() and (x.name.endswith(".h") or x.name.endswith(".h.in"))):
  s=clean(p.read_text(encoding="utf-8",errors="replace"))
  names.update(m.group(1) for m in DECL.finditer(s) if m.group(1) not in C_KEYWORDS and not m.group(1).startswith(("OSSL_","OPENSSL_")))
  for m in DEPR.finditer(s):
   ds=list(DECL.finditer(m.group(0)))
   if ds: deprecated[ds[-1].group(1)]=m.group(1)
 if not names: raise ValueError("no public API declarations parsed")
 return names,deprecated
def scan_text(text,names,depr,component,path):
 s=mask_define_directives(clean(text)); alt="|".join(re.escape(x) for x in sorted(names,key=lambda x:(-len(x),x)))
 rx=re.compile(r"\b("+alt+r")\s*\("); rows=[]
 for m in rx.finditer(s):
  api=m.group(1); rows.append({"component":component,"path":path,"line":s.count("\n",0,m.start())+1,
   "api":api,"deprecated_macro":depr.get(api,"")})
 return rows
def scan(root,names,depr):
 rows=[]
 for comp in COMP:
  base=root/comp
  if not base.is_dir(): raise ValueError("missing component source root: "+str(base))
  for p in sorted(x for x in base.rglob("*") if x.is_file() and x.suffix in EXT):
   rows.extend(scan_text(p.read_text(encoding="utf-8",errors="replace"),names,depr,comp,p.relative_to(root).as_posix()))
 return rows
def scan_macro_references(root,names,depr):
 defs={}; code_parts=[]
 for comp in COMP:
  base=root/comp
  for p in sorted(x for x in base.rglob("*") if x.is_file() and x.suffix in EXT):
   text=clean(p.read_text(encoding="utf-8",errors="replace"))
   lines=text.splitlines(keepends=True); code=[]; i=0
   while i<len(lines):
    line=lines[i]; m=re.match(r"^[ \t]*#[ \t]*define[ \t]+([A-Za-z_]\w*)",line)
    if not m:
     code.append(line); i+=1; continue
    name=m.group(1); rest=line[m.end():]; function_like=rest.startswith("(")
    body=rest; start=i+1; cont=line.rstrip("\r\n").endswith("\\")
    code.append(re.sub(r"[^\n]"," ",line))
    i+=1
    while cont and i<len(lines):
     part=lines[i]; body+=part; cont=part.rstrip("\r\n").endswith("\\")
     code.append(re.sub(r"[^\n]"," ",part)); i+=1
    defs.setdefault(name,[]).append({"component":comp,"path":p.relative_to(root).as_posix(),"line":start,"body":body,"function_like":function_like})
   code_parts.append("".join(code))
 macro_names=set(defs); edges={name:set() for name in macro_names}; roots=set()
 code_text="\n".join(code_parts)
 for name,items in defs.items():
  if any(x["function_like"] for x in items):
   if re.search(r"\b"+re.escape(name)+r"\s*\(",code_text): roots.add(name)
  elif re.search(r"\b"+re.escape(name)+r"\b",code_text):
   roots.add(name)
  body="\n".join(x["body"] for x in items)
  for other in macro_names:
   if other!=name and re.search(r"\b"+re.escape(other)+r"\s*(?:\(|\b)",body):
    edges[name].add(other)
 reachable=set(); todo=list(roots)
 while todo:
  name=todo.pop()
  if name in reachable: continue
  reachable.add(name); todo.extend(edges.get(name,()))
 out=[]
 for name,items in defs.items():
  for item in items:
   body=item["body"]
   for api in names:
    if api not in depr or not re.search(r"\b"+re.escape(api)+r"\b",body): continue
    state="ACTIVE_MACRO_EXPANSION_REQUIRES_CPP" if name in reachable else "UNREFERENCED_MACRO_DEFINITION"
    out.append({"component":item["component"],"path":item["path"],"line":item["line"],"macro":name,"api":api,"reachability":state})
 return out
def callsite_context(root,rows,radius=5):
 out=[]; cache={}
 for row in rows:
  rel=row["path"]
  if rel not in cache:
   lines=(root/rel).read_text(encoding="utf-8",errors="replace").splitlines()
   stack=[]; guards_by_line=[]
   for line in lines:
    stripped=line.strip()
    if re.match(r"^#\s*(if|ifdef|ifndef)\b",stripped):
     stack.append(stripped)
    elif re.match(r"^#\s*endif\b",stripped) and stack:
     stack.pop()
    guards_by_line.append(list(stack))
   cache[rel]=(lines,guards_by_line)
  lines,guards_by_line=cache[rel]
  n=row["line"]-1
  out.append({"component":row["component"],"path":rel,"line":row["line"],"api":row["api"],"preprocessor_guards":guards_by_line[n] if 0<=n<len(guards_by_line) else [],"context":"\n".join(f"{i+1}: {lines[i]}" for i in range(max(0,n-radius),min(len(lines),n+radius+1)))})
 return out

def const_audit(root):
 out=[]
 mutable=re.compile(r"(?m)^[ \t]*(?!const\b)(?:static[ \t]+)?EC_KEY\s*\*\s*(\w+)\s*=\s*(?:\(\s*EC_KEY\s*\*\s*\)\s*)?EVP_PKEY_get0_EC_KEY\s*\(")
 cast=re.compile(r"\(\s*EC_KEY\s*\*\s*\)\s*EVP_PKEY_get0_EC_KEY\s*\(")
 for c in COMP:
  for p in sorted(x for x in (root/c).rglob("*") if x.is_file() and x.suffix in EXT):
   s=clean(p.read_text(encoding="utf-8",errors="replace"))
   for rx,k in ((mutable,"MUTABLE_EC_KEY_POINTER_FROM_GET0"),(cast,"CONST_DISCARDING_EC_KEY_CAST")):
    for m in rx.finditer(s): out.append({"component":c,"path":p.relative_to(root).as_posix(),"line":s.count("\n",0,m.start())+1,"kind":k})
 return out
def csvout(path,rows,fields):
 with path.open("w",encoding="utf-8",newline="") as f:
  w=csv.DictWriter(f,fieldnames=fields); w.writeheader(); w.writerows(rows)
def main():
 ap=argparse.ArgumentParser()
 for x in ("repo-root","source-root","pristine-root","openssl-source","policy","output-dir"): ap.add_argument("--"+x,type=Path,required=True)
 ap.add_argument("--migration-map",type=Path,default=Path(__file__).with_name("openssl-111-to-359-migration-map.csv"))
 ap.add_argument("--strict",action="store_true"); a=ap.parse_args()
 for n,p in (("repo",a.repo_root),("source",a.source_root),("pristine",a.pristine_root),("OpenSSL",a.openssl_source)):
  if not p.is_dir(): ap.error(n+" directory missing: "+str(p))
 validate_openssl_source(a.openssl_source,a.repo_root)
 attestation_path=a.repo_root/"package/mtk/applications/easymesh-n60/tests/openssl-migration-baseline.attestation.json"
 baseline_attestation=json.loads(attestation_path.read_text(encoding="utf-8"))
 policy=json.loads(a.policy.read_text())
 if policy.get("schema_version")!=1 or policy.get("openssl_version")!="3.5.9" or not isinstance(policy.get("api_rules"),dict): ap.error("invalid OpenSSL API policy schema/version")
 required_map={"api","proposed_replacement","official_mapping_kind","official_mapping_section","official_migration_guide_url","official_target_manual_url","migration_status","approval","semantic_review_requirements","source_reachability_status","source_reachability_evidence"}
 with a.migration_map.open(encoding="utf-8",newline="") as mf:
  reader=csv.DictReader(mf)
  if not required_map.issubset(set(reader.fieldnames or [])): ap.error("migration map is missing required columns")
  migration_map={}
  for mr in reader:
   api=mr["api"].strip()
   if not api or api in migration_map: ap.error("empty or duplicate API in migration map: "+api)
   if mr["migration_status"] not in {"UNREVIEWED","REVIEWED_NOT_APPROVED","APPROVED"}: ap.error("invalid migration status for "+api)
   if mr["official_mapping_kind"] not in {"HIGH_LEVEL_API_MIGRATION","LEGACY_ALGORITHM_REVIEW","HIGH_LEVEL_OBJECT_MIGRATION","DIRECT_API_FAMILY_MAPPING","PARAMETER_GETTER_MIGRATION","PARAMETER_SETTER_MIGRATION","DIRECT_FUNCTION_MAPPING","READ_ONLY_PARAMETER_MIGRATION","PROVIDER_REDESIGN","REMOVE_REDUNDANT_CALL","KEY_IMPORT_MIGRATION","SEMANTIC_REDESIGN_REQUIRED","ENCODING_MIGRATION"}: ap.error("invalid official mapping kind for "+api)
   if not mr["official_mapping_section"].strip(): ap.error("missing official migration section for "+api)
   for field in ("official_migration_guide_url","official_target_manual_url"):
    if not mr[field].startswith("https://docs.openssl.org/3.5/"): ap.error("non-3.5 official reference URL for "+api+": "+field)
   if mr["source_reachability_status"] not in {"PREPROCESSOR_REACHABILITY_UNVERIFIED","UNREFERENCED_MACRO_DEFINITION","OPENSSL_NO_ENGINE_GUARD_REQUIRES_PREPROCESSOR"}: ap.error("invalid source reachability status for "+api)
   if not mr["source_reachability_evidence"].strip(): ap.error("missing source reachability evidence for "+api)
   if not mr["proposed_replacement"].strip() or not mr["semantic_review_requirements"].strip(): ap.error("incomplete migration research fields for "+api)
   if mr["approval"].lower() not in {"true","false"}: ap.error("invalid approval value for "+api)
   migration_map[api]=mr
 names,depr=catalog(a.openssl_source); rows=scan(a.source_root,names,depr); before=scan(a.pristine_root,names,depr); macro_refs=scan_macro_references(a.source_root,names,depr); contexts=callsite_context(a.source_root,[x for x in rows if x.get('deprecated_macro')]); const=const_audit(a.source_root)
 failures=[]; inventory=[]
 # The lexical inventory records macro-body references but does not decide
 # whether a macro expands in the N60 target. That decision belongs exclusively
 # to the exact target-preprocessor gate. The lexical gate still requires every
 # deprecated symbol found in a macro body to have a migration-map row.
 for mr in macro_refs:
  if mr["api"] not in migration_map:
   failures.append("missing migration reference row for macro API "+mr["api"]+" via "+mr["macro"]+" at "+mr["path"]+":"+str(mr["line"]))
 for api,mr in migration_map.items():
  if api not in depr: failures.append("migration map API is not deprecated in pinned OpenSSL 3.5.9 headers: "+api)
  if mr["migration_status"]=="APPROVED" and mr["approval"].lower()!="true": failures.append("migration map approval/status mismatch: "+api)
  if mr["migration_status"]!="APPROVED" and mr["approval"].lower()=="true": failures.append("migration map cannot approve non-APPROVED status: "+api)
 for r in rows:
  x=dict(r); rule=policy["api_rules"].get(r["api"]); mr=migration_map.get(r["api"])
  if r["deprecated_macro"]:
   if mr is None:
    x["classification"]="MIGRATION_MAP_MISSING"; x["policy_reason"]=""; failures.append("missing migration reference row for "+r["api"]+" at "+r["path"]+":"+str(r["line"]))
   elif mr["migration_status"]!="APPROVED" or mr["approval"].lower()!="true":
    x["classification"]="MAPPED_UNREVIEWED"; x["policy_reason"]=mr["proposed_replacement"]
   elif not isinstance(rule,dict):
    x["classification"]="APPROVED_MAP_WITHOUT_POLICY"; x["policy_reason"]=""; failures.append("approved migration map lacks detailed API policy: "+r["api"])
   else:
    st=rule.get("status"); reason=rule.get("reason",""); x["classification"]=st or "INVALID_POLICY"; x["policy_reason"]=reason
    if st not in {"DIRECT_REPLACEMENT","SEMANTIC_ADAPTATION","LEGACY_RETAINED","REQUIRES_REDESIGN","BLOCKED"} or not reason.strip() or rule.get("approved") is not True: failures.append("incomplete/unapproved policy: "+r["api"])
  else: x["classification"]="CURRENT_API"; x["policy_reason"]=""
  inventory.append(x)
 for api in policy["api_rules"]:
  if api not in depr: failures.append("policy entry not deprecated in pinned headers: "+api)
  if api not in migration_map: failures.append("policy API missing from migration map: "+api)
 for x in const: failures.append("const violation "+x["kind"]+" at "+x["path"]+":"+str(x["line"]))
 pc=Counter(x["api"] for x in before); qc=Counter(x["api"] for x in rows)
 delta=[{"api":k,"pristine_calls":pc[k],"prepared_calls":qc[k],"delta":qc[k]-pc[k],"deprecated":k in depr} for k in sorted(set(pc)|set(qc)) if pc[k]!=qc[k]]
 a.output_dir.mkdir(parents=True,exist_ok=True)
 csvout(a.output_dir/"openssl-api-inventory.csv",inventory,["component","path","line","api","deprecated_macro","classification","policy_reason"])
 csvout(a.output_dir/"openssl-api-delta.csv",delta,["api","pristine_calls","prepared_calls","delta","deprecated"])
 csvout(a.output_dir/"openssl-const-correctness.csv",const,["component","path","line","kind"])
 csvout(a.output_dir/"openssl-api-macro-references.csv",macro_refs,["component","path","line","macro","api","reachability"])
 (a.output_dir/"openssl-api-callsite-context.json").write_text(json.dumps(contexts,indent=2)+"\n")
 summary={"openssl_version":"3.5.9","baseline_attestation":{"run_id":baseline_attestation["run"]["id"],"run_attempt":baseline_attestation["run"]["attempt"],"git_sha":baseline_attestation["run"]["git_sha"],"artifact_sha256":baseline_attestation["artifact"]["sha256"],"attestation_file_sha256":sha256_file(attestation_path)},"components":COMP,"prepared_calls":len(rows),"pristine_calls":len(before),"header_apis":len(names),"deprecated_apis":len(depr),"migration_map_rows":len(migration_map),"migration_map_unreviewed":sum(1 for x in migration_map.values() if x["migration_status"]!="APPROVED" or x["approval"].lower()!="true"),"macro_definition_references":len(macro_refs),"macro_definition_unreferenced":sum(1 for x in macro_refs if x["reachability"]=="UNREFERENCED_MACRO_DEFINITION"),"macro_definition_active":sum(1 for x in macro_refs if x["reachability"]=="ACTIVE_MACRO_EXPANSION_REQUIRES_CPP"),"source_context_rows":len(contexts),"deprecated_call_sites":sum(1 for x in rows if x["deprecated_macro"]),"deprecated_source_apis":len({x["api"] for x in rows if x["deprecated_macro"]}),"const_findings":const,"failures":failures,"limitations":["lexical inventory, not Clang AST/type analysis","macro reachability is a conservative lexical graph; active macro expansions require target preprocessor evidence","indirect function-pointer calls require compiler evidence"]}
 (a.output_dir/"openssl-api-audit.json").write_text(json.dumps(summary,indent=2)+"\n")
 (a.output_dir/"openssl-api-audit.txt").write_text("\n".join([f"prepared calls: {len(rows)}",f"pristine calls: {len(before)}",f"strict failures: {len(failures)}"]+["FAIL: "+x for x in failures])+"\n")
 print("OpenSSL API inventory: prepared=%d pristine=%d failures=%d"%(len(rows),len(before),len(failures)))
 for x in failures: print("FAIL: "+x)
 return 1 if a.strict and failures else 0
if __name__=="__main__": raise SystemExit(main())
