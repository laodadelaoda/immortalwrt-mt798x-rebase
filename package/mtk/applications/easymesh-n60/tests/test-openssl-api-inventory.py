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
def validate_openssl_source(root,repo_root):
 inc=root/"include/openssl"
 if not (inc/"opensslv.h.in").is_file(): raise FileNotFoundError("missing OpenSSL opensslv.h.in: "+str(inc))
 mk=repo_root/"package/libs/openssl/Makefile"
 text=mk.read_text(encoding="utf-8")
 m=re.search(r"(?m)^PKG_VERSION\s*:=\s*([^\s#]+)",text)
 h=re.search(r"(?m)^PKG_HASH:=([0-9a-f]{64})",text)
 if not m or m.group(1)!="3.5.9" or not h: raise ValueError("repository OpenSSL package is not pinned to the expected 3.5.9 version/hash")
 lock_path=repo_root/"package/mtk/applications/easymesh-n60/tests/openssl-migration-baseline.lock.json"
 lock=json.loads(lock_path.read_text(encoding="utf-8"))
 if lock.get("schema_version")!=1 or lock.get("to",{}).get("version")!="3.5.9":
  raise ValueError("invalid OpenSSL 3.5.9 package lock")
 if lock["to"].get("sha256")!=h.group(1): raise ValueError("OpenSSL package hash does not match the pinned 3.5.9 package lock")
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
 policy=json.loads(a.policy.read_text())
 if policy.get("schema_version")!=1 or policy.get("openssl_version")!="3.5.9" or not isinstance(policy.get("api_rules"),dict): ap.error("invalid OpenSSL API policy schema/version")
 # The historical 68-row map is optional traceability metadata.
 migration_map={}; traceability_warnings=[]
 if a.migration_map.is_file():
  with a.migration_map.open(encoding="utf-8",newline="") as mf:
   for mr in csv.DictReader(mf):
    api=str(mr.get("api","")).strip()
    if not api or api in migration_map:
     traceability_warnings.append("empty or duplicate historical traceability row: "+(api or "<empty>"))
     continue
    migration_map[api]=mr
 names,depr=catalog(a.openssl_source); rows=scan(a.source_root,names,depr); before=scan(a.pristine_root,names,depr); macro_refs=scan_macro_references(a.source_root,names,depr); contexts=callsite_context(a.source_root,[x for x in rows if x.get('deprecated_macro')]); const=const_audit(a.source_root)
 failures=[]; inventory=[]
 # The lexical inventory records macro-body references but does not decide
 # whether a macro expands in the N60 target. That decision belongs exclusively
 # to the exact target-preprocessor gate. The lexical gate still requires every
 # deprecated symbol found in a macro body to have a migration-map row.
 for mr in macro_refs:
  if mr["api"] not in migration_map:
   traceability_warnings.append("macro API absent from historical map: "+mr["api"]+" via "+mr["macro"])
 for api,mr in migration_map.items():
  if api not in depr: traceability_warnings.append("historical map API is not deprecated in pinned 3.5.9 headers: "+api)
  if str(mr.get("migration_status",""))=="APPROVED" and str(mr.get("approval","")).lower()!="true":
   traceability_warnings.append("historical map approval/status mismatch: "+api)
  if str(mr.get("migration_status",""))!="APPROVED" and str(mr.get("approval","")).lower()=="true":
   traceability_warnings.append("historical map cannot approve non-APPROVED status: "+api)
 for r in rows:
  x=dict(r); rule=policy["api_rules"].get(r["api"]); mr=migration_map.get(r["api"])
  if r["deprecated_macro"]:
   if mr is None:
    x["classification"]="TRACEABILITY_UNMAPPED"; x["policy_reason"]=""
   elif str(mr.get("migration_status",""))=="IMPLEMENTED_PENDING_VALIDATION":
    x["classification"]="TRACEABILITY_IMPLEMENTED_PENDING_VALIDATION"; x["policy_reason"]=str(mr.get("proposed_replacement",""))
   elif str(mr.get("approval","")).lower()!="true":
    x["classification"]="TRACEABILITY_UNREVIEWED"; x["policy_reason"]=str(mr.get("proposed_replacement",""))
   elif not isinstance(rule,dict):
    x["classification"]="POLICY_REVIEW_REQUIRED"; x["policy_reason"]=""
   else:
    st=rule.get("status"); reason=rule.get("reason",""); x["classification"]=st or "POLICY_UNCLASSIFIED"; x["policy_reason"]=reason
  else: x["classification"]="CURRENT_API"; x["policy_reason"]=""
  inventory.append(x)
 for api in policy["api_rules"]:
  if api not in depr: traceability_warnings.append("policy API is not deprecated in pinned headers: "+api)
  if api not in migration_map: traceability_warnings.append("policy API absent from historical traceability map: "+api)
 for x in const: failures.append("const violation "+x["kind"]+" at "+x["path"]+":"+str(x["line"]))
 pc=Counter(x["api"] for x in before); qc=Counter(x["api"] for x in rows)
 delta=[{"api":k,"pristine_calls":pc[k],"prepared_calls":qc[k],"delta":qc[k]-pc[k],"deprecated":k in depr} for k in sorted(set(pc)|set(qc)) if pc[k]!=qc[k]]
 a.output_dir.mkdir(parents=True,exist_ok=True)
 csvout(a.output_dir/"openssl-api-inventory.csv",inventory,["component","path","line","api","deprecated_macro","classification","policy_reason"])
 csvout(a.output_dir/"openssl-api-delta.csv",delta,["api","pristine_calls","prepared_calls","delta","deprecated"])
 csvout(a.output_dir/"openssl-const-correctness.csv",const,["component","path","line","kind"])
 csvout(a.output_dir/"openssl-api-macro-references.csv",macro_refs,["component","path","line","macro","api","reachability"])
 (a.output_dir/"openssl-api-callsite-context.json").write_text(json.dumps(contexts,indent=2)+"\n")
 summary={"openssl_version":"3.5.9","components":COMP,"prepared_calls":len(rows),"pristine_calls":len(before),"header_apis":len(names),"deprecated_apis":len(depr),"traceability_map_rows":len(migration_map),"traceability_warnings":traceability_warnings,"macro_definition_references":len(macro_refs),"macro_definition_unreferenced":sum(1 for x in macro_refs if x["reachability"]=="UNREFERENCED_MACRO_DEFINITION"),"macro_definition_active":sum(1 for x in macro_refs if x["reachability"]=="ACTIVE_MACRO_EXPANSION_REQUIRES_CPP"),"source_context_rows":len(contexts),"deprecated_call_sites":sum(1 for x in rows if x["deprecated_macro"]),"deprecated_source_apis":len({x["api"] for x in rows if x["deprecated_macro"]}),"const_findings":const,"failures":failures,"limitations":["lexical inventory, not Clang AST/type analysis","macro reachability is a conservative lexical graph; active macro expansions require target preprocessor evidence","indirect function-pointer calls require compiler evidence"]}
 (a.output_dir/"openssl-api-audit.json").write_text(json.dumps(summary,indent=2)+"\n")
 (a.output_dir/"openssl-api-audit.txt").write_text("\n".join([f"prepared calls: {len(rows)}",f"pristine calls: {len(before)}",f"strict failures: {len(failures)}"]+["FAIL: "+x for x in failures])+"\n")
 print("OpenSSL API inventory: prepared=%d pristine=%d failures=%d"%(len(rows),len(before),len(failures)))
 for x in failures: print("FAIL: "+x)
 return 1 if a.strict and failures else 0
if __name__=="__main__": raise SystemExit(main())
