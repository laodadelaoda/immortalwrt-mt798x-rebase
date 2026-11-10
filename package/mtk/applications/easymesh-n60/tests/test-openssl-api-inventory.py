#!/usr/bin/env python3
"""Fail-closed source-call inventory against the pinned OpenSSL 3.5.9 headers."""
import argparse,csv,json,re
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
def validate_openssl_source(root,repo_root):
 inc=root/"include/openssl"
 # The release archive contains a Perl template, not numeric version macros.
 if not (inc/"opensslv.h.in").is_file(): raise FileNotFoundError("missing OpenSSL opensslv.h.in: "+str(inc))
 mk=repo_root/"package/libs/openssl/Makefile"
 text=mk.read_text(encoding="utf-8")
 m=re.search(r"(?m)^PKG_VERSION\s*:=\s*([^\s#]+)",text)
 if not m or m.group(1)!="3.5.9": raise ValueError("repository OpenSSL package is not pinned to 3.5.9")
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
 for p in sorted(inc.rglob("*.h")):
  s=clean(p.read_text(encoding="utf-8",errors="replace"))
  names.update(m.group(1) for m in DECL.finditer(s) if m.group(1) not in C_KEYWORDS and not m.group(1).startswith(("OSSL_","OPENSSL_")))
  for m in DEPR.finditer(s):
   ds=list(DECL.finditer(m.group(0)))
   if ds: deprecated[ds[-1].group(1)]=m.group(1)
 if not names: raise ValueError("no public API declarations parsed")
 return names,deprecated
def scan_text(text,names,depr,component,path):
 s=clean(text); alt="|".join(re.escape(x) for x in sorted(names,key=lambda x:(-len(x),x)))
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
 ap.add_argument("--strict",action="store_true"); a=ap.parse_args()
 for n,p in (("repo",a.repo_root),("source",a.source_root),("pristine",a.pristine_root),("OpenSSL",a.openssl_source)):
  if not p.is_dir(): ap.error(n+" directory missing: "+str(p))
 validate_openssl_source(a.openssl_source,a.repo_root)
 policy=json.loads(a.policy.read_text())
 if policy.get("schema_version")!=1 or policy.get("openssl_version")!="3.5.9" or not isinstance(policy.get("api_rules"),dict): ap.error("invalid OpenSSL API policy schema/version")
 names,depr=catalog(a.openssl_source); rows=scan(a.source_root,names,depr); before=scan(a.pristine_root,names,depr); const=const_audit(a.source_root)
 failures=[]; inventory=[]
 for r in rows:
  x=dict(r); rule=policy["api_rules"].get(r["api"])
  if r["deprecated_macro"]:
   if not isinstance(rule,dict): x["classification"]="DEPRECATED_UNCLASSIFIED"; x["policy_reason"]=""; failures.append("unclassified "+r["api"]+" at "+r["path"]+":"+str(r["line"]))
   else:
    st=rule.get("status"); reason=rule.get("reason",""); x["classification"]=st or "INVALID_POLICY"; x["policy_reason"]=reason
    if st not in {"DIRECT_REPLACEMENT","SEMANTIC_ADAPTATION","LEGACY_RETAINED","REQUIRES_REDESIGN","BLOCKED"} or not reason.strip() or rule.get("approved") is not True: failures.append("incomplete/unapproved policy: "+r["api"])
    elif st in {"REQUIRES_REDESIGN","BLOCKED"}: failures.append("blocked deprecated API remains: "+r["api"])
  else: x["classification"]="CURRENT_API"; x["policy_reason"]=""
  inventory.append(x)
 for api in policy["api_rules"]:
  if api not in depr: failures.append("policy entry not deprecated in pinned headers: "+api)
 for x in const: failures.append("const violation "+x["kind"]+" at "+x["path"]+":"+str(x["line"]))
 pc=Counter(x["api"] for x in before); qc=Counter(x["api"] for x in rows)
 delta=[{"api":k,"pristine_calls":pc[k],"prepared_calls":qc[k],"delta":qc[k]-pc[k],"deprecated":k in depr} for k in sorted(set(pc)|set(qc)) if pc[k]!=qc[k]]
 a.output_dir.mkdir(parents=True,exist_ok=True)
 csvout(a.output_dir/"openssl-api-inventory.csv",inventory,["component","path","line","api","deprecated_macro","classification","policy_reason"])
 csvout(a.output_dir/"openssl-api-delta.csv",delta,["api","pristine_calls","prepared_calls","delta","deprecated"])
 csvout(a.output_dir/"openssl-const-correctness.csv",const,["component","path","line","kind"])
 summary={"openssl_version":"3.5.9","components":COMP,"prepared_calls":len(rows),"pristine_calls":len(before),"header_apis":len(names),"deprecated_apis":len(depr),"const_findings":const,"failures":failures,"limitations":["lexical inventory, not Clang AST/type analysis","macro-generated and indirect function-pointer calls require compiler evidence"]}
 (a.output_dir/"openssl-api-audit.json").write_text(json.dumps(summary,indent=2)+"\n")
 (a.output_dir/"openssl-api-audit.txt").write_text("\n".join([f"prepared calls: {len(rows)}",f"pristine calls: {len(before)}",f"strict failures: {len(failures)}"]+["FAIL: "+x for x in failures])+"\n")
 print("OpenSSL API inventory: prepared=%d pristine=%d failures=%d"%(len(rows),len(before),len(failures)))
 for x in failures: print("FAIL: "+x)
 return 1 if a.strict and failures else 0
if __name__=="__main__": raise SystemExit(main())
