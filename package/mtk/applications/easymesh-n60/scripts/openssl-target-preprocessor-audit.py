#!/usr/bin/env python3
"""Preprocess-only OpenSSL reachability audit using actual component Make rules."""
import argparse,csv,hashlib,importlib.util,json,os,re,shlex,shutil,subprocess
from pathlib import Path

COMP=("wappd","mapd","1905daemon","libmapd")
EXT={".c",".cc",".cpp",".cxx"}
MARK=re.compile(r'^\s*#\s*(\d+)\s+"([^"]+)"')
ENTER=re.compile(r"make(?:\[\d+\])?: Entering directory ['\"](.+?)['\"]")
LEAVE=re.compile(r"make(?:\[\d+\])?: Leaving directory ['\"](.+?)['\"]")
CALL=re.compile(r"\b([A-Za-z_]\w*)\s*\(")
FOCUS_MACROS=("OPENSSL_NO_ENGINE","OPENSSL_NO_DEPRECATED_3_0","OPENSSL_IS_BORINGSSL",
 "CONFIG_NATIVE_WINDOWS","CONFIG_SUITEB","CONFIG_OPENSSL_CMAC","CONFIG_ECC","CONFIG_FIPS",
 "CONFIG_TESTING_OPTIONS","OPENSSL_NO_DH","OPENSSL_NO_DSA")

def sha(p):
 h=hashlib.sha256()
 with Path(p).open("rb") as f:
  for b in iter(lambda:f.read(1048576),b""): h.update(b)
 return h.hexdigest()

def tree_sha(root):
 h=hashlib.sha256()
 for p in sorted(x for x in Path(root).rglob("*") if x.is_file()):
  h.update(p.relative_to(root).as_posix().encode()+b"\0"+bytes.fromhex(sha(p))+b"\n")
 return h.hexdigest()

def canon(p,cwd):
 p=Path(p); return os.path.realpath(str(p if p.is_absolute() else Path(cwd)/p))

def branch_path(path):
 lines=Path(path).read_text(encoding="utf-8",errors="replace").splitlines()
 stack=[]; out=[[] for _ in lines]; i=0
 while i<len(lines):
  start=i
  if not re.match(r"^\s*#",lines[i]):
   out[i]=[dict(x) for x in stack]; i+=1; continue
  parts=[]
  while True:
   line=lines[i]; more=line.rstrip().endswith("\\")
   parts.append(line.rstrip()[:-1] if more else line); i+=1
   if not more or i>=len(lines): break
  d=" ".join(x.strip() for x in parts)
  if re.match(r"^\s*#\s*(if|ifdef|ifndef)\b",d): stack.append({"opening":d,"branch":d,"line":start+1})
  elif re.match(r"^\s*#\s*elif\b",d) and stack: stack[-1]["branch"]=d
  elif re.match(r"^\s*#\s*else\b",d) and stack: stack[-1]["branch"]=d
  elif re.match(r"^\s*#\s*endif\b",d) and stack: stack.pop()
  for n in range(start,i): out[n]=[dict(x) for x in stack]
 return out

def inventory_module(repo):
 p=repo/"package/mtk/applications/easymesh-n60/tests/test-openssl-api-inventory.py"
 s=importlib.util.spec_from_file_location("openssl_inventory",p)
 m=importlib.util.module_from_spec(s); s.loader.exec_module(m); return m

def make_specs(repo,build,a):
 cpp,cflags,ld=a.cppflags,a.cflags,a.ldflags
 easy=f"{cpp} {cflags} -Wno-error=deprecated-declarations -DCONFIG_SUPPORT_OPENWRT"
 st=str(a.staging); linux_rel=os.path.relpath(a.linux,repo)
 return {
 "libmapd":(["make","-B","-n","-w","-C",str(build/"libmapd"),"V=s",f"CC={a.cc}",f"CFLAGS={cpp} {cflags} -Werror -g",f"LDFLAGS={ld}","all"],{}),
 "wappd":(["make","-B","-n","-w","-C",str(build/"wappd"),"V=s",f"TOPDIR={repo}",f"UAPD_INCLUDE_PATH={a.linux}/include/uapi/linux/wapp -I{st}/usr/include","CONFIG_SUPPORT_OPENWRT=y","CONFIG_MAP_R2_SUPPORT=y","CONFIG_MAP_R3_SUPPORT=y",f"CC={a.cc}",f"EXTRA_CFLAGS={cpp} {cflags} -Wno-error=deprecated-declarations -I{a.linux}/include/uapi/linux/wapp",f"LDFLAGS={ld} -L{st}/usr/lib -lpthread -ldatconf -lkvcutil -lssl -lcrypto","all"],{}),
 "1905daemon":(["make","-B","-n","-w","-C",str(build/"1905daemon"),"V=s",f"TOPDIR={repo}",f"ROOTDIR={repo}",f"LINUXDIR={linux_rel}",f"STAGING_DIR={st}","CONFIG_MAP_R2_SUPPORT=y","CONFIG_MAP_R3_SUPPORT=y","MAP_R3_SUPPORT=y","SWTICH_DSA_ARCH=y",f"CC={a.cc}",f"AR={a.ar}",f"RANLIB={a.ranlib}",f"LDFLAGS={ld} -L{st}/usr/lib -Wl,--no-as-needed -lpthread -lnl-tiny -lssl -lcrypto","all"],{"EXTRA_CFLAGS":easy}),
 "mapd":(["make","-B","-n","-w","-C",str(build/"mapd"),"V=s",f"TOPDIR={repo}","CONFIG_SUPPORT_OPENWRT=y","CONFIG_MAP_R2_SUPPORT=y","CONFIG_MAP_R3_SUPPORT=y",f"CC={a.cc}",f"LDO={a.cc}",f"EXTRA_CFLAGS={easy}",f"LDFLAGS={ld} -L{st}/usr/lib","version","mapd"],{})
 }

def parse_commands(log,base,compiler):
 cmds=[]; errors=[]; dirs=[Path(base)]
 for n,line in enumerate(log.splitlines(),1):
  m=ENTER.search(line)
  if m: dirs.append(Path(m.group(1))); continue
  if LEAVE.search(line):
   if len(dirs)>1: dirs.pop()
   continue
  try: ts=shlex.split(line)
  except ValueError as e:
   if compiler in line and "-c" in line: errors.append(f"{n}: {e}")
   continue
  cwd=dirs[-1]
  if "cd" in ts and "&&" in ts:
   i=ts.index("cd")
   if i+2<len(ts):
    cwd=Path(ts[i+1]); cwd=cwd if cwd.is_absolute() else dirs[-1]/cwd
    ts=ts[i+3:]
  if "-c" not in ts: continue
  ci=next((i for i,t in enumerate(ts) if Path(t).name==compiler),None)
  if ci is None:
   candidates=[Path(t).name for t in ts if Path(t).name.endswith(("gcc","clang","cc")) or Path(t).name.startswith("clang")]
   if candidates: errors.append(f"{n}: non-target compiler in compile command: {candidates}")
   continue
  argv=ts[ci:]; srcs=[x for x in argv if Path(x).suffix.lower() in EXT]
  existing=[]
  for x in srcs:
   q=Path(x); q=q if q.is_absolute() else cwd/q
   if q.is_file(): existing.append((x,q.resolve()))
  if len(existing)!=1: errors.append(f"{n}: expected one source file, found {srcs}"); continue
  cmds.append({"cwd":str(cwd.resolve()),"argv":argv,"source":str(existing[0][1]),"line":n})
 return cmds,errors

def cpp_argv(cmd,out):
 src=cmd["argv"]; dst=[]; i=0
 while i<len(src):
  t=src[i]
  if t=="-c": dst.append("-E")
  elif t=="-o": i+=1
  elif t in ("-MF","-MT","-MQ"): i+=1
  elif t in ("-MMD","-MD","-MP","-MG") or t.startswith(("-Wp,-MD,","-Wp,-MMD,")): pass
  else: dst.append(t)
  i+=1
 dst.extend(["-dD","-o",str(out)]); return dst

def macro_argv(cmd,out):
 argv=cpp_argv(cmd,out)
 argv[argv.index("-dD")]="-dM"
 return argv

def macro_snapshot(path):
 found={}
 for line in Path(path).read_text(encoding="utf-8",errors="replace").splitlines():
  m=re.match(r"^#define\s+([A-Za-z_]\w*)(?:\s+(.*))?$",line)
  if m and m.group(1) in FOCUS_MACROS: found[m.group(1)]=m.group(2) or ""
 return {name:{"defined":name in found,"value":found.get(name)} for name in FOCUS_MACROS}

def pp_hits(path,cwd,names):
 hits=set(); filehits=set(); current=None; lineno=1
 for line in Path(path).read_text(encoding="utf-8",errors="replace").splitlines():
  m=MARK.match(line)
  if m: lineno=int(m.group(1)); current=canon(m.group(2),cwd); continue
  if line.lstrip().startswith("#"): continue
  if current:
   for m in CALL.finditer(line):
    if m.group(1) in names:
     hits.add((current,lineno,m.group(1))); filehits.add((current,m.group(1)))
   lineno+=1
 return hits,filehits

def prepare_mapd_version(build,repo,out,compiler):
 # The production Build/Compile invokes "version mapd". Run only the metadata
 # target after proving its dry-run has no compiler invocation.
 directory=build/"mapd"
 dry=subprocess.run(["make","-n","-w","-C",str(directory),"V=s","version"],cwd=repo,
                    text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
 (out/"mapd-version-dry-run.log").write_text(dry.stdout,encoding="utf-8")
 if dry.returncode: raise SystemExit("MAPD version target dry-run failed")
 for line in dry.stdout.splitlines():
  try: tokens=shlex.split(line)
  except ValueError: raise SystemExit("cannot parse MAPD version target dry-run; fail closed")
  candidates=[Path(t).name for t in tokens if Path(t).name.endswith(("gcc","clang","cc")) or Path(t).name.startswith("clang")]
  if compiler in candidates or candidates:
   raise SystemExit("MAPD version target dry-run contains a compiler invocation; refusing to execute it")
 run=subprocess.run(["make","-w","-C",str(directory),"V=s","version"],cwd=repo,
                    text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
 (out/"mapd-version-generation.log").write_text(run.stdout,encoding="utf-8")
 if run.returncode: raise SystemExit("MAPD version metadata generation failed")

def main():
 ap=argparse.ArgumentParser()
 for n in ("repo","build","staging","linux","output"): ap.add_argument("--"+n+"-dir" if n in ("repo","build","output") else "--"+n+"-dir",type=Path,required=True)
 ap.add_argument("--cc",required=True); ap.add_argument("--ar",required=True); ap.add_argument("--ranlib",required=True)
 ap.add_argument("--cppflags",default=""); ap.add_argument("--cflags",required=True); ap.add_argument("--ldflags",default="")
 a=ap.parse_args(); repo=a.repo_dir.resolve(); build=a.build_dir.resolve(); a.staging=a.staging_dir.resolve(); a.linux=a.linux_dir.resolve()
 out=a.output_dir.resolve(); out.mkdir(parents=True,exist_ok=True); (out/"preprocessed").mkdir(exist_ok=True)
 for c in COMP:
  if not (build/c).is_dir(): raise SystemExit(f"missing prepared component: {build/c}")
 hdr=a.staging/"usr/include/openssl"
 for f in ("configuration.h","opensslv.h"):
  if not (hdr/f).is_file(): raise SystemExit(f"missing Configure-generated target header: {hdr/f}")
 cc=shlex.split(a.cc)
 compiler=Path(cc[-1]).name if cc else ""
 if not cc or not (Path(cc[-1]).is_file() or shutil.which(cc[-1])): raise SystemExit(f"target compiler missing: {a.cc}")
 prepare_mapd_version(build,repo,out,compiler)
 inv=inventory_module(repo)
 with (repo/"package/mtk/applications/easymesh-n60/tests/openssl-111-to-359-migration-map.csv").open(encoding="utf-8",newline="") as f: mapping=list(csv.DictReader(f))
 names={x["api"] for x in mapping}
 if len(mapping)!=64 or len(names)!=64: raise SystemExit("migration map must contain 64 unique APIs")
 rows=[r for r in inv.scan(build,names,{x:"OSSL_DEPRECATED" for x in names}) if r.get("deprecated_macro")]
 branches={}
 for r in rows:
  p=build/r["path"]
  if str(p) not in branches: branches[str(p)]=branch_path(p)
  r["branch_path"]=branches[str(p)][r["line"]-1]
 specs=make_specs(repo,build,a); results={}; hits=set(); filehits=set(); api_hits_by_component={x:set() for x in COMP}
 for comp in COMP:
  argv,extra=specs[comp]; env=os.environ.copy(); env.update(extra)
  run=subprocess.run(argv,cwd=repo,env=env,text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
  log=out/f"make-dry-run-{comp}.log"; log.write_text(run.stdout,encoding="utf-8")
  cmds,parse_errors=parse_commands(run.stdout,build/comp,compiler); tus=[]; pp_errors=[]
  for i,cmd in enumerate(cmds):
   key=hashlib.sha256((comp+cmd["source"]+str(i)).encode()).hexdigest()[:16]
   dest=out/"preprocessed"/f"{comp}-{key}.i"; pargv=cpp_argv(cmd,dest)
   pp=subprocess.run(pargv,cwd=cmd["cwd"],text=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
   err=out/"preprocessed"/f"{comp}-{key}.stderr.txt"; err.write_text(pp.stderr,encoding="utf-8")
   macrofile=out/"preprocessed"/f"{comp}-{key}.macros.txt"; margv=macro_argv(cmd,macrofile)
   mp=subprocess.run(margv,cwd=cmd["cwd"],text=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
   merr=out/"preprocessed"/f"{comp}-{key}.macros.stderr.txt"; merr.write_text(mp.stderr,encoding="utf-8")
   item={"source":cmd["source"],"cwd":cmd["cwd"],"make_log_line":cmd["line"],"argv":pargv,"returncode":pp.returncode,
         "macro_argv":margv,"macro_returncode":mp.returncode,"stderr":str(err),"macro_stderr":str(merr)}
   if pp.returncode==0 and dest.is_file() and mp.returncode==0 and macrofile.is_file():
    item["preprocessed_sha256"]=sha(dest); item["macro_snapshot_sha256"]=sha(macrofile)
    item["target_macro_snapshot"]=macro_snapshot(macrofile)
    h,fh=pp_hits(dest,cmd["cwd"],names); hits.update(h); filehits.update(fh); api_hits_by_component[comp].update(x[2] for x in h)
   else: pp_errors.append(item)
   tus.append(item)
  complete=run.returncode==0 and bool(cmds) and not parse_errors and not pp_errors
  results[comp]={"make_returncode":run.returncode,"log":str(log),"compile_commands":len(cmds),"parse_errors":parse_errors,"preprocess_failures":pp_errors,"translation_units":tus,"complete":complete}
  (out/f"compile-commands-{comp}.json").write_text(json.dumps(cmds,indent=2)+"\n")
 complete={c for c,v in results.items() if v["complete"]}
 macro_refs=inv.scan_macro_references(build,names,{x:"OSSL_DEPRECATED" for x in names})
 macro_rows=[]; macro_counts={"EXCLUDED_WITH_EVIDENCE":0,"UNKNOWN_FAIL_CLOSED":0}
 for item in macro_refs:
  if item["reachability"]=="UNREFERENCED_MACRO_DEFINITION" and item["component"] in complete and item["api"] not in api_hits_by_component[item["component"]]:
   state="EXCLUDED_WITH_EVIDENCE"
  else: state="UNKNOWN_FAIL_CLOSED"
  macro_counts[state]+=1
  macro_rows.append({**item,"reachability_status":state,
    "reason":"unreferenced macro plus complete component preprocessor evidence" if state=="EXCLUDED_WITH_EVIDENCE" else "macro expansion cannot be attributed conclusively; fail closed"})
 callsites=[]; counts={"ACTIVE":0,"EXCLUDED_WITH_EVIDENCE":0,"UNKNOWN_FAIL_CLOSED":0}
 for r in rows:
  src=canon(build/r["path"],repo); key=(src,r["line"],r["api"])
  if key in hits: state="ACTIVE"
  elif (src,r["api"]) in filehits: state="UNKNOWN_FAIL_CLOSED"
  elif r["component"] in complete: state="EXCLUDED_WITH_EVIDENCE"
  else: state="UNKNOWN_FAIL_CLOSED"
  counts[state]+=1
  callsites.append({"component":r["component"],"path":r["path"],"line":r["line"],"api":r["api"],"reachability_status":state,
    "conditional_branch_path":r["branch_path"],"source_sha256":sha(build/r["path"]),
    "translation_units":[x["source"] for x in results[r["component"]]["translation_units"] if x["returncode"]==0]})
 summary={"schema_version":1,"git_sha":subprocess.run(["git","rev-parse","HEAD"],cwd=repo,text=True,stdout=subprocess.PIPE,check=True).stdout.strip(),
  "firmware_compile_invoked":False,"method":"make -B -n command enumeration; exact target compiler commands replayed as -E -dD",
  "target_compiler":a.cc,"target_cppflags":a.cppflags,"target_cflags":a.cflags,"target_ldflags":a.ldflags,
  "openssl_header_tree_sha256":tree_sha(hdr),"prepared_source_tree_sha256":tree_sha(build),"components":results,
  "callsite_counts":{"total":len(callsites),**counts},"macro_reference_counts":{"total":len(macro_rows),**macro_counts},
  "complete":len(complete)==4 and counts["UNKNOWN_FAIL_CLOSED"]==0 and macro_counts["UNKNOWN_FAIL_CLOSED"]==0,
  "limitations":["direct source expressions are classified separately from macro-body references","ambiguous source-line mapping is UNKNOWN_FAIL_CLOSED","no object, library, package or firmware is compiled or linked"]}
 (out/"callsite-reachability.json").write_text(json.dumps(callsites,indent=2)+"\n")
 (out/"macro-reference-reachability.json").write_text(json.dumps(macro_rows,indent=2)+"\n")
 (out/"openssl-target-preprocessor-summary.json").write_text(json.dumps(summary,indent=2)+"\n")
 files=sorted(x for x in out.rglob("*") if x.is_file() and x.name!="SHA256SUMS")
 (out/"SHA256SUMS").write_text("".join(f"{sha(x)}  {x.relative_to(out).as_posix()}\n" for x in files))
 print(json.dumps(summary["callsite_counts"],indent=2)); print("complete="+str(summary["complete"]))
 return 0 if summary["complete"] else 1

if __name__=="__main__": raise SystemExit(main())
