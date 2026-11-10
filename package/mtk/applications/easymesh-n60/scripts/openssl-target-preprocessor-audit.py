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

def classify_reference_text(text,api,line_number):
 lines=text.splitlines(keepends=True)
 if line_number<1 or line_number>len(lines): return "UNKNOWN_REFERENCE_KIND"
 line=lines[line_number-1]; pos=line.find(api)
 if pos<0: return "UNKNOWN_REFERENCE_KIND"
 start=sum(len(x) for x in lines[:line_number-1])+pos
 boundary=max(text.rfind(";",0,start),text.rfind("{",0,start),text.rfind("}",0,start))
 prefix=text[boundary+1:start]
 prefix=re.sub(r"(?m)^\s*#.*$"," ",prefix)
 if not prefix.strip(): return "CALL_EXPRESSION"
 if re.search(r"[=(),?:.]|->|&&|\|\||\b(return|if|while|for|switch|case|goto|sizeof)\b",prefix):
  return "CALL_EXPRESSION"
 if not re.fullmatch(r"[\w\s*&]+",prefix): return "CALL_EXPRESSION"
 tokens=re.findall(r"[A-Za-z_]\w*|\*|&",prefix)
 type_words={"void","int","char","short","long","signed","unsigned","float","double","size_t","ssize_t","bool",
  "BIGNUM","EC_KEY","DH","RSA","DSA","EVP_PKEY","EVP_MD_CTX","EVP_CIPHER_CTX","HMAC_CTX","CMAC_CTX",
  "ENGINE","BIO","SSL","X509","OSSL_PARAM","const","volatile","struct","enum"}
 if tokens and (tokens[-1] in ("*","&") or tokens[-1] in type_words or
    any(x in ("static","extern","inline","OSSL_DEPRECATEDIN_3_0","OSSL_DEPRECATEDIN_1_1_0") for x in tokens)):
  return "DECLARATION_OR_DEFINITION"
 return "CALL_EXPRESSION"

def classify_source_reference(build,row):
 path=build/row["path"]
 try: source=inv.mask_define_directives(inv.clean(path.read_text(encoding="utf-8",errors="replace")))
 except OSError: return "UNKNOWN_REFERENCE_KIND"
 return classify_reference_text(source,row["api"],row["line"])

def make_specs(repo,build,a):
 cpp,cflags,ld=a.cppflags,a.cflags,a.ldflags
 easy=f"{cpp} {cflags} -Wno-error=deprecated-declarations -DCONFIG_SUPPORT_OPENWRT"
 staging=str(a.staging); linux_rel=os.path.relpath(a.linux,repo)
 return {
  "libmapd":[{"name":"libmapd","cwd":build/"libmapd","env":{},"argv":["make","-n","-w","-C",str(build/"libmapd"),"V=s",
    f"CC={a.cc}",f"CFLAGS={cpp} {cflags} -Werror -g",f"LDFLAGS={ld}","all"]}],
  "wappd":[{"name":"wappd","cwd":build/"wappd","env":{},"argv":["make","-n","-w","-C",str(build/"wappd"),"V=s",
    f"TOPDIR={repo}",f"UAPD_INCLUDE_PATH={a.linux}/include/uapi/linux/wapp -I{staging}/usr/include",
    "CONFIG_SUPPORT_OPENWRT=y","CONFIG_MAP_R2_SUPPORT=y","CONFIG_MAP_R3_SUPPORT=y",f"CC={a.cc}",
    f"EXTRA_CFLAGS={cpp} {cflags} -Wno-error=deprecated-declarations -I{a.linux}/include/uapi/linux/wapp",
    f"LDFLAGS={ld} -L{staging}/usr/lib -lpthread -ldatconf -lkvcutil -lssl -lcrypto","all"]}],
  "1905daemon":[
   {"name":"1905daemon-main","cwd":build/"1905daemon","env":{"EXTRA_CFLAGS":easy},
    "argv":["make","-n","-w","-o","eth_ops_lib","-C",str(build/"1905daemon"),"V=s",f"TOPDIR={repo}",f"ROOTDIR={repo}",
    f"LINUXDIR={linux_rel}",f"STAGING_DIR={staging}","CONFIG_MAP_R2_SUPPORT=y","CONFIG_MAP_R3_SUPPORT=y",
    "MAP_R3_SUPPORT=y","SWTICH_DSA_ARCH=y",f"CC={a.cc}",f"AR={a.ar}",f"RANLIB={a.ranlib}",
    f"LDFLAGS={ld} -L{staging}/usr/lib -Wl,--no-as-needed -lpthread -lnl-tiny -lssl -lcrypto","all"]},
   {"name":"1905daemon-ethernet","cwd":build/"1905daemon"/"ethernet","env":{"EXTRA_CFLAGS":easy},
    "argv":["make","-n","-w","-C",str(build/"1905daemon"/"ethernet"),"V=s",f"TOPDIR={repo}",f"ROOTDIR={repo}",
    f"LINUXDIR={linux_rel}",f"STAGING_DIR={staging}","CONFIG_MAP_R2_SUPPORT=y","CONFIG_MAP_R3_SUPPORT=y",
    "MAP_R3_SUPPORT=y","SWTICH_DSA_ARCH=y",f"CC={a.cc}",f"AR={a.ar}",f"RANLIB={a.ranlib}",
    f"LDFLAGS={ld} -L{staging}/usr/lib -Wl,--no-as-needed -lpthread -lnl-tiny -lssl -lcrypto","all"]},
   {"name":"1905daemon-libbridge","cwd":build/"1905daemon"/"ethernet"/"mediatek_DSA"/"libbridge","env":{"EXTRA_CFLAGS":easy},
    "argv":["make","-n","-w","-C",str(build/"1905daemon"/"ethernet"/"mediatek_DSA"/"libbridge"),"V=s",
    f"TOPDIR={repo}",f"ROOTDIR={repo}",f"LINUXDIR={linux_rel}",f"STAGING_DIR={staging}",
    "CONFIG_MAP_R2_SUPPORT=y","CONFIG_MAP_R3_SUPPORT=y","MAP_R3_SUPPORT=y","SWTICH_DSA_ARCH=y",
    f"CC={a.cc}",f"AR={a.ar}",f"RANLIB={a.ranlib}",
    f"LDFLAGS={ld} -L{staging}/usr/lib -Wl,--no-as-needed -lpthread -lnl-tiny -lssl -lcrypto","all"]}
  ],
  "mapd":[{"name":"mapd","cwd":build/"mapd","env":{"EXTRA_CFLAGS":easy},"argv":["make","-n","-w","-C",str(build/"mapd"),"V=s",f"TOPDIR={repo}",
    "CONFIG_SUPPORT_OPENWRT=y","CONFIG_MAP_R2_SUPPORT=y","CONFIG_MAP_R3_SUPPORT=y",f"CC={a.cc}",
    f"LDO={a.cc}",f"LDFLAGS={ld} -L{staging}/usr/lib","version","mapd"]}]
 }

def validate_compile_recipe(path,repo,build,a):
 recipe=Path(path).read_text(encoding="utf-8",errors="replace")
 linux_rel=os.path.relpath(a.linux,repo); staging=str(a.staging)
 expected=[
  f"-C {build}/libmapd",f'CFLAGS="{a.cppflags} {a.cflags} -Werror -g"',
  f"-C {build}/wappd",f'UAPD_INCLUDE_PATH="{a.linux}/include/uapi/linux/wapp -I{staging}/usr/include"',
  f'EXTRA_CFLAGS="{a.cppflags} {a.cflags} -Wno-error=deprecated-declarations -I{a.linux}/include/uapi/linux/wapp"',
  f"-C {build}/1905daemon",f'LINUXDIR="{linux_rel}"',f'STAGING_DIR="{staging}"',
  f"-C {build}/mapd",'EXTRA_CFLAGS="$$OPENWRT_EASYMESH_CFLAGS"',
  'OPENWRT_EASYMESH_CFLAGS="$$TARGET_EASYMESH_CFLAGS -DCONFIG_SUPPORT_OPENWRT"',
  f'LDFLAGS="{a.ldflags}"',
  f'LDFLAGS="{a.ldflags} -L{staging}/usr/lib -lpthread -ldatconf -lkvcutil -lssl -lcrypto"',
  f'LDFLAGS="{a.ldflags} -L{staging}/usr/lib -Wl,--no-as-needed -lpthread -lnl-tiny -lssl -lcrypto"',
  f'LDFLAGS="{a.ldflags} -L{staging}/usr/lib"',
  "CONFIG_MAP_R2_SUPPORT=y","CONFIG_MAP_R3_SUPPORT=y","MAP_R3_SUPPORT=y","SWTICH_DSA_ARCH=y","version mapd"
 ]
 missing=[x for x in expected if x not in recipe]
 if missing: raise SystemExit("expanded EasyMesh Build/Compile recipe differs from audit assumptions: "+repr(missing))
 if recipe.count(f'CC="{a.cc}"')<4:
  raise SystemExit("expanded Build/Compile recipe does not bind target CC to all four component builds")
 if f'AR="{a.ar}"' not in recipe or f'RANLIB="{a.ranlib}"' not in recipe:
  raise SystemExit("expanded Build/Compile recipe does not bind target AR/RANLIB")
 return sha(path)

def object_output_path(argv,source,cwd):
 """Resolve the compiler's actual -o output, or its documented default."""
 output=None; i=0
 while i<len(argv):
  token=argv[i]
  if token=="-o":
   if i+1>=len(argv): return None
   output=argv[i+1]; i+=1
  elif token.startswith("-o") and len(token)>2:
   output=token[2:]
  i+=1
 if output is None: output=str(Path(source).with_suffix(".o").name)
 return canon(output,cwd)

def parse_libtool_objects(path):
 """Read only libtool's literal object-path metadata; never evaluate the file."""
 found=[]
 try: lines=Path(path).read_text(encoding="utf-8",errors="replace").splitlines()
 except OSError: return None
 for line in lines:
  m=re.match(r"^\s*(?:pic_object|non_pic_object)\s*=\s*['\"]([^'\"]+)['\"]\s*$",line)
  if m and m.group(1)!="none":
   found.append(canon(m.group(1),Path(path).parent))
 return sorted(set(found)) if found else None

def map_preexisting_objects(preexisting,compile_commands):
 """Map existing .o/.lo artifacts to real -o outputs and source files."""
 by_output={}
 for cmd in compile_commands:
  output=cmd.get("object_output")
  if output: by_output.setdefault(output,[]).append(cmd["source"])
 uncompiled=[]; ambiguous=[]; unmapped=[]; mapped=[]
 for artifact in preexisting:
  suffix=artifact.suffix.lower()
  if suffix not in (".o",".lo"): continue
  artifact_path=str(artifact.resolve())
  outputs=[artifact_path] if suffix==".o" else parse_libtool_objects(artifact)
  if suffix==".lo" and outputs is None:
   unmapped.append(artifact_path); continue
  matched=[]
  missing_outputs=[]
  for output in outputs or []:
   if output not in by_output: missing_outputs.append(output)
   else: matched.extend(by_output[output])
  if missing_outputs and suffix==".lo":
   unmapped.append({"artifact":artifact_path,"unmatched_libtool_objects":missing_outputs})
   continue
  if matched and len(set(matched))==1:
   mapped.append({"artifact":artifact_path,"sources":sorted(set(matched)),"method":"exact-compiler-output"})
   continue
  if len(set(matched))>1:
   ambiguous.append({"artifact":artifact_path,"sources":sorted(set(matched))}); continue
  candidates=[artifact.with_suffix(ext).resolve() for ext in EXT if artifact.with_suffix(ext).is_file()]
  if len(candidates)==1: uncompiled.append(str(candidates[0]))
  elif len(candidates)>1:
   ambiguous.append({"artifact":artifact_path,"source_candidates":[str(x) for x in sorted(candidates)]})
  else: unmapped.append(artifact_path)
 return {"mapped":mapped,"uncompiled_source_artifacts":sorted(set(uncompiled)),
         "ambiguous_object_mappings":ambiguous,"unmapped_object_artifacts":unmapped}

def source_reachability_is_complete(make_ok,parse_errors,preprocess_errors,
                                    uncompiled,ambiguous,unmapped,
                                    compile_command_count,source_call_count,
                                    non_call_reference_count,macro_reference_count):
 """Fail closed when references exist but no target translation unit was observed."""
 return bool(make_ok and not parse_errors and not preprocess_errors and
             not uncompiled and not ambiguous and not unmapped and
             (compile_command_count>0 or
              (source_call_count==0 and non_call_reference_count==0 and macro_reference_count==0)))

def classify_reference_reachability(source,line,api,reference_kind,hits,emitted_lines,
                                    compiled_sources,component_complete):
 """Do not exclude a reference unless its containing source was actually preprocessed."""
 key=(source,line,api)
 if reference_kind=="UNKNOWN_REFERENCE_KIND": return "UNKNOWN_FAIL_CLOSED"
 if key in hits: return "ACTIVE"
 if (source,line) in emitted_lines: return "UNKNOWN_FAIL_CLOSED"
 if source not in compiled_sources: return "UNKNOWN_FAIL_CLOSED"
 if component_complete: return "EXCLUDED_WITH_EVIDENCE"
 return "UNKNOWN_FAIL_CLOSED"

def parse_commands(log,base,compiler,component_roots):
 cmds=[]; errors={name:[] for name in component_roots}; dirs=[Path(base)]
 def locate(src,cwd):
  p=Path(src); p=p if p.is_absolute() else Path(cwd)/p
  resolved=Path(os.path.realpath(str(p)))
  for name,root in component_roots.items():
   try: resolved.relative_to(root)
   except ValueError: continue
   return name,resolved
  return None,resolved
 for n,line in enumerate(log.splitlines(),1):
  m=ENTER.search(line)
  if m: dirs.append(Path(m.group(1))); continue
  if LEAVE.search(line):
   if len(dirs)>1: dirs.pop()
   continue
  try: ts=shlex.split(line)
  except ValueError as e:
   if "-c" in line and any(str(root) in line for root in component_roots.values()):
    for name in errors: errors[name].append(f"{n}: cannot parse component compile command: {e}")
   continue
  cwd=dirs[-1]
  if "cd" in ts and "&&" in ts:
   i=ts.index("cd")
   if i+2<len(ts):
    cwd=Path(ts[i+1]); cwd=cwd if cwd.is_absolute() else dirs[-1]/cwd
    ts=ts[i+3:]
  if "-c" not in ts: continue
  srcs=[x for x in ts if Path(x).suffix.lower() in EXT]
  relevant=[]
  for src in srcs:
   name,resolved=locate(src,cwd)
   if name: relevant.append((name,src,resolved))
  if not relevant: continue
  ci=next((i for i,t in enumerate(ts) if Path(t).name==compiler),None)
  if ci is None:
   candidates=[Path(t).name for t in ts if Path(t).name.endswith(("gcc","clang","cc")) or Path(t).name.startswith("clang")]
   for name,src,resolved in relevant:
    errors[name].append(f"{n}: non-target or unrecognized compiler for {resolved}: {candidates or ts[:3]}")
   continue
  if len(relevant)!=1:
   for name,src,resolved in relevant:
    errors[name].append(f"{n}: expected one component source in compiler command, found {len(relevant)}")
   continue
  name,src,resolved=relevant[0]
  if not resolved.is_file():
   errors[name].append(f"{n}: component source file does not exist: {resolved}")
   continue
  argv=ts[ci:]
  cmds.append({"component":name,"cwd":str(Path(cwd).resolve()),"argv":argv,
               "source":str(resolved),"object_output":object_output_path(argv,resolved,cwd),"line":n})
 return cmds,errors

def cpp_argv(cmd,out):
 src=cmd["argv"]; dst=[]; i=0
 while i<len(src):
  t=src[i]
  if t=="-c": dst.append("-E")
  elif t=="-o": i+=1
  elif t.startswith("-o") and len(t)>2: pass
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
 hits=set(); emitted_lines=set(); current=None; lineno=1
 for line in Path(path).read_text(encoding="utf-8",errors="replace").splitlines():
  m=MARK.match(line)
  if m: lineno=int(m.group(1)); current=canon(m.group(2),cwd); continue
  if line.lstrip().startswith("#"): continue
  if current:
   emitted_lines.add((current,lineno))
   for m in CALL.finditer(line):
    if m.group(1) in names: hits.add((current,lineno,m.group(1)))
   lineno+=1
 return hits,emitted_lines

def audit_binary_inputs(build,out):
 rows=[]; nm_available=shutil.which("nm"); file_available=shutil.which("file"); strings_available=shutil.which("strings")
 nm_dir=out/"opaque-binary-nm"; nm_dir.mkdir(parents=True,exist_ok=True)
 for comp in COMP:
  component_root=build/comp
  candidates={}
  for p in sorted(component_root.rglob("*")):
   if p.is_file() and p.suffix.lower() in (".o",".lo",".a",".so"):
    candidates[str(p.resolve())]=p
  for lo in sorted(component_root.rglob("*.lo")):
   for object_path in parse_libtool_objects(lo) or []:
    obj=Path(object_path)
    if obj.is_file() and obj.suffix.lower()==".o":
     candidates[str(obj.resolve())]=obj
  for _,p in sorted(candidates.items()):
   suffix=p.suffix.lower()
   display_path=str(p.relative_to(component_root)) if p.is_relative_to(component_root) else str(p)
   item={"component":comp,"path":display_path,"sha256":sha(p)}
   if suffix==".lo":
    objects=parse_libtool_objects(p)
    metadata_ok=bool(objects) and all(Path(x).is_file() for x in objects)
    item["file_type"]="libtool object metadata"
    item["file_returncode"]=0 if metadata_ok else 1
    item["libtool_object_paths"]=objects or []
    item["nm_returncode"]=0 if metadata_ok else 1
    item["nm_output"]=None
    item["openssl_undefined_symbols"]=[]
    item["strings_returncode"]=0 if metadata_ok else 1
    item["openssl_string_hits"]=[]
    rows.append(item)
    continue
   if file_available:
    f=subprocess.run([file_available,"-b",str(p)],text=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    item["file_type"]=f.stdout.strip(); item["file_returncode"]=f.returncode
   else: item["file_type"]=None; item["file_returncode"]=127
   if nm_available:
    n=subprocess.run([nm_available,"-A","-u",str(p)],text=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    nm_path=nm_dir/(comp+"-"+hashlib.sha256(str(p).encode()).hexdigest()[:12]+".txt")
    nm_path.write_text(n.stdout+n.stderr,encoding="utf-8")
    item["nm_returncode"]=n.returncode; item["nm_output"]=str(nm_path)
    symbols=[]
    for line in n.stdout.splitlines():
     m=re.search(r"\bU\s+([A-Za-z_]\w*)\s*$",line)
     if m and re.match(r"^(OPENSSL_|EVP_|EC_|DH_|DSA_|RSA_|HMAC_|CMAC_|AES_|DES_|ENGINE_|CRYPTO_|BN_|BIO_|SSL_|X509_|OSSL_)",m.group(1)):
      symbols.append(m.group(1))
    item["openssl_undefined_symbols"]=sorted(set(symbols))
   else: item["nm_returncode"]=127; item["openssl_undefined_symbols"]=[]
   if strings_available:
    st=subprocess.run([strings_available,str(p)],text=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    hits=[line for line in st.stdout.splitlines() if re.search(r"libcrypto(\.so)?|libssl(\.so)?|OPENSSL_|EVP_|EC_KEY|ENGINE_|HMAC_|CMAC_|AES_|DES_|RSA_|DH_",line)]
    item["strings_returncode"]=st.returncode; item["openssl_string_hits"]=hits[:100]
   else: item["strings_returncode"]=127; item["openssl_string_hits"]=[]
   rows.append(item)
 complete=all(x.get("nm_returncode")==0 and x.get("file_returncode")==0 and x.get("strings_returncode")==0 for x in rows) if rows else True
 open_refs=any(x.get("openssl_undefined_symbols") or x.get("openssl_string_hits") for x in rows)
 (out/"opaque-binary-symbol-audit.json").write_text(json.dumps(rows,indent=2)+"\n")
 return rows,complete,open_refs

def prepare_mapd_version(build,repo,out,compiler,args):
 # Production Build/Compile calls "version mapd". Reproduce the exact target
 # Make variables for the metadata-only "version" target; never invoke "mapd".
 directory=build/"mapd"
 make_vars=[
  f"TOPDIR={repo}","CONFIG_SUPPORT_OPENWRT=y","CONFIG_MAP_R2_SUPPORT=y",
  "CONFIG_MAP_R3_SUPPORT=y",f"CC={args.cc}",f"LDO={args.cc}",
  f"EXTRA_CFLAGS={args.cppflags} {args.cflags} -Wno-error=deprecated-declarations -DCONFIG_SUPPORT_OPENWRT",
  f"LDFLAGS={args.ldflags} -L{args.staging}/usr/lib","V=s"
 ]
 dry=subprocess.run(["make","-n","-w","-C",str(directory),*make_vars,"version"],cwd=repo,
                    text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
 (out/"mapd-version-dry-run.log").write_text(dry.stdout,encoding="utf-8")
 if dry.returncode: raise SystemExit("MAPD version target dry-run failed")
 for line in dry.stdout.splitlines():
  try: tokens=shlex.split(line)
  except ValueError: raise SystemExit("cannot parse MAPD version target dry-run; fail closed")
  candidates=[Path(t).name for t in tokens if Path(t).name.endswith(("gcc","clang","cc","g++","clang++","c++"))]
  if compiler in candidates or candidates:
   raise SystemExit("MAPD version target dry-run contains a compiler invocation; refusing to execute it")
 run=subprocess.run(["make","-w","-C",str(directory),*make_vars,"version"],cwd=repo,
                    text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
 (out/"mapd-version-generation.log").write_text(run.stdout,encoding="utf-8")
 if run.returncode: raise SystemExit("MAPD version metadata generation failed")

def openssl_header_root(args):
  # Keep the CLI namespace contract explicit and unit-testable.
  return args.openssl_source_dir

def main():
 ap=argparse.ArgumentParser()
 for n in ("repo","build","staging","linux","output"): ap.add_argument("--"+n+"-dir" if n in ("repo","build","output") else "--"+n+"-dir",type=Path,required=True)
 ap.add_argument("--openssl-source-dir",type=Path,required=True); ap.add_argument("--openssl-patch-dir",type=Path,required=True)
 ap.add_argument("--openssl-pkg-source",required=True); ap.add_argument("--openssl-pkg-source-url",required=True)
 ap.add_argument("--openssl-pkg-hash",required=True); ap.add_argument("--openssl-options",required=True)
 ap.add_argument("--target-config",type=Path,required=True); ap.add_argument("--package-compile-recipe",type=Path,required=True)
 ap.add_argument("--cc",required=True); ap.add_argument("--ar",required=True); ap.add_argument("--ranlib",required=True)
 ap.add_argument("--cppflags",default=""); ap.add_argument("--cflags",required=True); ap.add_argument("--ldflags",default="")
 a=ap.parse_args(); repo=a.repo_dir.resolve(); build=a.build_dir.resolve(); a.staging=a.staging_dir.resolve(); a.linux=a.linux_dir.resolve(); a.openssl_source_dir=a.openssl_source_dir.resolve(); a.openssl_patch_dir=a.openssl_patch_dir.resolve(); a.target_config=a.target_config.resolve(); a.package_compile_recipe=a.package_compile_recipe.resolve()
 out=a.output_dir.resolve(); out.mkdir(parents=True,exist_ok=True); (out/"preprocessed").mkdir(exist_ok=True)
 for c in COMP:
  if not (build/c).is_dir(): raise SystemExit(f"missing prepared component: {build/c}")
 if not (a.openssl_source_dir/"Configure").is_file() or not (a.openssl_source_dir/"configdata.pm").is_file():
  raise SystemExit("missing configured OpenSSL source/configdata evidence")
 if not a.openssl_patch_dir.is_dir() or not a.target_config.is_file():
  raise SystemExit("missing expanded OpenSSL PATCH_DIR or target .config")
 if not re.fullmatch(r"[0-9a-f]{64}",a.openssl_pkg_hash):
  raise SystemExit("expanded OpenSSL PKG_HASH is not a SHA256 digest")
 hdr=a.staging/"usr/include/openssl"
 for f in ("configuration.h","opensslv.h"):
  if not (hdr/f).is_file(): raise SystemExit(f"missing Configure-generated target header: {hdr/f}")
 cc=shlex.split(a.cc)
 compiler=Path(cc[-1]).name if cc else ""
 if not cc or not (Path(cc[-1]).is_file() or shutil.which(cc[-1])): raise SystemExit(f"target compiler missing: {a.cc}")
 compiler_path=Path(shutil.which(cc[-1]) or cc[-1]).resolve()
 prepare_mapd_version(build,repo,out,compiler,a)
 inv=inventory_module(repo)
 with (repo/"package/mtk/applications/easymesh-n60/tests/openssl-111-to-359-migration-map.csv").open(encoding="utf-8",newline="") as f: mapping=list(csv.DictReader(f))
 mapped_api_names={x["api"] for x in mapping}
 if len(mapping)!=68 or len(mapped_api_names)!=68: raise SystemExit("migration map must contain 68 unique APIs")
 # Target evidence must cover every API deprecated by the exact pinned 3.5.9
 # public headers, not merely the 68 APIs in the 1.1.1w baseline map.
 names,depr=inv.catalog(openssl_header_root(a))
 rows=[r for r in inv.scan(build,names,depr) if r.get("deprecated_macro")]
 for row in rows: row["reference_kind"]=classify_source_reference(build,row)
 call_rows=[row for row in rows if row["reference_kind"] in ("CALL_EXPRESSION","UNKNOWN_REFERENCE_KIND")]
 non_call_rows=[row for row in rows if row["reference_kind"]=="DECLARATION_OR_DEFINITION"]
 branches={}
 for r in rows:
  p=build/r["path"]
  if str(p) not in branches: branches[str(p)]=branch_path(p)
  r["branch_path"]=branches[str(p)][r["line"]-1]
 recipe_sha=validate_compile_recipe(a.package_compile_recipe,repo,build,a)
 (build/"1905daemon"/"obj").mkdir(parents=True,exist_ok=True)
 specs=make_specs(repo,build,a); results={}; hits=set(); emitted_lines=set(); api_hits_by_component={x:set() for x in COMP}
 macro_refs=inv.scan_macro_references(build,names,depr)
 source_calls_by_component={x:sum(1 for row in call_rows if row["component"]==x) for x in COMP}
 macro_refs_by_component={x:sum(1 for item in macro_refs if item["component"]==x) for x in COMP}
 for comp in COMP:
  tus=[]; pp_errors=[]; parse_errors=[]; logs=[]; compile_commands=[]; run_codes=[]
  for spec in specs[comp]:
   env=os.environ.copy(); env.update(spec["env"])
   run=subprocess.run(spec["argv"],cwd=repo,env=env,text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
   log=out/f"make-dry-run-{spec['name']}.log"; log.write_text(run.stdout,encoding="utf-8")
   logs.append(str(log)); run_codes.append(run.returncode)
   cmds,perrors=parse_commands(run.stdout,spec["cwd"],compiler,{comp: (build/comp).resolve()})
   parse_errors.extend(perrors[comp]); compile_commands.extend(cmds)
  preexisting=[p for p in (build/comp).rglob("*") if p.is_file() and p.suffix.lower() in (".o",".lo",".a",".so")]
  object_mapping=map_preexisting_objects(preexisting,compile_commands)
  uncompiled_source_artifacts=object_mapping["uncompiled_source_artifacts"]
  for i,cmd in enumerate(compile_commands):
   key=hashlib.sha256((comp+cmd["source"]+str(i)).encode()).hexdigest()[:16]
   dest=out/"preprocessed"/f"{comp}-{key}.i"; pargv=cpp_argv(cmd,dest)
   pp=subprocess.run(pargv,cwd=cmd["cwd"],text=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
   err=out/"preprocessed"/f"{comp}-{key}.stderr.txt"; err.write_text(pp.stderr,encoding="utf-8")
   macrofile=out/"preprocessed"/f"{comp}-{key}.macros.txt"; margv=macro_argv(cmd,macrofile)
   mp=subprocess.run(margv,cwd=cmd["cwd"],text=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
   merr=out/"preprocessed"/f"{comp}-{key}.macros.stderr.txt"; merr.write_text(mp.stderr,encoding="utf-8")
   item={"source":cmd["source"],"cwd":cmd["cwd"],"make_log_line":cmd["line"],"make_subtarget":cmd.get("subtarget"),
         "argv":pargv,"returncode":pp.returncode,"macro_argv":margv,"macro_returncode":mp.returncode,
         "stderr":str(err),"macro_stderr":str(merr)}
   if pp.returncode==0 and dest.is_file() and mp.returncode==0 and macrofile.is_file():
    item["preprocessed_sha256"]=sha(dest); item["macro_snapshot_sha256"]=sha(macrofile)
    item["target_macro_snapshot"]=macro_snapshot(macrofile)
    h,emitted=pp_hits(dest,cmd["cwd"],names); hits.update(h); emitted_lines.update(emitted)
    source_root=(build/comp).resolve()
    for hit in h:
     try:
      Path(hit[0]).resolve().relative_to(source_root)
      rel=Path(hit[0]).resolve().relative_to(build.resolve())
     except ValueError: continue
     kind=classify_source_reference(build,{"path":str(rel),"line":hit[1],"api":hit[2]})
     if kind!="DECLARATION_OR_DEFINITION": api_hits_by_component[comp].add(hit[2])
   else: pp_errors.append(item)
   tus.append(item)
  make_ok=all(code==0 for code in run_codes)
  source_complete=source_reachability_is_complete(
   make_ok,parse_errors,pp_errors,uncompiled_source_artifacts,
   object_mapping["ambiguous_object_mappings"],object_mapping["unmapped_object_artifacts"],
   len(compile_commands),source_calls_by_component[comp],
   sum(1 for row in non_call_rows if row["component"]==comp),macro_refs_by_component[comp])
  results[comp]={"make_returncodes":run_codes,"logs":logs,"compile_commands":len(compile_commands),
    "parse_errors":parse_errors,"preexisting_binary_inputs":[str(p.relative_to(build/comp)) for p in preexisting],
    "object_output_mappings":object_mapping["mapped"],
    "uncompiled_source_artifacts":uncompiled_source_artifacts,
    "ambiguous_object_mappings":object_mapping["ambiguous_object_mappings"],
    "unmapped_object_artifacts":object_mapping["unmapped_object_artifacts"],"preprocess_failures":pp_errors,
    "translation_units":tus,"source_reachability_complete":source_complete}
  (out/f"compile-commands-{comp}.json").write_text(json.dumps(compile_commands,indent=2)+"\n")
 (out/"make-compile-command.txt").write_text("component-only Make -n -w dry-runs, bound to expanded Build/Compile recipe\n")
 binary_rows,binary_audit_complete,opaque_binary_openSSL_refs=audit_binary_inputs(build,out)
 complete={c for c,v in results.items() if v["source_reachability_complete"]}
 compiled_sources_by_component={
  comp:{canon(item["source"],repo) for item in results[comp]["translation_units"]}
  for comp in COMP}
 macro_rows=[]; macro_counts={"EXCLUDED_WITH_EVIDENCE":0,"UNKNOWN_FAIL_CLOSED":0}
 for item in macro_refs:
  if item["reachability"]=="UNREFERENCED_MACRO_DEFINITION" and item["component"] in complete:
   state="EXCLUDED_WITH_EVIDENCE"
   reason="macro definition has no lexical reference in the component and target preprocessing completed"
  else:
   state="UNKNOWN_FAIL_CLOSED"
   reason="macro is lexically reachable or target preprocessing cannot prove its expansion inactive"
  macro_counts[state]+=1
  macro_rows.append({**item,"reachability_status":state,"reason":reason})
 callsites=[]; counts={"ACTIVE":0,"EXCLUDED_WITH_EVIDENCE":0,"UNKNOWN_FAIL_CLOSED":0}
 for r in call_rows:
  src=canon(build/r["path"],repo)
  state=classify_reference_reachability(src,r["line"],r["api"],r["reference_kind"],
     hits,emitted_lines,compiled_sources_by_component[r["component"]],r["component"] in complete)
  counts[state]+=1
  callsites.append({"component":r["component"],"path":r["path"],"line":r["line"],"api":r["api"],"reference_kind":r["reference_kind"],"reachability_status":state,
    "conditional_branch_path":r["branch_path"],"source_sha256":sha(build/r["path"]),
    "translation_units":[x["source"] for x in results[r["component"]]["translation_units"] if x["returncode"]==0]})
 non_call_references=[]; non_call_counts={"ACTIVE":0,"EXCLUDED_WITH_EVIDENCE":0,"UNKNOWN_FAIL_CLOSED":0}
 for r in non_call_rows:
  src=canon(build/r["path"],repo)
  state=classify_reference_reachability(src,r["line"],r["api"],r["reference_kind"],
     hits,emitted_lines,compiled_sources_by_component[r["component"]],r["component"] in complete)
  non_call_counts[state]+=1
  non_call_references.append({"component":r["component"],"path":r["path"],"line":r["line"],"api":r["api"],
    "reference_kind":r["reference_kind"],"reachability_status":state,"conditional_branch_path":r["branch_path"],
    "source_sha256":sha(build/r["path"])})
 (out/"openssl-non-call-reference-reachability.json").write_text(json.dumps(non_call_references,indent=2)+"\n")
 summary={"schema_version":1,"git_sha":subprocess.run(["git","rev-parse","HEAD"],cwd=repo,text=True,stdout=subprocess.PIPE,check=True).stdout.strip(),
  "firmware_compile_invoked":False,"method":"expanded OpenWrt Build/Compile recipe validation followed by component Make -n -w V=s and exact-command -E -dD/-dM replay",
  "target_compiler":a.cc,"target_compiler_realpath":str(compiler_path),"target_compiler_sha256":sha(compiler_path),
  "target_compiler_triplet":subprocess.run([str(compiler_path),"-dumpmachine"],text=True,stdout=subprocess.PIPE,check=True).stdout.strip(),
  "target_compiler_version":subprocess.run([str(compiler_path),"-dumpfullversion"],text=True,stdout=subprocess.PIPE,check=True).stdout.strip(),
  "target_compiler_sysroot":subprocess.run([str(compiler_path),"-print-sysroot"],text=True,stdout=subprocess.PIPE,check=True).stdout.strip(),
  "target_ar":a.ar,"target_ranlib":a.ranlib,"target_cppflags":a.cppflags,"target_cflags":a.cflags,"target_ldflags":a.ldflags,
  "target_config_sha256":sha(a.target_config),"package_compile_recipe_sha256":recipe_sha,"openssl_pkg_source":a.openssl_pkg_source,"openssl_pkg_source_url":a.openssl_pkg_source_url,
  "openssl_pkg_hash":a.openssl_pkg_hash,"openssl_options":a.openssl_options,"openssl_build_dir":str(a.openssl_source_dir),
  "openssl_patch_dir":str(a.openssl_patch_dir),"openssl_patch_tree_sha256":tree_sha(a.openssl_patch_dir),
  "openssl_source_tree_sha256":tree_sha(a.openssl_source_dir),"openssl_configure_sha256":sha(a.openssl_source_dir/"Configure"),"openssl_configdata_sha256":sha(a.openssl_source_dir/"configdata.pm"),
  "openssl_header_tree_sha256":tree_sha(hdr),"prepared_source_tree_sha256":tree_sha(build),"components":results,
  "callsite_counts":{"total":len(callsites),**counts},"non_call_reference_counts":{"total":len(non_call_references),**non_call_counts},"macro_reference_counts":{"total":len(macro_rows),**macro_counts},
  "source_reachability_complete":len(complete)==4 and counts["UNKNOWN_FAIL_CLOSED"]==0 and non_call_counts["UNKNOWN_FAIL_CLOSED"]==0 and macro_counts["UNKNOWN_FAIL_CLOSED"]==0,
  "opaque_binary_input_count":len(binary_rows),"opaque_binary_symbol_audit_complete":binary_audit_complete,
  "opaque_binary_openSSL_references_found":opaque_binary_openSSL_refs,
  "complete":len(complete)==4 and counts["UNKNOWN_FAIL_CLOSED"]==0 and non_call_counts["UNKNOWN_FAIL_CLOSED"]==0 and macro_counts["UNKNOWN_FAIL_CLOSED"]==0 and binary_audit_complete and not opaque_binary_openSSL_refs,
  "workflow_build_scope":{"target_toolchain_install":True,"dependency_dev_packages":["datconf","libnl-tiny"],"openssl":"Configure and build_generated headers only","easymesh_component_compile":False,"firmware_compile":False},
  "limitations":["the audit script itself preprocesses only; the enclosing workflow builds the target toolchain and required dependency development packages","prebuilt objects and archives are inventoried and symbol-scanned; symbol absence cannot prove absence of statically embedded code or dlsym-based loading","direct source expressions are classified separately from macro-body references","ambiguous source-line mapping is UNKNOWN_FAIL_CLOSED"]}
 (out/"callsite-reachability.json").write_text(json.dumps(callsites,indent=2)+"\n")
 (out/"macro-reference-reachability.json").write_text(json.dumps(macro_rows,indent=2)+"\n")
 (out/"openssl-target-preprocessor-summary.json").write_text(json.dumps(summary,indent=2)+"\n")
 files=sorted(x for x in out.rglob("*") if x.is_file() and x.name!="SHA256SUMS")
 (out/"SHA256SUMS").write_text("".join(f"{sha(x)}  {x.relative_to(out).as_posix()}\n" for x in files))
 print(json.dumps(summary["callsite_counts"],indent=2)); print("complete="+str(summary["complete"]))
 return 0 if summary["complete"] else 1

if __name__=="__main__": raise SystemExit(main())
