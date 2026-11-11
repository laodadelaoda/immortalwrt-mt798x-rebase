#!/usr/bin/env python3
import importlib.util,tempfile
from pathlib import Path
p=Path(__file__).parents[1]/"scripts/openssl-target-preprocessor-audit.py"
spec=importlib.util.spec_from_file_location("target_audit",p)
m=importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
with tempfile.TemporaryDirectory() as d:
 root=Path(d); src=root/"conditional.c"
 src.write_text(
  "#if defined(OPENSSL_NO_ENGINE) && \\\n"
  "    !defined(OPENSSL_NO_DEPRECATED_3_0)\n"
  "ENGINE_by_id(\"dynamic\");\n"
  "#elif defined(CONFIG_NATIVE_WINDOWS)\nRSA_new();\n"
  "#else\n#if defined(CONFIG_SUITEB)\nEC_KEY_new();\n#else\nHMAC_Init_ex(ctx,key,len,md,impl);\n#endif\n#endif\n")
 paths=m.branch_path(src)
 assert paths[2][0]["branch"].startswith("#if defined(OPENSSL_NO_ENGINE) && !defined")
 assert paths[4][0]["branch"].startswith("#elif defined(CONFIG_NATIVE_WINDOWS)")
 assert paths[7][0]["branch"]=="#else"
 assert paths[7][1]["branch"]=="#if defined(CONFIG_SUITEB)"
 assert paths[8][1]["branch"]=="#else"
 assert paths[9][1]["branch"]=="#else"
 pp=root/"unit.i"
 pp.write_text('# 1 "/tmp/a.c"\nint f(void) { return EVP_PKEY_cmp(a,b); }\n'
               '# 20 "/tmp/inc.h" 1\nint g(void) { return ENGINE_by_id("x") != 0; }\n')
 hits,files=m.pp_hits(pp,root,{"EVP_PKEY_cmp","ENGINE_by_id"})
 assert ("/tmp/a.c",1,"EVP_PKEY_cmp") in hits
 assert ("/tmp/inc.h",20,"ENGINE_by_id") in hits
 assert ("/tmp/inc.h",20) in files
 cmd={"argv":["/tool/aarch64-gcc","-Iinc","-MMD","-MF","x.d","-c","x.c","-o","x.o"]}
 argv=m.cpp_argv(cmd,root/"x.i")
 assert "-E" in argv and "-c" not in argv and "-MMD" not in argv and "-MF" not in argv
 assert argv[-2:]==["-o",str(root/"x.i")]
 assert "-oignored.o" not in m.cpp_argv({"argv":["cc","-c","x.c","-oignored.o"]},root/"joined.i")
 macrofile=root/"macros.txt"
 macrofile.write_text("#define OPENSSL_NO_ENGINE 1\n#define CONFIG_SUITEB\n")
 snapshot=m.macro_snapshot(macrofile)
 assert snapshot["OPENSSL_NO_ENGINE"]=={"defined":True,"value":"1"}
 assert snapshot["CONFIG_SUITEB"]["defined"] is True
 assert snapshot["OPENSSL_IS_BORINGSSL"]["defined"] is False
 (root/"foo.c").write_text("int f(void) { return 0; }\n")
 log=f"make[1]: Entering directory '{root}'\n/tool/aarch64-test-gcc -c foo.c -o foo.o\nmake[1]: Leaving directory '{root}'\n"
 commands,errors=m.parse_commands(log,root,"aarch64-test-gcc",{"component":root.resolve()})
 assert not errors["component"] and len(commands)==1 and commands[0]["source"]==str((root/"foo.c").resolve())
 hostlog=f"/usr/bin/gcc -c '{root}/foo.c' -o foo.o\n"
 hostcommands,hosterrors=m.parse_commands(hostlog,root,"aarch64-test-gcc",{"component":root.resolve()})
 assert not hostcommands and hosterrors["component"],hosterrors
 from types import SimpleNamespace
 assert m.openssl_header_root(SimpleNamespace(openssl_source_dir=root/"openssl")) == root/"openssl"
 args=SimpleNamespace(cppflags="-Itarget",cflags="-O2",ldflags="-Wl,-z,now",
  staging=root/"staging",linux=root/"linux",cc="aarch64-test-gcc",ar="aarch64-test-ar",ranlib="aarch64-test-ranlib")
 assert m.classify_reference_text("static HMAC_CTX *HMAC_CTX_new(void)\n{\n}", "HMAC_CTX_new",1)=="DECLARATION_OR_DEFINITION"
 assert m.classify_reference_text("static void HMAC_CTX_free(HMAC_CTX *ctx)\n{\n}", "HMAC_CTX_free",1)=="DECLARATION_OR_DEFINITION"
 assert m.classify_reference_text("ctx = HMAC_CTX_new();\n", "HMAC_CTX_new",1)=="CALL_EXPRESSION"
 assert m.classify_reference_text("if (ENGINE_by_id(name)) return 1;\n", "ENGINE_by_id",1)=="CALL_EXPRESSION"
 source=root/"active.c"; source.write_text("line1\nEVP_PKEY_eq(a,b);\n#if 0\nENGINE_by_id(name);\n#endif\n",encoding="utf-8")
 preprocessed=root/"active.i"; preprocessed.write_text(f'# 2 "{source}"\nEVP_PKEY_eq(a,b);\n',encoding="utf-8")
 phits,pemitted=m.pp_hits(preprocessed,root,{"EVP_PKEY_eq","ENGINE_by_id"})
 assert (str(source.resolve()),2,"EVP_PKEY_eq") in phits
 assert (str(source.resolve()),2) in pemitted and (str(source.resolve()),4) not in pemitted
 specs=m.make_specs(root,root/"build",args)
 assert len(specs["1905daemon"])==3
 assert all(spec["env"].get("STAGING_DIR")==str(args.staging) for group in specs.values() for spec in group)
 main_1905=specs["1905daemon"][0]["argv"]
 assert main_1905[main_1905.index("-o")+1]=="eth_ops_lib"
 assert specs["1905daemon"][1]["name"]=="1905daemon-ethernet"
 assert specs["1905daemon"][2]["name"]=="1905daemon-libbridge"
 assert specs["1905daemon"][1]["env"]["EXTRA_CFLAGS"].endswith("-DCONFIG_SUPPORT_OPENWRT")
 assert specs["mapd"][0]["env"]["EXTRA_CFLAGS"].endswith("-DCONFIG_SUPPORT_OPENWRT")
 assert not any(x.startswith("EXTRA_CFLAGS=") for x in specs["mapd"][0]["argv"])
 build=root/"build"
 linux_rel=m.os.path.relpath(args.linux,root); staging=str(args.staging)
 recipe_lines=[
  f"-C {build}/libmapd",f'CFLAGS="{args.cppflags} {args.cflags} -Werror -g"',
  f'LDFLAGS="{args.ldflags}"',f"-C {build}/wappd",
  f'UAPD_INCLUDE_PATH="{args.linux}/include/uapi/linux/wapp -I{staging}/usr/include"',
  f'EXTRA_CFLAGS="{args.cppflags} {args.cflags} -I{args.linux}/include/uapi/linux/wapp"',
  "! grep -Fq -- '-Wno-error=deprecated-declarations' $WAPP_COMPILE_LOG",
  f'LDFLAGS="{args.ldflags} -L{staging}/usr/lib -lpthread -ldatconf -lkvcutil -lssl -lcrypto"',
  f"-C {build}/1905daemon",f'LINUXDIR="{linux_rel}"',f'STAGING_DIR="{staging}"',
  f'LDFLAGS="{args.ldflags} -L{staging}/usr/lib -Wl,--no-as-needed -lpthread -lnl-tiny -lssl -lcrypto"',
  f"-C {build}/mapd",'EXTRA_CFLAGS="$$OPENWRT_EASYMESH_CFLAGS"',
  'OPENWRT_EASYMESH_CFLAGS="$$TARGET_EASYMESH_CFLAGS -DCONFIG_SUPPORT_OPENWRT"',
  f'LDFLAGS="{args.ldflags} -L{staging}/usr/lib"',
  "CONFIG_MAP_R2_SUPPORT=y","CONFIG_MAP_R3_SUPPORT=y","MAP_R3_SUPPORT=y","SWTICH_DSA_ARCH=y","version mapd",
  *(f'CC="{args.cc}"' for _ in range(4)),f'AR="{args.ar}"',f'RANLIB="{args.ranlib}"'
 ]
 recipe=root/"Build-Compile.expanded.txt"; recipe.write_text("\n".join(recipe_lines),encoding="utf-8")
 assert m.validate_compile_recipe(recipe,root,build,args)==m.sha(recipe)
 # The expanded recipe and all component dry-runs must preserve strict
 # deprecation diagnostics; any demotion of -Werror is a hard failure.
 original_recipe=recipe.read_text(encoding="utf-8")
 recipe.write_text(original_recipe+"\\nCFLAGS=-Wno-error=deprecated-declarations\\n",encoding="utf-8")
 try:
  m.validate_compile_recipe(recipe,root,build,args)
  raise AssertionError("deprecated-warning demotion in expanded recipe must fail")
 except SystemExit as exc:
  assert "deprecated-API warning suppression is forbidden" in str(exc)
 recipe.write_text(original_recipe,encoding="utf-8")
 assert all("-Wno-error=deprecated-declarations" not in " ".join(spec["argv"]) for group in specs.values() for spec in group)

 # Target preprocessing must use the actual deprecated API set from
 # the pinned OpenSSL 3.5.9 headers, not mark every public API deprecated.
 inv_path=Path(__file__).with_name("test-openssl-api-inventory.py")
 inv_spec=importlib.util.spec_from_file_location("inventory_catalog_test",inv_path)
 inv=importlib.util.module_from_spec(inv_spec); inv_spec.loader.exec_module(inv)
 with tempfile.TemporaryDirectory() as td:
  hroot=Path(td)/"openssl"; inc=hroot/"include/openssl"; inc.mkdir(parents=True)
  (inc/"evp.h").write_text(
   "OSSL_DEPRECATEDIN_3_0 int legacy_api(void);\n"
   "int current_api(void);\n",encoding="utf-8")
  names,depr=inv.catalog(hroot)
  assert "legacy_api" in names and depr.get("legacy_api")=="OSSL_DEPRECATEDIN_3_0"
  assert "current_api" in names and "current_api" not in depr

 # MAPD's Makefile includes $(TOPDIR)/.config. The audit's isolated
 # metadata target must receive the same repository TOPDIR as production.
 from unittest.mock import patch
 calls=[]
 def fake_make(argv,**kwargs):
  calls.append(argv)
  return SimpleNamespace(returncode=0,stdout="make: Nothing to be done for 'version'.\n")
 with tempfile.TemporaryDirectory() as td:
  rr=Path(td); (rr/"build"/"mapd").mkdir(parents=True); out=rr/"out"; out.mkdir()
  with patch.object(m.subprocess,"run",side_effect=fake_make):
   m.prepare_mapd_version(rr/"build",rr,out,"aarch64-test-gcc",args)
  assert len(calls)==2
  for argv in calls:
   for expected in (f"TOPDIR={rr}","CONFIG_SUPPORT_OPENWRT=y","CONFIG_MAP_R2_SUPPORT=y",
                    "CONFIG_MAP_R3_SUPPORT=y",f"CC={args.cc}",f"LDO={args.cc}",
                    f"EXTRA_CFLAGS={args.cppflags} {args.cflags} -DCONFIG_SUPPORT_OPENWRT",
                    f"LDFLAGS={args.ldflags} -L{args.staging}/usr/lib","V=s","version"):
    assert expected in argv,(expected,argv)
   assert "mapd" not in argv[-1:]
  assert calls[0][1]=="-n" and calls[1][1]=="-w"
  assert (out/"mapd-version-dry-run.log").is_file()
  assert (out/"mapd-version-generation.log").is_file()
  unsafe_calls=[]
  def unsafe_make(argv,**kwargs):
   unsafe_calls.append(argv)
   return SimpleNamespace(returncode=0,stdout="/usr/bin/aarch64-test-gcc -c generated.c -o generated.o\n")
  with patch.object(m.subprocess,"run",side_effect=unsafe_make):
   try:
    m.prepare_mapd_version(rr/"build",rr,out,"aarch64-test-gcc",args)
    raise AssertionError("compiler invocation must block MAPD metadata generation")
   except SystemExit as exc:
    assert "compiler invocation" in str(exc)
  assert len(unsafe_calls)==1,"unsafe dry-run must never execute the real make target"

 # Exact compiler -o output, not same-directory filename guessing, is the
 # ownership key for existing object files.
 assert commands[0]["object_output"]==str((root/"foo.o").resolve())
 comp=root/"build"/"wappd"; (comp/"obj").mkdir(parents=True)
 source=root/"build"/"wappd"/"src.c"; source.parent.mkdir(parents=True,exist_ok=True)
 source.write_text("int f(void) { return EVP_PKEY_eq(a,b); }\n")
 obj=comp/"obj"/"actual.o"; obj.write_bytes(b"object")
 lo=comp/"libsample.lo"; lo.write_text("# libtool object file\npic_object='.libs/libsample.o'\nnon_pic_object='none'\n")
 (comp/".libs").mkdir()
 libobj=comp/".libs"/"libsample.o"; libobj.write_bytes(b"object")
 lo_source=comp/"libsrc.c"; lo_source.write_text("int g(void) { return 0; }\n")
 lo_cmd={"source":str(lo_source.resolve()),"object_output":str(libobj.resolve())}
 mapped=m.map_preexisting_objects([obj,lo],[
  {"source":str(source.resolve()),"object_output":str(obj.resolve())},
  lo_cmd])
 assert len(mapped["mapped"])==2 and not mapped["unmapped_object_artifacts"]
 partial_lo=comp/"partial.lo"
 partial_lo.write_text("# libtool object file\npic_object='.libs/not-built.o'\nnon_pic_object='none'\n")
 partial=m.map_preexisting_objects([partial_lo],[])
 assert partial["unmapped_object_artifacts"]
 # Multiple adjacent source candidates are not silently selected.
 ambiguous_obj=comp/"ambiguous.o"; ambiguous_obj.write_bytes(b"object")
 (comp/"ambiguous.c").write_text("int c;\n")
 (comp/"ambiguous.cpp").write_text("int cxx;\n")
 ambiguous=m.map_preexisting_objects([ambiguous_obj],[])
 assert len(ambiguous["ambiguous_object_mappings"])==1
 # A single adjacent source with no matching compiler output is uncompiled.
 stale_obj=comp/"stale.o"; stale_obj.write_bytes(b"object")
 (comp/"stale.c").write_text("int stale;\n")
 stale=m.map_preexisting_objects([stale_obj],[])
 assert stale["uncompiled_source_artifacts"]==[str((comp/"stale.c").resolve())]
 # A component with API references but zero target compile commands cannot pass.
 assert not m.source_reachability_is_complete(True,[],[],[],[],[],0,1,0,0)
 assert not m.source_reachability_is_complete(True,[],[],[],[],[],0,0,0,1)
 assert not m.source_reachability_is_complete(True,[],[],[],[],[],0,0,1,0)
 assert m.source_reachability_is_complete(True,[],[],[],[],[],0,0,0,0)
 assert not m.source_reachability_is_complete(True,[],[],[],[{"artifact":"x"}],[],1,0,0,0)
 compiled=str((comp/"libsrc.c").resolve())
 not_compiled=str((comp/"not-compiled.c").resolve())
 assert m.classify_reference_reachability(not_compiled,1,"EVP_PKEY_free","CALL_EXPRESSION",set(),set(),{compiled},True)=="UNKNOWN_FAIL_CLOSED"
 assert m.classify_reference_reachability(compiled,1,"EVP_PKEY_free","CALL_EXPRESSION",{(compiled,1,"EVP_PKEY_free")},set(),{compiled},True)=="ACTIVE"
 assert m.classify_reference_reachability(compiled,1,"EVP_PKEY_free","CALL_EXPRESSION",set(),{(compiled,1)},{compiled},True)=="UNKNOWN_FAIL_CLOSED"
 assert m.classify_reference_reachability(compiled,1,"EVP_PKEY_free","CALL_EXPRESSION",set(),set(),{compiled},True)=="EXCLUDED_WITH_EVIDENCE"
 assert m.classify_reference_reachability(compiled,1,"EVP_PKEY_free","UNKNOWN_REFERENCE_KIND",set(),set(),{compiled},True)=="UNKNOWN_FAIL_CLOSED"
 # Archives and shared objects remain in the independent symbol/string audit.
 import os
 bindir=root/"fake-bin"; bindir.mkdir()
 for name,body in {
  "nm":"#!/bin/sh\necho 'lib.a: U EVP_PKEY_free'\n",
  "file":"#!/bin/sh\necho 'ELF 64-bit LSB shared object'\n",
  "strings":"#!/bin/sh\necho 'libcrypto.so.3'\n",
 }.items():
  tool=bindir/name; tool.write_text(body); tool.chmod(0o755)
 old_path=os.environ.get("PATH",""); os.environ["PATH"]=str(bindir)+os.pathsep+old_path
 try:
  binary_build=root/"binary-build"; (binary_build/"wappd").mkdir(parents=True)
  (binary_build/"wappd"/"libsample.a").write_bytes(b"archive")
  (binary_build/"wappd"/"libsample.so").write_bytes(b"shared")
  (binary_build/"wappd"/".libs").mkdir()
  (binary_build/"wappd"/".libs"/"libsample.o").write_bytes(b"object")
  (binary_build/"wappd"/"libsample.lo").write_text("# libtool object file\npic_object='.libs/libsample.o'\nnon_pic_object='none'\n")
  binary_rows,binary_ok,openssl_refs=m.audit_binary_inputs(binary_build,root/"binary-audit")
  assert binary_ok and openssl_refs
  assert {Path(x["path"]).suffix for x in binary_rows}=={".a",".so",".lo",".o"}
  lo_row=next(x for x in binary_rows if Path(x["path"]).suffix==".lo")
  assert lo_row["file_type"]=="libtool object metadata" and lo_row["file_returncode"]==0
  invalid_build=root/"invalid-binary-build"; (invalid_build/"wappd").mkdir(parents=True)
  (invalid_build/"wappd"/"broken.lo").write_text("# libtool object file\npic_object='.libs/missing.o'\nnon_pic_object='none'\n")
  invalid_rows,invalid_ok,_=m.audit_binary_inputs(invalid_build,root/"invalid-binary-audit")
  assert not invalid_ok and next(x for x in invalid_rows if x["path"].endswith(".lo"))["file_returncode"]!=0
 finally:
  os.environ["PATH"]=old_path

# Lexical macro graphs can miss token-paste expansion. Target-preprocessed API
# hits must therefore revoke a lexical-only macro exclusion.
inactive={"reachability":"UNREFERENCED_MACRO_DEFINITION","api":"EVP_PKEY_cmp"}
status,reason=m.classify_macro_reference(inactive,True,set())
assert status=="EXCLUDED_WITH_EVIDENCE", (status,reason)
status,reason=m.classify_macro_reference(inactive,True,{"EVP_PKEY_cmp"})
assert status=="UNKNOWN_FAIL_CLOSED", (status,reason)
status,reason=m.classify_macro_reference(inactive,False,set())
assert status=="UNKNOWN_FAIL_CLOSED", (status,reason)
with tempfile.TemporaryDirectory() as td:
 root=Path(td)
 for c in ("wappd","mapd","1905daemon","libmapd"): (root/c).mkdir()
 (root/"wappd/macros.h").write_text(
  "#define WRAP() EVP_PKEY_cmp(a,b)\n"
  "#define CAT(a,b) a##b\n"
  "#define CALL CAT(WR,AP)\n",encoding="utf-8")
 (root/"wappd/use.c").write_text('#include "macros.h"\nCALL();\n',encoding="utf-8")
 refs=inv.scan_macro_references(root,{"EVP_PKEY_cmp"},{"EVP_PKEY_cmp":"OSSL_DEPRECATEDIN_3_0"})
 wrap=next(x for x in refs if x["macro"]=="WRAP")
 assert wrap["reachability"]=="UNREFERENCED_MACRO_DEFINITION",wrap
 # The target preprocessor observes EVP_PKEY_cmp in this component. The
 # macro may have been expanded through ##, so the only safe state is UNKNOWN.
 status,reason=m.classify_macro_reference(wrap,True,{"EVP_PKEY_cmp"})
 assert status=="UNKNOWN_FAIL_CLOSED",(status,reason)


# Source-reference classification must receive the inventory lexer explicitly;
# exercise the direct-source path as well as target-preprocessed callsite mapping.
inventory=m.inventory_module(Path(__file__).resolve().parents[5])
with tempfile.TemporaryDirectory() as td:
 root=Path(td)
 (root/"wappd").mkdir()
 (root/"wappd"/"call.c").write_text("void f(void) { EVP_PKEY_cmp(a,b); }\n",encoding="utf-8")
 row={"path":"wappd/call.c","line":1,"api":"EVP_PKEY_cmp"}
 assert m.classify_source_reference(root,row,inventory)=="CALL_EXPRESSION"

print("PASS: conditional branches, source mapping, preprocess-only argv, exact component flags, source classifier wiring, token-paste macro fail-closed classification and safe 1905 sub-build enumeration.")
