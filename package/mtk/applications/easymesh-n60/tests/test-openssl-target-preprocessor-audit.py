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
 assert paths[8][1]["branch"]=="#if defined(CONFIG_SUITEB)"
 assert paths[10][1]["branch"]=="#else"
 pp=root/"unit.i"
 pp.write_text('# 1 "/tmp/a.c"\nint f(void) { return EVP_PKEY_cmp(a,b); }\n'
               '# 20 "/tmp/inc.h" 1\nint g(void) { return ENGINE_by_id("x") != 0; }\n')
 hits,files=m.pp_hits(pp,root,{"EVP_PKEY_cmp","ENGINE_by_id"})
 assert ("/tmp/a.c",1,"EVP_PKEY_cmp") in hits
 assert ("/tmp/inc.h",20,"ENGINE_by_id") in hits
 assert ("/tmp/inc.h","ENGINE_by_id") in files
 cmd={"argv":["/tool/aarch64-gcc","-Iinc","-MMD","-MF","x.d","-c","x.c","-o","x.o"]}
 argv=m.cpp_argv(cmd,root/"x.i")
 assert "-E" in argv and "-c" not in argv and "-MMD" not in argv and "-MF" not in argv
 assert argv[-2:]==["-o",str(root/"x.i")]
print("PASS: multiline conditional branches, elif/else, nested guards, GCC line markers and preprocess-only argv conversion.")
