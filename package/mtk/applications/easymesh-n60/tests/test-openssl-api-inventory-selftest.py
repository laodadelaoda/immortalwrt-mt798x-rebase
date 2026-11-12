#!/usr/bin/env python3
import importlib.util,tempfile
from pathlib import Path
p=Path(__file__).with_name("test-openssl-api-inventory.py")
spec=importlib.util.spec_from_file_location("inventory",p); m=importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
s='/* EVP_sha1() */\nEVP_sha256();\nconst char *x="EC_KEY_new()";\nEVP_PKEY_get0_EC_KEY(p);\n// EVP_sha1()\n'
r=m.scan_text(s,{"EVP_sha1","EVP_sha256","EVP_PKEY_get0_EC_KEY"},{"EVP_PKEY_get0_EC_KEY":"OSSL_DEPRECATEDIN_3_0"},"wappd","x.c")
assert [(x["api"],x["line"]) for x in r]==[("EVP_sha256",2),("EVP_PKEY_get0_EC_KEY",4)],r
macro_text="#define UNUSED() EVP_PKEY_cmp(a,b)\n#define INNER() EVP_PKEY_cmp(a,b)\n#define OUTER() INNER()\n"
assert m.scan_text(macro_text,{"EVP_PKEY_cmp"},{"EVP_PKEY_cmp":"OSSL_DEPRECATEDIN_3_0"},"wappd","macro.h")==[]
with tempfile.TemporaryDirectory() as d:
 root=Path(d)
 for c in m.COMP: (root/c).mkdir()
 (root/"wappd/macros.h").write_text("#define UNUSED() EVP_PKEY_cmp(a,b)\n#define INNER() EVP_PKEY_cmp(a,b)\n#define OUTER() INNER()\n")
 (root/"wappd/use.c").write_text("OUTER();\n")
 refs=m.scan_macro_references(root,{"EVP_PKEY_cmp"},{"EVP_PKEY_cmp":"OSSL_DEPRECATEDIN_3_0"})
 states={(x["macro"],x["reachability"]) for x in refs}
 assert ("UNUSED","UNREFERENCED_MACRO_DEFINITION") in states,states
 assert ("INNER","ACTIVE_MACRO_EXPANSION_REQUIRES_CPP") in states,states
with tempfile.TemporaryDirectory() as d:
 root=Path(d)
 for c in m.COMP: (root/c).mkdir()
 (root/"1905daemon/guard.c").write_text('#ifndef OPENSSL_NO_ENGINE\nvoid f(void) { ENGINE_by_id("dynamic"); }\n#endif\n')
 rows=m.scan_text((root/"1905daemon/guard.c").read_text(),{"ENGINE_by_id"},{"ENGINE_by_id":"OSSL_DEPRECATEDIN_3_0"},"1905daemon","1905daemon/guard.c")
 ctx=m.callsite_context(root,rows)
 assert ctx and ctx[0]["preprocessor_guards"]==["#ifndef OPENSSL_NO_ENGINE"],ctx
with tempfile.TemporaryDirectory() as d:
 h=Path(d)/"include/openssl"; h.mkdir(parents=True)
 repo=Path(d)/"repo"; (repo/"package/libs/openssl").mkdir(parents=True)
 tests=repo/"package/mtk/applications/easymesh-n60/tests"; tests.mkdir(parents=True)
 to_hash="b"*64
 (repo/"package/libs/openssl/Makefile").write_text("PKG_VERSION:=3.5.9\nPKG_HASH:="+to_hash+"\n")
 lock={"schema_version":1,"baseline_id":"openssl-1.1.1w-to-3.5.9",
       "from":{"version":"1.1.1w","sha256":"a"*64},
       "to":{"version":"3.5.9","sha256":to_hash}}
 (tests/"openssl-migration-baseline.lock.json").write_text(__import__("json").dumps(lock))
 (h/"opensslv.h.in").write_text("/* OpenSSL version template */\n")
 assert m.validate_openssl_source(Path(d),repo)=="3.5.9"
 (repo/"package/libs/openssl/Makefile").write_text("PKG_VERSION:=3.5.9\nPKG_HASH:="+"0"*64+"\n")
 try:
  m.validate_openssl_source(Path(d),repo)
  raise AssertionError("a mismatched 3.5.9 package hash must fail")
 except ValueError as exc:
  assert "package hash" in str(exc)
with tempfile.TemporaryDirectory() as d:
 root=Path(d)
 for c in m.COMP: (root/c).mkdir()
 (root/"wappd/x.c").write_text("EC_KEY *bad=EVP_PKEY_get0_EC_KEY(p);\nconst EC_KEY *ok=EVP_PKEY_get0_EC_KEY(p);\n")
 assert len(m.const_audit(root))==1
traceability_path=Path(__file__).with_name("openssl-111-to-359-migration-map.csv")
traceability_rows=[]
if traceability_path.is_file():
 with traceability_path.open(encoding="utf-8",newline="") as f:
  traceability_rows=list(__import__("csv").DictReader(f))
print("INFO: optional historical OpenSSL API traceability rows:",len(traceability_rows))
print("PASS: inventory parser masks comments/literals, preserves call-site lines, excludes C type keywords, detects deprecated declarations/const loss, distinguishes active/unreferenced macro expansions and validates OpenSSL 3.5.9 package pinning independently of the optional historical traceability map.")
