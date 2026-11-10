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
 (h/"opensslv.h.in").write_text("/* OpenSSL version template */\n")
 repo=Path(d)/"repo"; (repo/"package/libs/openssl").mkdir(parents=True)
 tests=repo/"package/mtk/applications/easymesh-n60/tests"; tests.mkdir(parents=True)
 scripts=repo/"package/mtk/applications/easymesh-n60/scripts"; scripts.mkdir(parents=True)
 from_hash="a"*64; to_hash="b"*64
 (repo/"package/libs/openssl/Makefile").write_text("PKG_VERSION:=3.5.9\nPKG_HASH:="+to_hash+"\n")
 lock={"schema_version":1,"baseline_id":"openssl-1.1.1w-to-3.5.9","from":{"version":"1.1.1w","sha256":from_hash},"to":{"version":"3.5.9","sha256":to_hash}}
 lock_path=tests/"openssl-migration-baseline.lock.json"
 lock_path.write_text(__import__("json").dumps(lock))
 input_paths={
  "migration_lock":lock_path,
  "migration_map":tests/"openssl-111-to-359-migration-map.csv",
  "openssl_package_makefile":repo/"package/libs/openssl/Makefile",
  "api_inventory_script":tests/"test-openssl-api-inventory.py",
  "api_inventory_selftest":tests/"test-openssl-api-inventory-selftest.py",
  "baseline_auditor_script":scripts/"audit-openssl-migration-baseline.py",
  "baseline_auditor_selftest":tests/"test-openssl-migration-baseline-selftest.py",
  "api_policy":tests/"openssl-api-policy.json"
 }
 for key,path in input_paths.items():
  if key not in {"migration_lock","openssl_package_makefile"}: path.write_text("fixture:"+key+"\n")
 att={
  "schema_version":2,"status":"VERIFIED","baseline_id":lock["baseline_id"],
  "run":{"id":1,"attempt":1,"git_sha":"c"*40},
  "artifact":{"id":1,"sha256":"d"*64},
  "source":{"archive_sha256":{"1.1.1w":from_hash,"3.5.9":to_hash}},
  "results":{"failures":[],"migration_map_rows":68,"migration_map_apis_present_in_1_1_1w":68,"migration_map_apis_deprecated_in_3_5_9":68},
  "input_sha256":{key:m.sha256_file(path) for key,path in input_paths.items()}
 }
 (tests/"openssl-migration-baseline.attestation.json").write_text(__import__("json").dumps(att))
 att_path=tests/"openssl-migration-baseline.attestation.json"
 expected_sha="c"*40
 assert m.validate_openssl_source(Path(d),repo,att_path,expected_sha)=="3.5.9"
 # A credential from another Git revision is stale even when every input hash matches.
 stale=dict(att); stale["run"]=dict(att["run"]); stale["run"]["git_sha"]="e"*40
 att_path.write_text(__import__("json").dumps(stale))
 try:
  m.validate_openssl_source(Path(d),repo,att_path,expected_sha)
  raise AssertionError("a baseline credential from a different Git SHA must fail")
 except ValueError as exc:
  assert "stale" in str(exc)
 att_path.write_text(__import__("json").dumps(att))
 # A stale or incorrect input digest must invalidate the baseline credential.
 att_path=tests/"openssl-migration-baseline.attestation.json"
 saved_att=__import__("json").loads(att_path.read_text())
 bad_att=dict(saved_att); bad_att["input_sha256"]=dict(saved_att["input_sha256"])
 bad_att["input_sha256"]["api_policy"]="0"*64
 att_path.write_text(__import__("json").dumps(bad_att))
 try:
  m.validate_openssl_source(Path(d),repo,att_path,expected_sha)
  raise AssertionError("incorrect baseline input SHA256 must fail")
 except ValueError as exc:
  assert "input hash mismatch" in str(exc)
 att_path.write_text(__import__("json").dumps(saved_att))

 (h/"opensslv.h").write_text("# define OPENSSL_VERSION_MAJOR 3\n# define OPENSSL_VERSION_MINOR 5\n# define OPENSSL_VERSION_PATCH 9\n")
 assert m.validate_openssl_source(Path(d),repo,att_path,expected_sha)=="3.5.9"
 (h/"evp.h").write_text("int EVP_sha256(void);\nint (*openssl_callback)(void);\nOSSL_DEPRECATEDIN_3_0 const EC_KEY *EVP_PKEY_get0_EC_KEY(const EVP_PKEY *pkey);\n")
 (h/"ssl.h.in").write_text("OSSL_DEPRECATEDIN_3_0 int SSL_use_RSAPrivateKey(SSL *ssl, RSA *rsa);\n")
 names,depr=m.catalog(Path(d))
 assert "EVP_sha256" in names and depr.get("EVP_PKEY_get0_EC_KEY")=="OSSL_DEPRECATEDIN_3_0"
 assert "SSL_use_RSAPrivateKey" in names and depr.get("SSL_use_RSAPrivateKey")=="OSSL_DEPRECATEDIN_3_0"
 assert "int" not in names, names
with tempfile.TemporaryDirectory() as d:
 root=Path(d)
 for c in m.COMP: (root/c).mkdir()
 (root/"wappd/x.c").write_text("EC_KEY *bad=EVP_PKEY_get0_EC_KEY(p);\nconst EC_KEY *ok=EVP_PKEY_get0_EC_KEY(p);\n")
 assert len(m.const_audit(root))==1
with (Path(__file__).with_name("openssl-111-to-359-migration-map.csv")).open(encoding="utf-8",newline="") as f:
 rows=list(__import__("csv").DictReader(f))
 assert len(rows)==68, len(rows)
 assert len({r["api"] for r in rows})==68
 assert all(r["migration_status"]=="UNREVIEWED" and r["approval"]=="false" for r in rows)
 assert all(r["official_mapping_kind"] and r["official_mapping_section"] for r in rows)
 assert all(r["source_reachability_status"] and r["source_reachability_evidence"] for r in rows)
 assert next(r for r in rows if r["api"]=="EVP_CIPHER_CTX_iv_noconst")["source_reachability_status"]=="UNREFERENCED_MACRO_DEFINITION"
 assert all(r["official_migration_guide_url"].startswith("https://docs.openssl.org/3.5/") for r in rows)
 assert all(r["official_target_manual_url"].startswith("https://docs.openssl.org/3.5/") for r in rows)
 assert {"ASN1_STRING_data","SSL_use_RSAPrivateKey","SSL_use_RSAPrivateKey_ASN1","TLSv1_method"}.issubset({r["api"] for r in rows})
print("PASS: inventory parser masks comments/literals, preserves call-site lines, excludes C type keywords, detects deprecated declarations/const loss, distinguishes active/unreferenced macro expansions and validates the 68-row unapproved migration baseline.")
