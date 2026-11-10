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
 assert ("OUTER","ACTIVE_MACRO_EXPANSION_REQUIRES_CPP") in states,states
with tempfile.TemporaryDirectory() as d:
 h=Path(d)/"include/openssl"; h.mkdir(parents=True)
 (h/"opensslv.h.in").write_text("/* OpenSSL version template */\n")
 repo=Path(d)/"repo"; (repo/"package/libs/openssl").mkdir(parents=True)
 (repo/"package/libs/openssl/Makefile").write_text("PKG_VERSION:=3.5.9\n")
 assert m.validate_openssl_source(Path(d),repo)=="3.5.9"
 (h/"opensslv.h").write_text("# define OPENSSL_VERSION_MAJOR 3\n# define OPENSSL_VERSION_MINOR 5\n# define OPENSSL_VERSION_PATCH 9\n")
 assert m.validate_openssl_source(Path(d),repo)=="3.5.9"
 (h/"evp.h").write_text("int EVP_sha256(void);\nint (*openssl_callback)(void);\nOSSL_DEPRECATEDIN_3_0 const EC_KEY *EVP_PKEY_get0_EC_KEY(const EVP_PKEY *pkey);\n")
 names,depr=m.catalog(Path(d))
 assert "EVP_sha256" in names and depr.get("EVP_PKEY_get0_EC_KEY")=="OSSL_DEPRECATEDIN_3_0"
 assert "int" not in names, names
with tempfile.TemporaryDirectory() as d:
 root=Path(d)
 for c in m.COMP: (root/c).mkdir()
 (root/"wappd/x.c").write_text("EC_KEY *bad=EVP_PKEY_get0_EC_KEY(p);\nconst EC_KEY *ok=EVP_PKEY_get0_EC_KEY(p);\n")
 assert len(m.const_audit(root))==1
with (Path(__file__).with_name("openssl-111-to-359-migration-map.csv")).open(encoding="utf-8",newline="") as f:
 rows=list(__import__("csv").DictReader(f))
 assert len(rows)==64, len(rows)
 assert len({r["api"] for r in rows})==64
 assert all(r["migration_status"]=="UNREVIEWED" and r["approval"]=="false" for r in rows)
 assert all(r["official_mapping_kind"] and r["official_mapping_section"] for r in rows)
 assert all(r["official_migration_guide_url"].startswith("https://docs.openssl.org/3.5/") for r in rows)
 assert all(r["official_target_manual_url"].startswith("https://docs.openssl.org/3.5/") for r in rows)
print("PASS: inventory parser masks comments/literals, preserves call-site lines, excludes C type keywords, detects deprecated declarations/const loss, distinguishes active/unreferenced macro expansions and validates the 64-row unapproved migration baseline.")
