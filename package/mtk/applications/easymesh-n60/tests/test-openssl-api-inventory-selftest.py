#!/usr/bin/env python3
import importlib.util,tempfile
from pathlib import Path
p=Path(__file__).with_name("test-openssl-api-inventory.py")
spec=importlib.util.spec_from_file_location("inventory",p); m=importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
s='/* EVP_sha1() */\nEVP_sha256();\nconst char *x="EC_KEY_new()";\nEVP_PKEY_get0_EC_KEY(p);\n// EVP_sha1()\n'
r=m.scan_text(s,{"EVP_sha1","EVP_sha256","EVP_PKEY_get0_EC_KEY"},{"EVP_PKEY_get0_EC_KEY":"OSSL_DEPRECATEDIN_3_0"},"wappd","x.c")
assert [(x["api"],x["line"]) for x in r]==[("EVP_sha256",2),("EVP_PKEY_get0_EC_KEY",4)],r
with tempfile.TemporaryDirectory() as d:
 h=Path(d)/"include/openssl"; h.mkdir(parents=True)
 template=h/"opensslv.h.in"
 template.write_text("# define OPENSSL_VERSION_MAJOR 3\n# define OPENSSL_VERSION_MINOR 5\n# define OPENSSL_VERSION_PATCH 9\n")
 assert m.version_header(Path(d))==template
 assert not (h/"opensslv.h").exists()
 (h/"opensslv.h").write_text("# define OPENSSL_VERSION_MAJOR 3\n")
 assert m.version_header(Path(d))==template  # source template remains authoritative
 (h/"evp.h").write_text("int EVP_sha256(void);\nOSSL_DEPRECATEDIN_3_0 const EC_KEY *EVP_PKEY_get0_EC_KEY(const EVP_PKEY *pkey);\n")
 names,depr=m.catalog(Path(d)); assert "EVP_sha256" in names and depr.get("EVP_PKEY_get0_EC_KEY")=="OSSL_DEPRECATEDIN_3_0"
with tempfile.TemporaryDirectory() as d:
 root=Path(d)
 for c in m.COMP: (root/c).mkdir()
 (root/"wappd/x.c").write_text("EC_KEY *bad=EVP_PKEY_get0_EC_KEY(p);\nconst EC_KEY *ok=EVP_PKEY_get0_EC_KEY(p);\n")
 assert len(m.const_audit(root))==1
print("PASS: inventory parser masks comments/literals, preserves call-site lines and detects deprecated declarations/const loss.")
