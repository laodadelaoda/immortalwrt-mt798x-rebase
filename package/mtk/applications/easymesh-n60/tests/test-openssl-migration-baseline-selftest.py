#!/usr/bin/env python3
"""Self-test the migration baseline's OpenSSL 1.1.1 and 3.x deprecation parser."""
import importlib.util
import tempfile
from pathlib import Path

script=Path(__file__).resolve().parents[1]/"scripts/audit-openssl-migration-baseline.py"
spec=importlib.util.spec_from_file_location("openssl_migration_baseline",script)
mod=importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

with tempfile.TemporaryDirectory() as td:
    header=Path(td)/"openssl"/"test.h"
    header.parent.mkdir()
    header.write_text(
        "#define DEPRECATEDIN_1_1_0 __attribute__((deprecated))\n"
        "DEPRECATEDIN_1_1_0 int old_api(void);\n"
        "#define OSSL_DEPRECATEDIN_3_0 __attribute__((deprecated))\n"
        "OSSL_DEPRECATEDIN_3_0 int new_deprecated_api(void);\n",
        encoding="utf-8"
    )
    assert mod.deprecation_annotation([header],"old_api")=="DEPRECATEDIN_1_1_0"
    assert mod.deprecation_annotation([header],"new_deprecated_api")=="OSSL_DEPRECATEDIN_3_0"
    assert mod.deprecation_annotation([header],"not_present")==""

print("PASS: OpenSSL 1.1.1 DEPRECATEDIN and 3.x OSSL_DEPRECATEDIN annotations are detected.")
