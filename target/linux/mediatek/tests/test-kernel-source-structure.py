#!/usr/bin/env python3
"""Regression test for the Linux source-structure audit's lexical boundaries."""
import json
import subprocess
import sys
import tempfile
from pathlib import Path

if len(sys.argv) != 1:
    raise SystemExit("this test takes no arguments")

repo = Path(__file__).resolve().parents[4]
scanner = Path(__file__).with_name("audit-kernel-source-structure.py")

with tempfile.TemporaryDirectory(prefix="kernel-structure-audit-") as tmp:
    root = Path(tmp)
    (root / "Makefile").write_text("VERSION = 6\nPATCHLEVEL = 12\nSUBLEVEL = 112\n")
    (root / "drivers/net").mkdir(parents=True)
    (root / "include").mkdir()
    (root / "drivers/net/duplicate.c").write_text(
        "int duplicated(void) { return 0; }\n"
        "int duplicated(void) { return 1; }\n"
        "/* int commented(void) { return 0; } */\n"
        'const char *text = "int string_fake(void) { }";\n'
    )
    (root / "include/duplicate.h").write_text(
        "void duplicated_proto(void);\n"
        "void duplicated_proto(void);\n"
        "struct duplicated_tag { int a; };\n"
        "struct duplicated_tag { int b; };\n"
        "void conflicting_proto(void);\n"
        "int conflicting_proto(void);\n"
    )
    (root / "drivers/net/duplicate.dts").write_text(
        "/ {\\n"
        "    duplicate: node@0 { };\\n"
        "    duplicate: node@1 { };\\n"
        "};\\n"
    )
    (root / "Kconfig").write_text("config DUPLICATE_OPTION\n\nconfig DUPLICATE_OPTION\n")
    (root / "Makefile").write_text(
        "VERSION = 6\nPATCHLEVEL = 12\nSUBLEVEL = 112\n"
        "obj-y += duplicate.o\nobj-y += duplicate.o\n"
    )
    report_path = root / "report.json"
    run = subprocess.run(
        [sys.executable, str(scanner), "--kernel-src", str(root), "--output", str(report_path)],
        text=True, capture_output=True,
    )
    if run.returncode != 1:
        raise SystemExit("duplicate fixture must fail; stdout=" + run.stdout + " stderr=" + run.stderr)
    report = json.loads(report_path.read_text())
    kinds = {item["kind"] for item in report["findings"]}
    required = {"duplicate_function_definition", "duplicate_prototype", "duplicate_tag_definition", "duplicate_dts_label", "conflicting_prototype_declarations"}
    if not required.issubset(kinds):
        raise SystemExit("scanner missed duplicate fixture kinds: " + repr(required - kinds))
    if any(item.get("symbol") in {"commented", "string_fake"} for item in report["findings"]):
        raise SystemExit("scanner reported text inside a comment or string literal")

    clean = root / "clean"
    (clean / "drivers").mkdir(parents=True)
    (clean / "Makefile").write_text("VERSION = 6\nPATCHLEVEL = 12\nSUBLEVEL = 112\n")
    (clean / "drivers/clean.c").write_text(
        "/* int false_positive(void) { } */\n"
        'const char *text = "int also_false(void) { }";\n'
        "int real_function(void) { return 1; }\n"
        "#ifdef CONFIG_VARIANT_A\n"
        "int conditional_variant(void) { return 1; }\n"
        "#else\n"
        "int conditional_variant(void) { return 0; }\n"
        "#endif\n"
    )
    (clean / "drivers/conditional.dtsi").write_text(
        "/ {\\n"
        "#ifdef CONFIG_VARIANT_A\\n"
        "    conditional: node@0 { };\\n"
        "#else\\n"
        "    conditional: node@1 { };\\n"
        "#endif\\n"
        "};\\n"
    )
    clean_report = clean / "report.json"
    clean_run = subprocess.run(
        [sys.executable, str(scanner), "--kernel-src", str(clean), "--output", str(clean_report)],
        text=True, capture_output=True,
    )
    if clean_run.returncode != 0:
        raise SystemExit("clean fixture must pass; stdout=" + clean_run.stdout + " stderr=" + clean_run.stderr)

print("PASS: duplicate definitions/prototypes/tags detected; comments and strings ignored")
