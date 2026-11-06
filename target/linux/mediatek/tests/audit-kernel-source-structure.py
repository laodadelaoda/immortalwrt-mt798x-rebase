#!/usr/bin/env python3
"""Deterministic source-structure audit for an already prepared Linux kernel tree.

This is a conservative lexical audit, not a C compiler. It fails on same-file
duplicate declarations/definitions that can coexist, and reports cross-file
symbol, Kconfig, Makefile and macro candidates for manual/configuration review.
"""
import argparse
import hashlib
import json
import re
import sys
from collections import defaultdict
from pathlib import Path

SOURCE_ROOTS = ("arch", "block", "crypto", "drivers", "fs", "init", "ipc",
                "kernel", "lib", "mm", "net", "security", "sound", "virt", "include")
C_SUFFIXES = {".c", ".h"}\nDTS_SUFFIXES = {".dts", ".dtsi"}
CONTROL = {"if", "for", "while", "switch", "sizeof", "return", "typeof",
           "_Static_assert", "static_assert"}
SKIP_PARTS = {"Documentation", "samples", "scripts", "tools", ".git",
              "usr", "debian", "build"}

def sha(data):
    return hashlib.sha256(data).hexdigest()

def mask_noncode(text):
    """Blank comments and literals while preserving offsets and newlines."""
    out = list(text)
    i, n, state = 0, len(text), "code"
    while i < n:
        c = text[i]
        nxt = text[i + 1] if i + 1 < n else ""
        if state == "code":
            if c == "/" and nxt == "*":
                out[i] = out[i + 1] = " "
                i += 2
                state = "block"
                continue
            if c == "/" and nxt == "/":
                out[i] = out[i + 1] = " "
                i += 2
                state = "line"
                continue
            if c == '"':
                out[i] = " "
                state = "string"
            elif c == "'":
                out[i] = " "
                state = "char"
        elif state == "block":
            if c == "*" and nxt == "/":
                out[i] = out[i + 1] = " "
                i += 2
                state = "code"
                continue
            if c != "\n":
                out[i] = " "
        elif state == "line":
            if c == "\n":
                state = "code"
            else:
                out[i] = " "
        elif state in ("string", "char"):
            if c == "\\":
                out[i] = " "
                if i + 1 < n and text[i + 1] != "\n":
                    out[i + 1] = " "
                    i += 2
                    continue
            elif (state == "string" and c == '"') or (state == "char" and c == "'"):
                out[i] = " "
                state = "code"
            elif c != "\n":
                out[i] = " "
        i += 1
    return "".join(out)

def c_files(root):
    for base in SOURCE_ROOTS:
        folder = root / base
        if not folder.is_dir():
            continue
        for p in folder.rglob("*"):
            if p.suffix not in C_SUFFIXES or any(x in SKIP_PARTS for x in p.parts):
                continue
            if p.is_file():
                yield p

def line_at(text, offset):
    return text.count("\n", 0, offset) + 1

def scope_depths(code):
    depths = {}
    depth = 0
    for number, line in enumerate(code.splitlines(), 1):
        depths[number] = depth
        depth += line.count("{") - line.count("}")
    return depths

def depth_at(code, offset, depths):
    number = line_at(code, offset)
    start = code.rfind("\n", 0, offset) + 1
    prefix = code[start:offset]
    return depths.get(number, 0) + prefix.count("{") - prefix.count("}")

def conditional_contexts(code):
    """Map each line to its active #if/#elif/#else branch path."""
    stack = []
    contexts = {}
    group_id = 0
    for number, line in enumerate(code.splitlines(), 1):
        directive = re.match(r"\s*#\s*(if|ifdef|ifndef|elif|else|endif)\b", line)
        if directive:
            kind = directive.group(1)
            if kind in ("if", "ifdef", "ifndef"):
                group_id += 1
                stack.append([group_id, 0])
            elif kind in ("elif", "else") and stack:
                stack[-1][1] += 1
        contexts[number] = tuple((group, branch) for group, branch in stack)
        if directive and directive.group(1) == "endif" and stack:
            stack.pop()
    return contexts

def mutually_exclusive(left, right):
    a, b = dict(left), dict(right)
    return any(group in b and b[group] != branch for group, branch in a.items())

def has_coexisting_pair(entries):
    for i, left in enumerate(entries):
        for right in entries[i + 1:]:
            if not mutually_exclusive(left[1], right[1]):
                return True
    return False

def scan_c_file(path, rel, global_defs):
    raw = path.read_text(encoding="utf-8", errors="replace")
    code = mask_noncode(raw)
    contexts = conditional_contexts(code)
    depths = scope_depths(code)
    findings = []
    defs = defaultdict(list)
    fn = re.compile(
        r"(?m)^[ \t]*(?P<qual>(?:(?:static|inline|extern|__\w+|asmlinkage|notrace|"
        r"noinline|__always_inline|__maybe_unused)\s+)*)"
        r"[A-Za-z_][\w\s]*?[\*\s]+(?P<name>[A-Za-z_]\w*)\s*"
        r"\([^;{}]*\)\s*(?:__\w+\s*)?\{"
    )
    for m in fn.finditer(code):
        name = m.group("name")
        line = line_at(code, m.start("name"))
        context = contexts.get(line, ())
        if name not in CONTROL:
            defs[name].append((line, context))
            if "static" not in m.group("qual").split():
                global_defs[name].append((rel, line))
    for name, entries in sorted(defs.items()):
        if len(entries) > 1 and has_coexisting_pair(entries):
            findings.append({"severity": "error", "kind": "duplicate_function_definition",
                             "path": rel, "symbol": name, "lines": [x[0] for x in entries]})
    prototypes = defaultdict(list)
    proto = re.compile(
        r"(?m)^[ \t]*(?:(?:extern|static|inline|__\w+)\s+)*"
        r"[A-Za-z_][\w\s]*?[\*\s]+([A-Za-z_]\w*)\s*"
        r"\([^;{}]*\)\s*;"
    )
    for m in proto.finditer(code):
        signature = re.sub(r"\s+", " ", code[m.start():m.end()]).strip()
        line = line_at(code, m.start())
        if depth_at(code, m.start(), depths) == 0:
            prototypes[signature].append((m.group(1), line, contexts.get(line, ())))
    for signature, entries in sorted(prototypes.items()):
        if len(entries) > 1 and has_coexisting_pair([(x[1], x[2]) for x in entries]):
            findings.append({"severity": "review", "kind": "duplicate_prototype",
                             "path": rel, "symbol": entries[0][0],
                             "lines": [x[1] for x in entries], "signature": signature})
    prototype_names = defaultdict(list)
    for signature, entries in prototypes.items():
        for name, line, context in entries:
            prototype_names[name].append((signature, line, context))
    for name, entries in sorted(prototype_names.items()):
        signatures = {x[0] for x in entries}
        if len(signatures) > 1 and has_coexisting_pair([(x[1], x[2]) for x in entries]):
            findings.append({"severity": "error", "kind": "conflicting_prototype_declarations",
                             "path": rel, "symbol": name,
                             "lines": [x[1] for x in entries],
                             "signatures": sorted(signatures)})

    tags = defaultdict(list)
    tag_rx = re.compile(r"\b(struct|union|enum)\s+([A-Za-z_]\w*)\s*\{")
    for m in tag_rx.finditer(code):
        line = line_at(code, m.start())
        if depth_at(code, m.start(), depths) == 0:
            tags[(m.group(1), m.group(2))].append((line, contexts.get(line, ())))
    for (kind, name), entries in sorted(tags.items()):
        if len(entries) > 1 and has_coexisting_pair(entries):
            findings.append({"severity": "error", "kind": "duplicate_tag_definition",
                             "path": rel, "symbol": kind + " " + name,
                             "lines": [x[0] for x in entries]})
    macros = defaultdict(list)
    for m in re.finditer(r"(?m)^\s*#\s*define\s+([A-Za-z_]\w*)", code):
        macros[m.group(1)].append(line_at(code, m.start()))
    for name, lines in sorted(macros.items()):
        if len(lines) > 1:
            findings.append({"severity": "review", "kind": "repeated_macro_name",
                             "path": rel, "symbol": name, "lines": lines})
    return findings

def scan_dts_file(path, rel):
    text = path.read_text(encoding="utf-8", errors="replace")
    labels = defaultdict(list)
    contexts = conditional_contexts(text)
    for number, line in enumerate(text.splitlines(), 1):
        match = re.match(r"\s*([A-Za-z_][A-Za-z0-9_-]*)\s*:\s*[A-Za-z0-9_,.+@-]+\s*\{", line)
        if match:
            labels[match.group(1)].append((number, contexts.get(number, ())))
    findings = []
    for label, entries in sorted(labels.items()):
        if len(entries) > 1:
            severity = "error" if has_coexisting_pair(entries) else "review"
            findings.append({"severity": severity, "kind": "duplicate_dts_label",
                             "path": rel, "symbol": label, "lines": [x[0] for x in entries]})
    return findings

def scan_kconfig(root):
    found = defaultdict(list)
    for p in root.rglob("Kconfig*"):
        if any(x in SKIP_PARTS for x in p.parts) or not p.is_file():
            continue
        try:
            for n, line in enumerate(p.read_text(errors="replace").splitlines(), 1):
                m = re.match(r"\s*config\s+([A-Za-z0-9_]+)\s*$", line)
                if m:
                    found[m.group(1)].append((p.relative_to(root).as_posix(), n))
        except OSError:
            continue
    return [{"severity": "review", "kind": "repeated_kconfig_symbol",
             "symbol": name, "locations": locations}
            for name, locations in sorted(found.items()) if len(locations) > 1]

def scan_makefiles(root):
    findings = []
    for p in root.rglob("Makefile"):
        if any(x in SKIP_PARTS for x in p.parts) or not p.is_file():
            continue
        objects = defaultdict(list)
        try:
            for n, line in enumerate(p.read_text(errors="replace").splitlines(), 1):
                m = re.match(r"\s*(?:obj-[^\s+]+|[A-Za-z0-9_]+-y)\s*\+=\s*(.*?)\s*$", line)
                if m:
                    for obj in m.group(1).split():
                        objects[obj].append(n)
        except OSError:
            continue
        for obj, lines in sorted(objects.items()):
            if len(lines) > 1:
                findings.append({"severity": "review", "kind": "repeated_make_object",
                                 "path": p.relative_to(root).as_posix(),
                                 "symbol": obj, "lines": lines})
    return findings

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--kernel-src", required=True, type=Path)
    ap.add_argument("--output", required=True, type=Path)\n    ap.add_argument("--paths", nargs="*", default=None, help="Limit scan to paths relative to kernel source")
    args = ap.parse_args()
    root = args.kernel_src.resolve()
    if not (root / "Makefile").is_file():
        raise SystemExit("FAIL: kernel source Makefile not found")
    findings = []
    scanned = 0
    global_defs = defaultdict(list)
    if args.paths is None:
        selected = list(c_files(root))
        selected_dts = [p for base in ("arch", "drivers") for p in (root / base).rglob("*")
                        if p.is_file() and p.suffix in DTS_SUFFIXES
                        and not any(x in SKIP_PARTS for x in p.parts)]
    else:
        selected = []
        selected_dts = []
        for rel in args.paths:
            candidate = (root / rel).resolve()
            if root not in candidate.parents and candidate != root:
                raise SystemExit("Path escapes kernel source: " + rel)
            if not candidate.is_file():
                continue
            if candidate.suffix in C_SUFFIXES:
                selected.append(candidate)
            elif candidate.suffix in DTS_SUFFIXES:
                selected_dts.append(candidate)
    for p in selected:
        scanned += 1
        findings.extend(scan_c_file(p, p.relative_to(root).as_posix(), global_defs))
    for p in selected_dts:
        findings.extend(scan_dts_file(p, p.relative_to(root).as_posix()))
    if args.paths is None:
        for name, locations in sorted(global_defs.items()):
            if len(locations) > 1:
                findings.append({"severity": "review", "kind": "cross_file_global_definition_candidate",
                                 "symbol": name, "locations": locations})
        findings.extend(scan_kconfig(root))
        findings.extend(scan_makefiles(root))
    findings.sort(key=lambda x: (x["severity"], x["kind"], x.get("path", ""),
                                 x.get("symbol", "")))
    report = {
        "schema_version": 1,
        "kernel_source": "Linux 6.12.112",
        "c_header_files_scanned": scanned,
        "finding_count": len(findings),
        "error_count": sum(x["severity"] == "error" for x in findings),
        "review_count": sum(x["severity"] == "review" for x in findings),
        "findings": findings,
    }
    encoded = (json.dumps(report, sort_keys=True, separators=(",", ":")) + "\n").encode()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(encoded)
    print(f"Source structure audit: {scanned} C/header files; "
          f"{report['error_count']} errors; {report['review_count']} review candidates; "
          f"sha256={sha(encoded)}")
    if report["error_count"]:
        for item in findings:
            if item["severity"] == "error":
                print(json.dumps(item, sort_keys=True), file=sys.stderr)
        return 1
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
