#!/usr/bin/env python3
"""Fail-closed recursive dependency audit for the standalone package builder."""
from __future__ import annotations
import argparse
import re
import tempfile
from pathlib import Path

SAFE_ROOTS = {"kmod-fs-ksmbd"}
FORBIDDEN = ("easymesh-n60", "mt_wifi", "mt-wifi", "mtwifi", "conninfra", "warp", "datconf", "mapfilter")
SYSTEM_VIRTUAL = {"libc", "libgcc", "libpthread", "libatomic", "kernel", "toolchain"}

def resolve_closure(root: str, graph: dict[str, set[str]]) -> list[str]:
    if root not in graph:
        raise ValueError(f"package metadata not found: {root}")
    visited: set[str] = set()
    active: list[str] = []
    order: list[str] = []
    def visit(name: str) -> None:
        low = name.lower()
        if any(token in low for token in FORBIDDEN):
            raise ValueError("closed-source vendor dependency path: " + " -> ".join(active + [name]))
        if name == "__DYNAMIC_DEPENDS__":
            raise ValueError("dynamic dependency expression cannot be proven safe: " + " -> ".join(active))
        if name in SYSTEM_VIRTUAL or name in visited:
            return
        if name in active:
            raise ValueError("dependency cycle: " + " -> ".join(active + [name]))
        if name not in graph:
            raise ValueError("unresolved dependency (fail closed): " + " -> ".join(active + [name]))
        active.append(name)
        for dep in sorted(graph[name]):
            visit(dep)
        active.pop()
        visited.add(name)
        order.append(name)
    visit(root)
    return order

def parse_graph(root: Path) -> dict[str, set[str]]:
    graph: dict[str, set[str]] = {}
    files = []
    for base in ("package", "feeds", "target/linux", "toolchain"):
        folder = root / base
        if folder.exists():
            files.extend(folder.rglob("Makefile"))
            files.extend(folder.rglob("*.mk"))
    for path in files:
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        i = 0
        while i < len(lines):
            match = re.match(r"^define (Package|KernelPackage)/([^/\s]+)\s*$", lines[i])
            if not match:
                i += 1
                continue
            kind, package = match.groups()
            if kind == "KernelPackage" and not package.startswith("kmod-"):
                package = "kmod-" + package
            i += 1
            deps: set[str] = set()
            while i < len(lines) and lines[i].strip() != "endef":
                dep_match = re.match(r"^\s*DEPENDS\s*(?::=|\+=|\?=|=)\s*(.*)$", lines[i])
                if dep_match:
                    value = dep_match.group(1).strip()
                    while value.endswith("\\"):
                        value = value[:-1] + " "
                        i += 1
                        if i >= len(lines):
                            raise ValueError(f"unterminated DEPENDS continuation in {path}")
                        value += lines[i].strip()
                    if "$(" in value:
                        deps.add("__DYNAMIC_DEPENDS__")
                    else:
                        deps.update(
                            dep for dep in re.findall(
                                r"(?<![A-Za-z0-9_])\+([A-Za-z0-9][A-Za-z0-9_.+-]*)", value
                            ) if not dep.startswith("PACKAGE_")
                        )
                i += 1
            graph.setdefault(package, set()).update(deps)
            i += 1
    return graph

def self_test() -> None:
    # Exercise actual Makefile parsing, including KernelPackage -> kmod-*.
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        fixtures = {
            "package/kernel/linux/modules/fs.mk": (
                "define KernelPackage/fs-ksmbd\n"
                "  DEPENDS:=+kmod-lib-crc32c\n"
                "endef\n"
                "define KernelPackage/lib-crc32c\n"
                "  DEPENDS:=+libc\n"
                "endef\n"
            ),
            "feeds/luci/applications/luci-app-ttyd/Makefile": (
                "define Package/luci-app-ttyd\n"
                "  DEPENDS:=+ttyd\n"
                "endef\n"
            ),
            "feeds/packages/utils/ttyd/Makefile": (
                "define Package/ttyd\n"
                "  DEPENDS:=+libc\n"
                "endef\n"
            ),
        }
        for rel, content in fixtures.items():
            path = root / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8")
        graph = parse_graph(root)
        assert resolve_closure("kmod-fs-ksmbd", graph)
        assert resolve_closure("luci-app-ttyd", graph)

    cases = [
        ({"luci-app-ttyd": {"ttyd"}, "ttyd": {"mapfilter"}, "mapfilter": set()}, "vendor"),
        ({"luci-app-ttyd": {"missing-dep"}}, "unresolved"),
        ({"luci-app-ttyd": {"ttyd"}, "ttyd": {"luci-app-ttyd"}}, "cycle"),
        ({"luci-app-ttyd": {"__DYNAMIC_DEPENDS__"}}, "dynamic"),
    ]
    for graph, expected in cases:
        try:
            resolve_closure("luci-app-ttyd", graph)
        except ValueError as exc:
            message = str(exc)
            if expected not in message and not (expected == "vendor" and "closed-source" in message):
                raise AssertionError(f"expected {expected} failure, got: {message}") from exc
        else:
            raise AssertionError(f"dependency test should have failed: {expected}")
    print("PASS: dependency tests (Package/KernelPackage parsing, safe, nested vendor, unresolved, cycle, dynamic)")

def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("package", nargs="?")
    parser.add_argument("--root", default=".")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        self_test()
        return
    if args.package not in SAFE_ROOTS:
        raise SystemExit("FAIL: requested package is outside the reviewed safe allowlist")
    graph = parse_graph(Path(args.root).resolve())
    closure = resolve_closure(args.package, graph)
    print(f"PASS: {args.package} dependency closure contains {len(closure)} packages")
    print("Dependency order: " + " -> ".join(closure))
    print("PASS: no unresolved dependency or closed-source vendor component in closure")

if __name__ == "__main__":
    main()
