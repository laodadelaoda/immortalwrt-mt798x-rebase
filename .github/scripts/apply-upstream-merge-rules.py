#!/usr/bin/env python3
"""Apply only explicitly allow-listed, path-exact upstream conflict rules.

Automatic rules are intentionally limited to files with unambiguous ownership.
A 'theirs' rule must never overwrite a path changed by N60 Pro since the merge
base; such conflicts remain unresolved for explicit semantic resolution.
"""
import json
import subprocess
import sys
from pathlib import Path


def git(*args, check=True):
    return subprocess.run(
        ["git", *args],
        check=check,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


rules_path = Path(sys.argv[1])
rules_doc = json.loads(rules_path.read_text(encoding="utf-8"))
if rules_doc.get("version") != 1 or not isinstance(rules_doc.get("rules"), list):
    raise SystemExit("Invalid upstream merge rules document")

raw = git("diff", "--name-only", "--diff-filter=U").stdout
conflicts = sorted({line for line in raw.splitlines() if line})
rules = {}
for item in rules_doc["rules"]:
    if not isinstance(item, dict):
        raise SystemExit("Each merge rule must be an object")
    path = item.get("path")
    strategy = item.get("strategy")
    rationale = item.get("rationale")
    if not isinstance(path, str) or not path or path.startswith("/") or ".." in Path(path).parts:
        raise SystemExit(f"Invalid rule path: {path!r}")
    if strategy not in {"ours", "theirs"}:
        raise SystemExit(f"Unsupported strategy for {path}: {strategy!r}")
    if not isinstance(rationale, str) or not rationale.strip():
        raise SystemExit(f"Rule for {path} requires a non-empty rationale")
    if path in rules:
        raise SystemExit(f"Duplicate rule for {path}")
    rules[path] = {"strategy": strategy, "rationale": rationale.strip()}

merge_base = git("merge-base", "HEAD", "MERGE_HEAD").stdout.strip()
if not merge_base:
    raise SystemExit("Cannot determine upstream merge base; refusing automatic resolution")

applied = []
protected = []
for path in conflicts:
    rule = rules.get(path)
    if rule is None:
        continue
    strategy = rule["strategy"]

    # 'theirs' would replace the N60 Pro side. Permit it only when this path
    # has no N60 Pro delta since the common ancestor.
    if strategy == "theirs":
        downstream_delta = git("diff", "--quiet", merge_base, "HEAD", "--", path, check=False)
        if downstream_delta.returncode == 1:
            protected.append(path)
            print(f"PROTECTED downstream-change {path}: refusing 'theirs' rule")
            continue
        if downstream_delta.returncode != 0:
            raise SystemExit(f"Could not establish downstream ownership for {path}")

    git("checkout", f"--{strategy}", "--", path)
    git("add", "--", path)
    applied.append((path, strategy))

for path, strategy in applied:
    print(f"RULE_APPLIED {strategy} {path}")
remaining = git("diff", "--name-only", "--diff-filter=U").stdout.splitlines()
for path in remaining:
    print(f"UNRESOLVED {path}")
print(
    f"SUMMARY applied={len(applied)} protected={len(protected)} "
    f"unresolved={len(remaining)}"
)
