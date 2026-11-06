#!/usr/bin/env bash
# Optional audit wrapper used only by the N60 Linux patch-prepare workflow.
set -Eeuo pipefail
REAL_PATCH="${REAL_PATCH_BIN:-$(command -v patch)}"
AUDIT_ROOT="${PATCH_AUDIT_KERNEL_SRC:-}"
if [[ -z "$AUDIT_ROOT" ]]; then
  args=("$@")
  for ((i=0; i<${#args[@]}; i++)); do
    if [[ "${args[$i]}" == "-d" && $((i+1)) -lt ${#args[@]} ]]; then AUDIT_ROOT="${args[$((i+1))]}"; fi
  done
fi
AUDIT_DIR="${PATCH_AUDIT_REPORT_DIR:-}"
SCANNER="${PATCH_AUDIT_SCANNER:-}"
TESTS_DIR="${PATCH_AUDIT_TESTS_DIR:-}"
PATCH_NAME="${KERNEL_PATCH_AUDIT_PATCH:-unknown-patch}"
tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT
cat > "$tmp"
"$REAL_PATCH" "$@" < "$tmp"
if [[ -z "$AUDIT_ROOT" || -z "$AUDIT_DIR" || -z "$SCANNER" || -z "$TESTS_DIR" ]]; then
  exit 0
fi
mkdir -p "$AUDIT_DIR"
touched_output="$(python3 - "$tmp" <<'PY'
import re, sys
from pathlib import PurePosixPath
text = open(sys.argv[1], encoding="utf-8", errors="replace").read().splitlines()
paths = set()
for line in text:
    value = None
    if line.startswith("diff --git "):
        match = re.match(r"diff --git a/(.+?) b/(.+)$", line)
        if match:
            paths.update((match.group(1), match.group(2)))
            continue
    if line.startswith("Index: "):
        value = line[7:].strip()
    elif line.startswith("--- ") or line.startswith("+++ "):
        value = line[4:].split(chr(9), 1)[0].split(" ", 1)[0]
    if value and value != "/dev/null":
        value = re.sub(r"^[ab]/", "", value)
        value = re.sub(r"^linux-[^/]+(?:\.orig)?/", "", value)
        paths.add(value)
for path in sorted(paths):
    p = PurePosixPath(path)
    if not p.is_absolute() and ".." not in p.parts:
        print(path)
PY
)"
touched=()
if [[ -n "$touched_output" ]]; then
  mapfile -t touched <<< "$touched_output"
fi
report_name="$(basename "$PATCH_NAME")"
report_name="${report_name//[^A-Za-z0-9_.-]/_}"
if ! python3 "$SCANNER" --kernel-src "$AUDIT_ROOT" --output "$AUDIT_DIR/${report_name}.json" --paths "${touched[@]}"; then
  touch "$AUDIT_DIR/intermediate-failures"
fi
case "$report_name" in
  999-dsa-02-add-mt7531-netlink-support.patch)
    if ! python3 "$TESTS_DIR/test-dsa-mt7530-netlink-base.py" "$AUDIT_ROOT"; then touch "$AUDIT_DIR/intermediate-failures"; fi
    ;;
  999-dsa-09-harden-mt7530-netlink-lifecycle-and-bounds.patch)
    if ! python3 "$TESTS_DIR/test-dsa-mt7530-netlink.py" "$AUDIT_ROOT"; then touch "$AUDIT_DIR/intermediate-failures"; fi
    ;;
  999-dsa-10-harden-an8855-netlink-and-procfs-lifecycle.patch)
    if ! python3 "$TESTS_DIR/test-dsa-an8855-netlink.py" "$AUDIT_ROOT"; then touch "$AUDIT_DIR/intermediate-failures"; fi
    ;;
  999-pcie-04-pcie-mediatek-gen3-Add-soft-off-and-soft-on-API.patch)
    if ! python3 "$TESTS_DIR/test-pcie-gen3-irq-lifecycle.py" "$AUDIT_ROOT"; then touch "$AUDIT_DIR/intermediate-failures"; fi
    ;;
esac
