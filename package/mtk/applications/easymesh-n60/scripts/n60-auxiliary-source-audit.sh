#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="${GITHUB_WORKSPACE:-$(pwd)}"
python3 "$ROOT/package/mtk/applications/easymesh-n60/scripts/n60-vendor-source-transforms.py" verify-lock "$ROOT"
mapfile -t BND_LOCK < <(python3 - "$ROOT" <<'PY'
import json, sys
from pathlib import Path
lock = json.loads((Path(sys.argv[1]) / "package/mtk/vendor-sources.lock.json").read_text())
item = next(x for x in lock["sources"] if x["id"] == "bndstrg_plus")
for key in ("archive", "url", "sha256", "extract_root", "extract_to"):
    print(item[key])
PY
)
mapfile -t FWDD_LOCK < <(python3 - "$ROOT" <<'PY'
import json, sys
from pathlib import Path
lock = json.loads((Path(sys.argv[1]) / "package/mtk/vendor-sources.lock.json").read_text())
item = next(x for x in lock["sources"] if x["id"] == "fwdd")
for key in ("archive", "url", "sha256", "extract_root", "extract_to"):
    print(item[key])
PY
)
TMP="${RUNNER_TEMP:-/tmp}/n60-auxiliary-source-audit"
mkdir -p "$TMP"
rm -rf "$TMP/bndstrg" "$TMP/fwdd"
mkdir -p "$TMP/bndstrg" "$TMP/fwdd"

BND_ARCHIVE="$TMP/${BND_LOCK[0]}"
FWDD_ARCHIVE="$TMP/${FWDD_LOCK[0]}"
BND_URL="${BND_LOCK[1]}"
BND_SHA="${BND_LOCK[2]}"
BND_EXTRACT_ROOT="${BND_LOCK[3]}"
BND_EXTRACT_TO="${BND_LOCK[4]}"
FWDD_URL="${FWDD_LOCK[1]}"
FWDD_SHA="${FWDD_LOCK[2]}"
FWDD_EXTRACT_ROOT="${FWDD_LOCK[3]}"
FWDD_EXTRACT_TO="${FWDD_LOCK[4]}"
BND_DEST="$TMP/$BND_EXTRACT_TO"
FWDD_DEST="$TMP/$FWDD_EXTRACT_TO"
mkdir -p "$BND_DEST" "$FWDD_DEST"

curl -fL --retry 3 "$BND_URL" -o "$BND_ARCHIVE"
curl -fL --retry 3 "$FWDD_URL" -o "$FWDD_ARCHIVE"
printf '%s  %s\n' "$BND_SHA" "$BND_ARCHIVE" | sha256sum -c -
printf '%s  %s\n' "$FWDD_SHA" "$FWDD_ARCHIVE" | sha256sum -c -

tar -xjf "$BND_ARCHIVE" -C "$BND_DEST"
tar -xjf "$FWDD_ARCHIVE" -C "$FWDD_DEST"

BND_ROOT="$BND_DEST/$BND_EXTRACT_ROOT"
FWDD_ROOT="$FWDD_DEST/$FWDD_EXTRACT_ROOT"
BND_PATCH="$ROOT/package/mtk/applications/easymesh-n60/auxiliary-patches/001-bndstrg-gcc14-werror-and-init.patch"
FWDD_PATCH="$ROOT/package/mtk/applications/easymesh-n60/auxiliary-patches/002-fwdd-gcc14-bounded-ifname-copy.patch"

patch --dry-run -d "$TMP/bndstrg" -p1 < "$BND_PATCH"
patch -d "$TMP/bndstrg" -p1 < "$BND_PATCH"
patch --dry-run -d "$TMP/fwdd" -p1 < "$FWDD_PATCH"
patch -d "$TMP/fwdd" -p1 < "$FWDD_PATCH"

# Verify the duplicate user/kernel Band Steering message ABI before compiling.
MT_WIFI_SRC="$ROOT/build_dir/target-aarch64_cortex-a53_musl/linux-mediatek_filogic/mt_wifi"
test -s "$MT_WIFI_SRC/embedded/include/band_steering_def.h" || {
  echo "::error::Prepared MT Wi-Fi source is missing the Band Steering ABI header."
  exit 1
}
python3 - "$BND_ROOT/bndstrg.h" "$MT_WIFI_SRC/embedded/include/band_steering_def.h" <<'PY'
import re
import sys
from pathlib import Path

def structs(path):
    source = Path(path).read_text(encoding="utf-8")
    result = {}
    for match in re.finditer(r"\bstruct\s+(\w+)\s*\{", source):
        name = match.group(1)
        index = match.end()
        depth = 1
        while index < len(source) and depth:
            depth += (source[index] == "{") - (source[index] == "}")
            index += 1
        if depth == 0:
            result[name] = source[match.end():index - 1]
    return result

def field_names(body):
    body = re.sub(r"/\*.*?\*/|//[^\n]*", "", body, flags=re.S)
    names = []
    for line in body.splitlines():
        line = line.strip()
        if not line or "{" in line or "}" in line or ";" not in line:
            continue
        match = re.search(r"([A-Za-z_]\w*)\s*(?:\[[^]]*\])?\s*;\s*$", line)
        if match:
            names.append(match.group(1).lower())
    return names

user = structs(sys.argv[1])
kernel = structs(sys.argv[2])
common = sorted(set(user) & set(kernel))
assert len(common) >= 10, f"too few shared message structures found: {common}"
mismatches = []
for name in common:
    user_fields = field_names(user[name])
    kernel_fields = field_names(kernel[name])
    if user_fields != kernel_fields:
        mismatches.append((name, user_fields, kernel_fields))
assert not mismatches, f"user/kernel Band Steering ABI field mismatch: {mismatches}"
probe = field_names(user["bnd_msg_cli_probe"])
expected = ["ballowstaconnectinht", "bvhtcapable", "nss", "rssi"]
assert probe == expected, f"unexpected CLI probe layout: {probe}"
print(f"PASS: {len(common)} shared bndstrg/mt_wifi message structures have matching field order.")
print("PASS: CLI probe layout matches kernel: bAllowStaConnectInHt, bVHTCapable, Nss, Rssi.")
PY
grep -Eq '#define[[:space:]]+OID_BNDSTRG_MSG[[:space:]]+0x0950' "$BND_ROOT/driver_wext.h"
grep -Eq '#define[[:space:]]+OID_GET_SET_TOGGLE[[:space:]]+0x8000' "$BND_ROOT/driver_wext.h"
grep -Eq '#define[[:space:]]+OID_BNDSTRG_MSG[[:space:]]+0x0950' "$MT_WIFI_SRC/embedded/include/oid.h"
grep -Eq '#define[[:space:]]+OID_GET_SET_TOGGLE[[:space:]]+0x8000' "$MT_WIFI_SRC/embedded/include/oid.h"
grep -Fq 'case OID_BNDSTRG_MSG:' "$MT_WIFI_SRC/embedded/ap/ap_cfg.c"
grep -Fq 'BndStrgSendMsg(pAd, &msg)' "$MT_WIFI_SRC/embedded/ap/ap_band_steering.c"
grep -Fq 'RT_PRIV_IOCTL = SIOCIWFIRSTPRIV + 0x01' "$MT_WIFI_SRC/os/linux/ap_ioctl.c"
echo "PASS: MTK OID values and RT_PRIV_IOCTL / Band Steering driver handlers match bndstrg_plus."

TARGET_CC="$(find "$ROOT"/staging_dir/toolchain-* -maxdepth 3 -name '*aarch64*linux*musl*gcc' -print -quit)"
test -n "$TARGET_CC" || {
  echo "::error::AArch64 musl target compiler not found under staging_dir/toolchain-*."
  exit 1
}
echo "Using target compiler: $TARGET_CC"

make -C "$BND_ROOT" clean
make -C "$BND_ROOT" CONFIG_SUPPORT_OPENWRT=y CC="$TARGET_CC" \
  CFLAGS="-Os -pipe -Wall -Werror -DWPS_SUPPORT" \
  EXTRA_CFLAGS="-Os -pipe -Wall -Werror -lrt -DWPS_SUPPORT" \
  LDFLAGS="-lpthread" V=s
make -C "$FWDD_ROOT" clean
make -C "$FWDD_ROOT" CC="$TARGET_CC" \
  CFLAGS="-Os -pipe -Wall -Werror -O2" V=s

for binary in "$BND_ROOT/bndstrg2" "$FWDD_ROOT/fwdd"; do
  test -s "$binary"
  readelf -h "$binary" | grep -Fq 'AArch64' || {
    echo "::error::Auxiliary binary is not AArch64: $binary"
    exit 1
  }
done
mkdir -p "$ROOT/artifacts/easymesh-quick"
cp "$BND_ROOT/bndstrg2" "$FWDD_ROOT/fwdd" "$ROOT/artifacts/easymesh-quick/"
{
  echo "Scope: auxiliary source audit only; these packages are not selected by config/n60pro-1001.config."
  echo "Compiler: $TARGET_CC"
  echo "bndstrg_plus source SHA256: $(sha256sum "$BND_ARCHIVE" | cut -d' ' -f1)"
  echo "fwdd source SHA256: $(sha256sum "$FWDD_ARCHIVE" | cut -d' ' -f1)"
  echo "AArch64 outputs:"
  readelf -h "$BND_ROOT/bndstrg2" | grep -E 'Class:|Machine:'
  readelf -h "$FWDD_ROOT/fwdd" | grep -E 'Class:|Machine:'
  sha256sum "$BND_ROOT/bndstrg2" "$FWDD_ROOT/fwdd"
} > "$ROOT/artifacts/easymesh-quick/AUXILIARY-SOURCE-AUDIT.txt"
cat "$ROOT/artifacts/easymesh-quick/AUXILIARY-SOURCE-AUDIT.txt"
echo "PASS: bndstrg_plus and fwdd compile for AArch64 musl with -Wall -Werror; no firmware package integration was added."
