#!/bin/sh
set -eu

ROOT="$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)"
WTS="$ROOT/files/etc/map/wts_bss_info_config"
INIT="$ROOT/files/etc/init.d/easymesh"
WRAPPER="$ROOT/files/usr/bin/wapp-n60-wrapper"
MAKEFILE="$ROOT/Makefile"

EXPECTED="$(mktemp)"
trap 'rm -f "$EXPECTED"' EXIT HUP INT TERM
cat > "$EXPECTED" <<'EOF'
#ucc_bss_info
1,ff:ff:ff:ff:ff:ff 11x Multi-AP-1 0x00E0 0x0008 maprocks1 1 1 hidden-N 4095 pvid 5
2,ff:ff:ff:ff:ff:ff 11x Multi-AP-5LG-2 0x0060 0x0008 maprocks2 0 1 hidden-N 4095 N/A N/A
3,ff:ff:ff:ff:ff:ff 11x Multi-AP-5LG-3 0x0060 0x0008 maprocks3 0 1 hidden-N 4095 N/A N/A
4,ff:ff:ff:ff:ff:ff 11x Multi-AP-5LG-4 0x0060 0x0008 maprocks4 0 1 hidden-N 4095 N/A N/A
5,ff:ff:ff:ff:ff:ff 8x Multi-AP-1 0x00E0 0x0008 maprocks1 1 0 hidden-N 4095 N/A N/A
6,ff:ff:ff:ff:ff:ff 8x Multi-AP-24G-2 0x0060 0x0008 maprocks2 0 1 hidden-N 4095 N/A N/A
7,ff:ff:ff:ff:ff:ff 8x Multi-AP-24G-3 0x0060 0x0008 maprocks3 0 1 hidden-N 4095 N/A N/A
8,ff:ff:ff:ff:ff:ff 8x Multi-AP-24G-4 0x0060 0x0008 maprocks4 0 1 hidden-N 4095 N/A N/A
9,ff:ff:ff:ff:ff:ff 12x Multi-AP-1 0x00E0 0x0008 maprocks1 1 0 hidden-N 4095 N/A N/A
10,ff:ff:ff:ff:ff:ff 12x Multi-AP-5HG-2 0x0060 0x0008 maprocks2 0 1 hidden-N 4095 N/A N/A
11,ff:ff:ff:ff:ff:ff 12x Multi-AP-5HG-3 0x0060 0x0008 maprocks3 0 1 hidden-N 4095 N/A N/A
12,ff:ff:ff:ff:ff:ff 12x Multi-AP-5HG-4 0x0060 0x0008 maprocks4 0 1 hidden-N 4095 N/A N/A

EOF

cmp -s "$EXPECTED" "$WTS" || {
    echo "FAIL: WTS differs from the original vendor N60 EasyMesh default profiles" >&2
    diff -u "$EXPECTED" "$WTS" >&2 || true
    exit 1
}

test "$(grep -c '^[0-9][0-9]*,ff:ff:ff:ff:ff:ff ' "$WTS")" -eq 12
grep -Fq -- '-ne 12' "$INIT" || { echo "FAIL: init service does not validate the N60 12-row WTS template" >&2; exit 1; }
grep -Fq 'Multi-AP-24G-2' "$WTS"
grep -Fq 'Multi-AP-5LG-2' "$WTS"
grep -Fq 'Multi-AP-5HG-2' "$WTS"
! grep -Eq '(^| )13x |Multi-AP-6G-' "$WTS"

if grep -Fq 'generate-wts-bss-info' "$INIT" "$WRAPPER" "$MAKEFILE"; then
    echo "FAIL: runtime WTS/SSID generator is still wired into the package" >&2
    exit 1
fi

echo "PASS: original 16 vendor EasyMesh WTS test profiles restored; no SSID generator"
