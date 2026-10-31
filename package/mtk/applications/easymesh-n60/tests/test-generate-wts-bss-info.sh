#!/bin/sh
set -eu
ROOT="$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)"
GEN="$ROOT/files/usr/sbin/generate-wts-bss-info"
TMPDIR_TEST="$(mktemp -d)"
trap 'rm -rf "$TMPDIR_TEST"' EXIT HUP INT TERM

cat > "$TMPDIR_TEST/2g.dat" <<'EOF'
BssidNum=1
SSID1=n60-test-24
AuthMode=WPA2PSK
RRMEnable=1
EncrypType=AES
WPAPSK1=TestKey24G
HideSSID=0
EOF

cat > "$TMPDIR_TEST/5g.dat" <<'EOF'
BssidNum=1
SSID1=n60-test-5g
AuthMode=WPA2PSK
EncrypType=AES
WPAPSK1=TestKey5GHz
HideSSID=1
EOF

N60_WTS_DAT_24G="$TMPDIR_TEST/2g.dat" \
N60_WTS_DAT_5G="$TMPDIR_TEST/5g.dat" \
N60_WTS_OUTPUT="$TMPDIR_TEST/wts_bss_info_config" \
    sh "$GEN"

WTS="$TMPDIR_TEST/wts_bss_info_config"
test "$(sed -n '1p' "$WTS")" = '#ucc_bss_info'
test "$(grep -c '^[1-3],ff:ff:ff:ff:ff:ff ' "$WTS")" -eq 3
grep -qx '1,ff:ff:ff:ff:ff:ff 8x n60-test-24 0x0020 0x0008 TestKey24G 1 1 hidden-N 4095 N/A N/A' "$WTS"
grep -qx '2,ff:ff:ff:ff:ff:ff 11x n60-test-5g 0x0020 0x0008 TestKey5GHz 1 1 hidden-Y 4095 N/A N/A' "$WTS"
grep -qx '3,ff:ff:ff:ff:ff:ff 12x n60-test-5g 0x0020 0x0008 TestKey5GHz 1 1 hidden-Y 4095 N/A N/A' "$WTS"
! grep -Eiq 'maprocks|Multi-AP-|13x|6G' "$WTS"
test "$(stat -c '%a' "$WTS")" = 600

# Unsupported security profiles must fail closed and must not replace output.
cp "$WTS" "$TMPDIR_TEST/wts.before"
sed -i 's/AuthMode=WPA2PSK/AuthMode=SAE/' "$TMPDIR_TEST/5g.dat"
if N60_WTS_DAT_24G="$TMPDIR_TEST/2g.dat" \
   N60_WTS_DAT_5G="$TMPDIR_TEST/5g.dat" \
   N60_WTS_OUTPUT="$WTS" sh "$GEN" 2>/dev/null; then
    echo "FAIL: unsupported SAE profile was accepted" >&2
    exit 1
fi
cmp -s "$TMPDIR_TEST/wts.before" "$WTS"

echo "PASS: WTS generation, field mapping, privacy and fail-closed tests"
