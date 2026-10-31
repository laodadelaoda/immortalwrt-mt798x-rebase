#!/bin/sh
set -eu
ROOT="$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)"
GEN="$ROOT/files/usr/sbin/generate-wts-bss-info"
TMPDIR_TEST="$(mktemp -d)"
trap 'rm -rf "$TMPDIR_TEST"' EXIT HUP INT TERM
mkdir -p "$TMPDIR_TEST/bin"

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
RRMEnable=1
EncrypType=AES
WPAPSK1=TestKey5GHz
HideSSID=1
EOF

cat > "$TMPDIR_TEST/bin/iwconfig" <<'EOF'
#!/bin/sh
case "$1" in
    ra0) printf 'ra0 IEEE 802.11ax ESSID:"n60-test-24" Mode:Master\n' ;;
    rax0) printf 'rax0 IEEE 802.11ax ESSID:"n60-test-5g" Mode:Master\n' ;;
    *) exit 1 ;;
esac
EOF
chmod 0755 "$TMPDIR_TEST/bin/iwconfig"

N60_WTS_DAT_24G="$TMPDIR_TEST/2g.dat" \
N60_WTS_DAT_5G="$TMPDIR_TEST/5g.dat" \
N60_WTS_OUTPUT="$TMPDIR_TEST/wts_bss_info_config" \
PATH="$TMPDIR_TEST/bin:$PATH" sh "$GEN"

WTS="$TMPDIR_TEST/wts_bss_info_config"
test "$(sed -n '1p' "$WTS")" = '#ucc_bss_info'
test "$(grep -c '^[1-3],ff:ff:ff:ff:ff:ff ' "$WTS")" -eq 3
grep -qx '1,ff:ff:ff:ff:ff:ff 8x n60-test-24 0x0020 0x0008 TestKey24G 1 1 hidden-N 4095 N/A N/A' "$WTS"
grep -qx '2,ff:ff:ff:ff:ff:ff 11x n60-test-5g 0x0020 0x0008 TestKey5GHz 1 1 hidden-Y 4095 N/A N/A' "$WTS"
grep -qx '3,ff:ff:ff:ff:ff:ff 12x n60-test-5g 0x0020 0x0008 TestKey5GHz 1 1 hidden-Y 4095 N/A N/A' "$WTS"
! grep -Eiq 'maprocks|Multi-AP-|13x|6G' "$WTS"
test "$(stat -c '%a' "$WTS")" = 600

# A live radio whose SSID differs from its DAT profile must not be published.
cp "$WTS" "$TMPDIR_TEST/wts.before"
sed -i 's/n60-test-24/not-the-dat-ssid/' "$TMPDIR_TEST/bin/iwconfig"
if N60_WTS_DAT_24G="$TMPDIR_TEST/2g.dat" \
   N60_WTS_DAT_5G="$TMPDIR_TEST/5g.dat" \
   N60_WTS_OUTPUT="$WTS" PATH="$TMPDIR_TEST/bin:$PATH" sh "$GEN" 2>/dev/null; then
    echo "FAIL: live/DAT SSID mismatch was accepted" >&2
    exit 1
fi
cmp -s "$TMPDIR_TEST/wts.before" "$WTS"
sed -i 's/not-the-dat-ssid/n60-test-24/' "$TMPDIR_TEST/bin/iwconfig"

# Unsupported auth modes and disabled 11k RRM must fail closed and preserve
# the previously generated file without printing or committing real secrets.
sed -i 's/AuthMode=WPA2PSK/AuthMode=SAE/' "$TMPDIR_TEST/5g.dat"
if N60_WTS_DAT_24G="$TMPDIR_TEST/2g.dat" \
   N60_WTS_DAT_5G="$TMPDIR_TEST/5g.dat" \
   N60_WTS_OUTPUT="$WTS" PATH="$TMPDIR_TEST/bin:$PATH" sh "$GEN" 2>/dev/null; then
    echo "FAIL: unsupported SAE profile was accepted" >&2
    exit 1
fi
cmp -s "$TMPDIR_TEST/wts.before" "$WTS"

sed -i 's/AuthMode=SAE/AuthMode=WPA2PSK/; s/RRMEnable=1/RRMEnable=0/' "$TMPDIR_TEST/5g.dat"
if N60_WTS_DAT_24G="$TMPDIR_TEST/2g.dat" \
   N60_WTS_DAT_5G="$TMPDIR_TEST/5g.dat" \
   N60_WTS_OUTPUT="$WTS" PATH="$TMPDIR_TEST/bin:$PATH" sh "$GEN" 2>/dev/null; then
    echo "FAIL: RRMEnable=0 was accepted" >&2
    exit 1
fi
cmp -s "$TMPDIR_TEST/wts.before" "$WTS"

echo "PASS: WTS generation, live/DAT match, 11k gate, field mapping, privacy and fail-closed tests"
