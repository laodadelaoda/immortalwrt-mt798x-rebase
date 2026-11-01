#!/bin/sh
set -eu

ROOT="$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)"
WTS="$ROOT/files/etc/map/wts_bss_info_config"
INIT="$ROOT/files/etc/init.d/easymesh"
WRAPPER="$ROOT/files/usr/bin/wapp-n60-wrapper"
DIAG="$ROOT/files/usr/sbin/easymesh-n60-diagnose"
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
    echo "FAIL: WTS differs from the original vendor N60 dual-band profiles" >&2
    diff -u "$EXPECTED" "$WTS" >&2 || true
    exit 1
}

test "$(grep -c '^[0-9][0-9]*,ff:ff:ff:ff:ff:ff ' "$WTS")" -eq 12

# N60 EasyMesh steering prerequisites: both physical radios must expose
# Multi-AP mode and 802.11k RRM; MAPD must retain centralized 11v steering.
MAPD_CFG="$ROOT/files/etc/map/mapd_cfg"
P1905_CFG="$ROOT/files/etc/map/1905d.cfg"
DAT_DIR="$ROOT/../../drivers/wifi-profile/files/mt7986"
for dat in "$DAT_DIR/mt7986-ax6000.dbdc.b0.dat" "$DAT_DIR/mt7986-ax6000.dbdc.b1.dat"; do
    test -s "$dat" || { echo "FAIL: missing N60 radio DAT: $dat" >&2; exit 1; }
    grep -qx 'MapMode=1' "$dat" || { echo "FAIL: Multi-AP mode is not enabled in $dat" >&2; exit 1; }
    grep -qx 'RRMEnable=1' "$dat" || { echo "FAIL: 802.11k RRM is not enabled in $dat" >&2; exit 1; }
done
for setting in \
    'DeviceRole=1' \
    'SteerEnable=1' \
    'CentralizedSteering=1' \
    'NetworkOptimizationEnabled=1' \
    'LowRSSIAPSteerEdge_RE=40' \
    'MetricRepIntv=60' \
    'bss_config_priority=ra0;rax0'; do
    grep -qx "$setting" "$MAPD_CFG" || {
        echo "FAIL: MAPD steering prerequisite is missing: $setting" >&2
        exit 1
    }
done
for setting in \
    'map_root=1' \
    'map_agent=0' \
    'map_ver=R3' \
    'bh_type=eth' \
    'br_inf=br-lan' \
    'al_inf=rax0' \
    'radio_band=24G;5GL;5GH;' \
    'bss_config_priority=ra0;rax0;apclix0'; do
    grep -qx "$setting" "$P1905_CFG" || {
        echo "FAIL: P1905 N60 interface/role prerequisite is missing: $setting" >&2
        exit 1
    }
done

# MAP R3 must be enabled in both the N60 driver build and runtime startup.
REPO_ROOT="$ROOT/../../../.."
DRIVER_CONFIG="$REPO_ROOT/config/n60pro-1001.config"
grep -qx 'CONFIG_MTK_MAP_R2_VER_SUPPORT=y' "$DRIVER_CONFIG"
grep -qx 'CONFIG_MTK_MAP_R3_VER_SUPPORT=y' "$DRIVER_CONFIG"
for setting in mapR3Enable=1 DppEnable=1 mapTSEnable=1 cp_support=1; do
    grep -Fq "$setting" "$INIT" || {
        echo "FAIL: init service does not apply MTK MAP R3 driver setting $setting" >&2
        exit 1
    }
done
grep -Fq 'apply_map_r3_driver_config ra0' "$INIT"
grep -Fq 'apply_map_r3_driver_config rax0' "$INIT"

# Verify shell syntax and the MAP R3 driver startup contract.
sh -n "$INIT"
sh -n "$ROOT/usr/bin/wapp-n60-wrapper"
sh -n "$ROOT/usr/sbin/easymesh-n60-diagnose"
grep -Fq '/lib/libkvcutil.so.1' "$INIT"
grep -Fq 'LIB_WIRELESS_INTERFACE_INFO' "$ROOT/usr/sbin/easymesh-n60-diagnose"
grep -Fq 'cannot find suitable almac' "$ROOT/usr/sbin/easymesh-n60-diagnose"

grep -Fq -- '-ne 12' "$INIT" || { echo "FAIL: init service does not validate the N60 12-row WTS template" >&2; exit 1; }
grep -Fq -- '-ne 12' "$WRAPPER" || { echo "FAIL: WAPP wrapper does not validate the N60 12-row WTS template" >&2; exit 1; }
grep -Fq 'Multi-AP-24G-2' "$WTS"
grep -Fq 'Multi-AP-5LG-2' "$WTS"
grep -Fq 'Multi-AP-5HG-2' "$WTS"
! grep -Eq '(^| )13x |Multi-AP-6G-' "$WTS"
! grep -Eq '(^| )13x |Multi-AP-6G-' "$WRAPPER"

# WAPP must preserve its own startup output for diagnosing failures hidden by procd.
grep -Fq 'WAPP_LOG=/tmp/wapp-n60-startup.log' "$WRAPPER"
grep -Fq 'umask 077' "$WRAPPER"
grep -Fq '>> "$WAPP_LOG" 2>&1' "$WRAPPER"
WAPP_CMD="$(grep -E '^/usr/bin/wapp ' "$WRAPPER")"
for expected in '-m OPMODE_AP' '-i RA_WEXT' '-d1' '-v2' \
    '-f /etc/wapp_ap.conf' '-F /etc/map/mapd_cfg' \
    '-u /etc/map/mapd_user.cfg' '-e br-lan' '-w br-lan' \
    '-c ra0' '-c rax0'; do
    printf '%s\n' "$WAPP_CMD" | grep -Fq -- "$expected"
done
! printf '%s\n' "$WAPP_CMD" | grep -Eq '(^|[[:space:]])-(l|K)([[:space:]]|$)'
grep -Fq 'WAPP startup log (credentials redacted)' "$DIAG"
grep -Fq 'tail -n 120 "$WAPP_LOG"' "$DIAG"

if grep -Fq 'generate-wts-bss-info' "$INIT" "$WRAPPER" "$MAKEFILE"; then
    echo "FAIL: runtime WTS/SSID generator is still wired into the package" >&2
    exit 1
fi

echo "PASS: original 12 vendor N60 dual-band WTS profiles and WAPP startup-log privacy checks"
