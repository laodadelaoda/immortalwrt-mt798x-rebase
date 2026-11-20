#!/usr/bin/env bash
set -Eeuo pipefail

kind="${1:?usage: n60pro-kernel-full-gate.sh dsa|netlink}"
case "$kind" in
  dsa)
    # AN8855 DSA remains required by the current shared Filogic kernel
    # config (CONFIG_NET_DSA_AN8855=y), although it is not N60 Pro board hardware.
    # MT7531 VLAN FID deletion is used by the selected switch application.
    # N60 Pro also selects the HNAT/HQoS path: its PPE lifecycle, SER, DSA,
    # bridge, VLAN, PPPoE, PPD and QDMA integration must remain in this scope.
    # Proprietary debugfs patch 90 is intentionally removed; HNAT 91 and SER 93
    # must apply independently and remain in the native kernel patch series.
    required=(
      999-dsa-02-add-an8855-dsa-downstream.patch
      999-dsa-06-fix-mt7531-vlan-del-to-override-fid.patch
      999-eth-18-mtk_eth_soc-refactor-PSE-PPE-port-link-down.patch
      999-eth-19-mtk_eth_soc-add-ETH-ports-link-down-flow.patch
      999-eth-20-mtk_eth_soc-add-HQoS-configuration-restore.patch
      999-eth-27-mtk_eth_soc-add-skb-mark-support-for-qos.patch
      999-eth-32-mtk_eth_soc-add-SER-fast-mode.patch
      999-eth-48-mtk_eth_soc-add-PSE-port-link-handling-for-MAC-ports.patch
      999-eth-53-mtk_eth_soc-fix-spurious-mdio-timeout.patch
      999-eth-54-mtk_eth_soc-add-misc-interrupt.patch
      999-eth-55-mtk_eth_soc-fix-memory-leak-on-page-pool-creation-failure.patch
      999-eth-56-mtk_eth_soc-add-per-SoC-QDMA-TX-queue-count-and-register-paging.patch
      999-eth-57-mtk_eth_soc-add-per-conduit-DSA-user-port-to-QDMA-queue-map.patch
      999-eth-59-mtk_eth_soc-split-mtk_ppe_start-stop-handling-from-mtk_open-stop.patch
      999-eth-60-mtk_eth_soc-enable-L3-length-overrun-drop.patch
      999-eth-91-mtk_eth_soc-add-mtkhnat-driver-support.patch
      999-eth-93-mtk_eth_soc-add-internal-SER-notify-event.patch
      999-hnat-02-mtk_eth_soc-add-support-ppe-flow-check-interrupt.patch
      999-hnat-03-netfilter-nf_flow_table-support-hw-offload-through-v.patch
      999-hnat-04-net-8021q-support-hardware-flow-table-offload.patch
      999-hnat-05-net-bridge-support-hardware-flow-table-offload.patch
      999-hnat-06-net-pppoe-support-hardware-flow-table-offload.patch
      999-hnat-07-net-dsa-support-hardware-flow-table-offload.patch
      999-hnat-09-mtkhnat-add-support-for-virtual-interface-acceleration.patch
      999-hnat-12-net-core-skbuff-ipv6-fix-pskb-expand-head-limitation.patch
      999-hnat-13-netdevice-add-ndo_flow_offload_stats64_add-for-offload-stats-correction.patch
      999-hnat-14-net-vlan-add-ndo_flow_offload_stats64_add-for-offload-stats-correction.patch
      999-hnat-15-ppp-add-ndo_flow_offload_stats64_add-for-offload-stats-correction.patch
      999-zzz-5101-net-ethernet-mtk_eth_soc-mtkhnat-add-hnat-skb-magic-check.patch
      999-zzz-5102-mtk-hnat-set-ppe-entry.patch
      999-zzz-5103-mtk-hnat-debugfs-change-hook-toggle-read-to-stdout.patch
      999-zzz-5104-mtk-hnat-debugfs-only-set-BIND_RATE-instead-of-writel.patch
      999-zzz-5106-net-ethernet-mtk_eth_soc-disable-tnl-feature-on-NETSYS_V2.patch
      999-zzz-5107-mtk-hnat-debugfs-refactor-ppd-property-set.patch
      999-zzz-5108-mtk-hnat-debugfs-add-wan-lan-property-set.patch
      999-zzz-5109-mtk-hnat-add-rx-ppd.patch
      999-zzz-5110-net-mediatek-mtk_eth_soc-support-rx-ppd-redirect.patch
      999-zzz-5111-mtk-hnat-support-non-whnat-ext-device-ingress-hook.patch
      999-zzz-5112-mtk-hnat-add-ext-devices-prefix-match-support.patch
      999-zzz-5113-net-ethernet-mtk_eth_soc-change-qdma-txq-num-to-64.patch
      999-zzz-5114-mtk-hnat-skip-FDB-checks-for-non-L2-bridge-pkts.patch
      999-zzz-5115-mtk-hnat-fix-mcast-offload-feature-on-NETSYS_V2.patch
      999-zzz-5116-mtk-hnat-bypass-ge-ppd-carrier.patch
      999-zzz-5117-net-mediatek-mtkhnat-use-generic-nf-nat-dependency.patch
      999-zzz-5118-mtk-hnat-enable-wifi-hook-tx-hqos-on-NETSYS_V2.patch
    )
    ;;
  netlink)
    # The N60 Pro switch application uses the MT7531 DSA generic-netlink
    # family; AN8855 userspace netlink support is not part of this board path.
    required=(
      999-dsa-02-add-mt7531-netlink-support.patch
      999-dsa-09-harden-mt7530-netlink-lifecycle-and-bounds.patch
    )
    ;;
  *)
    echo "unknown gate kind: $kind" >&2
    exit 2
    ;;
esac

test "$(git rev-parse HEAD)" = "$GITHUB_SHA"
source_patch_dir=target/linux/mediatek/patches-6.12
test -d "$source_patch_dir"

# Resolve the exact N60 Pro profile before deriving its kernel patch scope.
cp config/n60pro-1001.config .config
grep -Fqx 'CONFIG_TARGET_DEVICE_mediatek_filogic_DEVICE_netcore_n60-pro=y' .config || \
  echo 'CONFIG_TARGET_DEVICE_mediatek_filogic_DEVICE_netcore_n60-pro=y' >> .config
make defconfig

for package in \
  CONFIG_PACKAGE_switch=y \
  CONFIG_PACKAGE_mtkhqos_util=y \
  CONFIG_PACKAGE_kmod-mediatek-hnat=y; do
  grep -Fqx "$package" .config || {
    echo "N60 Pro required package selection missing after defconfig: $package" >&2
    exit 1
  }
done

PATCH_SCOPE="$RUNNER_TEMP/n60pro-kernel-patches-6.12"
python3 .github/scripts/n60pro-kernel-patch-scope.py \
  --source "$source_patch_dir" \
  --output "$PATCH_SCOPE"
applied_patch_dir="$PATCH_SCOPE"
export PATCH_DIR="$applied_patch_dir"
test -d "$applied_patch_dir" || {
  echo "N60 Pro scoped kernel patch directory missing: $applied_patch_dir" >&2
  exit 1
}
for patch in "${required[@]}"; do
  test -s "$applied_patch_dir/$patch" || {
    echo "required $kind patch missing from the N60 Pro applied patch set: $patch" >&2
    exit 1
  }
done

log="$RUNNER_TEMP/n60pro-kernel-$kind-prepare.log"
if ! make target/linux/prepare V=s 2>&1 | tee "$log"; then
  echo "N60 Pro native kernel Prepare failed; preserving patch rejects and source context:" >&2
  while IFS= read -r reject; do
    echo "=== reject: $reject ===" >&2
    sed -n '1,220p' "$reject" >&2
  done < <(find build_dir -type f -name '*.rej' -print)
  kernel_source="$(find build_dir/target-* -path '*/linux-*/linux-6.12.*/drivers/net/ethernet/mediatek/mtk_eth_soc.c' -print -quit)"
  if [[ -n "$kernel_source" ]]; then
    for pattern in 'mtk_ppe_check_skb' 'mac->dsa_port_speed' 'mtk_ppe_internal_debugfs_init' 'mtk_ppe_start(eth->ppe'; do
      echo "=== source context: $pattern ===" >&2
      grep -n -F -B 16 -A 24 "$pattern" "$kernel_source" >&2 || true
    done
  fi
  exit 1
fi

last_line=0
for patch in "${required[@]}"; do
  line="$(grep -nF "$patch" "$log" | head -n1 | cut -d: -f1 || true)"
  if [[ -z "$line" ]]; then
    echo "required $kind patch was not observed in native kernel Prepare log: $patch" >&2
    exit 1
  fi
  if (( line <= last_line )); then
    echo "$kind patch dependency/order violation at $patch (line $line <= $last_line)" >&2
    exit 1
  fi
  last_line="$line"
done

if grep -Eiq 'offset[[:space:]]+[+-]?[0-9]+[[:space:]]+lines?|fuzz[[:space:]]+[0-9]+|FAILED|saving rejects|malformed patch|patch unexpectedly ends in middle of line|Reversed \(or previously applied\)' "$log"; then
  echo "$kind gate failed: offset/fuzz/reject/partial-application signature found" >&2
  grep -Ein 'offset[[:space:]]+[+-]?[0-9]+[[:space:]]+lines?|fuzz[[:space:]]+[0-9]+|FAILED|saving rejects|malformed patch|patch unexpectedly ends in middle of line|Reversed \(or previously applied\)' "$log" >&2 || true
  exit 1
fi

mkdir -p "$RUNNER_TEMP/n60pro-$kind-attestation"
test -s "$applied_patch_dir/scope-manifest.json"
cp "$applied_patch_dir/scope-manifest.json" "$RUNNER_TEMP/n60pro-$kind-attestation/scope-manifest.json"
cp "$applied_patch_dir/scope-manifest.sha256" "$RUNNER_TEMP/n60pro-$kind-attestation/scope-manifest.sha256"
(
  cd "$applied_patch_dir"
  find . -maxdepth 1 -name '*.patch' -print0 | sort -z | xargs -0 sha256sum
) > "$RUNNER_TEMP/n60pro-$kind-attestation/kernel-patches.sha256"
find "$source_patch_dir" -maxdepth 1 -name '*.patch' -printf '%f\n' | LC_ALL=C sort > "$RUNNER_TEMP/n60pro-$kind-attestation/source-patch-list.txt"
find "$applied_patch_dir" -maxdepth 1 -name '*.patch' -printf '%f\n' | LC_ALL=C sort > "$RUNNER_TEMP/n60pro-$kind-attestation/applied-patch-list.txt"
comm -23 "$RUNNER_TEMP/n60pro-$kind-attestation/source-patch-list.txt" "$RUNNER_TEMP/n60pro-$kind-attestation/applied-patch-list.txt" |
while IFS= read -r name; do
  sha256sum "$source_patch_dir/$name"
done > "$RUNNER_TEMP/n60pro-$kind-attestation/excluded-kernel-patches.sha256"
sha256sum "$log" > "$RUNNER_TEMP/n60pro-$kind-attestation/prepare-log.sha256"
python3 - "$kind" "$RUNNER_TEMP/n60pro-$kind-attestation/credential.json" "$RUNNER_TEMP/n60pro-$kind-attestation/kernel-patches.sha256" "$log" "$RUNNER_TEMP/n60pro-$kind-attestation/excluded-kernel-patches.sha256" <<'PY'
import hashlib, json, os, pathlib, subprocess, sys
kind, output, manifest, log_hash, excluded_manifest = sys.argv[1:]
def digest(path):
    return hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest()
data = {
    "schema": 1,
    "gate": kind,
    "git_sha": subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip(),
    "github_run_id": os.environ["GITHUB_RUN_ID"],
    "github_run_attempt": os.environ["GITHUB_RUN_ATTEMPT"],
    "kernel_patch_manifest_sha256": digest(manifest),
    "excluded_kernel_patch_manifest_sha256": digest(excluded_manifest),
    "scope_manifest_sha256": digest(pathlib.Path(output).parent / "scope-manifest.json"),
    "prepare_log_sha256": digest(log_hash),
    "native_target": "mediatek/filogic netcore_n60-pro",
    "kernel_patch_level": "6.12",
    "result": "pass"
}
pathlib.Path(output).write_text(json.dumps(data, sort_keys=True, indent=2))
PY

echo "PASS: $kind native kernel Prepare replay; attestation generated."
