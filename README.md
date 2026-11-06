# ImmortalWrt - MT798x

```
This repository is worked on ImmortalWrt with MTK OpenWrt Feeds patches imported.
```

## Commit Cutoff Revisions

### ImmortalWrt: [84b665b](https://github.com/immortalwrt/immortalwrt/commit/84b665b5de552e297d0f7d755b88a46fc0cfeb13)

```
Merge Official Source

Signed-off-by: Tianling Shen <cnsztl@immortalwrt.org>
```

### MTK OpenWrt Feeds: [08196fa](https://github.com/mediatek/mtk-openwrt-feeds/commit/08196fa6e5d338ce88aa0002f781e2d24289b1f1)

```
[HIGH][openwrt-25][MAC80211][WiFi7][Fix build failure due to license header]

[Description]
Fix image build failure for MP4.3 release SDK.

[Root Cause]
Relevant release patch already includes license header, while internal
commit does not. Hence, duplicate license header is automatically
added when transforming commit to patch, causing patching conflict.

[Solution]
Avoid adding duplicate license header.

[Release-log]
N/A

[How to Verify]
N/A

[Info to Customer]
N/A

Change-Id: Ieb659d0c7763cf11ce2e63cc6bdc53cc2f674000
```

### l1parser: [081bb31](https://github.com/chasey-dev/l1parser/commit/081bb31211efc74594d25bfd1bb5811f3408a205)

```
feat(ucode): add get all device map support
```
## N60 Pro project documentation

This repository also carries the N60 Pro MT7986 / ImmortalWrt 25.12-SNAPSHOT
integration. Project-specific design records and validation boundaries are
maintained separately from the upstream MT798x repository overview:

| Document | Scope |
|---|---|
| [Quick / Full dependency matrix](docs/easymesh-quick-dependency-matrix-2026-11-04.md) | Build responsibilities, dependency closure, audit coverage and CI validation boundaries |
| [N60 EasyMesh runtime validation](docs/easymesh-n60-runtime-validation.md) | Root AP role, dual-radio WTS defaults, startup ordering and runtime acceptance criteria |
| [N60 EasyMesh B-route hardening](docs/easymesh-n60-b-route-hardening-2026-11-01.md) | WTS validation, runtime interface checks and known vendor-binary limitations |
| [WAPP CLI ABI audit](docs/easymesh-wapp-cli-abi-audit-2026-10-31.md) | WAPP control utility / daemon interface evidence |
| [WAPP WTS ABI audit](docs/easymesh-wapp-wts-abi-audit-2026-10-31.md) | Vendor WTS parser behavior and compatibility evidence |

### Current N60 Pro build contract

- Device: Netcore N60 Pro (netcore,n60-pro), MT7986 / Filogic 830,
  dual-band only (ra0 + rax0); no 6 GHz.
- Firmware baseline: ImmortalWrt 25.12-SNAPSHOT, Linux 6.12, OpenSSL 3.x,
  standard ITB profile.
- EasyMesh: source-built MediaTek 7.6.7.3 WAPP / MAPD / P1905 userspace;
  MTK WEXT / iwpriv driver interface; wired-backhaul Root AP.
- Quick validates source preparation, compatibility contracts and the actual
  AArch64 userspace build/link path. Full independently builds the kernel,
  MTK driver and modules, installable packages, and final ITB.
- CI JavaScript actions use Node.js 24-compatible action releases
  (checkout v5, cache v5, upload-artifact v6); keep new workflow actions on
  Node.js 24 runtimes.
- A green static/source audit is not runtime proof. See the runtime document
  for the evidence required to claim topology discovery and client steering.
## About External Devices HNAT
> [!WARNING]
> Current HNAT support for external devices is basic and lack of complete test for various types. Please use with caution.

> [!IMPORTANT]
> Please keep interface `rxppd` in your bridge device (e.g. `br-lan`) while using external device HNAT.

### Support Matrix:
|               |  Ext as WAN   | Ext as LAN                |
|   :----:      |   :----:      | :----:                    |
|  **Ethernet** |      ✔️       |   ❌                     |
| **AP/ApCli**  |      ✔️       |   ⚠️(**Untested**)       |

## Acknowledgements
HNAT support for external devices is adapted from [Padavanonly's repo](https://github.com/padavanonly/immortalwrt-mt798x-6.6). 