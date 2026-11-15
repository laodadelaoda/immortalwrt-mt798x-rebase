# ImmortalWrt - MT798x

```
This repository is worked on ImmortalWrt with MTK OpenWrt Feeds patches imported.
```

## Commit Cutoff Revisions

### ImmortalWrt: [761b7ff](https://github.com/immortalwrt/immortalwrt/commit/761b7ff22cbf7c13f28fc631bd70a84d295fd627)

```
Merge Official Source

Signed-off-by: Tianling Shen <cnsztl@immortalwrt.org>
```

### MTK OpenWrt Feeds: [3f66af2](https://github.com/mediatek/mtk-openwrt-feeds/commit/3f66af253becc66364f90669e58d59db19de6d95)

```
[kernel-6.12][common][ppe][Fix patch conflict issue]

[Description]
Fix patch conflict issue.

[Root Cause]
Openwrt 25.12 linux version upgrade.

[Solution]
N/A

[How to Verify]
N/A

[Info to Customer]
N/A


Change-Id: Ie6b704c027b61032e496c0c7dc51fe268900e7d3
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