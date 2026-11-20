# Netcore N60 Pro platform support

## Scope

The maintained target is the **complete Netcore N60 Pro board**, not the MT7986A SoC in isolation. The SoC is one dependency in the board platform. This is a hardware-support ownership boundary only; it does not expand the audit or validation scope. Changes are made when needed to produce a correct N60 Pro firmware image and keep the normal OpenWrt build working.

The board-specific implementation remains in the repository's native OpenWrt locations (DTS, image profile, board scripts, target configuration, kernel/package patches, and MTK packages). This document defines ownership; it does not introduce a parallel build or patch-application mechanism.

## Hardware represented by the current N60 Pro DTS

Source of truth: `target/linux/mediatek/dts/mt7986a-netcore-n60-pro.dts`.

| Platform area | Current DTS declaration |
|---|---|
| SoC | MediaTek MT7986A-compatible platform |
| Memory | 512 MiB RAM |
| Ethernet MACs | Two MediaTek GMAC interfaces; factory MAC addresses read through NVMEM |
| Switch | MediaTek MT7531 switch |
| PHYs | Two external PHY nodes at MDIO addresses 5 and 6 |
| Storage | SPI-NAND; BL2, U-Boot environment, factory, FIP and UBI partitions |
| Wi-Fi calibration | Factory EEPROM NVMEM cell supplied to the Wi-Fi node |
| USB | SSUSB controller and USB PHY enabled |
| GPIO / controls | Reset and Mesh/WPS buttons |
| LEDs | WLAN, power, USB, WPS and WAN indicators |
| Power rails | Fixed 3.3 V and 5 V regulators |
| SoC services | Crypto engine, TRNG, UART0 and watchdog enabled |

These declarations are the current software description, not a substitute for board-level electrical validation. Any discrepancy with the physical N60 Pro revision must be resolved against its schematic, BOM, factory layout and measured hardware before changing the DTS.

## Required support layers

1. **Board identity and boot** — compatible strings, boot chain assumptions, memory map, image format, flash geometry, partition layout and recovery/update path.
2. **Storage and factory data** — SPI-NAND access, factory partition, EEPROM/calibration data, NVMEM layout, and stable per-interface MAC allocation.
3. **Wired networking** — GMAC, MT7531 switch, external PHYs, reset/interrupt wiring, port topology, link modes, VLAN/DSA/HNAT interactions and correct LAN/WAN naming.
4. **Wireless platform** — MT7986 radio integration, MTK closed driver, firmware, calibration, regulatory configuration, RF front-end dependencies and stable radio initialization.
5. **Board peripherals** — USB, regulators, GPIO, reset/Mesh buttons, LEDs, UART, watchdog and SoC crypto/TRNG services.
6. **System integration** — kernel configuration, device packages, init ordering, network configuration, firmware loading, diagnostics and upgrade behavior.
7. **EasyMesh service stack** — WAPP, MAPD, 1905 daemon, datconf, MAPFILTER, Conninfra, WARP and their ABI/runtime integration with the closed MTK driver and OpenSSL 3.5.9.

## Repository ownership boundaries

- Keep the upstream OpenWrt base and generic upstream patches aligned with the selected upstream branch.
- Do not maintain unrelated device-specific support merely because it shares the MediaTek target or kernel patch directory.
- Do not delete or rewrite generic upstream patches to avoid work for other boards. Let OpenWrt's native target/subtarget patch selection and package preparation determine applicability.
- Maintain N60 Pro board-specific DTS, image, board scripts, configuration and compatibility fixes in their existing native paths.
- Maintain the MTK closed-driver and EasyMesh integration required by this board, including its complete dependency chain.
- Keep N60 Pro-only fixes isolated and minimal; do not create a broad fork of generic MediaTek support.
- Do not infer hardware that is not established by the DTS or board evidence (for example, extra radios, PCIe devices, SFP, fan, eMMC or additional storage).

## Build-only acceptance criteria

The acceptance target for this repository work is a successful, reproducible N60 Pro firmware build. Use the existing OpenWrt build flow and the repository's already-required checks only:

- target configuration and dependency resolution complete;
- native source download, extraction, overlay and patch application complete;
- kernel and package compilation/linking complete, including the MTK closed-driver and EasyMesh packages selected by the N60 Pro configuration;
- firmware image generation completes and produces the expected N60 Pro image artifacts.

Do **not** turn the hardware inventory above into new audit gates, runtime test matrices, extra audit workflows, or mandatory device tests. Do not add checks merely to prove unrelated peripherals or services at runtime. Keep existing audit scope and thresholds unchanged; fix only concrete failures that block the normal build or produce incorrect build artifacts. Runtime/field validation is separate and is not a prerequisite for Quick or Full compilation.
