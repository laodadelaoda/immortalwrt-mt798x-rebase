# N60 Pro 全仓库闭源组件与预编译产物覆盖审计

日期：2026-11-05  
分支：n60pro-mtk-closed-driver  
目标：Netcore N60 Pro / MT7986 / ImmortalWrt 25.12-SNAPSHOT / Linux 6.12.112 / OpenSSL 3.x

## 1. 审计结论

本轮已把闭源组件从包名/Makefile 清单扩展为实际源码归档、预编译对象、固件二进制、开发头文件、构建依赖和安装产物清单。

关键发现：
- MAPD 源码归档内包含 7 个没有配套 C 源码的 AArch64 预编译对象；mapd_config 启用两个 proprietary library 选项，这些对象确实进入 MAPD 静态库重打包和最终链接。
- 7 个对象均带 GCC 8.4.0 编译标记；4 个静态归档也纳入 SHA256 与成员清单。Quick Build/Prepare 静态检查其目标架构、字节序、编译器标记、哈希、成员集合和链接引用。
- 仓库原先保留 8 个旧预编译 EasyMesh 文件（4 个可执行文件、4 个共享库），但当前安装规则使用源码编译输出。这些文件保留为审计参考；Quick preflight 检查其存在，静态测试确保它们不会进入新固件安装产物。
- 旧 libssl.so.1.1 / libcrypto.so.1.1 保留为审计参考，不进入当前包安装；Quick/Full 构建产物仍必须使用 libssl.so.3、libcrypto.so.3。
- N60 标准配置显式设置 CONFIG_first_card_name="MT7986"；新测试核实 defconfig 后仍选择 MT7986 profile，并检查对应 MT7986/MT7975 firmware payload。
- MT Wi-Fi 固件 .bin / MCU .elf 属于无线芯片固件，不是 Linux AArch64 用户态共享库或内核模块，单独归类。

**边界：** MAPD 预编译对象没有源码，不能做源代码级 API、安全或内存审计。静态检查只能证明哈希、AArch64 ELF 属性、GCC provenance、归档成员和构建引用关系；最终 ABI/符号兼容必须由当前目标工具链实际链接验证，运行行为仍需设备验证。

## 2. Vendor source archive inventory

| 组件 | 归档 | 文件数 | 头文件数 | 归档 SHA256 | 选择状态 |
|---|---|---:|---:|---|---|
| WAPP | wappd-80ca5724.tar.bz2 | 175 | 61 | 73fa8995533e701d3d5774faa92d274497f99e1a37c81ce445f25a959b4b7462 | N60 EasyMesh |
| MAPD | mapd-6eca4331.tar.bz2 | 126 | 38 | 39ab37cb347d372e352ade03181bc9c23429d4d849d32acbdff00973547d7e18 | N60 EasyMesh |
| P1905 | 1905daemon-35234223.tar.bz2 | 236 | 95 | 82f7cc4ad5731e750f87c9a4ad19a39d2456bb8fec0cf79bf4b3f3ccb4f14795 | N60 EasyMesh |
| libmapd | libmapd-0132d199.tar.bz2 | 9 | 5 | d325b4a8dc2bf44bd3bd639a0c300380c0a6240f407807f8f2eea80d006c8dba | N60 EasyMesh |
| datconf / libkvcutil | datconf-757f9679.tar.bz2 | 12 | 3 | 3cbb7489e3df1be52d184b600129a6081e7225981acdbcc5c2cb7149f11c37f1 | N60 dependency |
| mt_wifi 7.6.7.3 | mt79xx_20250408-705eb4.tar.xz | 1,107 | 551 | b029d7b43c498193092dc6a3c857361c8835ce34bb306561c550ac0539784a78 | N60 kernel driver |
| conninfra | mt79xx_conninfra_20250408-f2fa25.tar.xz | 47 | 24 | 3a82cfa69e68c8e584723b604dda565b2c085239ba1ac834d6d3b0ebd987e58c | N60 kernel dependency |
| WARP | warp_20250408-5f71ec.tar.xz | 71 | 35 | 0954055e165dcb71cd2703f07b0c2d521ca3e9c8968d2b17b68e8c9a7853f9b2 | N60 kernel dependency |
| MAPFILTER | mapfilter-96f2afed.tar.bz2 | 13 | 6 | 3928c6614b84e74f1f1762cee61de8e422299e792f5f363dc369dfc0ed0f1714 | N60 kernel dependency |
| bndstrg_plus | bndstrg_plus-8350508d.tar.bz2 | 24 | 13 | e6e64967c7dbc1b9c56183bcea279ad9718bc7267d61b7583965c2f700d179b4 | auxiliary audit only; not selected |
| fwdd | fwdd-bcbae0e4.tar.bz2 | 3 | 0 | 26a7ad4f55ca0a779e4178b5b8f918df99de90217d9d98a840a20fddd4123a65 | auxiliary audit only; not selected |

All listed archives are pinned by the corresponding package Makefile or auxiliary source-audit script. Quick verifies principal archive hashes and prepares selected EasyMesh source trees; the new inventory test checks the repository's archive/hash declarations.

## 3. MAPD precompiled object inventory

Seven objects have no matching .c files in the archive:

| Object | ELF | Compiler | SHA256 |
|---|---|---|---|
| mapd_lib/ApRoamAlgo/ap_roam_algo.o | ELF64 AArch64 little-endian | GCC 8.4.0 | cdac32bdd47b7e645385e4d3142efe7f39ca0d0b31f5b1e6dffb2284011909e3 |
| mapd_lib/apEstimator/ap_est_lib.o | ELF64 AArch64 little-endian | GCC 8.4.0 | 92fe9dc7adba28ca87efbfe80d03250577a887d290c42f9a4e8981c0c4d8c1ec |
| mapd_lib/ch_planning_r2/ch_planning_r2_lib.o | ELF64 AArch64 little-endian | GCC 8.4.0 | acc5c989a6f81f61585f00165b4b93fb295202c37dd13c3aa99dd326690ffa79 |
| mapd_lib/lib_score/lib_score.o | ELF64 AArch64 little-endian | GCC 8.4.0 | b7804d6599dd0eb6231ebea8afb5132a109801828a7a874fdf4d46bcc7cbb614 |
| mapd_lib/networkoptimization/network_optimization_lib.o | ELF64 AArch64 little-endian | GCC 8.4.0 | f48cf16c1853d46c03e4329f96ff7f62156a791479fdb0deaeced7a748ba2a78 |
| mapd_lib/steerAction/steer_action_lib.o | ELF64 AArch64 little-endian | GCC 8.4.0 | 4fa7c775f0cc94bed0e01b4540fc89c9277e2ffacb02efc7f42104da5efd4b89 |
| mapd_lib/topologySrv/topologySrv_lib.o | ELF64 AArch64 little-endian | GCC 8.4.0 | 262718af8a96a1d395ab5fd1345a29d4ddfd41488d634914370e3ddee35336de |

mapd_config enables CONFIG_MULTIAP_MTK_LIB=y and CONFIG_MULTIAP_MTK_STEER_LIB=y. MAPD Makefile uses these objects to construct libmapd_core.a and libmapd_steer_core.a, then links those libraries. They are active proprietary code, not unused samples.

Four static archives are also hash/member-pinned:
- libmapd_core.a: lib_score, network_optimization, topologySrv, ch_planning_r2; SHA256 16ed3bea9f0c807b1f700ce1f5282ec84bb34fdeae0c57c014c13e2238e0aea6
- libmapd_steer_core.a: ap_roam_algo, steer_action_lib, ap_est_lib; SHA256 ed5eedb8a9253ebf5742ae84b38de33e4c45f81e805ae77a4d4bda5208187d37
- libmapd_bs_core.a: lib_score, network_optimization, topologySrv, ch_planning_r2; SHA256 ab6cd29ccfc8492f59fb750f2ec474ea66ffcea69054a8078d89fccc564a7c23
- libmapd_bs_steer_core.a: ap_roam_algo, steer_action_lib, ap_est_lib; SHA256 b1b3c75d9761fe0cdccd214c3558bdf7b4089544f54808a0899192da919cd019

The package invokes explicit version/mapd targets rather than the all target whose clean prerequisite removes the prebuilt objects. The inventory test locks this behavior.

## 4. 保留的审计参考预编译文件

Retained as source-vs-binary audit references; current package install rules do not use them:
- usr/bin/wapp
- usr/bin/mapd
- usr/bin/p1905_managerd
- usr/bin/wappctrl
- usr/lib/libcrypto.so.1.1
- usr/lib/libssl.so.1.1
- usr/lib/libeth_1905ops.so
- usr/lib/libmapd_interface_client.so

The WAPP source-audit workflow copies the original wapp/mapd/p1905 executables for source-vs-binary comparison. The other files remain reference artifacts for historical ABI inspection. They are not package inputs. Quick preflight verifies their presence; the inventory test allows exactly these eight ELF references and proves package install uses source-built outputs.

## 5. Firmware and profile data classification

- mt_wifi archive contains source/header trees and chip firmware payloads. Embedded MCU .bin and microcontroller .elf files are not Linux AArch64 .so/.ko artifacts.
- N60 uses MT7986. wifi-dats selects profile data through CONFIG_first_card_name; standard config explicitly sets CONFIG_first_card_name="MT7986".
- 仓库共有 68 个 MT Wi-Fi 固件文件，分属 MT7916、MT7981、MT7986 多个版本；N60 只选 MT7986。mt_wifi/config.in 默认 MT7986 firmware 为 20260601；resolved .config 和匹配的 files/mt7986-fw-* 目录由静态测试检查，确认唯一版本及 MT7986/MT7975 专用文件。
- This records selected firmware independently of mt_wifi source archive date 20250408; it does not assert that driver and firmware release dates are identical. Hardware operation remains to be validated.

## 6. Build/header dependency closure

| Consumer | Required producer/interface | Static evidence |
|---|---|---|
| WAPP | MTK Linux WAPP UAPI | Quick checks wapp_cmm_type.h and mt_wlan_cmm_oid.h in target Linux headers |
| WAPP | datconf / libkvcutil | Build/InstallDev stages libdatconf.h, libkvcutil.h, libdatconf.a, libkvcutil.so*; WAPP links -ldatconf -lkvcutil |
| WAPP | OpenSSL 3 | target headers and libssl.so.3/libcrypto.so.3 staged; WAPP links -lssl -lcrypto |
| P1905 | libnl-tiny | target headers/library; P1905 links -lnl-tiny |
| P1905 | OpenSSL/internal crypto | OpenSSL DPP backend plus source-built src/crypto/libcrypto.a |
| P1905 | DSA Ethernet ops | libeth_1905ops.so built from source; libbridge.a built by DSA subdirectory with target tools propagated |
| MAPD | WAPP control API | source-built libwapp_usr_intf_client.a |
| MAPD | proprietary Multi-AP libraries | seven pinned prebuilt AArch64 objects repacked into selected static libraries |
| MAPD | libmapd | libmapd_interface_client.so source-built with target CFLAGS/LDFLAGS |
| mt_wifi | conninfra/WARP | build dependency warp conninfra; conninfra Module.symvers passed to modpost |
| MAPFILTER | netfilter | runtime dependency kmod-nf-conntrack + kmod-nf-nat; Full builds mapfilter.ko |

bndstrg_plus and fwdd are auxiliary audit inputs, not selected by N60 standard config and not silently included in the EasyMesh runtime package.

## 7. New static gate

test-vendor-artifact-inventory.py is wired into EasyMesh Build/Prepare; Quick preflight verifies that wiring. It checks:
1. selected source archive names and SHA256 pins, plus auxiliary audit-only pins;
2. exact MAPD object/archive inventory, hashes, AArch64 ELF class/machine/endianness, GCC 8.4.0 .comment metadata and archive members;
3. MAPD config/link rules proving active consumption;
4. no unexpected .o/.a/.so/.ko files in the four extracted EasyMesh source trees;
5. exactly eight reviewed ELF audit-reference files under package files/, their ELF headers and MAPD undefined-symbol inventories, no unexpected ELF files, and no package install rule copying them;
6. source-built install paths for WAPP/MAPD/P1905/wappctrl and EasyMesh shared libraries;
7. N60 MT7986 profile and firmware payload;
8. WAPP/P1905/MAPD/libmapd/datconf/OpenSSL/libnl-tiny/libbridge/conninfra/WARP/mt_wifi/MAPFILTER dependency declarations.

## 8. What this audit does not prove

- MAPD object source was not supplied, so its machine code cannot receive source-level API/security review.
- GCC 8.4.0 objects are not proven behaviorally correct; target linker must resolve them with current toolchain/runtime libraries.
- OpenSSL 3 compile/link remains required.
- Linux 6.12.112 module compile/modpost remains required for mt_wifi, conninfra, WARP and MAPFILTER.
- Driver probe, radio bring-up, WAPP/P1905/MAPD protocol, Steering and BTM remain runtime validations.

**Acceptance:** static inventory success is necessary but insufficient. Quick must pass actual user-space compile/link; Full must pass kernel modules, modpost, APK and ITB integration; device runtime validation is a separate final stage.
