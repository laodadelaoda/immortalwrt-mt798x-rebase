# N60 Pro EasyMesh Quick / Full 依赖矩阵

更新日期：2026-11-04  
适用分支：`n60pro-mtk-closed-driver`  
目标：MT7986 / Filogic 830，ImmortalWrt 25.12，MTK closed driver 7.6.7.3

## 1. 设计边界

- **Quick** 是用户态 EasyMesh 源码编译与产物审计工具，不是固件打包工具。
- **Full** 是最终固件生产流程，负责完整内核、内核模块、EasyMesh APK、运行时依赖解析和 ITB。
- Quick 不调用全局 package scheduler，不编译 `mt_wifi`、`mapfilter.ko`，不生成 EasyMesh APK。
- Full 必须独立完成自己的 EasyMesh package build。Reusable workflow 在独立 runner 上运行，不能把 Quick runner 的工作目录当作共享构建目录。

## 2. 依赖矩阵

| 层级 | 依赖 / 生产者 | 消费者 | Quick 必需工作 | Full 工作 | 验收条件 |
|---|---|---|---|---|---|
| 配置 | `config/n60pro-1001.config`、feeds、`make defconfig` | 所有构建目标 | 解析 N60 Pro 配置；只在临时 Quick .config 禁用可选 devcrypto | 使用正式 N60 Pro 配置 | MTK AP、MBO、MAP、设备 profile 保留；不选择 mtkuboot |
| Host 工具 | apt 主机依赖、`make tools/install` | CMake、patch、内核准备、源码构建 | 必需 | 必需 | host sed、cmake 等实际工具存在 |
| 交叉工具链 | `make toolchain/install` | WAPP、MAPD、P1905、共享库 | 必需 | 必需 | AArch64 编译器和 target libgcc 可用 |
| OpenSSL | `package/libs/openssl` 的 InstallDev | WAPP、P1905 | 直接请求 `.openssl_installed`，只准备 target 开发接口 | Full package scheduler 生成运行时包 | `x509.h`、`libssl.so`、`libssl.so.3`、`libcrypto.so`、`libcrypto.so.3` |
| datconf | `package/mtk/applications/datconf` 的 Prepare / InstallDev | WAPP | 清理旧缓存；应用 UCODE 条件补丁；以 `BUILD_UCODE=OFF` 构建开发接口 | 保留默认 UCODE 行为，按正式配置构建 | CMakeCache 为 OFF；`libdatconf.h`、`libkvcutil.h`、`libdatconf.a`、`libkvcutil.so.1` 存在 |
| libnl-tiny | `package/libs/libnl-tiny` 的 InstallDev | P1905 | 直接请求 `.libnl-tiny_installed` | Full package scheduler 负责运行时包 | include 目录非空，`libnl-tiny.so.1` 存在 |
| WAPP UAPI | `target/linux/mediatek/files-6.12/include/uapi/linux/wapp/`，由 kernel prepare 应用 | WAPP | `make kernel_oldconfig` 准备内核源和配置，不编译内核模块 | 完整内核构建同样使用 | `wapp_cmm_type.h`、`mt_wlan_cmm_oid.h` 存在 |
| WAPP 源码 | `wappd-80ca5724.tar.bz2` | WAPP、wappctrl | 校验并 Prepare；编译 | 同样编译并打包 | AArch64 ELF；WTS、11k/11v 关键符号检查 |
| MAPD 源码 | `mapd-6eca4331.tar.bz2` | MAPD | 校验并 Prepare；编译 | 同样编译并打包 | AArch64 ELF；steering/topology 关键符号检查 |
| P1905 源码 | `1905daemon-35234223.tar.bz2` | P1905、`libeth_1905ops.so` | 校验并 Prepare；应用 DSA patch；编译 | 同样编译并打包 | AArch64 ELF；libnl、OpenSSL、libeth 依赖检查 |
| libmapd 源码 | `libmapd-0132d199.tar.bz2` | MAPD/P1905 接口 | 校验并 Prepare；编译 `libmapd_interface_client.so` | 同样编译并打包 | AArch64 shared object |
| mt_wifi | `mt79xx_20250408-705eb4.tar.xz` | MTK 无线内核驱动 | **不下载、不编译**；Quick 所需 WAPP UAPI 已由 mediatek kernel files 提供 | 完整驱动构建 | Full 的驱动构建单独验证 |
| mapfilter | `package/kernel/mapfilter`、内核配置 | P1905 运行时 / 固件 | **不编译** | 完整内核后构建 `mapfilter.ko` 和 APK | `CONFIG_MAP_FILTER_SUPPORT=m`；非空 `.ko` 和 kmod APK |
| EasyMesh APK | OpenWrt package scheduler / `CheckDependencies` | 固件安装 | **不生成**；Quick 只构建 package 的 `.built` stamp | 正常 package compile，解析运行时依赖并生成 APK | Full 中 APK 非空，包内文件与依赖完整 |
| ITB 固件 | Full image pipeline | N60 Pro | 不生成 | 完整构建 | Standard ITB 非空并通过固件检查 |

## 3. Quick 的实际依赖调用顺序

1. 安装 Ubuntu host build dependencies。
2. 更新 feeds，复制 N60 Pro 配置并执行 `make defconfig`。
3. 静态检查 WTS、MAP 配置、R2/R3 宏、DSA patch 和 datconf patch 语法。
4. 下载四个 EasyMesh vendor 源码包，以及 OpenSSL、datconf、libnl-tiny 的构建源。
5. 清理缓存中的 datconf / easymesh package build stamps。
6. 在昂贵的工具链构建之前执行 datconf 和 EasyMesh 的 `prepare`，校验源码哈希、补丁应用和源码目录。
7. 执行 `make tools/install`、`make toolchain/install`。
8. 分别通过 `.openssl_installed`、`.datconf_installed`、`.libnl-tiny_installed` 准备 target 开发接口。
9. 执行 `make kernel_oldconfig`，准备 kernel source/config/UAPI；不执行 `target/linux/compile`。
10. 直接构建 `build_dir/target-aarch64_cortex-a53_musl/easymesh-n60-7.6.7.3/.built`。
11. 检查六个 AArch64 产物、动态链接依赖、WTS/steering/topology 符号，并上传源码构建产物和日志。

## 4. Quick / Full 关键目标差异

| 目标 | Quick | Full |
|---|---|---|
| `tools/install` | 执行 | 执行 |
| `toolchain/install` | 执行 | 执行 |
| OpenSSL / datconf / libnl InstallDev | 显式准备 target 开发文件 | 由完整 package 构建依赖关系准备 |
| `kernel_oldconfig` | 执行，仅准备内核源和配置 | 可作为完整内核构建前置步骤 |
| `target/linux/compile` | 不执行 | 执行 |
| `package/kernel/mapfilter/compile` | 不执行 | 执行并验证 .ko / APK |
| EasyMesh package `compile` | 不执行；直接请求 `.built` | 执行，生成可安装 APK 并检查运行时依赖 |
| ITB | 不生成 | 生成并验证 |

## 5. 已定位的重复失败根因

| Action | 已见错误 | 根因归类 | 本轮修订 |
|---|---|---|---|
| #53 | `libopenssl3` package dependency scan 缺少 `libc.so`、`libgcc_s.so.1` | Quick 不应生成 OpenSSL APK；只需要 InstallDev | 保留 `.openssl_installed` 直接目标 |
| #56 | WAPP 旧 OpenSSL EC key prototype 与目标 OpenSSL 声明冲突 | vendor 源码适配 | 保留 EasyMesh Build/Prepare 兼容处理 |
| #57 | WAPP 找不到 `libdatconf.h` | Quick 绕过 package scheduler 后未准备 datconf 开发接口 | 显式构建 datconf InstallDev 并检查头文件 |
| #59 | datconf 进入 ucode 子目录，报缺少 ucode library/headers | UCODE 条件没有可靠应用 | 修正 patch，并在实际 Prepare 后验证 CMakeLists |
| #60 | `malformed patch at line 17` | datconf unified diff hunk 行数声明错误 | 修正 hunk 计数；加入 `git apply --numstat` 预检 |
| #64 | `Hunk #1 FAILED at 3` | 同一 datconf patch 无法可靠应用 | 修正 hunk，并把实际源码 Prepare 前移到工具链构建之前 |

另外，原 Quick 虽然使用 package-local `compile`，但 `include/package-pack.mk` 仍会将其连接到 APK 生成和 `CheckDependencies`。因此“package-local”并不等于“source-only”。本轮改为直接构建 `.built` stamp，避免再次进入运行时包依赖扫描和 APK 生成。

原 Full workflow 的 `easymesh_prebuilt` 输入只跳过 clean，并没有把 Quick runner 的源码构建目录传递到 Full runner。本轮移除这项不成立的复用声明，Full 始终在自己的 runner 上清理并构建完整 EasyMesh package。

## 6. 缓存与触发依赖

Quick 的触发路径和 cache key 必须覆盖：
- `include/**`、`scripts/**`、`tools/**`、`toolchain/**`、根 Makefile / rules.mk；
- `target/linux/generic/**`、`target/linux/mediatek/**`，包含 UAPI files、kernel patches 和配置；
- N60 配置、feeds；
- EasyMesh、datconf、OpenSSL、libnl-tiny 的 Makefile、源码准备脚本和补丁；
- Quick workflow 自身。

Full cache key 还覆盖 mapfilter 和 mt_wifi 源码构建输入。内核 Prepare stamp 本身也根据 kernel patch/files 目录计算依赖摘要；cache key 负责避免错误复用不相关的旧构建环境。

Quick 专属的 datconf、OpenSSL、libnl-tiny 和 EasyMesh 源码修改只自动触发 Quick，不再因为 `package/**` 的宽泛匹配而同时启动完整 Full 构建。需要验证最终固件时，可在 Quick workflow 手动选择 `quick_only=false`，或单独 dispatch Full workflow。

## 7. 验证状态

### 已由仓库 / 日志确认
- `easymesh-n60` 声明的源码构建依赖为 `datconf openssl libnl-tiny`。
- WAPP 需要 datconf / kvcutil 和 OpenSSL 3 接口；P1905 需要 libnl-tiny、libeth 及 OpenSSL 3。
- WAPP UAPI 头文件由 Mediatek kernel files 提供。
- `kernel_oldconfig` 的调用链会准备内核源码、应用 kernel patch/files 并生成配置，不会触发 kernel modules 编译。
- Quick 的 APK dependency scan 与其 source-only 目标冲突。
- Run #53、#56、#57、#59、#60、#64 的失败分别对应上表中的依赖层问题。

### 已修改，等待下一次 Quick 实际验证
- datconf UCODE patch hunk。
- Quick 先 Prepare、后工具链/目标依赖构建的顺序。
- datconf 缓存清理，避免旧 CMakeCache 污染 `BUILD_UCODE=OFF`。
- OpenSSL / datconf / libnl 开发文件的 ABI 级检查。
- EasyMesh 直接构建 `.built`，Quick 不再打 APK。
- Quick / Full 的缓存依赖和触发路径。
- Full 不再假定跨 runner 复用 Quick 工作目录。

### 仍须由实际构建证明
- datconf patch 能否应用到当前固定 SHA 的真实源包。
- Quick 是否能完成六个 AArch64 产物及全部 NEEDED 检查。
- Full 是否生成正确的 `mapfilter.ko`、kmod APK、EasyMesh APK 和最终 ITB。

**验收原则：**下一次 Quick 只负责证明用户态 EasyMesh 依赖闭环；只有 Quick 全部通过后，Full 才负责证明内核模块、运行时 APK 和最终固件闭环。不能用 Quick 的成功替代 Full 验收，也不能让 Quick 为了 APK 依赖扫描而重新触发完整内核构建。
