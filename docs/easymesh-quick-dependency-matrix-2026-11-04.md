# N60 Pro EasyMesh Quick / Full 依赖矩阵

更新日期：2026-11-05  
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
| libnl-tiny | `package/libs/libnl-tiny` 的 InstallDev | P1905 | 直接请求 `.libnl-tiny_installed` | Full package scheduler 负责运行时包 | include 目录非空，链接接口 `libnl-tiny.so` 与 ABI 库 `libnl-tiny.so.1` 均存在 |
| WAPP UAPI | `target/linux/mediatek/files-6.12/include/uapi/linux/wapp/`，由 kernel prepare 应用 | WAPP | `make target/linux/prepare` 只准备补丁后的内核源码和 UAPI，不进入 Kconfig | 完整内核构建同样使用 | `wapp_cmm_type.h`、`mt_wlan_cmm_oid.h` 存在 |
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
3. 静态检查 WTS、MAP 配置、R2/R3 宏，并分别用 `git apply --numstat` 检查 DSA 与 datconf 两个补丁的 unified-diff 语法。
4. 下载四个 EasyMesh vendor 源码包，以及 OpenSSL、datconf、libnl-tiny 的构建源。
5. 执行 `make tools/install`，确保 host patch/tar/CMake 等工具已经就绪。
6. 清理缓存中的 datconf / easymesh package build stamps；执行两者的 `prepare`，校验源码哈希、补丁应用和源码目录。
7. 执行 `make toolchain/install`。源码预检在 target toolchain 和 OpenSSL 构建之前完成。
8. 分别通过 `.openssl_installed`、`.datconf_installed`、`.libnl-tiny_installed` 准备 target 开发接口。
9. 执行 `make target/linux/prepare`，准备并应用 kernel source/files/patches；只验证 WAPP UAPI 头文件，不生成内核 .config。
10. 直接构建 `build_dir/target-aarch64_cortex-a53_musl/easymesh-n60-7.6.7.3/.built`。
11. 检查六个 AArch64 产物、动态链接依赖、WTS/steering/topology 符号，并上传源码构建产物和日志。

## 4. Quick / Full 关键目标差异

| 目标 | Quick | Full |
|---|---|---|
| `tools/install` | 执行 | 执行 |
| `toolchain/install` | 执行 | 执行 |
| OpenSSL / datconf / libnl InstallDev | 显式准备 target 开发文件 | 由完整 package 构建依赖关系准备 |
| `target/linux/prepare` | 执行，只准备补丁后的内核源码/UAPI | 由完整内核构建调用 |
| `kernel_oldconfig` | 不执行 | 执行；通过空行输入选择新 Kconfig 符号默认值 |
| `target/linux/compile` | 不执行 | 执行；syncconfig 同样以非交互默认值处理新符号 |
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

## 5.1 本轮全链路审计新增发现

- 当前分支的 P1905 DSA 补丁 `001-dsa-use-linux-mii-ioctl.patch` 第二个 hunk 声明 `-649,24 +651,26`，实际内容为旧 23 行、新 25 行；独立执行 `git apply --numstat` 可复现 `corrupt patch at line 49`。已修正为 `-649,23 +651,25`。
- Quick 预检现在同时检查 datconf UCODE 补丁和 P1905 DSA 补丁，任何 unified-diff 语法错误都在 `tools/install`、`toolchain/install` 和目标依赖构建之前失败。
- `libnl-tiny` 原检查只验证 ABI 库 `libnl-tiny.so.1`，但 P1905 使用 `-lnl-tiny` 链接；现在同时验证开发链接入口 `libnl-tiny.so`，避免把运行时 ABI 文件误当成完整链接接口。

## 6. 缓存与触发依赖

Quick 的触发路径和 cache key 必须覆盖：
- `include/**`、`scripts/**`、`tools/**`、`toolchain/**`、根 Makefile / rules.mk；
- `target/linux/generic/**`、`target/linux/mediatek/**`，包含 UAPI files、kernel patches 和配置；
- N60 配置、feeds；
- EasyMesh、datconf、OpenSSL、libnl-tiny 的 Makefile、源码准备脚本和补丁；
- Quick workflow 自身。

Full cache key 还覆盖 mapfilter 和 mt_wifi 源码构建输入。内核 Prepare stamp 本身也根据 kernel patch/files 目录计算依赖摘要；cache key 负责避免错误复用不相关的旧构建环境。

Quick workflow 仅提供 `device` 输入，不存在 `quick_only` 参数。Quick 专属的 datconf、OpenSSL、libnl-tiny 和 EasyMesh 源码修改通过 `easymesh-quick.yml` 手动运行时只执行用户态验证；需要验证最终固件时，必须单独 dispatch Full workflow（`.github/workflows/main.yml`）。主 Full workflow 的 push 触发路径仍会先运行内置 Quick gate，再进入 Full。

## 7. 验证状态

### 已由仓库 / 日志确认
- `easymesh-n60` 声明的源码构建依赖为 `datconf openssl libnl-tiny`。
- WAPP 需要 datconf / kvcutil 和 OpenSSL 3 接口；P1905 需要 libnl-tiny、libeth 及 OpenSSL 3。
- WAPP UAPI 头文件由 Mediatek kernel files 提供。
- Quick 的 WAPP UAPI 只依赖 patched kernel source/files，使用 `target/linux/prepare` 即可；`kernel_oldconfig` 还会进入 Kconfig 配置，不应放进 Quick。
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
- Full 的 `kernel_oldconfig` 和 `target/linux/compile` 对新 Kconfig 符号输入空行，采用各符号默认值；验证 USB MTK debugfs 选项仍关闭。

### 仍须由实际构建证明
- datconf patch 能否应用到当前固定 SHA 的真实源包。
- Quick 是否能完成六个 AArch64 产物及全部 NEEDED 检查。
- Full 是否生成正确的 `mapfilter.ko`、kmod APK、EasyMesh APK 和最终 ITB。

**验收原则：**下一次 Quick 只负责证明用户态 EasyMesh 依赖闭环；只有 Quick 全部通过后，Full 才负责证明内核模块、运行时 APK 和最终固件闭环。不能用 Quick 的成功替代 Full 验收，也不能让 Quick 为了 APK 依赖扫描而重新触发完整内核构建。


## 8. 内核 Kconfig 与 GPIO 默认包边界

Full #500 的完整日志证明，实际失败发生在 `target/linux/compile` 的 Kbuild
`syncconfig` 阶段：非交互 runner 遇到新增 Kconfig 符号
`USB_XHCI_MTK_DEBUGFS` 时因输入 EOF 退出。它并没有到达 EasyMesh package
compile。Full 现在对 `kernel_oldconfig` 和 `target/linux/compile` 提供空行输入，
让新增符号采用 Kconfig 声明的默认值，并在编译后检查
`CONFIG_USB_XHCI_MTK_DEBUGFS` 仍为关闭状态。

`kmod-gpio-button-hotplug` 来自 `target/linux/mediatek/Makefile` 的
`DEFAULT_PACKAGES`，属于 Full 固件默认包，不是 EasyMesh 的
`PKG_BUILD_DEPENDS`。Quick 必须继续绕过全局 package scheduler，但不能为了
消除 Quick 的误触发而从 Full 默认包中删除 gpio-button-hotplug。

## 9. 闭源组件与预编译产物覆盖审计（2026-11-05）

本节记录当前已纳入静态门禁的输入范围。文件数量是固定归档解压后的
盘点基线，不代表所有文件都已完成逐行人工审查。

| 源码/组件归档 | 文件数 | 头文件数 | 当前审计定位 |
|---|---:|---:|---|
| WAPP (`wappd`) | 175 | 61 | 源码、WTS/DPP、WEXT、OpenSSL API 与编译/链接 |
| MAPD (`mapd`) | 126 | 38 | 源码、steering/topology、7 个预编译对象及 4 个静态库 |
| P1905 (`1905daemon`) | 236 | 95 | 源码、DSA、WTS/topology、libnl/OpenSSL/以太网库链接 |
| libmapd | 9 | 5 | 共享库源码和目标编译/链接 |
| datconf | 12 | 3 | UCODE 构建开关、开发头文件和静态/共享库 |
| MT Wi-Fi 7.6.7.3 | 1,107 | 551 | 闭源驱动源码、补丁、固件与架构分类；Full 编译 |
| conninfra | 47 | 24 | MT7986 平台依赖；Full 编译/modpost |
| WARP | 71 | 35 | 驱动依赖；Full 编译/modpost |
| MAPFILTER | 13 | 6 | 内核模块源码；Full 编译、`.ko` 和 APK |
| bndstrg_plus（辅助审计） | 24 | 13 | OID/结构 ABI 对照、补丁应用和 AArch64 编译 |
| fwdd（辅助审计） | 3 | 0 | 补丁应用和 AArch64 编译 |

### 9.1 MAPD 预编译对象边界

- MAPD 归档含 7 个 AArch64 ELF64 relocatable `.o`，`.comment` 标记为
  OpenWrt GCC 8.4.0；同名 C 源文件未随归档提供。
- 另含 4 个静态 `.a`。测试固定每个对象/归档 SHA256，并校验归档成员集合。
- 当前门禁执行 `readelf -h`、`readelf -p .comment`、`nm -u` 和
  `readelf --version-info`；记录 undefined symbol 数量，并在实际 MAPD
  目标链接时验证这些对象能否与当前工具链及依赖闭合。
- 这不等同于源代码审计：没有对应 C 源文件，无法对对象内部实现做完整
  静态安全审查；GCC 8.4.0 也不是当前 GCC 版本的同义保证。实际链接
  成功仍不能替代运行时功能验证。

### 9.2 OpenSSL 1.1 遗留 ELF 与 OpenSSL 3 当前构建

- `files/usr/bin/` 下旧 WAPP、MAPD、P1905、wappctrl，以及
  `files/usr/lib/` 下旧 `libcrypto.so.1.1`、`libssl.so.1.1`、
  `libeth_1905ops.so`、`libmapd_interface_client.so`，被明确作为 8 个
  ELF 审计参考文件保留；当前 Makefile 的 install 规则不安装这些旧 ELF。
- 当前安装规则使用本次源码构建的四个可执行文件和两个共享库；
  EasyMesh 运行时依赖声明为 `+libopenssl`，Build/Compile 检查 target
  `opensslv.h` 的 `OPENSSL_VERSION_MAJOR` 必须为 3。
- Quick 的 vendor inventory test 会通过 `readelf` 输出遗留 ELF 的
  ELF64/AArch64、SONAME、DT_NEEDED；校验两个 OpenSSL 1.1 库的 SONAME，
  并确认 `libssl.so.1.1` 依赖 `libcrypto.so.1.1`。四个旧可执行文件
  是否直接 NEEDED OpenSSL 1.1 以实际日志为准，不能由文件名推断。
- 这些是准备阶段测试，不代表 Run #674 已经执行成功。必须从 Run #675
  日志取得实际 `readelf` 输出和 OpenSSL 3 header guard 通过记录。

### 9.3 MT7986 无线 profile

`wifi-dats` 上游默认 `first_card_name` 为 MT7981，但 N60 标准配置
当前显式设置 `CONFIG_first_card_name="MT7986"`。vendor inventory test
同时检查配置片段、解析后的 `.config`、MT7986 firmware 版本和 MT7975
专用固件文件，防止默认值回退或只改 profile 名称而遗漏固件。

### 9.4 覆盖范围的限制

- 已固定归档哈希、文件数和头文件数；这能检测输入变化或归档缺失，
  不能声称每个头文件的 include 关系已经完全闭环。
- MT Wi-Fi 内同时包含 x86-64 主机工具、Andes 固件等不同 ELF 类别，
  不能把所有 ELF 都按 AArch64 用户态程序检查。
- bndstrg_plus/fwdd 是辅助源码审计输入，不表示它们已被 N60 标准配置
  选中或安装进固件。
- 当前仍需逐项通过 Quick 实际编译/链接，以及 Full 的 MTK 驱动、
  conninfra、WARP、MAPFILTER、EasyMesh APK 和 ITB 验证。

## 10. WTS 补丁迁移与 Quick 验收状态（2026-11-05）

- Run #677/#678 的失败均发生在旧 `n60-wts-hardening.py` 执行期间，
  没有进入 EasyMesh 编译/链接。Run #678（`41999049273`）的首个错误为
  `P1905 WTS key log: expected one source match, found 0`。
- 已将旧脚本的必要安全修改整理为标准补丁
  `patches/011-wapp-wts-security.patch`，并从仓库删除旧 Python 源码改写脚本。
- 当前补丁保留供应商 WAPP/P1905 原字段解析顺序与 WTS 格式；只修复读取
  缓冲区边界、字符串字段长度、转换结果检查、错误输出复位和 Wi-Fi 密钥日志。
  P1905 原解析器已有的有界字段读取没有被重写。
- `Build/Prepare` 先以 `--fuzz=0` 做完整 dry-run，再应用补丁并检查源码标记；
  Quick 静态契约测试另外核对 WAPP/P1905 边界保护、错误处理和 WAPP/P1905/MAPD
  密钥脱敏。任何 hunk 不匹配均必须终止准备阶段。
- 当前提交已完成静态代码接线，但新补丁尚未取得 Quick 实际应用、编译和链接
  成功日志；Full ITB 集成同样待验证。不得把旧 Run #678 的结果或补丁语法检查
  当作新补丁已通过构建。
- 后续所有 GitHub JavaScript Actions 使用 Node.js 24 运行时兼容版本：
  `actions/checkout@v5`、`actions/cache@v5`、`actions/upload-artifact@v6`。
  这里的 Node.js 24 指 GitHub Action 运行时，不代表 AArch64 C/C++
  交叉工具链由 Node.js 构建。

**状态用语：**仓库静态断言存在 ≠ Action 已执行；Action 成功 ≠ Full 固件
成功；Full ITB 成功 ≠ WAPP/P1905/MAPD 运行时拓扑与 Steering 已通过。


## 11. Copilot AI Audit #1 后的静态门禁加固（2026-11-05）

- EasyMesh Build/Prepare 的所有供应商补丁统一通过 `apply_patch_strict`：先执行 `patch --dry-run --batch --forward --fuzz=0`，再以相同的零 fuzz 参数实际应用；任何缺失、已应用、上下文不匹配或需要 fuzz 的补丁都会立即失败。该流程覆盖 DPP、OpenSSL、WAPP、libmapd、P1905 DSA 和 WTS 补丁。
- OpenSSL 源码扫描和 Quick DPP 源码扫描遇到文件读取错误立即失败并报告路径，不再静默跳过。
- Quick 对六个 AArch64 ELF 产物逐个读取动态段，检查所有直接 NEEDED 依赖能在 target staging 或本次 EasyMesh 构建目录中解析，拒绝任何 OpenSSL 1.1 依赖，并保留完整动态依赖报告；WAPP / P1905 的 OpenSSL 3、datconf、libnl-tiny 和以太网库关键依赖仍单独断言。
- Full 在最终固件构建成功后，逐项验证 `conninfra.ko`、`mtk_warp.ko`、`mt_wifi.ko`、`mtk_warp_proxy.ko` 的 AArch64 ELF 产物、Conninfra `Module.symvers`，以及对应的 conninfra / WARP / MT Wi-Fi APK。
- 源码归档 SHA256 已覆盖归档内所有源码与头文件字节；不重复增加逐文件哈希表。文件数和头文件数继续作为解压完整性盘点，不将其误称为逐文件安全审计。
- 上述门禁仍属于静态/产物检查；Quick 必须实际通过零 fuzz 补丁应用、用户态编译和 ELF 依赖解析，Full 必须实际通过内核模块、APK 和 ITB 验证。不得用静态检查替代构建结果。
