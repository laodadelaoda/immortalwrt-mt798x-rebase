# N60 Pro 源码 / 补丁 / API / 依赖闭环审计

审计日期：2026-11-05  
目标分支：`n60pro-mtk-closed-driver`  
目标平台：MT7986 / ImmortalWrt 25.12-SNAPSHOT / Linux 6.12 / OpenSSL 3.5.9  
审计范围：本轮上传的 `dl-release.zip`、固定上下文 `n60-pro固件编译.txt`、当前分支 EasyMesh / MTK 驱动 Makefile、Workflow、Quick Action 和相关补丁。

> 本文区分“已证实”“已修复、待 CI 编译证明”“未覆盖/待验证”。不能把静态检查或补丁文件存在等同于完整兼容。

## 1. 审计输入与边界

### 1.1 上传源码包

已解压 `dl-release.zip`，包含 8 个归档，共 1,693 个文件：

| 组件 | 归档 | 文件数 | SHA256 |
|---|---|---:|---|
| WAPP | `wappd-80ca5724.tar.bz2` | 175 | `73fa8995533e701d3d5774faa92d274497f99e1a37c81ce445f25a959b4b7462` |
| MAPD | `mapd-6eca4331.tar.bz2` | 126 | `39ab37cb347d372e352ade03181bc9c23429d4d849d32acbdff00973547d7e18` |
| P1905 | `1905daemon-35234223.tar.bz2` | 236 | `82f7cc4ad5731e750f87c9a4ad19a39d2456bb8fec0cf79bf4b3f3ccb4f14795` |
| libmapd | `libmapd-0132d199.tar.bz2` | 9 | `d325b4a8dc2bf44bd3bd639a0c300380c0a6240f407807f8f2eea80d006c8dba` |
| mt_wifi | `mt79xx_20250408-705eb4.tar.xz` | 1,107 | `b029d7b43c498193092dc6a3c857361c8835ce34bb306561c550ac0539784a78` |
| mapfilter | `mapfilter-96f2afed.tar.bz2` | 13 | `3928c6614b84e74f1f1762cee61de8e422299e792f5f363dc369dfc0ed0f1714` |
| bndstrg_plus | `bndstrg_plus-8350508d.tar.bz2` | 24 | `e6e64967c7dbc1b9c56183bcea279ad9718bc7267d61b7583965c2f700d179b4` |
| fwdd | `fwdd-bcbae0e4.tar.bz2` | 3 | `26a7ad4f55ca0a779e4178b5b8f918df99de90217d9d98a840a20fddd4123a65` |

以上哈希均由本轮实际解包后的文件计算，与仓库 Makefile 对 WAPP、MAPD、P1905、libmapd、mt_wifi、mapfilter 声明的哈希相符。

### 1.2 conninfra 源码已下载并完成真实归档校验

本 ZIP 本身不包含 conninfra，但已从当前分支 Makefile 指定的公开下载仓库取得确切归档，并由独立 GitHub Actions 工作流实际下载、解压和校验：
- 源码：`mt79xx_conninfra_20250408-f2fa25.tar.xz`
- 版本：`20250408`
- 文件大小：49,208 bytes
- SHA256（实际校验通过）：`3a82cfa69e68c8e584723b604dda565b2c085239ba1ac834d6d3b0ebd987e58c`
- 来源：`immortalwrt-mt798x/immortalwrt` / `openwrt-21.02/dl`
- 审计工作流：`conninfra-source-audit.yml`

固定上下文原记录的 conninfra 版本 `20231229-f2fa25` 已过时；当前构建基准应更新为 `20250408-f2fa25`。本轮已对归档本体进行源码检查，不再把“ZIP 未包含”误判为“源码无法取得”。

### 1.3 源码包与构建包的对应关系

| 源码 | 仓库消费者 | Quick 职责 | Full 职责 |
|---|---|---|---|
| WAPP / MAPD / P1905 / libmapd | `easymesh-n60` | 用户态源码准备、编译、ELF/API 检查 | 重新构建并打包 APK |
| mt_wifi | `package/mtk/drivers/mt_wifi` | 不编译内核驱动 | 编译 MTK Wi-Fi 内核模块 |
| conninfra | `package/mtk/drivers/conninfra` | Quick 下载、哈希、解压、补丁真实应用、Linux API/DT/符号依赖静态检查 | Full 编译 `conninfra.ko` 并验证模块依赖 |
| mapfilter | `package/kernel/mapfilter` | 当前 Quick 不编译 | 编译 `mapfilter.ko` 并打包 |
| bndstrg_plus / fwdd | 不由当前 `easymesh-n60/Makefile` 解包 | 不属于本 EasyMesh package 的四个源码输入 | 按各自包定义决定是否构建 |

## 2. 源码错误清单

| ID | 组件 / 位置 | 发现 | 证据与影响 | 状态 |
|---|---|---|---|---|
| SRC-01 | WAPP `wappd/dpp/dpp.c` | 自定义实现 `EVP_PKEY_get0_EC_KEY(EVP_PKEY *)` 直接访问 `pkey->pkey.ec` | WAPP Makefile 固定启用 `DPP_R2_RECONFIG`。OpenSSL 3 已声明原生函数为 `const EC_KEY *EVP_PKEY_get0_EC_KEY(const EVP_PKEY *)`，且 `EVP_PKEY` 为不透明类型；自定义函数产生冲突声明并访问不完整类型。用本机 OpenSSL 3.5.5 头文件做最小语法验证，复现“conflicting types”与“invalid use of incomplete typedef”。 | **已增加 007 补丁删除旧 shim；本地对真实 WAPP 源码 dry-run/apply 成功；等待 Quick 目标工具链编译证明** |
| SRC-02 | WAPP `dpp_read_config_file_for_connection()` | 原代码未检查多处 `get_dpp_parameters()` 返回值，hex 字段长度和内容未完整验证 | 可能把缺失/截断的 DPP 配置继续传给 credential/key 解析。该函数依赖的读取函数实际返回 int；不是 void API。 | 002 已覆盖主要字段；QR count 和禁用代码块等残留调用仍需逐一确认是否处于有效编译路径 |
| SRC-03 | WAPP `get_dpp_parameters()` | 超长 DAT 值原先被静默截断 | 新增 patch 008 改为检查 `len >= val_len` 并返回错误，完整复制 NUL 终止字符串；WAPP 专项 Action 检查该边界逻辑及错误传播。 | **源码修复已提交；Quick 必须成功执行 Build/Prepare 并完成目标编译，边界测试仍待补充** |
| SRC-04 | WAPP WTS parser `wapp_read_wts_map_config()` | 原始 parser 的文件长度、转义、字段宽度、转换计数、未知 operating class 和空结果处理不完整 | 新增 scripts/n60-wts-hardening.py，在 Build/Prepare 中对实际 WAPP 源码做严格锚点变换：有界读取、转义尾部检查、字段宽度/转换数校验、未知 band 拒绝、输出计数初始化、空配置拒绝和密钥日志脱敏。Run #615 已真实触发该脚本并发现 Python 拼接语法错误；该语法错误已在提交 bf6b1ba6 修复，之后 28820afb 修正目标编译器定位。 | **修订已提交；待最新 Quick Run #621 验证脚本真实执行、补丁应用和 AArch64 编译。未宣称 parser 已通过回归测试** |
| SRC-05 | P1905 `src/crypto/tls_openssl.c` | 存在 `SSL_library_init()`、`TLSv1_method()` 旧代码分支 | 重新核对源码条件编译后确认：`SSL_library_init()` 位于 `OPENSSL_VERSION_NUMBER < 0x10100000L` 分支；EAP-FAST 的 `TLSv1_method()` 也位于同一旧 OpenSSL 版本条件内，因此 OpenSSL 3.5.9 构建不会编译这两处旧调用。OpenSSL 3 路径使用 `SSL_CTX_new(SSLv23_method())`（OpenSSL 1.1+ 兼容路径）。 | **此前“OpenSSL 3 活跃调用旧 TLS API”的判断已纠正；仍需目标编译与实际 TLS/EAP 行为验证** |
| SRC-06 | WAPP `wappd/hotspot/hotspot.c` | realloc 后结构体成员偏移使用非字节指针算术 | 005 将偏移基址改为 `(u8 *)`，避免按结构体大小缩放偏移。 | 已有补丁并由 Build/Prepare 应用；需 CI 实际编译 |
| SRC-07 | WAPP `wappd/common/wapp_cmm.c` | 多处固定长度字段用 `os_strncpy` 写入，且 token 边界检查不完全 | 003 将固定长度拷贝改为 `os_memcpy` 并增加部分长度检查；但 OSU friendly-name 等分支仍需检查后续 `strtok` 是否返回 NULL 再调用 `os_strlen`。 | 003 已应用；剩余 token 安全检查待修 |
| SRC-08 | mt_wifi 7.6.7.3 | 原始源码含 `mm_segment_t/get_fs/set_fs/prandom_u32` 等旧内核接口 | 这些符号在源归档中确实存在；必须按 022/026 等补丁应用后的结果审计，不能仅 grep 原始归档或仅检查补丁文件存在。 | 有版本补丁；Full 实际内核编译待证明 |

## 3. 补丁缺陷清单

| ID | 补丁 | 缺陷 / 审计结果 | 修订或后续动作 |
|---|---|---|---|
| PATCH-01 | `002-dpp-parser-safety.patch` | 修复 DPP 配置读取、hex 长度、hex 解码错误路径；但没有移除 `dpp.c` 中自行实现的 OpenSSL 原生 accessor。单独删掉 `dpp.h` 的旧声明不能消除函数定义与 OpenSSL 3 声明冲突。 | 新增 `007-openssl3-use-native-evp-pkey-get0-ec-key.patch`，删除旧 shim；Makefile Build/Prepare 已接入。真实源包本地 dry-run/apply 成功。 |
| PATCH-02 | `022-since-v5.18-drop-deprecated-mm_segment_t-usages.patch` | `ap_cfg.c` hunk 原先把变量声明写成 `fs`，但函数体使用的是 `orig_fs`；旧内核条件编译时会产生未声明标识符。 | 已改为 `orig_fs`，并保留 `OS_FS_INFO.fs` 字段名。已增加 Quick `git apply --numstat` 语法预检；实际对完整 mt_wifi 补丁序列的应用仍需验证。 |
| PATCH-03 | `003-wapp-gcc14-copy-semantics.patch` | 已处理多个定长字段拷贝，但不是完整输入校验补丁；仍须检查每次 `strtok` 后的 NULL 与长度。 | 不扩大补丁语义；单独建立剩余 token 检查项。 |
| PATCH-04 | `004-libmapd-target-flags.patch` | 已让 libmapd 对象编译和共享库链接接收目标 CFLAGS/LDFLAGS。 | Build/Prepare 已应用；Quick 目标 ELF/NEEDED 检查待完成。 |
| PATCH-05 | `005-wapp-hotspot-realloc-pointer-arithmetic.patch` | 修复字节偏移计算；需防止今后相同结构体指针偏移回归。 | Build/Prepare 已应用；编译验证待完成。 |
| PATCH-06 | `006-p1905-libbridge-tool-propagation.patch` | 将递归 `make` 改为 `$(MAKE)`，传递 CC/AR/RANLIB/CFLAGS/LDFLAGS/INCLUDE，修复 DSA libbridge 子构建脱离目标工具链的风险。 | Build/Prepare 已应用；Full 必须核对实际子命令使用 AArch64 TARGET_CC/TARGET_AR/TARGET_RANLIB。 |
| PATCH-07 | `001-dsa-use-linux-mii-ioctl.patch` | 已有历史记录显示其 hunk 行数曾出现格式错误并修正；当前 Action 对补丁语法执行 `git apply --numstat`，但语法检查不等于对归档应用成功。 | 保留现有修订；应在 P1905 实际解包目录做 dry-run + apply。 |
| PATCH-08 | mt_wifi `035-change-strlcpy-to-strscpy.patch` | 补丁覆盖驱动中 5 处 strlcpy 调用；不能把文件名中的“6.8”视为全驱动 API 已兼容证明。 | 保留补丁，实际应用后检查所有调用点与目标内核头文件。 |
| PATCH-09 | conninfra patch series | 20250408 真实归档已校验；007 remove 回调补丁及 004、011–014、099、100 等共 17 个非空补丁均已对真实源码 dry-run + apply。 | 独立 Actions 已验证补丁顺序和应用结果；目标 Linux 6.12.112 编译仍待 Full。 |

## 4. API 兼容性矩阵

| 组件 | API / ABI 面 | 当前证据 | 结论 |
|---|---|---|---|
| WAPP | Linux WAPP UAPI | Quick 检查 `wapp_cmm_type.h`、`mt_wlan_cmm_oid.h`，由 MTK kernel files 提供 | 文件存在可静态验证；字段/IOCTL ABI 仍需与驱动头文件逐项比较 |
| WAPP | WEXT / iwpriv | 目标驱动为 MTK proprietary WEXT；WAPP 使用 `RA_WEXT`，不是 mac80211/nl80211 | 架构一致；运行时 ioctl 行为需设备验证 |
| WAPP | OpenSSL 3 EC/DPP | 原 shim 与 OpenSSL 3 不兼容；新增 007 改用原生 accessor | 补丁已应用到本地真实源码；目标交叉编译待验证 |
| WAPP | musl / libc | `inet_make_mask` 声明从 `__uint32_t` 改为 `uint32_t`，并加入 `stdint.h` | Build/Prepare 内联修复存在；目标编译待验证 |
| WAPP | GCC 14 | 003 定长字段拷贝语义修复；Makefile 将 `EXTRA_CFLAGS` 桥接到真实使用的 `CFLAGS` | 有静态与编译检查；边界输入仍需单元测试 |
| MAPD | WAPP 控制协议 / WTS ABI | 已有 WAPP-WTS ABI 审计文档记录命令、事件、结构字段顺序和 packed size | 已有专项证据；仍须以本轮实际源码 SHA 复核结构定义 |
| P1905 | Linux 6.12 DSA | 001 使用 Linux MII ioctl；006 修复递归构建工具链传递 | 需实际 target build 验证 `libeth_1905ops.so` 和 libbridge archive |
| P1905 | OpenSSL 3 | 旧初始化及 TLS 1.0 调用均受旧 OpenSSL 版本宏保护；OpenSSL 3.5.9 活跃路径不编译这些代码 | 目标编译待 Quick；TLS 握手/协议协商仍需设备或集成测试 |
| P1905 | libnl-tiny | 使用 `-lnl-tiny`，且 package runtime 依赖 `+libnl-tiny` | 构建/运行时依赖方向一致；须同时检查开发链接入口与运行时 SONAME |
| libmapd | target ABI | 004 确保对象编译和 .so 链接接收目标 CFLAGS/LDFLAGS | 编译待 Quick 验证 |
| mt_wifi | Linux 6.12 | 022 mm_segment_t、026 random API、034 unaligned header、035 strlcpy | 补丁存在；已增加 Quick 语法预检；Full 仍需实际应用和模块编译证明 |
| conninfra | Linux 6.11/6.12 platform driver API | 真实 20250408 归档已校验；17 个非空补丁真实应用；新增 N60 DT alias、probe 状态和资源失败处理 | 静态源码审计完成；目标模块编译与运行时 probe 待 Full/设备验证 |
| mapfilter | Linux 6.12 netfilter API | 源码包存在；仓库有 cb mutex、sockptr_t setsockopt 补丁 | 需要实际应用全部补丁并构建 .ko；Quick 不负责此项 |

## 5. 依赖闭环矩阵

### 5.1 EasyMesh 用户态

| 生产者 / 开发接口 | 直接消费者 | 仓库声明 | 闭环判断 |
|---|---|---|---|
| datconf 的 `Build/InstallDev` | WAPP | `PKG_BUILD_DEPENDS:=datconf`；WAPP 链接 `-ldatconf` | datconf Makefile 同时安装 `libdatconf.h`、`libdatconf.a`，该源码包还提供 libkvcutil 开发文件 |
| libkvcutil（datconf 同源包 InstallDev） | WAPP | 运行时 `+libkvcutil`；WAPP 链接 `-lkvcutil` | 通过 datconf 的同源 Build/InstallDev 提供；需检查实际 staging 中 `libkvcutil.so` 和 SONAME |
| OpenSSL InstallDev | WAPP / P1905 | `PKG_BUILD_DEPENDS:=openssl`；链接 `-lssl -lcrypto` | 头文件与目标库必须来自 target staging，不得使用 runner host OpenSSL |
| libnl-tiny InstallDev | P1905 | `PKG_BUILD_DEPENDS:=libnl-tiny`；链接 `-lnl-tiny` | 构建时需要开发链接文件；运行时需要对应 ABI 库 |
| WAPP UAPI headers | WAPP | target Linux 6.12 WAPP UAPI 路径 | Quick 的 kernel prepare 应提供；缺头文件必须在编译前失败 |
| P1905 DSA bridge | `libeth_1905ops.so` / p1905_managerd | 001 DSA patch + 006 递归 Make 工具传递 | 需确认子 Make 的 CC/AR/RANLIB 均为 target 工具 |
| libmapd source | `libmapd_interface_client.so` | 004 目标 CFLAGS/LDFLAGS | 目标 ELF 和动态依赖待 Quick 验证 |

当前 `easymesh-n60` 声明：
- Build：`PKG_BUILD_DEPENDS:=datconf openssl libnl-tiny`
- Runtime：`+kmod-mapfilter +libnl-tiny +libkvcutil +libopenssl`

注意：`datconf` Makefile 中的 `Build/InstallDev` 同时安装 `libkvcutil.h` 和 `libkvcutil.so*`；因此不能仅因 EasyMesh Build 依赖没有单列 `libkvcutil` 就判定缺失，必须按实际 staging 产物判断。

### 5.2 内核与固件

| 生产者 | 消费者 | 关系 | 验收点 |
|---|---|---|---|
| conninfra | mt_wifi | `+kmod-conninfra` + `PKG_BUILD_DEPENDS:=kmod-conninfra` + `KBUILD_EXTRA_SYMBOLS=$(KERNEL_BUILD_DIR)/conninfra/Module.symvers` | 已补齐构建顺序和 modpost 符号表输入；Full 仍需证明实际 Module.symvers 生成与模块链接 |
| mt_wifi | N60 Wi-Fi | KernelPackage 运行时依赖 WARP、conninfra、wifi-dats、HNAT；构建时依赖 kmod-conninfra 并传入其 Module.symvers | 已补齐构建顺序与 modpost 符号表输入；Full 验证模块编译和符号解析 |
| mapfilter | P1905 / MAP netlink | EasyMesh runtime 依赖 `+kmod-mapfilter`；mapfilter 还依赖 nf-conntrack/nf-nat | Full 验证 .ko、APK、模块自动加载和内核配置 |
| EasyMesh 用户态 | 固件 APK | Full package scheduler 构建 | APK 内二进制、配置、init service、动态库依赖齐全 |
| 全部模块和 APK | Standard ITB | Full image pipeline | ITB 非空、目标设备正确、标准分区布局不变 |

## 6. 已提前修复的问题与补丁对应

| 修复项 | 位置 | 修复内容 | 本轮验证 |
|---|---|---|---|
| FIX-01 | 新增 `patches/007-openssl3-use-native-evp-pkey-get0-ec-key.patch` | 删除 WAPP 自定义 OpenSSL EC accessor shim，使用 OpenSSL 3 原生声明和实现 | 对上传的真实 WAPP 源码本地 dry-run + apply 成功；目标 AArch64 编译待 CI |
| FIX-02 | `easymesh-n60/Makefile` | Build/Prepare 在 002 后应用 007 | 已提交；Quick 静态预检加入补丁存在、应用命令及 unified-diff 语法检查 |
| FIX-03 | mt_wifi patch 022 | 修正 `ap_cfg.c` 的 `orig_fs` 变量名；保留 `OS_FS_INFO.fs` 成员名 | 已提交；Quick 增加 022/026/034/035 的 `git apply --numstat` 语法预检 |
| FIX-04 | Quick Action | 对新 DPP patch 使用单引号匹配字面量 `$(PKG_BUILD_DIR)`，避免 shell 将其当命令替换 | 已修正；新一轮 Quick 等待验证 |
| FIX-05 | Quick Action | 对四个 Linux 6.12 驱动兼容补丁执行语法预检 | 已提交；实际 hunk 应用仍由 Full/独立源码审计验证 |

## 7. 尚未关闭的审计项与验收条件

1. **conninfra 源码编译验收**：源码归档已下载并实测 SHA256；17 个非空补丁已逐个 dry-run + apply。仍需 Full 证明目标 Linux 6.12.112 交叉编译、Module.symvers 生成和运行时 probe 成功。
2. **驱动补丁真实应用**：Quick 已调用 mt_wifi 和 mapfilter 包的真实 prepare 目标，并检查补丁日志/应用后源码；最新 Run #636 待验证。Full 仍需证明内核模块完整编译和 modpost。
3. **WAPP DPP 目标编译**：007、008 已进入真实 Build/Prepare；WAPP 专项 Run #160 已通过脚本语法和补丁语法检查。Quick 仍需以 OpenSSL 3.5.9 target headers 完成 WAPP 实际编译。
4. **WTS parser 健壮性**：parser hardening 已写入 Build/Prepare 转换脚本，必须由 Quick 对真实归档执行并通过；仍需建立 malformed WTS 测试集，证明有效的 12 条 vendor profile 格式与语义未改变。
5. **OpenSSL 3 TLS 行为**：源码条件编译已确认旧 `SSL_library_init()` / `TLSv1_method()` 仅用于 OpenSSL 1.1 以下分支；OpenSSL 3.5.9 活跃路径仍需目标编译和 TLS/EAP 行为验证。WAPP/P1905 的 `-Wno-deprecated-declarations` 仅抑制旧 vendor API 的弃用告警，不能作为 API 现代化或运行时兼容证明。
6. **最终依赖闭环**：Quick 将验证 WAPP/MAPD/P1905/libmapd 的 AArch64 ELF、六个产物的 NEEDED/SONAME/RPATH 信息和关键依赖；Full 证明 conninfra、mt_wifi、mapfilter、APK、动态库和 ITB。
7. **补丁适用性**：对所有 EasyMesh、mt_wifi、conninfra、mapfilter 补丁逐个记录 dry-run/apply 结果、修改文件、补丁顺序和应用后 API 证据。

## 8. 验收结论

- 源码错误清单：**已形成 WAPP/DPP、mt_wifi、conninfra 的首轮证据清单；不宣称已穷尽所有源码问题**。
- 补丁缺陷清单：**已修复 DPP OpenSSL 3 shim、mt_wifi 022 变量名、conninfra N60 DT 匹配、probe 失败检测、EEPROM 读错误、MMIO/EMI 资源检查、core thread 初始化回收和寄存器访问错误传播问题**。
- API 兼容性矩阵：**conninfra 20250408 真实源码静态审计和 17 个非空补丁应用已完成；WAPP DPP/WTS 和辅助组件补丁已进入 Quick 验证；Linux 6.12.112 目标内核模块编译仍待 Full**。
- 依赖闭环矩阵：**已核实 mt_wifi 对 conninfra 的三个导出符号依赖，并补齐构建时依赖和 Module.symvers；Quick 还将检查 WAPP/MAPD/P1905/libmapd 用户态 ELF；最终 modpost 和 ITB 闭环仍待 Full**。
- 可提前修复的问题及补丁：**已将 conninfra 关键源码/API/DT/依赖检查前移 Quick；保留 `-Werror`，没有关闭告警或跳过非空补丁**。

**本报告不是最终固件验收通过声明。conninfra 源码级静态审计已完成；只有 Quick 最新 Action、Full 目标内核模块/固件编译，以及设备运行时 probe 验证全部通过，才能签署整体通过。**

## 9. conninfra 20250408 源码级审计补充（2026-11-05）

### 9.1 真实归档与补丁应用结果

- 已下载并实测 SHA256：`mt79xx_conninfra_20250408-f2fa25.tar.xz`，SHA256 `3a82cfa69e68c8e584723b604dda565b2c085239ba1ac834d6d3b0ebd987e58c`。
- 同时下载并实测 mt_wifi 归档：`mt79xx_20250408-705eb4.tar.xz`，SHA256 `b029d7b43c498193092dc6a3c857361c8835ce34bb306561c550ac0539784a78`。
- 独立审计工作流对 conninfra 目录内 17 个非空补丁按文件名字典序执行 `patch --dry-run -p1` 和真实 `patch -p1`，均成功。空的历史 `096` 文件被明确记录为 empty patch 并跳过；不是失败补丁。
- patch 007 因前序补丁插入代码而以 offset -2 应用，但没有 fuzz；该补丁已真实应用，不属于跳过或失败。
- 真实补丁序列：001、002、003、004、006、007、008、009、010、011、012、013、014、099、100、101、102。
- 审计产物：Actions artifact `n60-conninfra-source-audit-30`，包含 patch log、SHA256 清单和 mt_wifi/conninfra 符号依赖审计报告。

### 9.2 Linux 6.12 API 与构建策略修订

| 项目 | 原始问题 | 当前修订 |
|---|---|---|
| `class_create` | 旧代码传入 `THIS_MODULE`，Linux 6.4 起接口移除 owner 参数 | patch 002 使用单参数接口 |
| `ioremap_nocache` | 旧 API 已移除 | patch 003 改用 `ioremap` |
| `platform_driver.remove` | Linux 6.11 起回调签名改为 void | patch 007 改为 void |
| `of_device_id` | 不再依赖隐式头文件包含 | patch 008 显式包含 mod_devicetable 头文件 |
| 旧式声明 / missing prototype | 在新内核和严格告警下可能失败 | patch 006/009 修订 |
| MCU / AP2CONN clocks | 原补丁忽略 `clk_prepare_enable` 错误，且手动资源释放不完整 | patch 004 使用 `devm_clk_get_enabled`；失败时返回错误，devres 自动回收 |
| compiler warning | 原 Makefile 用 `-Wno-error=format`、`-Wno-error=format-extra-args` 降低格式告警级别 | patch 011 删除两项豁免，保留 `-Werror`；099 修复已定位的格式字符串 |
| modpost warning flag | `KBUILD_MODPOST_FAIL_ON_WARNINGS` 不是上游 Linux 6.12 Kbuild 接受的变量，原注释所称“强制所有 modpost warning 失败”没有证据 | patch 011 删除无效变量；保留默认 modpost 策略，不设置 `KBUILD_MODPOST_WARN`。不能把它表述成“所有 modpost warning 均已强制失败” |

静态扫描在补丁应用后未发现 `get_fs/set_fs/mm_segment_t/strlcpy/prandom_u32/ioremap_nocache` 等本轮扫描的旧 API 残留。该结论是源码扫描结果，不替代目标内核编译。

### 9.3 N60 Pro 的关键 DT 匹配错误

**已证实的原始缺陷：**
- conninfra 原始 `apconninfra_of_ids` 只匹配 `mediatek,mt7986-consys`。
- 仓库 N60 Pro DTS `target/linux/mediatek/dts/mt7986a-netcore-n60-pro.dts` 包含 `mt7986a.dtsi`，并通过 `&wifi` 节点配置 `nvmem-cells = <&eeprom_factory_0>`、`nvmem-cell-names = "eeprom"`、`status = "okay"`。
- Linux v6.12 上游 `mt7986a.dtsi` 中 Wi-Fi 节点 compatible 是 `mediatek,mt7986-wmac`，并提供 `clock-names = "mcu", "ap2conn"` 和 `memory-region = <&wmcpu_emi>`。
- 因此旧 conninfra match table 无法匹配 N60 的实际设备节点；`platform_driver_register()` 返回 0 本身并不能证明 probe 已执行。

**已修复：**
- patch 013 为同一 MT7986 平台数据增加 `mediatek,mt7986-wmac` compatible alias，不修改 N60 DTS。
- patch 014 增加 probe 状态检查：驱动注册后若没有匹配设备或 probe 未成功，初始化返回错误并 unregister platform driver；probe 中途失败会按阶段回收已初始化资源。
- patch 004 使用设备节点中的 mcu/ap2conn clocks；patch 100 校验 MMIO 映射失败并回收此前已映射窗口。

### 9.4 EEPROM / NVMEM 错误处理

- patch 010 将 conninfra EEPROM 读取接到 kernel `mt_eeprom_read_wifi` backend；该符号由仓库 kernel patch 999 导出。
- 原 `FlashRead()` 忽略 backend 返回值，调用者可能继续消费旧值或未初始化值。
- patch 012 将 `FlashRead` 改为返回 int，读前清零输出缓冲区，记录错误；MT7986/MT7981 调用点检查返回值。MT7986 两项 EEPROM 参数只有在 chip ID、stream 和 LNA/PA 数据读取都成功时才使用，否则回到默认配置。
- N60 DTS 的 factory 分区是 read-only，EEPROM NVMEM cell 为 4 KiB；conninfra 的 `FlashWrite()` 仍为 no-op，没有增加对 factory 分区的写入路径。

### 9.5 MMIO / EMI 资源检查

- patch 100 检查 MT7986 每个固定寄存器窗口的物理地址和大小，并检查 `ioremap()` 返回值；任一映射失败则回收此前已映射窗口并返回错误，避免后续 NULL MMIO dereference。
- 同一 patch 修正 `consys_reg_mng_init()` 的正 errno 返回值为负 errno。
- EMI 初始化现在释放 `of_parse_phandle()` 返回的 node 引用，并校验 reserved memory base、size 是否覆盖平台要求的 firmware EMI size。
- N60 的 SoC dtsi 声明 `wmcpu_emi`，MT7986 平台代码要求 firmware EMI size 1 MiB；Full 仍需验证最终 DTB 中 reserved memory 的实际值和 probe 日志。

### 9.6 mt_wifi ↔ conninfra 符号闭环

- mt_wifi 20250408 源码实际引用 conninfra 的 `conninfra_pwr_on`、`conninfra_pwr_off`、`conninfra_get_emi_phy_addr`。
- conninfra 源码实际导出上述三个符号。
- 原 mt_wifi Makefile 仅有运行时 `+kmod-conninfra`，没有显式构建时依赖，也没有向外部模块 Kbuild 传递 conninfra Module.symvers。
- 已修改 mt_wifi Makefile：`PKG_BUILD_DEPENDS:=warp conninfra`；在启用 `CONFIG_MTK_CONNINFRA_APSOC` 时检查 `$(KERNEL_BUILD_DIR)/conninfra/Module.symvers` 存在，并通过 `KBUILD_EXTRA_SYMBOLS` 传给 mt_wifi Kbuild。
- 独立审计工作流已对 mt_wifi 和 conninfra 两个真实归档校验 SHA256，并逐一验证三个符号在 conninfra 中导出、在 mt_wifi 中引用，同时检查 Makefile 的 build dependency 和 KBUILD_EXTRA_SYMBOLS 声明。

### 9.7 寄存器访问 API 错误传播补充

- 原 `conninfra_core_reg_read/write()` 在 core mutex 获取失败时返回 0，造成调用方误判为成功；未上电或寄存器不可读时也可能返回 0。
- 原 `conninfra_core_reg_read()` 未检查空输出指针，失败时也没有清零输出，可能留下调用方旧值。
- 原 `consys_reg_mng_reg_read/write()` 在 `ioremap()` 失败时返回通用 `-1`，且 read 未检查输出指针。
- patch 102 已修复：读写 API 传播锁错误；未上电返回 `-EHOSTDOWN`；不可访问返回 `-EACCES`；read 校验空指针并预先清零输出；MMIO 映射失败返回 `-ENOMEM`。
- 该 API 当前没有在本次 mt_wifi 源码中发现直接调用，属于 conninfra 内部公开头文件的健壮性修复；不会改变 N60 的正常读写路径。

### 9.8 Quick / Full 验收边界

Quick 已加入 conninfra 源码下载、SHA256 校验、完整 patch dry-run/apply、旧 API 残留扫描、MT7986 DT compatible、probe status、EEPROM、MMIO、EMI 和 mt_wifi Module.symvers 静态闭环检查；同时核验 kernel patch 999 将 `mt_wifi_eeprom.o` 编入内核、导出 `mt_eeprom_read_wifi`，并识别 `mediatek,mt7986-wmac`；并在 defconfig 后断言：
- `CONFIG_MTK_CONNINFRA_APSOC=y`
- `CONFIG_MTK_CONNINFRA_APSOC_MT7986=y`
- `CONFIG_CONNINFRA_EMI_SUPPORT=y`
- `CONFIG_CONNINFRA_AUTO_UP=y`

**仍待实际构建验收：**
1. Quick 最新 Action 的 conninfra 静态审计步骤通过。
2. Full 对 conninfra.ko 和 mt_wifi.ko 完成目标内核编译，且 mt_wifi modpost 能解析 conninfra 三个符号。
3. 构建产物中 conninfra.ko、mt_wifi.ko 的依赖和 autoload 顺序正确。
4. 设备运行时确认 conninfra platform probe 成功、mcu/ap2conn clocks 已启用、EMI base/size 正确、EEPROM chip ID 读取成功。

在以上四项完成前，不宣称 conninfra 运行时已验收通过。


## 10. bndstrg_plus / fwdd 辅助组件专项审计（2026-11-05）

### 10.1 固件集成边界

- 两个归档均存在于 release dl-sources-7.6.7.3，SHA256 与上传 ZIP 一致。
- 当前仓库递归 Git tree 中没有 bndstrg_plus 或 fwdd 的 package Makefile；config/n60pro-1001.config 也未选择对应 package。
- 当前 easymesh-n60/Makefile 仅解包、编译 WAPP、MAPD、P1905、libmapd 四个源码树。
- 因此这两个组件目前属于**源码归档存在、未集成到 N60 标准固件构建**。本轮不擅自新增固件包、不改变标准固件内容；仅通过 Quick 的辅助审计脚本做目标架构独立编译。

### 10.2 bndstrg_plus

原始源码使用 MTK proprietary WEXT private ioctl（SIOCIWFIRSTPRIV + 0x01）、iwreq 和自带 wireless extensions definitions，符合 MTK WEXT 架构方向；不依赖 nl80211。

GCC 14.2.0 host -Wall -Werror 实测发现：
1. driver_wext.c:119 的 if (data) 与后续 if (buf) 缩进不一致，触发 -Wmisleading-indentation。
2. driver_wext_set_oid() 在 os_zalloc(len) 失败时仍可能对 NULL buf 执行 memcpy。
3. main.c 的 opmode 和 drv_mode 未初始化，编译器报告 -Wmaybe-uninitialized；process_options() 并未给这两个参数赋值。

新增 auxiliary-patches/001-bndstrg-gcc14-werror-and-init.patch：
- 为分配失败加检查，只有 data && len 才复制；
- 统一条件块结构；
- N60 Pro 是双频设备，设置 OP_DUALBAND；当前 WEXT backend 不使用 drv_mode，初始化为 0；
- 删除用户态 bnd_msg_cli_probe 中多出的 bIosCapable 字段，并移除只读取该字段的无效分支。

**ABI 缺陷已证实：** mt_wifi 7.6.7.3 的 band_steering_def.h 定义 CLI probe 字段为 bAllowStaConnectInHt、bVHTCapable、Nss、Rssi[4]；原 bndstrg_plus 头文件在中间多了 bIosCapable。mt_wifi 的 ap_band_steering.c 确实通过 BndStrgSendMsg() 发送 CLI_EVENT/PROBE_REQ，因此原字段偏移会让用户态把 VHT/NSS/RSSI 读错位。OID_BNDSTRG_MSG=0x0950、OID_GET_SET_TOGGLE=0x8000、RT_PRIV_IOCTL=SIOCIWFIRSTPRIV+0x01 与当前 mt_wifi 源码匹配。
- 已在辅助 Quick 脚本增加所有共享 bnd_msg_* 结构字段顺序比对，不能仅凭单个 probe 结构或编译通过判断 ABI 一致。

补丁应用后的完整 host GCC 14.2.0 构建通过，保留 -Wall -Werror。AArch64 musl 编译及 23 个共享消息结构的字段顺序自动比对由最新 Quick Action 验证中。用户态默认接口提示仍写 ra0/rai0；N60 Pro 实际 5GHz 接口为 rax0，因此若将来集成必须显式配置 -i ra0 -i rax0，不能沿用 vendor 默认示例。

### 10.3 fwdd

原始源码使用 Linux AF_NETLINK/NETLINK_EXT=25 vendor protocol、WEXT SIOCGIWFREQ/SIOCGIWMODE/SIOCGIWESSID 和 MTK private ioctl SIOCIWFIRSTPRIV+1。当前仓库和 mt_wifi 20250408 源码检索未找到 NETLINK_EXT=25 的内核端协议注册/接收实现；因此其 vendor netlink 对端 ABI 目前没有闭环证据。即使用户态目标编译成功，也不能宣称 fwdd 在当前内核可运行。

GCC 14.2.0 host -Wall -Werror 实测发现 io_get_cmd() 的 strncpy(..., MIN(sizeof-1, strlen(ifname))) 触发 -Wstringop-truncation。

新增 auxiliary-patches/002-fwdd-gcc14-bounded-ifname-copy.patch：使用 strnlen 限定到 IFNAMSIZ-1、memcpy 和显式 NUL 终止。补丁应用后的完整 host GCC 14.2.0 构建通过，保留 -Wall -Werror。目标 AArch64 musl 编译由最新 Quick Action 验证中。

### 10.4 Quick 辅助编译门

新增 scripts/n60-auxiliary-source-audit.sh，由 Quick Action 调用：下载两个精确归档、校验 SHA256、逐个 dry-run/apply 补丁、用当前 OpenWrt AArch64 musl toolchain 编译，并验证输出 ELF Machine 为 AArch64。二进制仅作为审计 artifact 上传，不进入固件 APK 或 ITB。

**限制：** AArch64 编译通过只能证明目标工具链下的用户态编译/链接；NETLINK_EXT=25 和 MTK WEXT private ioctl 的运行时协议仍需确认内核端对应实现，且两个组件当前并未集成到标准固件。

## 11. 最新 Quick 状态与下一步

- Run #615（commit cf455437）真实进入 EasyMesh Build/Prepare，在执行 n60-wts-hardening.py 时发现 Python SyntaxError：两条 once() 调用意外拼接在同一行。此为 Quick 脚本语法错误，不是 C 源码或目标工具链错误。
- 已在 commit bf6b1ba6 修复 Python 语句分隔，并在 commit 28820afb 修正 AArch64 编译器搜索，避免把 toolchain compiler symlink 排除。
- 当前最新完整验证 Run #636：https://github.com/laodadelaoda/immortalwrt-mt798x-rebase/actions/runs/41960190837，排队待执行。该 run 包含 WTS 全调用链错误传播/输出清零/每条记录复位、mapfilter sockptr.h include、bndstrg/fwdd AArch64 辅助审计及全六个 ELF 的动态依赖报告。Run #634 仍在旧提交执行；分支 concurrency 将只保留最新 run。
- Run #621 成功后仍需执行 Full，验证 conninfra.ko、mt_wifi.ko、mapfilter.ko、APK 和 Standard ITB；Quick 不替代这些步骤。


## 12. 基线版本核对

用户上传的固定上下文 V3.4-F 将 conninfra 写为 20231229-f2fa25；但当前 GitHub 分支 package/mtk/drivers/conninfra/Makefile 实际锁定的是 mt79xx_conninfra_20250408-f2fa25.tar.xz，PKG_VERSION=20250408，SHA256=3a82cfa69e68c8e584723b604dda565b2c085239ba1ac834d6d3b0ebd987e58c。当前专项审计以仓库 Makefile 的真实构建输入 20250408 为准。conninfra 独立审计 Run #30（41945324144）成功，且该 run 对应提交已包含 patch 102；17 个非空补丁真实应用的结论基于该精确归档。
