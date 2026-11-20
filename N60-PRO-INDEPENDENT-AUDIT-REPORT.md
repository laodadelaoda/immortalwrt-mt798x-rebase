# N60 Pro 发布前独立定向代码审查报告

- **审查基准：** `4acfbb037c134e822aac3d52de9f6e63f5cc1b51`
- **仓库 / 分支：** `laodadelaoda/immortalwrt-mt798x-rebase` / `n60pro-mtk-closed-driver`
- **审查类型：** 只读独立审查；本次只新增本报告，不修改项目代码，不启动 Actions。
- **总体结论：FAIL**

## 总体结论和发布阻断项

基准提交与目标分支 HEAD 相同。Full Workflow #700（SHA 与基准一致）失败在 EasyMesh `Build/Prepare` 阶段：零 fuzz 应用 WAPP WTS 安全补丁时，`wappd/common/main.c` 的第 6、12 个 hunk 失败，步骤退出 1。该失败发生在源码编译/链接及固件生产之前，因此基准提交没有通过 Quick 源码构建、Full 固件构建或 ITB 验收。WAPP Source Audit #211 虽然同 SHA 且成功，但它验证的是独立新鲜解包上的 WTS 补丁应用，不能证明 Full 的完整补丁顺序能成功，也不能覆盖实际编译。

报告仅解决了“形成审查记录”的工作；不是修复提交或发布批准。**不得据此发布当前基准固件。**

## 证据状态与审查限制

### 已读取的核心文件

- `.github/workflows/main.yml`（完整，733 行）
- `.github/workflows/easymesh-quick.yml`（完整，37 行）
- `.github/workflows/wapp-source-audit.yml`（完整，177 行）
- `.github/actions/easymesh-quick/action.yml`（GitHub 文件读取输出在第 1000 行附近截断，未能取得文件余部；无法确认其结尾步骤、后半段产物验证与上传逻辑）
- `package/mtk/applications/easymesh-n60/Makefile`、所列补丁、依赖包 Makefile、N60 config、审计脚本及测试、依赖矩阵与审计文档。

长审计文档的部分超长行在工具输出中也有截断；所以报告使用其可见内容和仓库当前代码/Actions 证据，不声称已逐字读完被截断行。没有本地构建工作区，不能运行编译、补丁或测试。

### 供应商归档可用性

GitHub release `dl-sources-7.6.7.3` 的资产清单可确认以下归档名存在：WAPP、MAPD、P1905、libmapd、mt_wifi、mapfilter，以及审计辅助用 bndstrg_plus/fwdd。发布页不包含 datconf、conninfra 或 WARP 归档；它们在包 Makefile 中指向外部 raw GitHub 下载地址。本审查环境没有提供可下载/展开这些归档的本地接口，故不能声称已逐行审查供应商源码。

文档记录了先前独立归档校验/补丁审计信息，但这些记录不是本次的源码读取或当前基准提交的编译证明。WAPP Audit #211 的 Action 实际运行信息和日志另行检查；conninfra/WARP 独立审计在本次没有取得可核实的成功运行日志/产物。

### 证据术语

- **已证实问题：** 由基准源码或该提交 Actions 的实际结果直接证明。
- **高可信度推断：** 根据流程和代码关系可推断，但仍需源码/运行时证据确认。
- **待验证问题：** 当前材料不足以判定通过或失败。
- **已通过验证：** 仅限引用的特定静态检查或 Action 步骤，不扩展为编译、链接或运行时通过。

## Actions 结果核对

| Workflow | Run | SHA | 实际结果 | 审查意义 |
|---|---:|---|---|---|
| Audit WAPP 7.6.7.3 source | [#211](https://github.com/laodadelaoda/immortalwrt-mt798x-rebase/actions/runs/42013225088) | `4acfbb037c134e822aac3d52de9f6e63f5cc1b51` | completed / success | WAPP audit workflow 实际成功；它包含下载并校验 WAPP/MAPD/P1905 源归档、源扫描、对三棵新解包源码树 dry-run 后真实应用 WTS patch 的步骤。仅证明该 audit workflow 所运行检查通过。上传内容见 workflow 第 165–176 行，主要是归档、文件清单和旧 ELF 参考文件，不包含完整源码扫描日志/补丁后目录；本次没有取得 artifact 内容。 |
| Quick gate（Full 工作流中的 Quick job） | Full [#700](https://github.com/laodadelaoda/immortalwrt-mt798x-rebase/actions/runs/42013225117) 的依赖 job | `4acfbb037c134e822aac3d52de9f6e63f5cc1b51` | Full run failure；Quick job 在 `Build/Prepare` 失败 | 没有证据表明本基准有独立 Quick workflow_dispatch run 完成。#700 执行的 Quick 共享 gate 失败，Full job 因 `needs: quick_compatibility` 不会进入完整固件 build。实际失败不是编译器诊断，也不是链接，而是补丁应用。 |
| Build N60 Pro - ImmortalWrt 25.12 (Standard Only) | [#700](https://github.com/laodadelaoda/immortalwrt-mt798x-rebase/actions/runs/42013225117) | `4acfbb037c134e822aac3d52de9f6e63f5cc1b51` | completed / failure | 日志明确报告 `wappd/common/main.c` Hunk #6、#12 failed，`2 out of 16 hunks FAILED`，step exit code 1；后续验证步骤 skipped。未取得用户态 EasyMesh 编译/链接、mapfilter、MTK 模块、APK 或 ITB 通过证据。 |

#211 与 #700 的 SHA 均为审查基准，故两者证据可以直接用于本次基准判断。仓库 Actions API 显示 #211 成功、#700 失败；#700 的真实 job log 明确定位了失败阶段和 hunk。#211 成功不覆盖 #700 报告的组合补丁顺序失败。

## 八项实质审查

### 1. 闭源组件覆盖率 — **FAIL（发布证据不完整）**

**已通过验证：** `tests/test-vendor-artifact-inventory.py` 将 WAPP、MAPD、P1905、libmapd、datconf、mt_wifi、conninfra、WARP、mapfilter 等 9 个源归档的 SHA256 声明纳入静态 pin 检查，并检查 EasyMesh 四棵源码树、datconf 文件/头文件数、MAPD 7 个 AArch64 GCC 8.4.0 预编译 `.o` 和 4 个 `.a` 的 hash/成员等（脚本第 24–46、48–135、206–217 行）。文档还明确承认 MAPD proprietary 对象无配套源码，不能做源码级审计（脚本第 135 行；`docs/n60pro-closed-component-coverage-2026-11-05.md` 第 19、114–120 行）。

**已证实问题：** 当前 Run #700 在 EasyMesh Prepare 失败，完整的构建输入/产物覆盖检查没有形成当前基准的成功执行证据。当前仓库有 8 个旧 ELF 参考文件，但它们不是当前 source-built 产物；代码中的 inventory test 能检查引用 ELF 元数据与禁止安装（脚本第 137–205 行），不能替代这次真实 source build。

**待验证：** WAPP/MAPD/P1905/libmapd 与 datconf 的归档本体是否与 pin 相符、MTK 三个驱动归档实际内容、MT7986 固件 payload、最终安装包闭环。本审查没有取得这些归档的本地字节内容。Release 资产清单没有 datconf、conninfra、WARP；对应下载源在 `package/mtk/applications/datconf/Makefile:10–14`、`package/mtk/drivers/conninfra/Makefile:11–16`、`package/mtk/drivers/warp/Makefile:9–15`。

**影响：** proprietary MAPD 对象的机器码不可源码审查；未完成基准产物的输入、对象、模块和固件覆盖证明。

**最小建议：** 保持明确的闭源对象限制；归档可达后记录确切 hash、文件清单、ELF 分类和目标链接结果，不把静态 inventory 或历史报告标成此次通过。

**验证方式：** 获取当前基准所有固定输入归档，实际完成 inventory test；成功 Quick/Full 后保存源 hash、MAPD object/archive 审计、模块/APK/ITB 产物清单及 SHA256。

### 2. 补丁实际应用和补丁完整性 — **FAIL（已证实）**

**已证实问题：** `package/mtk/applications/easymesh-n60/Makefile:50–57` 按 DPP patches 002、007–010 后应用 WTS patch 011；该 workflow 的完整执行日志在 Full #700 显示 WTS patch 对 `wappd/common/main.c` 有 2 个 hunk 失败（Hunk #6 at 874、Hunk #12 at 967），共 16 个 hunk 中失败 2 个，随后流程退出。零 fuzz helper 在 Makefile 第 26–30 行会 fail closed，因此构建没有悄悄带 fuzz 继续。

**对照证据：** WAPP Audit #211 第 153–163 行把 WTS patch 在 WAPP、MAPD、P1905 三棵**新鲜解包、尚未经过 EasyMesh 前置 DPP patch 序列**的源码上应用并报告成功。因此 #211 证明了 WTS patch 单独适用于原始 pin，不证明完整 Build/Prepare 序列兼容。Full #700 的真实失败恰好暴露了该覆盖缺口。

**影响：** 基准提交不能准备 EasyMesh 源码；Quick 被阻断，后续所有编译、链接、APK、Full 内核及 ITB 步骤均未取得证据。

**最小建议：** 修订 patch 011 或其应用顺序，使其基于先前补丁修改后的实际树仍可零 fuzz 应用；审计 workflow 应按 package 完整顺序在同一临时树复现全部补丁，而不只单独试 WTS patch。

**验证方式：** 用 pinned archives 从干净目录执行 Makefile 中完全相同的提取、换行规范化及补丁顺序；要求每个补丁 dry-run 和 apply 均成功、零 fuzz；随后运行 Build/Prepare 并成功进入 target compile。不能以 `git apply --numstat` 代替应用。

### 3. OpenSSL 3 源码/API/ABI 兼容性 — **INCOMPLETE**

**已通过验证：** OpenSSL package 锁定 `3.5.9` 和 SHA256（`package/libs/openssl/Makefile:10–24`）；WAPP Makefile 有修复本地 OpenSSL EC accessor shim 的 patch 007 接线（EasyMesh Makefile 第 50–52 行）；测试禁止 EVP_PKEY 内部访问并检查原生 accessor 的使用（`tests/test-easymesh-static-contract.py:21–77`、`tests/test-dpp-source-contract.py:80–85`）。EasyMesh Build/Compile 还要求 target staging 的 OpenSSL major 为 3（Makefile 第 106–109 行），并链接 `-lssl -lcrypto`（第 114、131 行）。这些是静态门禁/构建接线，不是实际 API/ABI 兼容证明。

**待验证：** #700 失败在补丁 Prepare，未执行 WAPP/P1905 的 OpenSSL 3 target 编译链接或 `readelf` NEEDED 检查。即使版本头文件声明 major 3，也不能说明所有 OpenSSL API 调用、符号版本、运行时 provider/配置均兼容。

**影响：** OpenSSL 3 兼容和使用的真实动态 ABI 没有当前基准构建证据；旧 OpenSSL 1.1 ELF 仅为审计参考的约束还需由实际 source-built 产物与包安装校验确认。

**最小建议：** 不要扩展 deprecated API 的抑制范围；保留修复和错误诊断门禁，完成真实 target compile/link 和逐产物动态段审计。

**验证方式：** 用目标 OpenSSL 3.5.9 headers/libs 编译 WAPP/P1905；对所有 6 个 EasyMesh 目标产物检查 ELF machine、SONAME、DT_NEEDED、RPATH/RUNPATH，解析每个直接依赖并拒绝 `libssl.so.1.1`/`libcrypto.so.1.1`；Full 再检查最终 APK/runtime 包依赖。设备上 TLS/DPP 行为仍需运行时测试。

### 4. DPP 调用链及 `dpp_read_config_file_for_connection` — **INCOMPLETE**

**静态审查证据：** Quick action 中的 DPP source audit 脚本设计为解析唯一实现、完整函数体、`cred_len` 引用、声明、调用位置和配置 gate（可见 action.yml 第 510–603 行）；后续契约检查关注 MAP R3 caller 错误传播、datconf API、hex key 长度、错误清理及凭据日志（第 604–743 行）。仓库的 `tests/test-dpp-source-contract.py:14–129` 对空指针先于解引用、hex decode 长度/结果、caller 返回错误、动态字段副本和回滚路径设有静态断言。脚本本身不能证明跨所有预处理路径的语义正确。

**已证实问题/当前限制：** Full #700 在 DPP contract test 之前因 WTS patch 失败，没有证明这些断言实际在准备完成的供应商源码上运行，更没有 DPP target compile 或运行时验证。`patches/010-dpp-wdev-config-allocation-rollback.patch:74–106` 是错误回滚代码，但其边界涉及 `wdev->config` 已挂接对象和调用者更大范围状态；仅凭补丁片段不能证明后续生命周期不会重复释放、残留已分配的共享状态或可安全重试。

**影响：** DPP 的配置读取、解析失败传播、R3 重配置与每接口配置所有权不能作为已验收发布功能。

**最小建议：** 先修复补丁串行应用失败；随后对实际预处理后的源逐条审阅返回值和所有分配/释放路径，特别检查 wdev 配置对象的所有权、共享 `wapp->dpp_csign` 生命周期以及错误回滚后状态。

**验证方式：** 在完整补丁树上运行 DPP contract test；以 MAP R3 与 DPP 编译宏构建目标 WAPP；对缺字段、超长/奇数长度/非 hex key、配置文件读取失败及逐个分配失败注入测试，确认 caller 返回错误、无泄密、无越界/泄漏/双重释放；最终做设备侧 DPP 连接验证。

### 5. Quick/Full 职责边界 — **PASS WITH WARNINGS（设计接线静态通过，执行未通过）**

**已通过验证：** `.github/workflows/main.yml:35–55` 将 Quick 设置为独立 job，Full `build` 依赖 Quick；`.github/workflows/easymesh-quick.yml:21–37` 是手动 Quick 入口。文档明确 Quick 是用户态源码编译审计，不产出固件，Full 独立构建内核、APK、ITB（`docs/easymesh-quick-dependency-matrix-2026-11-04.md:7–12、48–60`）。Full 工作流第 540–544 行也明确两个 hosted runner 不共享 Quick build tree，Full 自己 clean/compile package。实现边界总体清晰。

**已证实问题：** Full #700 的 Quick gate 失败，因而 Full job 没有运行。不能把职责边界正确等同于功能构建通过。

**高可信度审计风险：** `.github/actions/easymesh-quick/action.yml` 被读取工具在约 1000 行处截断；本文无法核对剩余 action steps、最后的 ELF 闭环、报告上传及错误处理。该文件的可见部分包含 Prepare/依赖 staging 等内容，但不是全文件审查。

**最小建议/验证：** 通过分段或其他可无损读取方式审查 action.yml 尾部；确认 Quick 只生成 `.built`/用户态产物、不调用 APK/runtime scheduler，Full 仍自行 compile 并检查 APK/ITB。修复补丁后分别运行独立 Quick 和 Full。

### 6. 实际编译、链接和动态依赖闭环 — **FAIL（没有基准成功证据）**

**已证实：** Full #700 的真实失败发生在 patch prepare，日志报告 Hunk FAILED 并 exit 1。由于 `main.yml:38–54` Quick job 是 `build` 的 `needs`，本次 Full build 被拦截；主流程中后续 EasyMesh compile、AArch64 检查、OpenSSL/libnl NEEDED、mapfilter `.ko`/APK、驱动模块、完整 package scheduler 和 sysupgrade ITB 检查没有执行。

**静态设计：** EasyMesh Makefile 第 94–150 行接线了 libmapd、WAPP、P1905、MAPD 构建并检查文件存在；Full workflow 第 546–584 行计划检查六个 AArch64 文件以及若干关键 NEEDED。计划和 shell 断言不是成功的链接日志。现有 `test-vendor-artifact-inventory.py:243–279` 明确承认静态检查不能证明实际 link/modpost/runtime。

**影响：** 发布必须有的构建链闭环未成立，且不存在当前 SHA 的成功 ITB 证明。

**最小建议：** 不以历史 SHA 的成功或 README/doc 状态替代基准重新验证；先解决 Prepare 失败。

**验证方式：** Quick 完成所有用户态编译与链接；检查六产物 AArch64、DT_NEEDED/SONAME及依赖可解析；Full 在另一 runner 完成 mapfilter/conninfra/WARP/mt_wifi 的编译和 modpost，检查 APK 内文件、运行依赖和安装脚本，再生成非空指定 N60 sysupgrade ITB 并核对 manifest/hash。运行时功能需设备验收。

### 7. 审计脚本自身可靠性 — **FAIL（发现覆盖不一致）**

**已证实问题：** WAPP Source Audit #211 第 153–163 行只在新解包的三棵原始归档树上单独验证 WTS patch。它没有先对 WAPP 源应用 EasyMesh 的 002、007–010 DPP 补丁，也没有复现 Makefile 第 50–57 行的完整序列。故 audit workflow 的 patch-success 断言通过，但相同 patch 在真实 Full #700 的完整 Prepare 序列中失败。这是可复现的覆盖缺口，不是推测。

**已证实限制：** 源码审计 workflow 对输出做��配数限制（例如最多 180 个命中，第 74–94 行），这适用于候选清单而不能当作穷举审查；它会输出若干指定函数，但只选择少数入口。该 workflow artifact 不上传完整文本报告/补丁后源码（第 165–176 行），不便于复核审计输出。

**静态脚本限制：** `test-vendor-artifact-inventory.py` 的动态依赖检查首先针对保留的旧 ELF 参考文件（第 157–185 行），源构建 NEEDED 的全面验证在 Full workflow 后续步骤，而非该脚本本身；脚本第 279 行承认实际 link/modpost 尚需执行。DPP 用正则和字符串片段提取函数，不是 C parser/控制流证明。

**最小建议：** 将 WAPP audit 的 patch 校验改为完整 Package Build/Prepare patch 序列，并在每个序列步骤后验证差异；保存可复核的完整日志/补丁后源码或 hash 清单；对 source-built ELF 实际 NEEDED 做独立依赖解析。

**验证方式：** 人工比对其临时解包/应用顺序与 Makefile；提交后在同 SHA 的 WAPP audit 和 Quick 日志确认相同输入、相同 patch 序列通过；审计脚本运行测试用负例验证错误文件读取、缺失符号、额外 ELF/依赖都 fail closed。

### 8. N60 Pro 固件固定约束 — **PASS WITH WARNINGS（静态配置检查通过，固件未验收）**

**已通过验证（静态）：** `config/n60pro-1001.config:6–10、66–91、109–120` 设置 Mediatek/Filogic、Conninfra APSOC MT7986、EMI/auto-up、MT Wi-Fi、MAP R2/R3、AP mode、WARP chipset 与 MT7986 profile，不指定 target device 或 mtkuboot variant；Full workflow `main.yml:86–107、324–404` 根据 `netcore_n60-pro` 选目标、添加设备、跑 defconfig 并拒绝 mtkuboot；Quick action 可见第 314–387 行再次检查目标、驱动版本及相关 Kconfig。N60 WTS/以太网/双频配置亦有静态检查（Quick action 第 55–84、843–889 行）。

**待验证：** `config/n60pro-1001.config:55` 选择 libopenssl-devcrypto；Quick action 的临时配置只在 Quick 中禁用该可选包（action.yml 可见第 319–350 行）。Full 仍使用标准 config，OpenSSL package 的 devcrypto 运行时依赖 `kmod-cryptodev`（`package/libs/openssl/Makefile:186–200`），而当前 Run #700 未到最终 defconfig/package/firmware 产物验证。不能从 Quick 的临时设置推断 Full 配置安全。

**影响：** 静态约束意图已表达，但没有实际 defconfig 完成日志和最终 ITB；板级 flash/layout、驱动固件选择与设备运行仍未验收。

**最小建议：** 修复构建阻断后保留标准配置；如果 Full 在 devcrypto 依赖或固件路径失败，应按产品约束处理，而不要把 Full 约束通过删选项掩盖。

**验证方式：** 对 Full 的 `.config`/buildinfo 逐项核对设备、MT7986 firmware、mtkuboot 排除、devcrypto/kmod dependency、模块与包清单；检查最终 ITB 目标和分区格式，并在实际 N60 Pro 设备验证无线、EasyMesh、以太网回程和升级流程。

## 问题清单（按严重程度）

| ID | 定性 | 位置 | 影响 | 最小修复建议 | 验证 |
|---|---|---|---|---|---|
| F-01 | 已证实问题 | `package/mtk/applications/easymesh-n60/Makefile:50–57`；Full #700 日志 | WTS patch 011 在前置 DPP patches 已应用的 WAPP 树上 2/16 hunk 失败；Quick/Full 均未到源码编译 | 使 patch 011 与真实前置补丁序列零 fuzz 兼容，或调整经审计的安全应用顺序；不跳过失败、不启用 fuzz | 同 SHA 完整 prepare 顺序逐 patch dry-run+apply；成功 Quick 和 Full |
| F-02 | 已证实审计缺口 | `.github/workflows/wapp-source-audit.yml:153–163`；对照 F-01 | WAPP audit #211 的 WTS 独立应用成功，却未覆盖 package 的组合补丁序列；形成 audit green/build red 的错位 | audit workflow 加入完整 Build/Prepare patch 序列 | 用相同 pin 和顺序跑 audit + Quick，二者结果一致并保留日志 |
| F-03 | 已证实发布阻断 | `.github/workflows/main.yml:35–55、427–545`；Run #700 | Full gate 失败导致 EasyMesh 编译、内核模块、APK、ITB 未执行 | 不发布此基准；先解决 F-01 | Quick、Full 都在目标 SHA 成功，所有产物检查通过 |
| W-01 | 待验证/工具限制 | `.github/actions/easymesh-quick/action.yml`（当前读取输出止于约 1000 行） | action 尾部/末尾逻辑未独立审查，无法验证全部错误处理和上传/收尾步骤 | 获取无截断完整文件后补审 | 分段读取至 EOF，逐段检查条件、错误传播、产物与 workflow 调用关系 |
| W-02 | 待验证/供应商源码缺失 | `package/mtk/applications/datconf/Makefile:10–14`；`package/mtk/drivers/conninfra/Makefile:11–16`；`package/mtk/drivers/warp/Makefile:9–15` | 本次无归档字节内容；不能声称源码审计完成 | 下载并记录对应 pin，检查真实补丁应用和源码/API | 当前 SHA 的实际 source audit 日志与可复核产物 |
| W-03 | 待验证 | EasyMesh `Makefile:94–150`；`main.yml:546–619、627–662` | 真实 target 编译/链接/依赖 APK/内核模块/ITB 均无基准成功日志 | 保持全产物检查，不以静态 grep 替代 | 真实 target build、readelf dependency closure、APK/ITB 检查和设备验收 |
| W-04 | 待验证 | `patches/010-dpp-wdev-config-allocation-rollback.patch:74–106` | 不能仅凭当前静态断言证明 DPP 错误回滚后对象所有权和后续生命周期安全 | 审查完整 caller/context，加入 allocation-failure 测试 | DPP 宏配置构建、错误注入、泄漏/双重释放和设备功能测试 |
| W-05 | 待验证 | `config/n60pro-1001.config:55`；`package/libs/openssl/Makefile:186–200` | Full 标准配置的 devcrypto/kmod 依赖和最终产物未通过本次 build 验证 | 保持 Full 标准配置，分析真实失败原因，不用 Quick 临时配置推断 | resolved Full `.config`、package dependency 检查及 ITB 内容检查 |

## 总结判定

- **已通过验证：** 指定基准 SHA 等于目标 branch HEAD；WAPP Source Audit #211 在该 SHA 实际成功；若干静态配置和依赖门禁在源码中存在。
- **已证实问题：** Full #700 在该 SHA 的 EasyMesh Prepare 中，patch 011 两个 WAPP hunk 失败；因此此基准没有到达 Quick 编译/链接或 Full 固件步骤。审计 workflow 的单 patch 应用和真实构建序列覆盖不一致。
- **高可信度推断：** 只修 audit workflow 或仅通过单独 WTS patch audit 不会修复 package Prepare 的失败；需以完整补丁顺序验证。
- **待验证问题：** 供应商源码逐文件审核、OpenSSL 3 实际 API/ABI 构建、DPP 真实目标构建与错误路径、驱动/module modpost、依赖闭环、最终 APK/ITB 及 N60 Pro 设备运行。

**总体结论：FAIL。** 这是基于一个当前基准 SHA 的直接构建失败，不是对所有历史版本的泛化结论。只有在修复后新的目标 SHA 完成完整 Quick + Full，并具备对应日志和产物证据，才能重新评估发布状态。
