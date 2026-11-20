# Quick Action 失败模式与前置检测规范

- 文档类型：独立质量门禁规范（不属于 EasyMesh 源码补丁）
- 建立日期：2026-11-08
- 适用分支：`n60pro-mtk-closed-driver`
- 建立时分支 HEAD：`9fc7cf1499304bb3e4fce648ac27ed0cd3d1710a`
- 参考失败样本：Actions runs `42438995442`、`42442715503`、`42450445807`
- 参考成功样本：Actions run `42432421578`
- 目的：把最近 Quick 失败转化为可重复、可在编译前执行的检测；本文件本身不修改任何供应商源码、补丁、八个设计产物或 SHA256 凭证。

> 本清单记录的是已取得日志支持的失败模式及其检测要求，不把未检查的项目标记为已通过。新增失败必须补充样本、根因分类和对应检测，不得只增加临时断言。

## 1. 不可突破的治理规则

1. **供应商源码与审计工具分开定责。** 任何失败先确定失败发生在源码准备、补丁应用、源码语义、审计脚本、构建环境还是产物/凭证传递层。
2. **审计工具误判不得驱动源码修改。** 若错误来自 grep/正则、shell quoting、路径假设、日志匹配、artifact attempt 语义或断言自身，先修审计逻辑并用正反样本验证；不得修改正确的供应商补丁来迎合错误断言。
3. **固定供应商源码全集不得抽样跳过。** 至少覆盖 MT Wi-Fi、conninfra、WARP、datconf、MAPFILTER，以及既定审计清单中的其他固定供应商源码/补丁/预编译对象和依赖。以锁定清单和 SHA256 inventory 为全集依据。
4. **八个原始设计产物及其全部 SHA256 凭证只读保全。** 不覆盖、不重命名、不重新生成、不删除；新增审计报告另存独立路径。验收前后对照原始文件清单、字节数和 SHA256，要求完全一致。
5. **Quick 编译/链接是最后阶段。** 固定源码全集审计、完整补丁栈重放、Quick Prepare、路径/函数/依赖/工具链/产物凭证检查全部通过前，不得进入实际 EasyMesh 编译和链接。
6. **失败即停止下游。** 不允许以 `continue-on-error`、空文件、`|| true`、弱化 grep 或跳过步骤把失败伪装为通过。可容忍的非致命告警必须有明确 allowlist 和理由。
7. **证据可复核。** 每个 PASS/FAIL 都记录 commit SHA、run ID/attempt、源归档 SHA256、补丁 SHA256、实际路径、命令、退出码及相关日志片段。

## 2. 最近失败样本与归类

| Run / Job | 日志可确认的现象 | 归类 | 应前置检测 |
|---|---|---|---|
| `42450445807`，attempt 1，Quick build job `128639192352` | OpenSSL 版本头文件实际输出 `OPENSSL_VERSION_MAJOR 3`，但检查命令的 ERE 含未闭合括号，grep 报 `Unmatched ( or \\( `，随后错误报告 OpenSSL 主版本不满足 | **审计工具正则错误 / 假阴性**，不是 OpenSSL 源码不兼容 | 对所有正则执行语法自检；对 OpenSSL 3、OpenSSL 1.x、缺失宏三种 fixture 做正反测试；优先用 awk/Python 解析宏定义，避免脆弱正则 |
| `42450445807`，attempt 2，compatibility job `128650953141` | 下载的 vendor attestation 属于另一个 run attempt，验证器报 `attestation belongs to another run attempt`；本次 rerun 复用了成功上游 job 的 artifact | **CI attempt/artifact 生命周期设计问题**，不是源码/补丁问题 | 验证器显式区分 run ID、run attempt、producer attempt；rerun failed jobs 时必须重新生成上游 attestation，或按受控规则校验同一 run 的 producer attempt；禁止把不同 attempt 的证据误当源码失败 |
| `42442715503`，compatibility job `128616073789` | 大量依赖/源码路径检查命令已执行；日志末尾对预期路径 `.../mt_wifi/embedded/common/rt_os_util.c` 的 grep 报 No such file or directory | **MT Wi-Fi 源码定位/断言脆弱**；路径断言没有以实际准备结果为依据 | 先从 Package Prepare 输出、源码 inventory 和 find 结果解析实际源码根；验证唯一命中、文件集合和 SHA256；再检查目标文件/函数；不允许把猜测路径当固定事实 |
| `42438995442`，compatibility job `128606402235` | 同类 MT Wi-Fi 目标路径检查失败；日志伴随上游下载 403/404，不能仅凭最终 grep 失败断定补丁未应用 | **源码获取/准备与路径定位混合诊断** | 将下载状态、归档校验、解包目录、prepare log、patch apply 记录和最终文件存在性分层；HTTP 403/404 必须单独分类，不可被后续 grep 覆盖根因 |
| `42442715503` | 该轮提交说明修正 P1905 linker audit regex escaping；相关 Quick job 仍失败于其他路径检查 | **审计脚本 shell/正则转义风险** | shellcheck + 正则 fixture；在真实日志和合成日志上测试成功/失败匹配；禁止只用静态字符串断言证明正则正确 |
| `42438995442` | 该轮提交说明修正 DPP parser boundary check；后续失败日志显示仍有其他路径/环境问题 | **源语义测试与执行环境诊断必须分离** | DPP 边界检查应直接读取真实源码并验证长度、边界、NULL、分配/释放路径；断言错误需用最小源码 fixture 证明，不得仅靠 grep 文本命中 |
| `42432421578`（成功参考） | Conninfra audit heredoc shell syntax 修复后该次标准固件 Action 成功 | **shell/heredoc 语法前置检测样本** | 所有 shell 脚本先执行 bash -n/sh -n；嵌入式 heredoc 单独抽取/语法检查；静态检查脚本本身也要接受测试 |

### 样本解读边界

- Run `42450445807` 的固定供应商补丁审计 job 和 Quick precompile Package Prepare job成功；attempt 1 的编译门禁暴露了 OpenSSL grep 正则问题；attempt 2 的失败发生在 attestation attempt 校验。两者均不能被归因为供应商补丁缺陷。
- Run `42442715503` 与 `42438995442` 的供应商补丁审计及 Quick precompile job成功，但 compatibility job在 MT Wi-Fi 源码定位断言处失败。应优先修正定位证据链，而不是改动已通过补丁。
- 下载日志中出现的 403/404 是独立的网络/上游资源获取信号。只有在确认对应资源确实缺失、URL/版本/权限无误后，才能将其升级为源码缺陷。
- Node.js 20 deprecation warning 在日志中属于告警，不应与导致 job 失败的错误混为一谈；工作流仍须维持用户要求的 Node.js 24。

## 3. 前置检测矩阵

### A. 运行身份、输入锁定和八个产物保全

- [ ] 记录目标分支、HEAD SHA、workflow SHA、run ID 和 run attempt。
- [ ] 确认 Quick build 消费的 commit 与 vendor audit、Quick Prepare 证据中的 commit 完全一致。
- [ ] 校验 vendor source archives、patch lock、patch inventory、依赖 CSV 和所有原始 SHA256 manifest。
- [ ] 对八个原始设计产物建立只读清单：相对路径、大小、SHA256；与基线逐字节比较。
- [ ] 新生成文件只能写入独立 audit output 目录；禁止覆盖八个原始产物或原 SHA256 凭证。
- [ ] 检查 artifact 的 run ID、producer run attempt、consumer run attempt、commit SHA、manifest digest；不匹配即停止并报告为证据链错误。
- [ ] 对 rerun failed jobs 制定显式规则：若复用上游成功 job 的 artifact，验证逻辑必须正确识别 producer attempt；若要求 attempt 严格一致，则 rerun 必须连同证据生产 job 一起重跑。

### B. 固定供应商源码全集审计（必须先完成）

- [ ] 使用 lock/inventory 枚举完整固定供应商源码集合，不依赖人工记忆或目录抽样。
- [ ] 覆盖 MT Wi-Fi、conninfra、WARP、datconf、MAPFILTER，以及已锁定的其他组件。
- [ ] 对每个归档记录来源、版本、文件数、解包根目录和 SHA256；归档/解包后 inventory 必须可追溯。
- [ ] 对所有补丁记录序号、路径、依赖、SHA256、目标文件和应用阶段。
- [ ] 对预编译库/对象记录架构、ABI、编译器信息、undefined symbols、依赖 SONAME 和 SHA256；无法取得源码的项目明确标注静态审计边界。
- [ ] MT Wi-Fi 源码根目录从实际 Package Prepare 输出和 inventory 发现；不硬编码未经证实的目录层级。
- [ ] 检查源码定位唯一性：目标文件应唯一命中；零命中或多命中都失败，并输出全部候选路径。
- [ ] 检查关键函数、结构体、宏和 API 必须在真实目标文件中存在；输出命中路径、行号和上下文。
- [ ] 供应商组件全集报告完整后才允许进入补丁栈重放。

### C. 完整补丁栈重放

- [ ] 在与真实构建相同的源码版本/目录布局中按真实顺序完整重放，不使用拼接或手工构造的近似源码代替。
- [ ] 每个补丁先做格式/语法检查，再做 dry-run，再实际应用。
- [ ] 严格模式：fuzz=0；不得出现 offset、fuzz、reject、skip、already-applied、partial apply。
- [ ] 每个 Hunk 记录 old context、实际源上下文、应用前后差异和补丁 SHA256。
- [ ] 应用失败时保留失败前源文件、补丁、reject/orig 文件和 SHA256；不自动跳过。
- [ ] 同一补丁不得通过重复应用、反向应用或弱化上下文检查来“修复”报告。
- [ ] 检查补丁重叠文件链及最终结构；特别是同一文件跨多个补丁被修改时，必须按真实应用顺序验证。
- [ ] 对所有供应商补丁应用结果形成单一 manifest，并与锁定清单一一对应。

### D. 审计工具自身质量门禁（防止误判）

- [ ] 所有 Bash 脚本执行 `bash -n`；POSIX sh 脚本执行 `sh -n`；Python 脚本执行 `python3 -m py_compile`。
- [ ] 所有 grep/ERE/PCRE 表达式做语法自检，并用正/负 fixture 测试；禁止未闭合括号、错误字符类和 shell 双重转义。
- [ ] 对路径断言测试：真实路径、路径变化、零命中、多命中、空目录、符号链接和 CRLF。
- [ ] 对日志断言测试：预期 PASS、预期 FAIL、空日志、错误信息跨行、命令输出被 tee/重定向等情况。
- [ ] 对 heredoc、变量展开、引号、管道和 `set -euo pipefail` 的组合进行语法及最小执行测试。
- [ ] 不用 `grep -q` 的单一文本命中证明函数替换成功；需检查函数定义/调用关系或编译器预处理结果。
- [ ] 不用 `|| true` 隐藏必要检查失败；仅允许对明确可选诊断使用，并记录原因。
- [ ] 每个审计断言必须说明它证明的事实、数据来源、预期输入/输出及失败分类。
- [ ] 审计断言失败时，先用独立命令/fixture复现；若工具无法区分真实缺陷与路径/格式变化，断言本身不得作为源码缺陷证据。

### E. Quick Prepare 和真实构建输入检查

- [ ] 使用固定源码归档和锁定补丁完成原生 Package Prepare；不得提前调用编译目标。
- [ ] 确认实际源码路径、文件 inventory、patch log、函数替换结果三项证据一致。
- [ ] MT Wi-Fi 026 等关键补丁：分别核验真实源码路径、补丁应用记录、函数替换结果；三项缺一不可。
- [ ] 检查 Linux 6.12.112、ImmortalWrt 25.12、OpenSSL 3.x 的版本事实来自实际构建输入，而非只看配置字符串。
- [ ] 检查 OpenSSL 版本宏解析：正确接受 `OPENSSL_VERSION_MAJOR 3`；拒绝 1/2、缺失、重复或格式歧义；测试解析器本身。
- [ ] 检查目标架构、交叉编译器、CC/AR/RANLIB/LDO、CFLAGS/LDFLAGS、递归 make 参数传递。
- [ ] 检查 WAPP、P1905、MAPD、libmapd、datconf、libnl-tiny、libbridge 等依赖闭包、头文件、库文件和链接接口。
- [ ] 检查 6 GHz 配置未被意外纳入；AL MAC/BSS MAC 仍动态获取；WAPP/P1905/MAPD 启动顺序符合既定约束。
- [ ] 检查 DPP 参数长度、边界、NULL、EVP_PKEY opaque API、分配/释放和错误回滚的源码语义。
- [ ] 检查编译日志检查器的正则和退出码逻辑；不能把“日志无 error 字符串”当作编译成功的唯一依据。
- [ ] 检查所有 build input、生成源文件和配置均可追溯到锁定输入。

### F. 编译/链接阶段（仅在 A–E 全通过后）

- [ ] Quick Prepare 所有 job 成功且证据 commit/attempt/manifest 匹配。
- [ ] 固定供应商源码全集审计成功，所有必需组件均有结果，不存在 skipped/unknown。
- [ ] 完整补丁栈零 fuzz、零 offset、零 reject、零 partial apply。
- [ ] 审计工具自检通过，最近已知误判的回归 fixture 全通过。
- [ ] 八个原始产物及 SHA256 凭证前后完全一致。
- [ ] 先按依赖顺序执行 EasyMesh 实际编译和链接；记录每个目标的完整命令、日志和产物 SHA256。
- [ ] 编译/链接失败只归类到具体目标、文件、符号或工具链问题；不得回头修改无关补丁。
- [ ] Quick 通过后才进入 Full 固件集成；Full 另行验证内核模块、modpost、固件打包和运行时行为。

## 4. 失败分类与处置规则

| 分类 | 典型证据 | 首要处置 | 禁止动作 |
|---|---|---|---|
| SRC：供应商源码缺陷 | 真实文件/函数存在，独立语义检查确认缺陷 | 定位最小源码范围，形成有依据的补丁 | 修改无关组件或扩大补丁范围 |
| PATCH：补丁缺陷 | 对锁定原始源码严格重放时 Hunk 失败/语义错误 | 逐 Hunk 对照真实上下文，批量修订后重放全栈 | 逐次追加临时补丁、容忍 fuzz/offset |
| AUDIT：审计工具误判 | 独立检查证明源码正确，断言/正则/路径解析错误 | 修正检测器并增加回归 fixture | 为通过错误断言而改供应商源码 |
| ENV：构建环境问题 | 工具链、下载、权限、缓存、网络或宿主环境证据 | 修复环境/资源获取，重新执行对应前置检查 | 把 403/404、缺工具或缓存异常判为源码缺陷 |
| EVIDENCE：凭证/attempt 问题 | run/attempt/commit/hash 不一致 | 重新生成或正确关联证据，核对来源 | 关闭校验、接受来源不明的 artifact |
| BUILD：真实编译/链接问题 | 前置门禁均通过，编译器/链接器明确报错 | 定位目标、符号、头文件、ABI、工具链 | 在未定位根因时修改补丁栈 |

### 冲突处理优先级

1. 原始供应商源码/归档及其 SHA256。
2. 锁定补丁及其 SHA256、依赖顺序。
3. 实际 patch/prepare 日志和前后源码快照。
4. 独立语义检查、编译器预处理/符号证据。
5. 审计脚本的文本断言和日志匹配。

低优先级断言与高优先级证据冲突时，先隔离断言并调查；不得直接判定供应商源码有错。

## 5. Quick 编译启动许可（Release Gate）

只有下列项目全部为 PASS，才允许启动 EasyMesh 实际编译/链接：

- [ ] 固定供应商源码全集覆盖率 100%，MT Wi-Fi、conninfra、WARP、datconf、MAPFILTER 均有可复核报告。
- [ ] 全部归档、补丁、依赖清单和 SHA256 锁定一致。
- [ ] 完整补丁栈重放：零 fuzz、零 offset、零 reject、零 partial apply。
- [ ] 真实源码路径、关键函数替换和补丁应用记录相互印证。
- [ ] 审计工具语法、正则、路径、日志和 artifact attempt 回归测试通过。
- [ ] Quick Prepare 原生执行成功，无编译目标被提前调用。
- [ ] 目标 OpenSSL 版本、Linux 版本、工具链、依赖闭包和配置检查通过。
- [ ] 八个原始设计产物及全部 SHA256 凭证前后完全一致。
- [ ] 所有报告均绑定当前 commit SHA 和正确的 run/attempt 证据。
- [ ] 不存在 skipped、unknown、未解释告警或未关闭失败项。

任何一项为 FAIL/UNKNOWN：**禁止进入编译/链接**。修复后从受影响的最早关卡重新验证；若源码、补丁或锁定清单变化，必须重跑完整供应商源码全集审计及完整补丁栈重放。

## 6. 每轮 Action 必须归档的报告

建议每次 Quick 生成独立目录（不覆盖原始八个设计产物）：

- `run-metadata.json`：branch、commit、run ID、attempt、workflow SHA。
- `source-inventory.json`：供应商源码/预编译对象完整 inventory 与 SHA256。
- `patch-stack-replay.json`：顺序、依赖、每个 Hunk 结果、fuzz/offset/reject 计数。
- `source-location-and-symbols.json`：实际路径、唯一性、关键函数/符号及行号。
- `audit-tool-selftest.json`：shell/python/regex/path/log fixtures 结果。
- `quick-prepare.json`：原生 Prepare 结果、依赖、工具链和配置。
- `design-artifacts-preservation.json`：八个原始产物逐项前后 SHA256 对照。
- `failure-classification.json`：失败类别、证据、责任层、修复措施和回归用例。
- `release-gate.json`：逐项 PASS/FAIL/UNKNOWN；只有全部 PASS 才能授权后续编译 job。

## 7. 当前状态声明

本规范已把上述已检查的最近失败样本映射到前置检测要求。**规范文件建立不等于检测器已经实现，也不等于当前分支已通过本规范。** 在把本规范接入 Action 前，应先对现有审计脚本和工作流做差异审查，再单独实现/测试缺失的检测；不得在本次文档提交中顺带改动供应商补丁或触发 Quick 编译。

当前确认事实：
- Run `42450445807` 的 vendor patch audit 与 Quick Prepare job 成功；compatibility job在 attempt 1/2分别暴露正则误判和 attestation attempt 关联问题。
- Run `42442715503`、`42438995442` 的 vendor patch audit 与 Quick Prepare job成功；compatibility job失败在 MT Wi-Fi 路径定位检查。
- Run `42432421578` 是相关 shell/heredoc 修订后的成功参考，但不能替代本规范的全项验收。
