# 跨组件自然文本案例 v73：有界内容复核

## 范围与结论

只读已结束的 `D:\VulnGym-bv2-runtime\t2-representative-20260913\03-chain-v73` 中 summary/review/actions，并与 `03-chain-v72` 的同输入 `GHSA-X2MW-7J39-93XQ` 比较。证据均为运行实际保存的公共 receipts，不新增目标源码、网络、模型调用或目标执行；不修改原 JSONL、代码或其它文档。此复核不是人工认可、盲测或准确率统计。

父任务确认会话 62303 退出 0。summary：`completed`，1 输入、0 完整、1 草稿，10 次 HTTP、21 次工具、184.965 秒，终态格式/模型/字段/工具/pipeline 异常均为 0；本轮没有读取计划或编码拒收，`verify=0`。v72 与 v73 的 E0002 自然公告正文逐字相同，没有换材料。

**v73 虽仍为草稿，但 Git 消费者已从“仅搜索”变成真实源码阅读，属于实质进步。** 尚未闭合的是特定写入资源到后续 Git 配置/命令行为的联系，以及必要 helper、条件和版本依据，不能把草稿当成公告不成立，也不能因读到了 Git 就确认整条命令执行链。

| 对比项 | v72 | v73 |
| --- | --- | --- |
| 模型 / 工具 | 9 / 19 | 10 / 21 |
| 成功 source read | 4 次，3 个不同文件；均为 ReadWriteFile 侧 | 6 次，4 个不同文件；增加 Git.node.ts 两个窗口 |
| 实际模型 followup | 0 次，因 review context 跳过 | 2 次成功读取；第 3 次因 review context 跳过 |
| 最终状态 | commit/EP/CO 空，trace 空 | 同样留空；不确定理由已包含实际 Git 条件证据 |

以下编号均指 v73 本输入，除非明确注明 v72。

## 1. 实际生产方与消费者证据

- E0013 `ReadWriteFile.node.ts:1–74` 完整覆盖节点定义和 execute：59–70 读取 operation，在 `operation === 'write'` 时调用 `write.execute.call(this, items)`。这不是未找到任何注册入口/分派。
- E0017 `actions/write.operation.ts:1–135`：67–74 按 item 读取 `fileName`/options，选择 append 或 write/create/truncate flag；86–93 从 binary stream 或编码数据形成 `fileContent`；96–100 调用 `writeContentToFile(await resolvePath(fileName), fileContent, flag)`。写入调用和来源处理实际已读，但这两个 framework helper 的实现仍没有 receipt。
- E0018 `helpers/utils.ts:1–55` 只是本节点的 errorMapper/selector utilities，**不是** `this.helpers.resolvePath` 或 `writeContentToFile` 的实现，不能用“helper 文件已读”补掉不同符号的缺口。
- E0023 `Git/Git.node.ts:300–400`：先 resolve/check repository path，再设 `baseDir: resolvedRepositoryPath`、`config: gitConfig` 创建 simpleGit；包含 add、addConfig 和 clone 调用。
- E0024 请求 400–560，实际保存到 **559**，`truncated=true`、`has_more=true`，全文件 731 行；包含 commit、fetch、log、pull、push 等分支，及 517–527 的 `listConfig()`、读取 `remote.origin.url`、prepareRepository 和 push。不能声称已读完 Git 文件或 560 行。

E0023/E0024 是 v72 没有的真实消费者内容。它们支持“Git 以某 repository baseDir 和配置工作，并可能读取 repository 配置值”的局部事实；没有保存源码建立生产方 `resolvePath(fileName)` 与该 `resolvedRepositoryPath` 下特定配置文件的身份关系、写入成功及执行先后，也没有所需 helper/第三方实现来证明该配置值触发公告所述 shell 命令。

E0002 仅说 specific configuration files 与后续 Git 操作，并未给出具体文件名。最终 trace 理由中的“same .git state”应作为待核实的共享资源假设，不能说是公告或源码已明确标定。这里可能通过共享文件和有序工作流连接，**不要求虚构 Write handler 直接调用 Git handler 的函数栈**。

## 2. 读取调度确有改善，原低收益步骤仍存在

4 次探索模型调用后，保存 `read_context_closed=reserve_annotation_review_context`；第 5/6 次为 draft assessment/annotation。自动 E0020/E0021 仍先在另一已 inspect SHA `3cdfff7e6cbbc82111dda0303b7a7a1d8b111c28` 搜索并读 write 文件 1–93；自动 E0022 再做全仓 `execute` 搜索，截断且 `entry_navigation.stop_reason=no_usable_reference_hit`。

随后第 7 次模型调用实际读 E0023，第 8 次读 E0024。上下文压缩记录依次为 73,531 和 80,011 字符；紧接着明确记录 `evidence_followup_skipped=reserve_review_context`，第 9/10 次完成自审。因此本例是 **2 次实际依赖补读，第 3 次受最终自审上下文保留限制**；不是三次全部执行，也不是工具/模型失败导致停止。

消费者最终读到了，但不能说已把它完全前移到另一快照的重复 write 窗口及泛 execute 查询之前。这两个低收益步骤仍消耗上下文，后续调度应分开评价“允许追加补读”和“先读最相关缺口”。

## 3. 保留不确定合理，guard 表述需要收紧

草稿没有把文件写入本身当作已证命令执行，这是合理保留；版本范围未映射、两个关键 write helper 未读、资源身份和配置执行关系未闭合，也都有真实缺口。最终 commit reason 正确认出 4 个 inspect 记录，不再重复 v72 “只检查过一个 SHA”的错误。

但以下条件不能省略：

1. E0023:329–332 仅在 `!securityConfig.enableGitNodeHooks` 时追加 `core.hooksPath=/dev/null`。commit reason 保留了 when hooks are disabled，最终 trace 理由却缩写成“Git node ... disables hooks”；默认值、部署值未读，不能变成所有运行都禁用 hooks。
2. E0023:372–377 只在 `!enableGitNodeAllConfigKeys && !ALLOWED_CONFIG_KEYS.includes(key)` 时拒绝 addConfig；不能无条件称所有 key 均受 allowlist。该节点操作的 key 检查也不等于对另一个文件写入节点修改磁盘配置的全面防护。
3. E0023:300–307 的路径拒绝依赖 `isFilePathBlocked` 返回值，helper 未读；325–327 的 bare-repository 配置只在 `isCloud || disableBareRepos` 时加入。这些是实际限制线索，不是所有共享文件链都不可达的结论。
4. E0005–E0008 的 changed paths 均完整且未涉及 Git/ReadWriteFile，故“这些提交没有修改两节点”有依据；但差异未修改节点不等于整个 snapshot 没有对应缺陷。没有修复 diff、正式版本文件或发布映射，不能从 ref/提交主题猜公告的 2.2.0 / 1.123.8 修复归属。

EP 的自审理由承认 E0013 已有 execute 分派、E0017 已有参数读取，只把边界选择及工作流作者来源保留为不确定。不要再缩写成“入口完全未读”；值在 operation callee 读取这一点本身也不推翻已读调用关系。最终留空不妨碍报告这个有限入口证据，但不能借此补齐未闭合的整条缺陷链。

最终各显式行引用均落在对应 receipt 可见范围；没有发现 v73 此例的越界编号。分类 reason 的 `source-based` 实际只引用 E0002 公告，应在交验中称公告归因/描述，不是源码已证明命令执行。

## 4. 最小剩余项

后续只围绕已定位的缺口核对：写入/路径 helper 的实际作用、Git 路径与具体配置资源身份、已读 guard 的条件及部署/版本依据。保留新获得的消费者证据，不重跑整个探索来抹去本次成功，也不以完整数为目标强行补字段。v72/v73 原始结果及验证标志全部不变。
