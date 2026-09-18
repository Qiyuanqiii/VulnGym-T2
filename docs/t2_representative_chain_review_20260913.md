# 跨组件自然文本案例 v72：有界内容复核

## 范围与终态

已结束目录：`D:\VulnGym-bv2-runtime\t2-representative-20260913\03-chain-v72`，输入 `GHSA-X2MW-7J39-93XQ`。父任务确认统一会话 14752 退出 0。

本次只读该目录 `summary.json` 和 `review.jsonl` 中的保存 actions/公共证据；没有另读目标源码、网络、模型调用或目标执行，没有修改生产代码或原输出。不是人工验收或独立准确率。没有读取未结束的 crawler 运行。

终态 `completed`，1 个输入、1 草稿、0 完整；9 次 HTTP、19 次工具、86.24 秒；最终格式/模型/工具/pipeline/当前字段协议异常数均为 0，人工确认数为 0。**内部确实有一次读取计划拒收并恢复**，包括在 9 次请求内，不能把这一运行描述成“全过程从未格式出错”。

## 1. 自然文本输入已真实接受

E0002 为 `03-chain-natural.md`，`document_kind=advisory`、`document_role=primary`：内容是 Markdown 标题、GHSA URL、公告 Impact/Patches/Workarounds 自然正文，不是固定字段 JSON。E0001 正确得到项目 n8n、repo URL、GHSA；`fix_commits=[]`、`vulnerable_commit=null`，没有输入冲突或警告。

该文本包括工作流创建/修改权限前提、先写配置文件再触发 Git 操作的组合描述，以及修复版本 2.2.0 / 1.123.8；没有 CVE，也没有修复 SHA。输出未编造 CVE。此例证明灵活输入解析可用，但**不证明信息缺失时已经自动补齐全部修复材料**。

实际融合的材料是公告正文与公共仓库 refs/history/search/source。没有额外支持公告或 patch 文档，也没有一次 diff。不能声称完成了“公告 + patch + 源码”三方对照；缺的修复关联应保持未证，不能从 refs 顺序猜修复版本。

## 2. 一次读取计划拒收：已恢复、坏值未保存

保存 actions 的精确结构为：

| 字段 | 保存值 |
| --- | --- |
| action | `read_plan_rejected` |
| code | `invalid_plan_argument_type` |
| stage（阶段字段名） | `plan_and_read` |
| path | `$[0].arguments` |
| schema_path | `$[0].arguments.prefix` |
| schema_reason | `expected_string` |

第 2 次 `plan_and_read` 请求之后拒收，第 3 次调用阶段为 `read_plan_encoding_review`，随后 `read_plan_reencoding` 的 `summary=recovered`。这是原有最多一次、整份计划重新编码，不是 HTTP 自动重试；`automatic_retries=0`、`read_plan_rejection_count=1`。

这里没有保存 `phase` 或 `child_code` 字段，也没有原始坏参数值；不能替它们造值，更不能断定当时是 null、数组、数字或某个特殊内容导致。能证明的是 prefix 参数不符合字符串要求，受控纠正成功，后面继续正常读取、自查并产出草稿。

## 3. 跨组件依赖没有被强行简化，但尚未读全

公告主张是一个组合：具有工作流编辑权限的使用者配置文件写入，再触发会使用相关配置的 Git 操作。最终模型仍将命令操作作为待核实 CO，而没有把“文件写入”直接替换为“已确认命令执行”。这一克制正确。

实际 source receipts 只有 4 次：

| 证据 | 快照 / 文件 | 实际覆盖 |
| --- | --- | --- |
| E0013 | `24af748fd3c809920afddfe58bf99c7fce6063d9` / `Files/ReadWriteFile/ReadWriteFile.node.ts` | 1–74，完整节点声明；按 operation 分派到 read/write |
| E0017 | 同 SHA / `Files/ReadWriteFile/actions/write.operation.ts` | 1–135，完整写入 handler |
| E0018 | 同 SHA / `Files/ReadWriteFile/actions/read.operation.ts` | 1–163，读取 handler |
| E0021 | `3cdfff7e6cbbc82111dda0303b7a7a1d8b111c28` / 同 write.operation 文件 | 1–93，另一快照的写入窗口 |

上述相对路径均在 `packages/nodes-base/nodes/` 下。

E0013 59–73 的 operation 分派和 E0017 62–100 的局部流程有直接代码：读取 `fileName`、选择 append/写入标记，获取 binary，调用 `resolvePath`，再交给 `writeContentToFile`。不能省略 binary 检查、路径解析及错误分支后描述成“任何路径任意写入”；相关 helpers 实现本轮没有读到。

**Git 消费者只搜索过，没有实际 source read。** E0019 在 `packages/nodes-base/nodes/Git` 搜索，已经定位到 `Git.node.ts` 的配置/创建 Git 对象/操作位置，也命中 `safe.bareRepository`、`core.hooksPath` 和配置项拒绝信息。这些是值得核对的可能限制线索；没有完整条件窗口就既不能说其防护总是生效，也不能说全部不存在。

因此最终 `commit/entry_point/critical_operation=null`、`trace=[]` 是对当前证据未闭合的保留，不是已证明公告不成立。也不能用这条草稿当作“复杂跨文件准确提取”通过样例。

## 4. 仍可避免的漏读与不准确理由

1. E0019 已提供目标 Git 文件和行号，但之后没有转为该消费者的 `read_file`，反而读取另一快照 write 窗口，又做全仓泛 `execute` 搜索（E0022，截断/上下文截断）。这不是目标文件无法定位，是原预算下读取优先级没有对准已知缺口。
2. `read_context_closed=reserve_annotation_review_context`、`evidence_followup_skipped=reserve_review_context` 均已保存；材料不全受上下文调度影响，不应表述成唯一材料源确实没有相关实现。多次短语 history 空结果也标 `negative_result_conclusive=false`。
3. 最终 commit reason 说“the only inspected SHA”是 24af...，与保存证据不符：E0005–E0008 明确成功 inspect 了 24af...、3cd...、4c6b...、6067... 四个 SHA；E0021 还实际读过 3cd 的源码。正确说法应是“主要分析的 24af 快照与该公告缺乏关联，其他检查也未建立受影响版本”，而不是只检查过一个版本。
4. 这些 inspected commit message 分别是 AI-builder callback、SSO invites、editor ready-to-run、AI-builder URL 等主题，不能凭 ref 被列出就将其认定为本公告修复。模型没有填入确定 commit 是合适的。
5. 跨组件关系**未必是 write handler 直接调用 Git 函数**。本公告描述可能通过共享文件/配置和有序工作流操作连接；后续应核对生产方创建的资源、消费者使用的资源及触发条件，而不是要求编造一个不存在的直接调用栈。最终理由中“没有 bridge”作为证据缺口成立，但不能将“没有直接函数调用”本身视为否定该类依赖的标准。

## 5. 最小下一步与结论

不扩大为源仓全面分析。最小修正是：对于公告明确的两个组件，在已取得写入分派后，优先把消费者已有搜索命中变成一个有上下文的 source 窗口；检查共享资源及条件，再判断是否需要补相关 helper/旧快照。把这个补读排到另一快照的重复写入窗口和全仓泛查询之前，仍受原请求/工具预算限制。

本轮证明自然文本入口和读取计划的受控格式恢复可用，也正确保留了组合操作前提及不确定性；但相关修复版本、消费者源码和完整依赖仍没有建立。它是**成功运行、内容未完成的代表性失败记录**，不是全部失败，也不是复杂场景已达标。原始结果保留，后续应另存修正版复测结果。
