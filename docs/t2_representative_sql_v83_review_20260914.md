# SQL v83 代表性回归内容复核

日期：2026-09-14。对象为 `D:\VulnGym-bv2-runtime\t2-representative-20260913\12-sql-v83-low`。仅读本批保存的公开 summary、review、actions、entries、drafts，并参考 [v81 QA](t2_representative_sql_v81_review_20260914.md) 对比先前问题；不从旧批补入证据，不新读或执行目标源码，不调用模型、联网或改写原结果。这是 AI 辅助复核，不是人工认可、独立盲测或漏洞有效性认证。

## 结果与过程

主线程回收正式会话退出码 0；公开 `summary.status=completed`。1 份输入、**0 完整候选、3 草稿**，输入状态 draft；**16/20 HTTP、11 个工具调用、363.853 秒**。`entries.jsonl` 为 0 字节，`drafts.jsonl` 为 3 条 15 字段空值导出，均 `verify=0`；commit、EP、CO 为空，不能充当完整数据集。

- 三槽均 `initial_draft_status=accepted`、`self_review_status=completed`，`evidence_followup_status=not_requested`；模型、流水线、工具、格式及 annotation 终态错误均为 0。
- 过程并非零异常：第一槽 draft 缺少 7 个根字段，记录 `annotation_snapshot_rejected / missing_root_fields`。call 6 的 `encoding_shape_review` 成功恢复，`annotation_encoding_reserve=consumed`、`annotation_snapshot_reencoding=recovered`。三个自审均未留下编码错误；不能把这次初稿恢复说成自审曾失败。
- `candidate_plan` 提出 4、选中 3、未选 1、去重 0、共享编码预留 1。`budget_slots` 与 `budget_slots_without_reserve` 都为 3，所以本批不能把未选 1 条归因于新增预留少选了一槽。未选提案没有逐条处理，也不是一份未处理输入。
- 本批为 `snapshot-guidance-v83`、deepseek-flash、staged_tool、assessed_tool、plan_tool、thinking enabled、low、32768 输出上限，HTTP 自动重试 0。结束快照为 2687 次生成，加历史 1 次是 **2688/3000、余 312**；这是 SQL 结束时点，不是后续批次完成后的总余额。账本授权 3000、有效生成上限 2999 保持生效。

## 操作文件有新增读取，但不是 probe 已验证

actions **没有 `candidate_source_probe` 或 `candidate_source_probe_skipped`**。此前未读的 Postgres `deleteTable.operation.ts` 确有新回执 E0014，但它出现在候选选择前的普通规划读取中，`automatic=false`，不是候选 probe。

该读取请求所选 SHA `9ce3ac092cf7339f3c4a416cdea6e5fa2d5b22b9` 下 `packages/nodes-base/nodes/Postgres/v2/actions/database/deleteTable.operation.ts` 的 1–160 行；实际仅显示 **1–68／总 162 行**，`truncated=true`、`context_truncated=true`，还没读到 execute。紧接着记录 `read_context_closed / reserve_annotation_review_context / result_allowance_chars=0`。

因此，只能确认读取已到达操作文件头部，不能宣称候选分组 probe 已在本批真实触发，或所缺操作本体已经补齐。三个槽位均未请求模型补读；尚余 HTTP 次数也不等于仍有可用上下文。

## MySQL 的错误猜测未再获支持

两个 MySQL 原始候选提案仍声称 `escapeSqlIdentifier` 不处理内部反引号，可能形成所述问题；这是提案，不是结论。最终 commit/CO 理由均改为 uncertain，指出本批 E0010:23–37 会先用 `` /(`[^`]*`|[^.`]+)/g `` 切分，再引用未引用的片段、保留已有引用并以点连接，当前提案的缺陷未被证明。

与 v81 QA 所记录的过强支持相比，本批没有再把“没有 replace”直接升级为缺陷事实，MySQL select 也不再完整导出。这里的改进是保留了不确定，不是证明这个 helper 安全，亦不是已找准公告真正修改机制。E0006 仍是截断的全局 diff，没有本批完整 MySQL 路径差异；不得借用历史批次的局部 diff 填补。

## 三条草稿的实际缺口

| 候选 | 本批已有依据 | 尚缺什么／不应如何解释 |
| --- | --- | --- |
| MySQL deleteTable，entry-67033 | E0012 已读全 1–139；90–92 读取 table，68–78 有 displayOptions；113–120 构造 DELETE 并调用 addWhereClauses。E0010 有标识符 helper。 | 提案所述缺陷未成立，MySQL helper 只读 1–200／577，相关 addWhereClauses 本体及完整修复差异未读。EP 理由首句提到 selected commit 无匹配，不能据此说入口源码没读到：该入口确实已读，但 commit 未获支持，坐标没有批准为正式字段。 |
| MySQL select，entry-00000 | E0013 已读全 1–133；82–86 读取 table/outputColumns，92–97 构造 SELECT。E0010 有同节点 helper。 | 缺陷机制未证；派发/注册实现未读，EP 保留 uncertain。局部参数读取事实仍成立，不等于操作本体完全未读。 |
| Postgres，entry-00001 | E0011 读到 helper 1–200／657，含 addWhereClauses 产生 `$N:name` 的过程；E0014 仅操作文件头部。 | execute、提案所指 Postgres escapeSqlIdentifier 与 prepareQueryAndReplacements/prepareQueryLegacy 实现均未在保存源码窗口中出现。没有移植 MySQL/MSSQL 的实现或位置来补齐，保留未知有依据。 |

三个草稿最终均因 commit、EP、CO 未获支持而保留，不是遗留格式故障或工具读取报错。可选 trace 全为空合法；它既不制造额外失败，也不能弥补必要字段的缺口。分类保留公告归因，不等于这些机制已由源码独立确认。

## 结论

本批证实共享编码预留被实际消费并成功恢复，三个自审完成；同时避免了把先前 MySQL 猜测继续标为完整候选。但候选 probe 尚无真实触发证据，Postgres 操作读取仍停在头部，关键替换与修复差异仍缺。下一步应针对已知必要实现的读取覆盖及语义依据，而不是追求把 0 完整改成更好看的数字；本复核不启动追加请求，也不改动任何原始产物。
