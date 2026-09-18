# 原两例 v73 真实回归：有界内容复核

## 范围、终态与结论

只读已结束的 `D:\VulnGym-bv2-runtime\t2-representative-20260913\regression-v73-04` 中 `summary.json`、`review.jsonl`、`actions.jsonl`，并与 `regression-v72-03` 保存的同两条记录比较。没有新增模型请求、网络访问、目标执行或目标仓源码补查；不修改原 JSONL、生产代码或其它文档。另只读 T2 调度代码解释分支条件，不将此诊断当成模型读过的目标证据。下文证据编号均以所指运行和单条输入为命名空间。

父任务确认会话 66342 退出 0；summary 为 `completed`：2 输入、1 完整候选、1 草稿、22 次 HTTP、35 次工具、148.865 秒，终态格式/模型/字段异常为 0。过程中 Airflow 有一次 `read_plan_rejected` 后格式恢复，已计入 22 次请求；LangChain 的 `git_output_limit`、`commit_unavailable` 共 2 次工具错误，与 2 次 pipeline 错误同源，不重复相加。全部 `verify=0`，不是人工认可或独立准确率。

**结果不能表述为两例内容通过。** LangChain 首次源码导航回退；Airflow 真实补齐了日志消费者，但漏掉上游 `_build_metrics` 后仍把局部写日志提升成了已证缺陷，完整导出不构成该语义主张的验收。

| 输入 | v72 保存结果 | v73 保存结果 | 内容变化 |
| --- | --- | --- | --- |
| LangChain / GHSA-45PG-36P6-83V9 | 11 模型、17 工具；5 次 source read、1 次成功按文件 diff；草稿 | 11 模型、22 工具；0 source read、0 成功按文件 diff；草稿 | 从实际前后比较退回到单快照重复导航 |
| Airflow / GHSA-8R55-RV5W-6PFM | 9 模型、16 工具；6 次 source read；草稿 | 11 模型、13 工具；3 次 source read；完整候选 | 消费者及注册已读；原上游条件未再读，不能按条数认定整体更准确 |

## 1. LangChain：为何首次快照补读未触发

v73 E0005 成功 inspect 公告链接 SHA `c2a3021bb0c5f54649d380b42a0684ca5778c255`（下称 c2），记录父 SHA `d9813bdbbc1264ecb843b0a15284d708b3bae264`；E0006 整份 diff 超限；E0007 的另一公告 SHA 不可用。E0008 又成功 inspect 唯一 ref 的 `b7d1831f9d3560ed4fb45134861eef3f4544eff3`（下称 b7）。此后所有 search/list/history 都在 b7，没有对 c2 或父版本执行 search/read。

实际查询没有满足已有 early probe 条件：

- E0010 裸 `GraphCypherQAChain`：`complete=true`，12 命中，不是空声明查询。
- E0011 裸 `allow_dangerous_requests`：1 个其它 API chain 命中，不是目标声明。
- E0014 裸 `cypher_query_corrector`：`complete=true`、0 命中，但不是 `class/def/function/func + 名称`。
- E0017 `GraphCypherQAChain` 限 `libs/community`，E0020 `cypher` 限其 chains 目录：均 0 命中、`complete=false`，不能作为完整空查询。
- E0024 裸 `cypher`：52 命中；唯一 followup E0025 在 classic shim 文件搜索裸 `GraphCypherQAChain`，3 命中。没有一次实际声明查询。

只读代码定位：`vulngym_t2/revision_navigation.py:15`、`:148`、`:173` 要求原样完整空声明查询，并选择已经成功 inspect、尚无 search/read 尝试的另一 SHA；`pipeline.py:1642` 再检查一次性、工具/模型/上下文余量。现有 c2 满足候选身份条件，但**无合格查询 seed** 已足以解释本轮没有 `initial_snapshot_search/source`；不能归因于旧源码已被证明不存在，也没有证据指向 provider 中止。

v72 的 E0014–E0020 曾成功进入 c2、按文件比较 c2 与父版本、读取父版本 168–197 和 c2 的 `_call`/query 主体。v73 没有读取这些材料；本复核不把 v72 receipts 回填给 v73。由于零 source read，`focused_diff_seed` 所需的已引用真实源码路径也不存在（`revision_navigation.py:25`），原整份 diff 失败后未形成按文件恢复，旧运行主体更未验证。

### 1.1 三次补读上限为什么只执行一次

动作序列为 6 次 `plan_and_read` → 第 7/8 次 draft assessment/annotation → 第 9 次 followup（E0025 search）→ 第 10/11 次自审。保存动作含 `read_context_closed=reserve_annotation_review_context`；没有 `evidence_followup_skipped/stopped`，不能编造一个显式停止日志。

父任务确认每输入 `max_calls=12`、`max_tool_calls=64`。按 `pipeline.py:1480,1504–1513` 重建门槛：assessed 单输入保留 1 次最终编码纠正及 2 次自审，每次新 followup 共需至少 4 次余量；第 9 次后仅余 3 次，因此不再进入第二次决策。**三次是上限，不是保证三次执行。** 这是保存调用序列与当前代码的调度解释，不是模型明确说过的停止理由。

### 1.2 版本与引用问题

- 最终 commit/EP/CO 留空、trace 为空，符合本轮无源码机制证据的状态；未把 c2 或父 SHA 强填成受影响版本。
- commit reason 称 c2 是“1406-path pydantic-2 refactor with no graph-qa change”。E0005 只返回前 200/1406 个路径且 `truncated=true`，E0006 又失败，因此 **“no graph-qa change”不受该 receipt 支持**。提交标题也不能否定后面未展示路径的变化；v72 的成功按文件 diff 是跨运行反例，不能隐去。
- EP reason 用 E0010/E0024 支持“list_files ... empty”，但这两条都是非空 search；实际空目录在 E0009/E0013/E0016/E0023 等 list receipts。这是引用错配，不是所有目录搜索都没有发生。
- 自审文本“only present tree is b7”至多能说实际检索集中在 b7；已有 c2 inspect 不允许据此宣称只有一个可读历史快照。公告分类仍须保持公告归因。

## 2. Airflow：消费者真实补齐，但完整候选存在语义越界

选定 SHA 为 `19c1a16dc8b44ba470198c300b25defc7848576f`（下称 19c）。本轮 3 次 source read 全部来自 3 次实际 followup，先前探索阶段没有 source read：

1. 第 7 次模型调用 → E0014 `airflow-core/src/airflow/utils/cli_action_loggers.py:100–167`：`default_action_log` 接收 `full_command`，132–146 组装 `Log.extra` 并 bulk insert，147 `session.commit()`，后续异常分支 rollback，167 注册默认 pre-exec callback。
2. 第 8 次 → E0015 `airflow-core/src/airflow/utils/cli.py:55–130`：wrapper 的参数检查、`_build_metrics(f.__name__, args[0])`、pre/post execution 调用；128 起只有 `_build_metrics` 声明和 docstring 开头，没有正文。
3. 第 9 次 → E0016 logger `1–99`：40–52 的注册函数把 callback 加入列表；70–84 的 `on_pre_execution` 遍历列表调用 callback，并捕获异常。

这直接证明 v73 顺序补读依赖链的三次上限真实运行；不能说消费者仍完全未读。三个决策已用尽，第 9 次后也仅剩 2 次自审＋1 次编码保留额度，不存在已执行的第四次正文补读。

### 2.1 位置、局部链与条件

以 v73 自己保存的同 SHA source text 按行切片比较，EP、CO、3 个 trace 的代码 **5/5 逐字一致**；EP 和 CO 分别在 trace 重复，所以只有 3 个不同位置窗口。这是原保存证据一致性，不是独立源码重读或准确率。

wrapper 调 pre-exec、回调分派、默认注册与 logger 消费的局部控制关系有实际语句支持。callback 接收 kwargs，logger 对所收 `full_command` 没有再次脱敏，这个局部描述成立。持久化还受 DB/session 操作成功条件约束；已保存代码明确可能 rollback，不能写成任何调用都必然产生持久化记录。

### 2.2 未读的正文不是可以省略的前提

最终 EP reason 和 trace reason 承认 `_build_metrics` 正文、CLI argparse 边界未读；但 commit/CO/分类仍称“full CLI command unredacted / reported defective mechanism”，EP desc 还把 metrics 概括为来自 parsed CLI arguments。这把 **logger 不再脱敏** 偷换为 **送到 logger 的值包含未脱敏敏感输入**。声明缺口不能同时保留依赖该缺口的 supported 缺陷结论。

仅凭 v73 自己的 E0014–E0016，可证明接收值进入 Log 的局部操作，不能证明输入未经上游处理。_build_metrics 是 wrapper 到 full_command 内容的关键转换，应优先读清，而非依据公告跨过它。

跨运行对照进一步确认该缺口重要：v72 同一 19c 的 E0016 `cli.py:54–158` 实际显示 `full_command = list(sys.argv)`（145 行），而不是直接复制 handler 的 Namespace；v72 E0016/E0017（158–230）还保存 password 形式、conn-json 敏感键、conn-uri password 等条件 masking。**这是 v72 当时看到、v73 没看到的反证线索**，不回填为 v73 覆盖；它反驳“整条链没有脱敏”的泛化，但也不证明所有连接值均安全。要判断公告对应缺陷，仍需具体旧行为和敏感值残留路径的支持。

### 2.3 旧版本与引用边界

本轮只 inspect 19c、df4 两个现有 refs；所有 3 次源码阅读都在 19c，没有旧版本源码、发布版本文件或修复 diff。commit reason 如实写 `<2.11.1` 发布范围未映射，但 `behavior_at_revision` 本身也必须有缺陷行为支持，不能用它豁免上一节的上游处理缺口。历史查询的未穷尽/非决定性边界仍应保留，不能将“PR absent”扩大成相关历史不存在。

v73 保存的 EP/CO/trace 行引用均落在对应 receipt 可见范围；未重现 v72 的 `E0017 line 145` 越界。行号正确不能替代语义正确。最终日志部分取得真进步，旧版本目标仍未完成，当前完整候选不宜作为已独立证明的准确结果计入分子。

## 3. 冻结后的最小复核落点

- 首次导航：避免只因模型使用裸符号而停留在同一失配快照；任何泛化仍须以实际保存字面查询、已 inspect SHA 和真正唯一声明为依据，不设置项目答案或预填源码位置。
- 调度：后续读机会受探索用量和最终自审/编码余量约束；“上限 3”需与“实际几次、为何停”分别展示。
- 语义：消费者本身无处理，不等于其输入未经生产方处理；保留关键转换/guard 缺口，不将 disclaimer 当成 supported 的替代证据。
- 原 v72/v73 结果全部保留。本复核只记录事实和未解原因，不改草稿、完整候选或验证标志，也不启动额外运行。
