# 原两例 v72 真实回归的有界内容复核

## 范围与终态

只读已结束运行 `D:\VulnGym-bv2-runtime\t2-representative-20260913\regression-v72-03` 的 `summary.json`、`review.jsonl` 中保存的 actions/公共 receipts，并与 `regression-v71-02` 的同两条记录比较。没有新增模型请求、网络访问、目标执行或源仓扫描；未修改原结果或生产代码。本次未另行读取目标仓源码，以下均为模型运行实际保存的证据。不是盲测、人工认可或准确率统计。

父任务已确认统一会话 68483 退出 0。保存终态为 `completed`，2 个输入均处理，0 完整、2 草稿；20 次 HTTP、33 次工具、320.651 秒；格式失败数、模型错误数、当前字段协议异常数均为 0。两个读取错误均属于 LangChain：原整份 diff 的 `git_output_limit`、另一个指定提交的 `commit_unavailable`；`pipeline_error_count=2` 与 `tool_error_count=2` 是同源计数，不合计成 4 个独立失败。没有 HTTP 自动重试。

LangChain actions 另记录一次 CO 缺 `source_id` 的字段拒收，随后 `annotation_field_recovered`；最终字段协议异常为 0。不能把“最终没有格式失败”写成过程中完全没有内部纠正。

## 1. 相比 v71 的真实变化

| 项目 | v71 | v72 | 可以得出的结论 |
| --- | --- | --- | --- |
| LangChain | 11 次模型、19 次工具；0 次成功 source read | 11 次模型、17 次工具；5 次成功 source read，1 个文件、2 个 SHA | 跨快照首次源码导航和定向比较实际生效，不是只通过单测 |
| Airflow | 8 次模型、16 次工具；5 次 source read，涉及 handler/测试 | 9 次模型、16 次工具；6 次 source read，涉及 handler/真实 cli helper | 读取从测试转向了正确别名对应实现；不是读取了 6 个不同文件 |
| 最终导出 | 0 完整、2 草稿 | 0 完整、2 草稿 | 工程阅读有进步，但不能宣称完整提取目标已完成 |

## 2. LangChain：前后比较目标已发生，旧实现验证仍不足

输入 `GHSA-45PG-36P6-83V9` / `entry-09520`。

### 2.1 已实际完成的阅读

1. 原唯一 ref 上完整声明查询没有命中。E0014 原样复用 E0012 的 `class GraphCypherQAChain` 查询，转到 E0005 已检查的 `c2a3021bb0c5f54649d380b42a0684ca5778c255`，得到真实声明位置；`initial_snapshot_search` 与 `initial_snapshot_source` 均成功。
2. E0015 读取 `libs/community/langchain_community/chains/graph_qa/cypher.py:144–223`。这里确实包含类声明、可选 corrector 默认值、`allow_dangerous_requests` 默认值和构造时 opt-in 检查。
3. E0018 成功取得同文件的完整 path-scoped diff：`d9813bdbbc1264ecb843b0a15284d708b3bae264` → `c2a3021bb0c5f54649d380b42a0684ca5778c255`。没有再次依赖超限的整份 diff。
4. E0019 读取父版本实际 `168–197`：包含 corrector 默认值、随后直接到 input/output property 的旧代码。与 E0015/E0018 对照，确实覆盖新增 opt-in 检查前后的位置；不再是 v70 的 import/doc 无关 hunk。
5. E0016 原请求 `224–400` 只保存到 318，E0017 覆盖 `1–143`，E0020 补读 `318–400`。c2 快照的原文合起来完整覆盖 `1–400`，包括 `_call`、输入读取、生成文本、可选 corrector 和 `graph.query` 调用。

因此，“找到文件后按文件比较修复前后代码并读取真实 hunk”这一动作要求在本次有直接证据，不能继续表述为完全没做过。

### 2.2 为什么仍是草稿

- 最终模型建议的行为版本仍是公告中作为修复给出的 c2 SHA。控制器记录 `selected_revision_is_reported_fix`，随后相关代码坐标因 `commit_not_established` 未成为正式字段。这里不能直接取消冲突，也不能把父 SHA 自动填成受影响版本。
- E0020 的 `_call`/query 消费发生在 c2；**父版本只读了 168–197**，没有旧 `_call` 的实际 source receipt。path diff 可以指导旧窗口位置，但不能把新窗口直接复制成旧行号。下一步缺的是在已经观察到的 before 快照核对实际运行主体，不是再找整个文件。
- 保存理由明确 corrector 仅配置时应用、构造需 opt-in；未把这些条件描述成无条件安全，也未宣称 GraphStore 数据库端实现或上游调用已读。当前 `trace=[]`，suggested steps 没有升级为已验证链路。
- c2/父版本与公告 `<0.2.19` 发布范围都没有实际映射证据。局部行为、公告修复角色、发布范围是三个不同问题。
- 公告分类沿用 SQL Injection，但已读代码是 Cypher。保存理由明确这是公告归因而非源代码直接证明的 SQL 分类，报告应继续保留这一区别。

### 2.3 最小下一步

在原预算内把**已观察到的 before 快照的同函数实际阅读**排到重复检索/已覆盖 after 窗口之前；优先补与“选定版本是 reported fix”冲突直接相关的那一小段。若旧实现和版本归属仍不能确证，继续留空。无需重写完整提取系统，也不应为提高完整数放松 fix-role 冲突检查。

## 3. Airflow：正确 helper 已读，最终日志及旧版本未完成

输入 `GHSA-8R55-RV5W-6PFM` / `entry-67227`。

### 3.1 已实际完成的阅读

- E0011 保存 `connection_command.py:1–112`，其中 39 行真实导入为 `from airflow.utils import cli as cli_utils, helpers, yaml`；E0012 保存同文件 `200–303`，包含 `@cli_utils.action_cli` 与 handler。E0014 补同文件 `300–382`。
- E0015/E0016 的 `imported_call_search/source` 正确沿这个词法线索查到 `airflow-core/src/airflow/utils/cli.py`，读取 `54–158`。这不同于 v71 进入测试或混淆别名。
- E0016 中 wrapper 先检查参数、构建 metrics，然后调用 `cli_action_loggers.on_pre_execution(**metrics)`（97 行），finally 调 post-execution。`_build_metrics` 从 `sys.argv` 构建 `full_command`（145 行），不是从 handler 的 `args` 直接复制。
- E0017 补 `158–230`，覆盖 password 参数其他形式、conn-json 敏感键、conn-uri password 的条件处理与 metrics 返回；字段理由没有宣称“所有连接信息都一定得到完全遮蔽”。

这证明正确 helper 导航生效，也证明 helper 与 handler 参数来源不同；不能把这个区别省略成简单的同一变量直传。

### 3.2 尚未完成或需要准确限定

1. **最终日志未读。** 保存的 6 次 source read 仅两个文件；没有 `cli_action_loggers` 实现、注册及最终持久化的 source receipt。E0016 只展示调用和文档说明，文档中的 Log 字样不是实现证据。最终 CO/EP/commit 继续空，理由承认这一点。
2. **相关旧版本未读。** 源码 SHA 只有两个现有 refs：`19c1a16dc8b44ba470198c300b25defc7848576f` 和 `df4cb30b116c8628afc465876e08d58f2bcb897b`。没有在相应源码中读取发布版本，也没有公告 `<2.11.1` 与该 SHA 的映射，不能称已验证受影响旧版本。
3. E0019 的 `alternative_snapshot_read` 读取 df4 的 `cli.py:139–251`，其中又是相同的 metrics/masking 内容及旁边 `process_subdir`。读取另一个 SHA 不等于获得更早的受影响实现，也没有补掉最终 logger 缺口。
4. 历史查询并非穷尽：E0007 `audit log`、E0008 `sensitive` 各 20 条且 `has_more=true`，均非浅库、`negative_result_conclusive=false`；E0013 当前路径内 `connection` 有 4 条，但也不是所有迁移前历史。不能据此说相关旧代码不存在。
5. EP 和 trace 理由引用 `E0017 line 145` 指向 `sys.argv`，但 E0017 实际从 158 起；程序已记录 `reason_citation_out_of_bounds`。同 SHA 真正 145 行在 E0016。**这是引用编号错误，不是 sys.argv 事实缺失**；不应藏掉警告，也不需要为这条事实再次付费读源码。

### 3.3 最小下一步

优先沿**已读 wrapper 明确调用的日志实现**补一段必要 source/注册范围，替代收益较低的另一 ref 上相同 masking 窗口；历史部分使用已观察机制关键词与迁移前路径的有界检索，不把现有两个 refs 当作全部历史。模型应根据实际所得说明旧版本支持/缺失，不预填额外诊断发现的答案。

## 4. 本次结论

- 已达到：LangChain 首次源码导航、真实按文件前后 diff 与相关父 hunk；Airflow 已读导入别名到真实 action wrapper、metrics 与条件处理。
- 未达到：LangChain 旧运行主体与版本冲突的充分核实；Airflow 最终日志实现及相关旧版本的充分核实。
- 没有用“仍为草稿”否定已得到的阅读进步，也没有用“工具已成功”认定剩余语义前提完成。下轮只针对这些明确缺口作小范围调度修正，保留 v72 原结果，不开启新的大修或扩大验收范围。
