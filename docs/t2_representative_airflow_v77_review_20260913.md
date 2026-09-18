# Airflow v77：未到达源码读取，终态零错误不等于全程零拒收

## 范围与终态

只读已结束的 `D:\VulnGym-bv2-runtime\t2-representative-20260913\regression-airflow-v77-08` 中 summary/review/actions。读取 actions.jsonl 时从每条包装记录的 `.action` 取得动作对象，再检查其 action/field/call，未把外层 entry/report 标识当动作。与 [v76 同例](t2_representative_airflow_v76_review_20260913.md) 比较，不新增目标源码、网络、模型请求或目标执行，不改原结果。

统一会话 25465 退出 0：11 HTTP、10 工具、98.218 秒；0 完整、1 草稿，`initial_draft_status=partial`，followup、自审最终均 completed。终态模型/工具/pipeline/格式/字段错误为 0，读取计划和整份编码拒收计数为 0；**过程中另有 4 次字段拒收，最终自审恢复 2 个字段协议形状**，不能省略。累计 2479 次生成 + 1 次历史查询 = 2480/2600，余 120；无自动 HTTP 重试。

最终 commit、EP、CO 为 null，trace 为空、`verify=0`；这是源码机制未建立的草稿，不是完整验证结果。`model_uncertain` 是未确定原因，不是终态技术失败。

## 1. 本轮只有导航回执，read_file 为零

E0005/E0006 成功 inspect `19c1a16dc8b44ba470198c300b25defc7848576f`（19c）与 `df4cb30b116c8628afc465876e08d58f2bcb897b`（df4）。除此之外，所有模型读取都是 history 或 search_code；**没有 read_file、read_diff、命令主体、模块头、decorator 定义、日志值构造、最终 logger 或相关旧版本源码**。

| 回执 | 实际查询 | 保存结果及边界 |
| --- | --- | --- |
| E0007/E0008 | 19c 的 history：`audit log` / `sensitive`，各 limit 20 | 各 20 命中，has_more/truncated=true；只返回消息/SHA/parent，negative_result_conclusive=false |
| E0009 | 19c 全局裸词 `audit_log` | 30 命中，complete=true |
| E0010 | 19c `airflow-core/src/airflow/models` 下 `Log` | 60 命中，complete=true；含 models/log.py:36 类声明，但没有其连续源码读取 |
| E0011 | 自动将原 `audit_log` 转到已 inspect 的 df4 | 25 个可见命中，complete=false/truncated=true；既有 initial_snapshot_search，不是新 decorator 导航 |
| E0012 | followup call 8，全局 `DEFAULT_SENSITIVE_FIELDS` | 25 命中，complete=true；没有接着读定义 |
| E0013 | followup call 9，CLI 路径下 `audit_log` | 0 命中，complete=true；只否定该字面查询，不否定 CLI 可能经 wrapper 写日志 |

E0007/E0008 仍实际显示 `826f3bd3803ecc0c9aad17e549735ad0e7b6b0ee` 的 connection audit masking 测试消息，以及 `144aab6a9191c17963da262590830d72dafdcab5` 的 CLI masking 修复消息。本轮未跟进 inspect/source/diff，不能当作旧版本已核实，也不能概括为所有历史都无相关线索。

v76 的三个窗口曾覆盖 connection_command.py 全部 382 行；v77 **没有任何本轮可用源码窗口**，不能把 v76 原文回填到本次字段或把旧成果改写为从未发生。本轮源码覆盖确实回退，但仅凭草稿数不构成准确率比较。

## 2. 先关闭初读，再花请求恢复字段，补读仍只搜索

1. call 1–2 执行两次 inspect、两次 history、两次 source 搜索及一次自动快照搜索，尚无源码 read_file。
2. call 3 提交 **4 操作**计划，在首项 search_history 前记录 `read_context_closed`、`reason=reserve_annotation_review_context`、`result_allowance_chars=0`。该计划没有生成任何新回执；不能把四操作当已执行，也不能猜剩下三项具体内容。
3. call 4–5 初稿评估/编码；EP 与 CO 两个位置占位形状被拒收。
4. call 6–7 显式字段恢复；仍拒收相同两字段，恢复状态 unresolved。两次请求已计入总 11 次，并未得到源码。
5. call 8–9 是两次 followup，分别实际执行 E0012、E0013 搜索；均 completed，没有第三次 followup 模型调用，也没有 finish_reading 的公开动作或理由。
6. call 10–11 自审评估/编码，恢复两字段的协议形状，但没有补出语义位置。

非 read_file 初读操作当时需要完整 16,000 字符结果预留；因此 allowance=0 表示该 history 操作未获预留，**不等于实际剩余空间为零、权限失败或目标材料不可用**。公开 actions 没有保存 call 3 完整请求消息和全部参数，不重建未记录的精确开销。

初稿后保存压缩 54,582 → 52,708 字符；字段恢复后 53,572 → 52,708；两次 followup 后分别 57,677 → 56,958、58,203 → 57,458。这些是不同阶段的实测消息量，不能替代初读关闭点。call 9 后单例 12 次上限仅余 3 次，随后用了 2 次自审；结合既有编码预留，与无法再容纳一轮 followup 相符，但日志未保存独立的 budget-stop 原因，不把解释冒充动作。

## 3. 四次拒收与两字段恢复的正确口径

actions 中 `annotation_field_rejected` 恰为 4 条，全部 `location_placeholder_invalid`：call 5 对 entry_point/critical_operation 各一次，call 7 对相同字段再各一次。不是四个不同字段、四次 HTTP 失败或四次整份编码拒收。

显式 `annotation_field_recovery` 记录两个字段 unresolved。直到 call 11，自审后才出现 `annotation_field_recovered` 两条：critical_operation、entry_point。最终 `annotation_errors=[]` 与 summary 的 0 终态字段错误因此成立；“全程无字段拒收”不成立。草稿字段仍为 null，格式恢复不等于漏洞位置恢复或语义证实。

## 4. 最终理由合理保留了未知，但导航目标未完成

EP/CO/trace 均明确只有公告输入/审计写入描述、没有源码连接，未拼造 trace；分类、标题、标识归因于公告，分类不是公告原列 CWE。这些不确定性处理符合本轮实际证据。`location_checks=[]`，没有可报告的源码位置通过率。

commit reason 的“both local refs … touch unrelated paths”只能限定为 E0005/E0006 的变更路径；提交差异无关不等于整个 snapshot 没有相关机制。最终没有选择 SHA，受影响 `<2.11.1` 范围也仍为公告归因、未映射。宽词搜索和局部空搜索不能代替相关历史或消费者读取。

**不能将零 source 归因于 v77 lexer 失败。** 新 decorator/import 导航需要实际源码回执作为起点，本轮在前面的规划、预留、字段恢复及后续搜索选择中一直没有到达 read_file；它没有获得验证词法修复所需的输入。因此 v77 lexer 的真实效果在本例未被检验。后续读取调度修正属于另行开发诊断，本文不提前宣称它已修好或启动新批次。

结论：终态流程完成、字段形状最终恢复，但源码读取目标未达成；无权据此认定材料缺失、词法修复失败或机制已经验证。保留本次全部草稿、失败过程与原回执，不重写结果。
