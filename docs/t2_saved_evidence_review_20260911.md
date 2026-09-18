# run-12 / run-13 已保存材料一致性核对

日期：2026-09-11。范围限定为当前产品 `D:\GitProjects\VulnGym-T2` 内已公开的 run-12、run-13 JSON/JSONL、对应 assessment 及 docs 自评。这是开发助手对已有记录的离线一致性检查，不是独立人工确认、漏洞重新验证或准确率评测。未访问目标仓库、网络、模型、密钥或私有材料，也未修改原运行文件和人工复核表。并行进行的新复测不属于本文范围。

## 定位方法与结论边界

- 两批 `review.jsonl` 都只有第 1 行；下文用“本地文件行号 + JSON 字段 / 证据 ID”定位。run-12 的 `entries.jsonl`、`reports.jsonl` 也各为第 1 行，run-13 这两个文件为空。
- `E0006 / middleware.py:2341` 等表示 **JSONL 中保存片段所声明的源码坐标**，不是本次重新打开了目标源码。`E0002.text` 的逻辑行号是对该已保存字符串按换行拆分所得，不是 JSONL 物理行号。
- “已知支持”只表示记录之间相符或文字确实出现在保存材料中；不把模型的 `supported`、源码字节匹配或完整 schema 当作漏洞语义正确。所有原始 `verify=0`、原状态和模型意见保持不变。

## 一、已知支持

| 核对项 | 已保存记录支持的结论 | 精确定位 |
|---|---|---|
| 条目完整性 | run-12 有 1 条完整候选，恰为 15 字段；entry 与 review 的 `draft_fields` 相同，report 指向 `entry-16602` 且 `num_entries=1`。run-13 有 1 条 draft、0 条正式 entry/report。两批都是同一 `entry-16602` / `GHSA-CM35-V4VP-5XVX`，不是两个独立样本。 | [run-12 entries:1](../examples/run-12/entries.jsonl#L1)、[reports:1](../examples/run-12/reports.jsonl#L1)、[review:1](../examples/run-12/review.jsonl#L1)；[run-13 summary:2](../examples/run-13/summary.json#L2)、[summary:6](../examples/run-13/summary.json#L6)、[review:1](../examples/run-13/review.jsonl#L1)。 |
| 保存片段与字段代码 | 本次仅从保存的 `read_file.result.text` 按保存行号取片段，6 个导出位置均与 entry 的 `code` 完全相同：EP、trace[0] 对应 E0009；trace[1] 对应 E0008；CO、trace[2]、trace[3] 对应 E0006。原 `location_checks` 亦记录 6 次 valid、无坐标修正。这不检验描述或调用关系。 | run-12 `review.jsonl:1` 的 `draft_fields`、`location_checks`、E0006/E0008/E0009；对应字段见 `entries.jsonl:1`。 |
| 证据引用存在性 | run-12 的 15 个字段评语引用均可定位到 9 条已保存证据之一，或明确的 `controller:*` 引用；没有悬空 ID。控制器引用不等于源码证据，ID 存在也不意味着它支持评语中的全部主张。 | run-12 `review.jsonl:1`，`field_reviews.*.evidence_refs` 与 `evidence[].id`。 |
| 版本 basis 的表达 | 模型选 `9762ef3ef6f230bfed8d550dde69df6187f6267d`，E0004 将其记为修复线索 `8af6a4cf…` 的父提交；E0005 保存对应差异，E0006/E0008/E0009 的独立文件片段在这个父 SHA。`commit.revision_basis=behavior_at_revision`，理由明确没有建立公告版本范围映射。这个表达与保存记录一致，不能升级成 `affected_range_and_source`。 | run-12 `review.jsonl:1`，`field_reviews.commit`、E0004 `result.parents`、E0005 `before/after`、E0006/E0008/E0009 `result.commit`；[run-12 assessment:25](../examples/run-12/assessment.md#L25)。 |
| 入口声明 | 保存的 E0009 包含 `main.py:1431–1436` 的两个路由、`chat_completion` 声明和 `Depends(get_verified_user)`。EP 1430–1436 不再只是函数体内部变量片段。仅此并未独立核验该依赖的实现、完整权限策略或实际部署行为。 | run-12 `review.jsonl:1`，E0009、`entry_point`、`field_reviews.entry_point`；[assessment:24](../examples/run-12/assessment.md#L24)。 |
| 公告分类 | E0002 正文确在 `Primary:` 下并列 CWE-829 与 CWE-95；829 有“公告主分类之一”的文字依据。`vuln_category_l1=Code Injection` 与保存标题/正文主题一致。分类来自公告的依据，不等于本次独立确认的源码分类。E0002 有 `truncated=true`，但上述分类段完整留在保存前缀中。 | run-12 `review.jsonl:1`，E0002.text 逻辑行 80–82、E0002.advisory_metadata、`field_reviews.vuln_category_l1/l2`；[assessment:36](../examples/run-12/assessment.md#L36)、[docs 自评:194](t2_v41_results.md#L194)。 |
| run-13 执行失败 | 原记录为 `provider_stopped`、`provider.halted=deepseek_staged_protocol_invalid`，两条模型错误和同样的两条管线说明中含 `Model request failed during draft: ProviderError` 及未取得初稿。第 11 个模型调用进入 annotation/draft；补读与自查均 `not_requested`。这不是一次已经形成有效判断后的主动保守弃答。 | [run-13 summary:37](../examples/run-13/summary.json#L37)、[summary:57](../examples/run-13/summary.json#L57)、[actions:32](../examples/run-13/actions.jsonl#L32)；`review.jsonl:1` 的 `model_errors/pipeline_errors`、两项阶段状态。 |

## 二、未知、支持范围不足及可保留的替代解释

### 1. trace 相邻记录不自动构成已证实的链路

定位均为 run-12 `review.jsonl:1` / `entries.jsonl:1`：

| 相邻记录 | 保存材料中实际存在什么 | 本次可作的限定 |
|---|---|---|
| trace[0] → trace[1] | E0009 的入口声明与 E0008 的同函数后续窗口；E0008 在 1447 写出 direct 条件，在 1466 设置 `request.state.direct`。 | 有同函数上下文，不是仅凭列表相邻。但 trace[1] 选定的 1461–1466 本身未包含 1447 的条件；有关条件的描述依赖同份 E0008 的额外上下文。 |
| trace[1] → trace[2] | 前者是 E0008 `main.py:1461–1466`，后者是 E0006 `middleware.py:2320–2340`。已保存 main.py 窗口未给出到 `process_chat_response` 的调用或分派桥接；E0005 的差异 hunk 提供函数名称，不提供该跨函数调用。 | 中间连接仍未知。`field_reviews.trace.reason` 中“unmodified post-fix code path”及“no unsupported middle hop”没有在所引保存片段中得到对应连接证据；不能据此断言真实连接不存在，也不能把它记为已经证明。 |
| trace[2] → trace[3] | E0006 在同一连续保存窗口中给出了解析、过滤处理、event 条件及后续操作。 | 局部顺序有记录可看；仍不能把同文件局部顺序扩张为从外部入口直到浏览器执行的完整链路。 |

这与 [run-12 assessment:33](../examples/run-12/assessment.md#L33) 的连接保留意见一致。非空 trace 的原记录不在本次改写；合法的空 trace 或不同但有证据的路径也不应被排除为“非唯一答案”。

### 2. desc 与引用区间必须区分“选中片段”及“同份证据上下文”

- **JSON 解析：** trace[2] 选择 `2320–2340`，desc 写到 JSON 解析；实际 `json.loads` 在保存 E0006 的 **2341**。相关语句存在于同一 E0006，但不在所选区间内。
- **转发操作：** CO 与 trace[3] 选择 `2350–2352`，只包含空行、`if data` 和 event 条件；实际 `event_emitter(...)` 在 E0006 的 **2353**。条件可能正是检查缺口的合理位置，不机械判定“行号错”；可保留条件位置并收窄说明，或在另一次标注中把所描述操作所在行纳入片段。本文不替换原答案。
- **direct 分支：** trace[1] 选择 `1461–1466`，说明提到 direct 条件。条件位于保存 E0008 的 **1447**；选择范围内的赋值及同份证据的条件上下文可分别陈述，不应说条件也在选定片段内。

定位：run-12 `review.jsonl:1` 的 `draft_fields.critical_operation`、`draft_fields.trace`、E0006/E0008；对应 [assessment:35](../examples/run-12/assessment.md#L35)。本次不采用唯一标准行或机械固定行距判定。

### 3. “只检查 event / 原样 / 无过滤”超出了已读证据

E0006 的 **2343–2349** 明确调用 `process_filter_functions` 并重新赋值 `data`，随后才在 **2352** 检查 event、**2353** 调用 `event_emitter`。因此 CO/trace[3] 的 `forwarded verbatim`、`forwarded unchanged` 等绝对措辞不能由这份保存片段独立支持。

可支持的窄陈述是：保存的父版本 event 条件没有 E0005 所示后来加入的 direct guard。过滤函数和 `event_emitter` 的实现、运行配置以及实际效果未在 run-12 相关证据中展开；不能反过来断言过滤一定消除或一定保留某种内容。run-12 对前端执行的说明由 E0002 公告提供，没有对应的前端 `read_file`；模型二级分类理由已把前端部分称作公告的说法，应该保留这层来源区分。定位：[review:1](../examples/run-12/review.jsonl#L1)，E0005/E0006、CO/trace desc、`field_reviews.vuln_category_l2`；[assessment:34](../examples/run-12/assessment.md#L34)。

### 4. 版本范围与更细失败参数仍有边界

- E0002.text 逻辑行 **14–15** 保存 npm/pip 的 `<= 0.6.34` 及首个修复版本 `0.6.35`，正文逻辑行 **25/72** 又描述或报告测试 `v0.6.33`。应分别归于公告结构化范围、叙述/测试版本，不能据任一处直接建立所选 SHA 与版本范围的映射。run-12 的 basis 限定没有补齐这项未知。
- run-13 的 E0006–E0008、E0010–E0011、E0013–E0014 共 **7 次 read_file**，E0009/E0012 共 **2 次 search_code**，其参数均为修复 SHA `8af6a4cf…`。父 SHA 出现在历史记录和差异端点中，不等于对父版本做过独立文件读取。其 `commit=null`、`revision_basis=unknown`、`status=missing` 不可用 run-12 回填。
- 更细的 `location_values_limit`、`$[0].arguments.entry_point[0].value` 来自 [run-13 assessment:19](../examples/run-13/assessment.md#L19) 保存的固定诊断摘录。该文档说明它摘自原账本；本次没有访问账本。公开 `summary.json/review.jsonl/actions.jsonl` 可交叉支持停止代码与 annotation 阶段，**未保存这些细诊断键或坏参数全文**，故不能称本次已由 JSONL 独立复现“多几个位置/分别是什么位置”。参见该 assessment 的 [16 行](../examples/run-13/assessment.md#L16)、[24 行](../examples/run-13/assessment.md#L24)。

## 三、文字勘误与需要保持的归因

| 原表述及位置 | 保存材料中的对照 | 本文采用的准确表述 |
|---|---|---|
| [迭代记录:137](t2_v2_iteration_history.md#L137) 仍留有“CWE-829 被称为 primary 不符合公告仅列多项依据”的旧自评。 | E0002.text 逻辑行 80–82 明确写 Primary 并列 829/95；同一迭代记录 [159 行](t2_v2_iteration_history.md#L159) 和 [run-12 assessment:36](../examples/run-12/assessment.md#L36) 已作更正。 | 137 行是已被后文勘正的历史误读，不应继续引用为现行结论。829 是公告主分类之一，不能无依据排除这个合理分类。原模型 `the primary classification` 也宜解释为其中之一，而非唯一主分类。 |
| [run-13 assessment:33](../examples/run-13/assessment.md#L33) 写“父 SHA 只出现在自动 diff”。 | run-13 `review.jsonl:1` 的 **E0004.result.parents** 也保存了 `9762ef3e…`；E0005 则保存该值为 `before`。 | 父 SHA 在自动 `inspect_commit` 父链信息和 `read_diff` 端点中出现；没有对它独立进行 `read_file/search_code`。后半项主结论成立，前半句“只在 diff”需收窄。 |
| 将“技术失败草稿”理解成已排他确定唯一原因，或将两条模型错误当作两条失败输入。 | run-13 只有 `review.jsonl:1` 一个条目；两条说明同时出现在 `model_errors` 和 `pipeline_errors`。其 `format_failure_count=0`，但 `provider.halted` 有 staged 协议错误。 | 按条目记为 **1 条伴技术异常的草稿**；不证明不存在其它证据缺口，不把重复错误数组或错误条数当作条目数。 |

本次只在新文档中记录上述核对与勘误，不改历史自评、模型输出、人工空表或审批意见。

## 四、诊断统计与保留未知

以下只按两个批次各自已保存的 review 条目计数，不计算跨批“准确率”：

| 批次 | complete | input_failure | 伴技术异常的 draft | 未记录技术异常的 draft | draft 诊断不足 |
|---|---:|---:|---:|---:|---:|
| run-12 | 1 | 0 | 0 | 0 | 0 |
| run-13 | 0 | 0 | 1 | 0 | 0 |

依据是两个 `review.jsonl:1` 的原状态、`model_errors/tool_errors/pipeline_errors` 及 `self_review_status/evidence_followup_status`。两批这些诊断字段均有记录；run-13 的 `not_requested` 不是自查/补读失败，也不是已经完成。`format_failure_count` 不是上述分层的替代依据：[run-13 summary:16](../examples/run-13/summary.json#L16) 为 0，[22–23 行](../examples/run-13/summary.json#L22) 各有 2 条模型/管线说明，[37 行](../examples/run-13/summary.json#L37) 记录停止代码。旧记录若缺诊断字段，应留作“诊断不足”，不能用默认 0 断言没有异常。

run-12 最终所有字段为 `supported`、建议值为空；run-13 的五个关键字段缺失是在未获得有效 annotation 的技术异常背景下保存的。二者都不能单独证明“真实模型完成判断后合理保留不确定”的效果。完整率、引用可解析性和本次离线一致性检查不能替代该项语义评价。

结论：保存材料足以支持上述结构、来源、阶段和计数事实；trace 跨函数连接、部分描述强度、版本范围映射及未公开参数仍须保持未知或待审。本文不产生人工认可标签，不宣称漏洞确认，也不评价并行新复测的结果。
