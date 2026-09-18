# LangChain v75 已完成单例内容复核

日期：2026-09-13。这是基于保存公共回执的机器内容复核，不是人工认可、独立准确率或目标运行验证。

## 范围与终态

- 仅以 `regression-v75-06/review.jsonl` 的完整第一行为本次结果来源，读取后先核对 `report_id=GHSA-45PG-36P6-83V9`、`entry_id=entry-09520`；没有读取第二行或批次 summary。
- 开始复核时第一例已收到 `report_finished`，第二例仍运行。随后根节点确认统一会话 `21954` 已退出 `0`：整批 21 HTTP、26 tools、319.599 秒、1 complete + 1 draft；本文件仍只复核第一例，不代替另行进行的 Airflow 复核。
- 第一例保存状态 `complete`，`snapshot-guidance-v75`，11 model calls、15 tool calls，draft 后补读与 self-review 均已结束。`verify=0` 未变。
- 两条既有工具失败是全库 diff 的 `git_output_limit`、另一提交的 `commit_unavailable`；对应的两条 pipeline error 是同一事件的重复呈现，不能数成四次独立失败。局部成功不能抹掉这些历史事件。
- 本复核只比较保存回执及历史同例记录，没有新增目标源码读取、网络、付费请求或执行；没有改动生产代码或原输出。

## 核心结论

**v75 真正补上了旧侧 `_call` 主体，并把最终选定版本从公告列出的 fix 改为有实际源码的父版本。** 这不是只把旧草稿改成“字段齐全”。但保存候选仍有条件描述过宽，不能直接宣告全部语义通过。

| 同一已见输入 | 实际源码与前后比较 | 最终版本／状态 |
| --- | --- | --- |
| v72，`regression-v72-03` | 5 次成功 source read；有按文件完整 diff 和旧侧 168–197，但没有旧侧 `_call` 主体 | 仍选择 fix `c2a3021bb0c5f54649d380b42a0684ca5778c255`，触发 `selected_revision_is_reported_fix`，draft |
| v74，`regression-v74-05` | 0 次成功 source read；只有失败的全库 diff，没有成功按文件比较 | 版本、入口和操作未证，draft |
| v75，本例 | 6 次成功 source read、2 个 SHA；完整按文件 diff；旧侧 168–197 与 **300–370** 均真实读取 | 选择 `d9813bdbbc1264ecb843b0a15284d708b3bae264`，`behavior_at_revision`，complete |

三轮各 11 次 model call；tool calls 分别为 17、18、15。它们是同一诊断输入的连续复测，不能作为新输入泛化成绩或累计正确率。

## 实际读取与版本依据

文件均为 `libs/community/langchain_community/chains/graph_qa/cypher.py`。

- fix 侧 `c2a3021bb0c5f54649d380b42a0684ca5778c255`：E0012 为 1–118，E0013 为 150–241，E0014 为 241–330，E0015 为 330–400。119–149 没有 source receipt，不能写成读取了整个文件。
- E0016 是上述文件从 `d9813bdbbc1264ecb843b0a15284d708b3bae264` 到 fix 侧的成功完整 diff，`truncated=false`。它显示新增 `allow_dangerous_requests=False` 及初始化时显式 opt-in 检查，还含 import 调整。不能说这份修复新增了查询内容净化、数据库授权检查或删除了原有 corrector。
- E0017 是父版本实际 168–197：包含 `input_key="query"`、`cypher_query_corrector=None` 和相邻字段／属性。
- **E0018 是父版本实际 300–370**：包括 `_call` 的声明、输入读取、参数构造、生成结果提取、可选 corrector、truthiness 分支、query 调用以及函数返回。`has_more=false`、`truncated=false`。这是此前没有完成的关键阅读。
- E0005 明确记录 fix 的父版本，E0016/17/18 提供前后及旧侧机制证据。最终 EP/CO/trace 使用父版本，没有把 fix 的行号或代码挪到父版本。
- 所选 SHA 与公告中具体受影响发布范围的对应关系仍未建立；最终 reason 明确不主张 release-range mapping，这个限制需要保留。旧侧局部行为依据不等于官方受影响版本认证。

## EP、CO 与 trace

本复核把最终 EP、CO、4 个 trace 位置与所选 SHA 的保存 source receipt 按行切片比较：**6/6 位置的路径、范围和代码精确一致，均来自 E0018**。CO 与最后 trace 是同一个位置，所以不是六个独立证据。

| 字段 | 保存位置 | 支持的局部事实 |
| --- | --- | --- |
| EP | 305–313 | `_call` 读取 `inputs[self.input_key]`；E0017 给出默认 key。用户 prompt 来源归因于 E0002 公告，不是实际部署入口验证 |
| trace 1 | 313–318 | 构造 `question/schema` 参数后执行 `args.update(inputs)` |
| trace 2 | 322–325 | 调用生成链，再调用 `extract_cypher` |
| trace 3 | 328–329 | 仅在 `self.cypher_query_corrector` truthy 时调用该对象并覆盖生成值 |
| CO／trace 4 | 340–341 | 仅在最终 `generated_cypher` truthy 时调用 `self.graph.query`，之后对结果切片 `top_k` |

局部输入边界与同函数连接比 v72/v74 有实质支持；没有独立读取 base-Chain 的完整调度、具体部署调用方、数据库驱动和权限配置，不能扩展成端到端实际可达／越权验证。

## 仍需明确的语义边界

1. **“no content validation shown in this path”过宽。** E0018 已显示可选 corrector，E0017 默认其为 `None`。可支持的窄表述是：在 corrector 未配置且生成结果 truthy 的分支，生成结果被交给 query；若 corrector 被配置，其实际处理效果尚未读取，不能仍把该分支概括为没有内容校验。当前 trace 保留了 corrector，但 CO desc/reason 没有充分限定这个否定判断。
2. **不能把参数构造概括为原 question 必然原样传递。** `args.update(inputs)` 在后，可覆盖先前建立的 `question` 或 `schema`。保存 trace 如实包含此句，这是好事；描述完整输入到生成链的关系时也必须保留该覆盖可能。
3. **`extract_cypher` 不等于笼统的“去掉周围反引号”。** 直接读取该 helper 的回执是 fix 侧 E0012：取第一个 fenced match，否则返回原文本。E0016 未显示该 helper 变更，但没有父版本该 helper 的独立 source receipt；不能把 E0012 伪称为旧侧源码读取，或把这一操作说成内容安全验证。最窄的旧侧 trace 可以只陈述“调用提取 helper”。
4. **调用 query 不等于已证明具体数据库危害。** truthiness、可选 corrector 和前序调用成功是路径条件；`top_k` 是调用后结果切片，不是查询前限制。数据库权限、查询实现及实际生成内容未验证，公告所述广泛影响只能作为公告归因。
5. **对比结论也应限定位置。** E0017 的几个相邻字段加 E0016 能证明对应位置新增 opt-in，不能只引用 181–183 三行便概括整个 class 没有任何其它限制。
6. EP reason 提到 E0002 的公告归因，但该字段 `evidence_refs` 只列 E0017/E0018。公告确实存在于保存材料，不是捏造来源；用户可读导出应让这个实际来源也可追溯，不能把它显示为独立源码证明。

## 收口建议

保持此次旧侧真实读取和按文件比较，不回到“只看 fix 后重写 reason”的方式。下一步的收益在于让局部结论准确保留上述条件，而不是继续增加笼统否定词拦截或以 `complete` 自动背书。

本文件冻结于单例内容 QA；不修改本次候选、不补造历史回执、不把本复核新增的解释计为模型当时读取证据。跨文件及多候选能力由后续同代码代表性材料另行检验。
