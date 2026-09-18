# NLTK v79 low：定位进步与剩余边界

日期：2026-09-13。对象为已结束的 `D:\VulnGym-bv2-runtime\t2-representative-20260913\02-nltk-v79-low`。仅依据本轮 summary/actions/entries/review 和其中保存的公共回执；未读新目标源码、联网、调用模型或执行目标。本文是 AI 辅助内容 QA，不是人工认可或独立准确率。原结果与生成代码未改。

## 1. 终态与草稿的真实原因

执行器退出 0、status completed：15 HTTP、12 tools、115.59 秒、2 完整候选、1 草稿；provider halted 为 null。全部 HTTP 返回成功不等于零技术问题：本轮有 1 次 encoding rejection（encoding_missing_root=1），model_error_count=2、pipeline_error_count=2；终态 format/tool/annotation 错误及 read-plan 拒收均为 0，自动重试 0。

草稿是槽 2 `entry-00000` 的 word_tokenize 范围，不是普通语义弃答：

- 调用 9 的 draft_assessment 对八个模型字段都给了 supported，并提出 EP/CO/trace；这只是原模型评估，不表示本 QA 同意全部内容。
- 调用 10 的 draft 编码被 `annotation_snapshot_rejected: missing_root_fields` 拒收，path 为 `$[0].arguments`；缺失 `critical_operation / entry_point / trace / vuln_category_l1 / vuln_category_l2 / vuln_ids / vuln_title` 七个根字段。
- 随后的 `annotation_snapshot_reencoding` 为 `budget_unavailable`。本批上限 16 且要为后续候选保留初稿/自检；这是本批恢复预算不足，不是用户总授权已用完。不能把最后未花的一个请求当成足够重做完整评估/编码对。
- 两条 model_errors 分别是“Snapshot encoding remains rejected; no values from the rejected object were applied.”和“No model draft obtained; retaining input metadata and collected evidence for review.”；pipeline_errors 重复同两条。它们是同一槽编码失败及未取得初稿的后果，不是四个独立故障。

槽 2 因此 `initial_draft_status=not_received`、`self_review_status=not_requested`，关键字段为空，仅保留输入身份等。没有把被拒收对象的部分字段偷偷导出，也不能从其 missing_value 倒推模型已经判定相关事实缺失。

## 2. 范围与逐槽证据时间

选择记录为 4 个提案、选 3、漏选 1、duplicate 0；三个原范围仍为 sent_tokenize、word_tokenize、debug_decisions。槽 1/3 的最终 EP/CO 没有替换成另一个入口；槽 2 只保留原提案而无有效初稿。三者共享同一公告、正则和修复机制，前两个入口还有嵌套关系，不能按三个独立漏洞或三个独立输入计成绩。

| 槽位 | 实际调用及证据截止 | 终态 |
| --- | --- | --- |
| 1 sent_tokenize | 5/6 初稿、7/8 自检，均到 E0015 | 完整；E0016 后来共享，但未参加本槽评估 |
| 2 word_tokenize | 9 评估、10 编码，均到 E0015 | 编码拒收草稿；E0016 同样是后来共享 |
| 3 debug_decisions | 11/12 初稿到 E0015；13 补读阶段、14/15 自检已到 E0016 | 完整 |

E0016 是旧版本 `punkt.py`:1361–1440，包含 `_realign_boundaries` 的实际循环，而不是 v78 的修复侧文档窄窗。本轮确实补到了它；但槽 1/2 的 `later_shared_evidence_refs=[E0016]` 必须保留，不能倒灌为这两槽当时已经评估。

## 3. 两条完整候选的明确进步

两条都选择父提交 `0b7b076247ec41f9b6b8a94400d48ea299e4b507`，而非修复提交 `1405aad979c6b8080dbbc8e0858f89b2e3690341`。版本 reason 保留 `behavior_at_revision`，没有将未建立的发布范围映射说成已证。

- sent_tokenize 的 CO 从静态模式定义改到 `_slices_from_text`:1336–1349，包含 1338 行对 text 的 `finditer` 迭代及后续切片条件。
- debug_decisions 的 CO 改到 1287–1288，直接是同一参数的 `finditer` 迭代和匹配上下文构造。模式定义/编译转为机制依据，而不再充当执行点。
- 两条 entries 与 review 当前字段一致；槽 1 的 EP/CO/5 步 trace 共 7 个窗口、槽 3 的 EP/CO/1 步 trace 共 3 个窗口，10/10 与同 SHA 保存源码逐字匹配。这不是语义准确率。
- E0008/E0009/E0007 支持前导 word-material `\S*` 被删除及两个匹配分支改走辅助方法；不支持把所有正则、所有非空白匹配或其余分支一并描述成被删除。

## 4. 仍需限定的内容，不抹掉已解决的 CO 定位

**生成器消费。** E0010 已保存 debug_decisions 的 yield，因此仅调用该方法会创建生成器；实际消费者推进它后才开始匹配。本轮 EP/CO/trace 仍使用“consumes / executes / directly callable”等表述，没有明确写出消费前提；“同函数内没有改写 text”不等于“调用立即执行”。这是已读条件遗漏，不是缺少这段源码。实际外部消费者仍未提供，本 QA 不猜测它。

**类型与默认 realign 路径。** sent 的 EP reason 正确保留“加载 pickle 的具体类未独立证明”；trace reason 却同时说“每条连接都是直接已读调用”，又承认类身份是推断，二者应统一为有条件连接。E0010:1334 的列表推导式消费 span_tokenize，但该生成器默认 True 会先经过 realign 包装；槽 1 当时仅到 E0015，尚未获得包含该循环的 E0016。当前全批材料已显示 `_realign_boundaries` 经 `_pair_iter(slices)` 迭代，仍未给出 `_pair_iter` 实现或运行态类型证据；应保留局部关系/未知前提，不因此无端否认已读的实际 finditer 点，也不强制增加递归追读门槛。

**缓存与描述精度。** E0015 表明 period_context_re 先取缓存，仅取缓存失败才编译。两条完整 trace 已不再列“每次必定编译”的运行步骤，这是比 v78 更好的范围控制；debug 的 CO reason 仍宜将“compile the fmt”限定为该分支，不能当作每次执行事实。sent EP desc 把 103 行说成读取 text 参数，但该行是参数文档；真正的函数边界/使用分别在 96/107 行。代码窗口正确，说明中的行号措辞仍需修正。

**强度与独立性。** “catastrophic / backtracking”来自公告归因和修复源码对应，本轮未做复杂度实测。多个公共 API 复用同一机制不增加独立证据数量。2 个完整候选不能自动宣称 2 个语义通过。

## 5. 收口判断

本轮真正修正了 CO 的静态定义/实际操作混淆，且两个完整候选无传输或字段应用异常；不能再说这一项毫无进展。还保留一个明确的编码形状/恢复预算问题，以及完整候选中可从已存源码说明清楚的消费/类型条件和少量描述问题。

最小后续是分别处理编码完整性与内容说明：保持被拒收原结果，不能拿 assessment 文本代替 schema 条目；对两个完整候选保留上述限定，不把“字段齐全”升级为人工认可。没有理由据此给全项目重打失败标签，也没有新增无条件读满文件或重新运行所有材料的要求。
