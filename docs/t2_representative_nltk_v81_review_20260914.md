# NLTK v81：逐槽编码边界与完整候选内容复核

日期：2026-09-14。只读 `D:\VulnGym-bv2-runtime\t2-representative-20260913\09-nltk-v81-low` 与 `05-nltk-v80-low` 的公开 summary/review/actions，并核对新轮 `entries.jsonl`。未读取目标仓库、私有 gold、source-map 或密钥，未联网、调用模型或执行保存的代码；本次只新增本文，不修改原结果。

结论：v81 正常终止并输出 1 完整、2 草稿，但**不是同一候选稳定复现完整，也不是质量提高的证据**。v80 完整的是 sent_tokenize，v81 完整的是 debug_decisions；新轮前两槽都因最终编码缺根字段而未完成自审。两轮 E0001-E0015 的完整 JSON 回执逐一相同，没有新增源码覆盖。新完整项有真实的局部调用位置，但生成器消费条件、`_lang_vars` 类型绑定及 trace 的运行顺序仍须勘误/复核。

## 1. 终态与两轮差异

| 指标 | 05 / v80 | 09 / v81 |
| --- | ---: | ---: |
| summary 终态 | completed | completed |
| HTTP / 工具 | 15 / 11 | 16 / 11 |
| 耗时 | 98.276 秒 | 198.538 秒 |
| 完整 / 草稿 | 1 / 2 | 1 / 2 |
| missing_root 编码拒收 | 2 | 2 |
| 实际编码纠正请求 | 1，恢复末槽初稿 | 0，两次均 budget_unavailable |
| model / pipeline 错误计数 | 1 / 1 | 2 / 2 |

两轮均为 low、多候选、assessed_tool；读取计划拒收、format_failure、annotation_error 均为零，自动 HTTP 重试为零。`format_failure=0` 不会抹除整份 snapshot 编码拒收，`completed` 也不表示每槽流程成功。v80 保存的运行级 `run_request_limit=80`，v81 为 16；运行级额度与单输入/剩余候选预留不是同一概念，不宜仅用“15/80”解释旧末槽为何没有自审。

两轮都是 call 1/2 读取、call 3 `finish_reading: enough_evidence`、call 4 提候选；提出 4 个、因预算选择 3 个、遗漏 1 个。每槽开始和结束均有 15 份证据，所有模型评估/编码阶段的证据边界同为 E0015。三槽 followup 均 `not_requested`；没有本轮新增的补读、候选源码预读成功或末轮上下文关闭事件可供宣称。

## 2. 每槽初稿、自审与恢复边界

| 槽 / entry_id / 范围 | v80 | v81 |
| --- | --- | --- |
| 1 / `entry-20579` / sent_tokenize | call 5/6 初稿接受；7/8 自审完成；complete | call 5/6 初稿接受；7 有自审评估，8 编码拒收；纠正 budget_unavailable；draft、self_review=failed |
| 2 / `entry-00000` / word_tokenize | call 9/10 初稿接受；11 有自审评估，12 编码拒收；纠正 budget_unavailable；draft、self_review=failed | 同样为 9/10 接受、11/12 自审编码失败、无纠正；draft、self_review=failed |
| 3 / `entry-00001` / debug_decisions | call 13 评估、14 初稿编码拒收；15 encoding_shape_review 恢复；初稿 accepted，但自审 not_requested，仍 draft | call 13/14 初稿接受；15/16 自审完成；complete |

新轮两次拒收都发生在 `self_review`，保存代码为 `missing_root_fields`，缺少 `critical_operation`、`entry_point`、`trace`、两级分类、IDs、title 七个根字段。没有把拒收对象的值补回旧初稿，也没有把“有文字评估”当成已完成的自审。槽 1/2 均保留 `initial_draft_status=accepted` 和既有字段，以 `self_review_incomplete` 留作草稿；不能误报为“初稿未收到”。

按新轮 16 次总上限、每个剩余槽初稿/自审各两次的基础安排：call 8 后的 8 次、call 12 后的 4 次恰好用于剩余两槽/一槽的基础阶段。保存的 `annotation_snapshot_reencoding: budget_unavailable` 与这一账目一致，不是自动重试耗尽或目标证据不存在。末槽本次没有发生初稿拒收，所以 call 15/16 留给了自审；旧轮 call 15 用于恢复初稿，之后没有完整自审阶段。

这体现了次数有界的保护，也暴露结构化最终编码仍会失败；不能将前两槽失败一概描述成合理语义弃答。两个错误计数来自同一输入中的两槽，不能写成两个输入失败。

## 3. 实际证据与新完整条目

两轮全部 15 份输入/公告/工具回执相同，包括 11 次工具结果，不能宣称 v81 读到了旧轮未读的初始化或消费者。

- 候选源码 SHA：`0b7b076247ec41f9b6b8a94400d48ea299e4b507`。E0008 为 `nltk/tokenize/punkt.py:254-284`；E0010 为 `punkt.py:1270-1360`；E0014 为 `nltk/tokenize/__init__.py:90-132`；E0015 为 `punkt.py:280-300`。
- 另一实际源码 SHA：`1405aad979c6b8080dbbc8e0858f89b2e3690341`。E0009 为 `punkt.py:254-283`；E0011 为 `punkt.py:1270-1400`。
- E0006 实际 inspect 后者并保存前者为 parent；E0007 为两者的实际差异。公告 E0002 也明确引用该修复提交。因此此处与 Airflow 的纯标题候选不同，但 fix-parent 本身依旧不能证明某发布范围成员资格。

新 `entries.jsonl` 唯一完整项为 `entry-00001`，`verify=0`，commit 为上面的 `0b7b...`，`revision_basis=behavior_at_revision`：

| 字段 | 实际保留位置 | 可直接核对的内容 |
| --- | --- | --- |
| EP | E0010 / `punkt.py:1279-1288` | `debug_decisions(self, text)` 定义、文档和 finditer 循环开头 |
| CO | E0010 / `punkt.py:1287` | `for match in self._lang_vars.period_context_re().finditer(text):` |
| trace | E0010:1279-1288 → E0015:280-294 → E0008:268-275 | 方法局部调用、正则获取/编译方法、模式声明三份依赖证据 |

这些代码和行号都在保存的同 SHA 源码窗口中；新三槽 `reason_citation_checks` 的保存引用均为 covered。旧槽 2 的 `E0008:268-294` 越界引用本轮未重现（E0008 实际只到 284，285-294 要由 E0015 覆盖）。字节核验改善或通过，不等于调用关系、影响和候选独立性均已正确。

## 4. 必须保留的内容勘误和条件

1. **生成器不是调用即执行。** E0010:1293 明确有 `yield`，因此 `debug_decisions(text)` 创建生成器；只有返回的生成器被推进/消费时，才执行函数体并进入 1287 的正则迭代。完整项 EP、CO 与 trace 的“直接执行”描述均未写这一必要条件。窗口中没有具体消费者或部署调用；可描述“生成器被消费时的局部入口/操作”，不能宣称仅调用方法就已触发或已验证外部可达。
2. **类型绑定仍是未读前提。** E0015 确实给出 `period_context_re` 获取缓存、或以 `_period_context_fmt` 编译的实现，E0008 确实给出 `\S*` 模式；但 `self._lang_vars` 的初始化/赋值和实际类型不在任何本轮 source window 中。新完整项 EP/trace 的 reason 自己保留了这一 caveat。不能因同名方法、同文件或差异上下文，就把当前接收者与该模式的绑定视为已独立证实；需要补证或把对应关系明确降为有条件的候选，而不是加一句 caveat 就自动清除必要前提缺口。
3. **trace 三项不是已建立的连续运行链。** 它将 finditer 所在方法、`period_context_re`、类中的模式声明依次列出。模式声明是配置来源，不是在每次 finditer 之后执行的下一跳；E0015:283-294 又显示可直接返回缓存，不必每次编译。这些是有效的依赖证据，不应包装成三个按所列顺序发生的运行步骤。可选 trace 未建立时应收窄或留空，而非靠排列真实位置凑出链。
4. **前两槽的调用条件也没有因留草稿消失。** E0014:129 只有 `preserve_line=False` 路径转入 sent_tokenize；`True` 时直接用 `[text]`。sent_tokenize 在 106 行通过 `load(...)` 获得 tokenizer，文档称 Punkt，但本轮未读取 pickle 对象的实际类型。槽 1 的原判断已承认这一前提，不能当作源码类型检查完成。E0010 的 span_tokenize / _slices_from_text 同样需迭代消费；默认 realign 分支还涉及本轮只读到文档前部的 `_realign_boundaries`。
5. **复杂度与源码归因不得过度陈述。** 公告提供 ReDoS 及其示例计时，本轮没有执行该示例或独立计时；`\S*` 前缀和修复差异是静态机制线索，不等于本轮独立证明“指数阶”“catastrophic”或实际资源耗尽。新槽 2 的 CO 选的是 E0008:268-275 的模式声明，不是 1338 的应用点；声明可以是配置缺陷候选，但要说明为何选择这一层，不能用一条实际 finditer 引用替代对所选 CO 意义的解释。

当前判断明确没有声称 `<3.6.6` 到 SHA 的独立映射，这个限制应保留；不必机械要求官方版本表，但也不能用 parent 关系替代版本或行为论证。三个候选共享同一报告和模式，不应仅按不同公开方法就计成三个独立漏洞。

## 5. 可报告的结果与下一复核点

本轮可报告：同一公开证据集下，完整候选从 sent_tokenize 转成 debug_decisions；三份初稿都成功保留，两个最终编码失败被隔离，末槽完成了自审。不能报告“仍然 1 完整所以稳定通过”、新读取策略成功、准确率提升或完整项已人工确认。

后续需要分别处理工程与内容：前两槽的最终整份编码/恢复预算边界是工程问题；完整项的生成器消费、`_lang_vars` 绑定、缓存/配置与执行顺序是证据和解释问题。无需新读取就能先指出生成器条件和 trace 顺序不准确；绑定及调用环境则仍需适当授权后的源码证据。本次仅存档上述复核，不修代码、不补读目标、不改写历史候选，也不把技术失败或可避免缺口改称全部合理弃答。

## 6. 编码失败的有界根因检查（本地，0 HTTP）

另对当前控制器组装路径与公开回执做了核对。现有证据**不支持**“控制器只要求输出 commit，所以其余七根被故意省略”的归因：assessed review 规则要求每个字段的当前判断；两个失败槽保存的评估文本也列出了八字段结论。`encoding_context` 重新构建编码上下文，只有真正的 field_recovery 才携带 targeted_field_review；普通 self_review 不传该定向指令。编码请求最后仍追加 all eight / entire snapshot 约束，schema 八个根均 required。旧非 staged 的增量更新规则不能套用到这条路径。

因此可以确认的是：两次返回的 native 编码没有满足完整快照契约，恢复又被原剩余候选预算阻止；不能凭缺七根反推某一条提示词冲突，更不能还原或背书被拒的 commit 值。此次没有修改编码协议、复用被拒对象、降低自审要求或启动重试。

下一次应专门比较编码完整率与候选预算分配，保持同一份已保存评估和相同字段契约，明确记为编码诊断而非新样本成绩；不能靠增加字段模板文字便声称修好。若另给恢复留额，会影响可处理候选数或请求安排，应提前说明这一取舍，不把未处理提案藏起来。本轮请求使用已结束，该实验尚未执行。
