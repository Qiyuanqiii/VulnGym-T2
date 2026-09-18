# NLTK v83：编码未再失败，但两个完整候选仍需关系复核

日期：2026-09-14。仅核对 `D:\VulnGym-bv2-runtime\t2-representative-20260913\11-nltk-v83-low` 的公开保存 summary、review、actions、entries，并与[既有 v81 复核](t2_representative_nltk_v81_review_20260914.md)对照。没有新增目标源码读取、执行、模型请求或访问凭证；没有改写原始产物。**本文是 AI 辅助证据审查，不是人工批准；2 完整不等于 2 正确，也不是两个独立漏洞的成绩。**

## 1. 已确认的运行事实

- summary 为 completed：1 输入、2 完整候选、0 草稿；13 HTTP、13 本地工具调用，110.934 秒。外层运行上限 20，输入控制器仍限 16；没有自动 HTTP 重试。
- 读取计划、snapshot 编码拒收、最终 model/tool/pipeline/format/annotation 错误均为 0；两条初稿均 accepted，自审均 completed。共有四份评估／编码配对，不是只有初稿。
- `candidate_plan` 实际为 3 提案、选 2、遗漏 1，`budget_slots_without_reserve=3`、`encoding_reserve=1`。共享预留确实影响了准入；没有 `annotation_encoding_reserve` 消费或 `annotation_snapshot_reencoding` 动作。本次未复现 v81 的缺根字段失败，**不能据此声称真实编码纠正路径已经恢复了失败**，也不能从单轮推断编码失败率。
- 第一槽 sent_tokenize：call 5/6 初稿、7 followup、8/9 自审；第二槽 word_tokenize：call 10/11 初稿、12/13 自审。前四次为读取和提案。第一槽 followup completed，但该模型轮次没有增加新的工具回执；第二槽因 `reserve_review_context` 未再发起模型补读。
- 两条正式记录均为 15 字段、`verify=0`；保存的 8 个位置校验均为 verbatim_match，无坐标校正。单输入共享费用只记在第一条 review，第二条的零调用计数不能解释为它未经过模型处理。

## 2. 本轮实际新增了什么证据

选定 SHA 为 `0b7b076247ec41f9b6b8a94400d48ea299e4b507`。E0008、E0010、E0014、E0015 的读取范围与旧 v81 复核所列相同；对另一 SHA `1405aad979c6b8080dbbc8e0858f89b2e3690341` 的比较也有本轮自己的 E0006/7/9/11，不从旧轮借证据。

| 保存证据 | 可见范围与出现时点 | 可报告的作用与限制 |
| --- | --- | --- |
| E0016 | `nltk/tokenize/punkt.py:1361–1440`，第一槽初稿后、call 7 前 | 补到 `_realign_boundaries` 函数体，能看见它调用 `_pair_iter(slices)` 及局部 yield 条件；不包含 `_pair_iter` 实现或 `_lang_vars` 初始化 |
| E0017 | `nltk/tokenize/__init__.py:1–89`，第二槽初稿后、自审前 | 补到 `load`、`PunktSentenceTokenizer` 等 import 和包文档；导入类不等于已确定 `load(...)` 返回对象的类型 |

E0016 的动作摘要为 `next-read-v1`，范围是 80 行：这是既有窗口续读分支的真实使用，不能冒称已验证新版 `called_body_continuations` 的 40 行分支。E0017 是 `entry_context_read`。第一槽 `slot_end` 与 call 9 的证据边界均为 E0016；E0017 在其 review 中标为 `later_shared_evidence_refs`，不能倒灌成第一槽当时已经使用的依据。

## 3. 真实入口与到所选 CO 的关系必须分开判断

两条公开函数确实存在：E0014:96–107 显示 sent_tokenize 接收 text、加载对象并调用其 tokenize；114–131 显示 word_tokenize 的 `preserve_line=False` 分支将同一个 text 传给 sent_tokenize。**不能因为未单独读取对象类型，就把这两个局部输入边界一概判错。**

但本条记录的 CO 均选在 E0008 的 `punkt.py:268–275` 模式声明；从上述 API 到这个具体实现／模式的关联仍需依据。公告 E0002 报告这些 API 受影响，docstring 指明推荐的 tokenizer 类，这些可以作为明确归属的材料前提；它们不能被表述成“本轮源码已经证明了加载对象的具体方法分派”。这里缺的是所声称的局部连接，不是必须做运行时类型测试或证明所有部署。

以下为保存的公开字段理由原文，不是隐藏推理：

第一槽 `entry_point.reason`：

> E0014 L96-107 shows the public function reading external text and calling tokenize; E0010 L1273-1277 shows tokenize -> sentences_from_text -> span_tokenize -> _slices_from_text. The loaded object's identity as PunktSentenceTokenizer is inferred from the punkt pickle path/docstring, not separately read; advisory 'unpredictable user input' provenance is reported, not independently proven.

第一槽 `trace.reason`：

> All steps read at 0b7b076247ec41f9b6b8a94400d48ea299e4b507; each link is a shown call/order in saved reads. Step 2's range is widened to E0010 L1316-1338 so it contains the span_tokenize->_slices_from_text call at L1321, matching the description. Type identity of the loaded tokenizer (step 1) is an inference noted under entry_point and adds no unproven runtime step.

这两个字段仍为 supported、`support_consistency_checks={}`。已知类型身份推断不能同时被说成每个连接都已在源码中显示；有限 v5 规则没有覆盖这种表述，不代表它已经判断语义成立，也不是自动证据证明该 API 错误。

第二槽 `entry_point.reason` 只主张已读的分支转发：

> E0014 at 0b7b0762 shows the public word_tokenize signature receiving external text and line 129 calling sent_tokenize(text, language) in the non-preserve_line branch; only that branch is claimed.

其 trace 原评估则为 uncertain，保存在 `field_reviews.trace.omitted_assessment.reason`：

> Steps are read at 0b7b0762, but the sent_tokenize->tokenize edge is not fully proven locally: tokenizer comes from load("tokenizers/punkt/{language}.pickle") (E0014:106) and its being a PunktSentenceTokenizer rests on docstring/advisory, not a read receiver binding; no other same-SHA read establishes dispatch to PunktSentenceTokenizer.tokenize.

控制器正确导出 `trace=[]` 并保存六个建议步骤；这证明可选 trace 的未知值能够保留。但这个身份前提若是把该 EP 与本条 CO 相连所必需，就不只是“可选 trace 细节”：省略 trace 不会自动补好 EP→CO 关联。应保留已证实的 API 边界，同时对这条配对关系补证、限定其材料前提或继续标注不确定，而不是只因入口函数真实存在就宣告完整因果连接。两槽对同一分派前提的判断需要统一复核，不能把第一槽 supported 当成第二槽的证据。

## 4. 生成器消费、模式绑定与 CO 选择

1. **消费证据有增量，不是完全未读。** E0010:1334 的列表推导式消费 span_tokenize；1321–1325 显示 `_slices_from_text`、可选 realign 包装和迭代。E0016 又补到 `_realign_boundaries` 的 `_pair_iter(slices)` 和 yield 分支。因此不能沿用旧结论说本轮完全没看到消费者。
2. **默认分支仍不能压成一个无条件箭头。** `realign_boundaries=True` 时，1323 将 slices 包装为 `_realign_boundaries(...)`；其继续消费又经 E0016:1365 的 `_pair_iter(slices)`，该 helper 本体不在本轮 read_file 范围。若仅主张 False 分支，E0010 已显示直接迭代；但当前 sent_tokenize 调用没有传 False。第一槽 trace 把这些概括为 `_slices_from_text` 直接运行，未交代必要消费／分支条件，也未引用新增 E0016，不能宣称默认路径的完整执行关系已建立。
3. **`_lang_vars` 的绑定仍未读取。** E0015:280–294 显示 period_context_re 返回缓存，或将 `_period_context_fmt` 编译；E0010:1338 则调用 `self._lang_vars.period_context_re()`。本轮没有 `_lang_vars` 赋值／构造的源窗口。能确认模式和调用位置分别存在，不能仅凭同名方法、同文件就把实际接收者与这份实现视为已独立绑定。
4. **模式声明不是必然错误的 CO，也不是执行点。** 两条 CO 都选 E0008:268–275，理由已明确是在指认被修复改动的模式文本；E0007 确实显示删除该前缀。可以保留为配置／模式缺陷候选，但不能把这几行说成 finditer 的执行行，执行位置另在 E0010:1338。第一槽将复杂度影响归属公告的措辞较清楚；第二槽自审中出现 `observed super-linear matching`，本轮没有执行计时或独立复杂度证明，不宜表述成实际观察的运行结果。
5. **trace 改善与残留问题要分别说。** 第一槽不再把模式静态声明排为运行链最后一步，且把第三个范围从初稿 1327–1338 扩至 1316–1338，实际包含 1321 的调用。这是可核对的修正；它仍不解决对象绑定与默认消费路径的未知。其四个 trace 步骤也未真正抵达所选静态 CO，应区分“输入到正则应用”的路径与“模式来源”的依赖证据。

两条 commit 都明确使用 behavior_at_revision，并保留发布范围未独立映射；**不因缺官方版本表而强制降级**。需继续复核的是其报告机制与必要前提是否足以支撑当前配对，而不是重新要求 fix-parent 等于受影响版本。

## 5. 本轮可交验的结论

可报告：这次真实运行的四份 snapshot 均接收成功，两个候选完成自审；预算预留导致少接纳一个提案且如实记录；实际发生两个局部源码补读，第二槽保留不确定 trace。不能报告：编码失败已根治、v5 已拦住所有必要关系矛盾、两条记录均正确、两个独立漏洞或人工认可。

两个候选是同一公告、同 SHA、同一模式 CO，分别从两个嵌套的公共 API 进入。可作为两个待核的 API 路径展示，但是否符合独立条目拆分要求仍需复核，不能据条数提升计算准确率。下一步应聚焦“局部输入边界已证实”与“到选定 CO 的必要连接仍未证实”的一致表述，及加载对象／语言变量绑定和默认消费路径的证据，保留本轮原样产物，不回填为人工确认。
