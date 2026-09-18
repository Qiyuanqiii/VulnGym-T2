# NLTK v78 low：代表性结果内容复核

日期：2026-09-13。对象仅为已结束的 `D:\VulnGym-bv2-runtime\t2-representative-20260913\02-nltk-v78-low`，公告 `GHSA-F8M6-H2C7-8H9X`。依据本轮 summary、entries、review 中已保存的公共源码/差异回执与模型评估；未读取新目标源码、联网、付费或执行目标。本文是 AI 辅助内容 QA，不是人工认可、独立准确率或复现成功证明。

## 1. 真实终态和候选范围

执行器退出 0；summary 为 completed，16 HTTP、12 tools、182.575 秒、1 份输入、3 个完整候选、0 草稿，model/format/tool/pipeline/annotation 终态错误均为 0，read-plan/encoding 拒收均为 0，自动重试 0，三条 `verify=0`。配置为 v78、low、thinking enabled、max_tokens 32768。

选择 action 为 proposed 4、selected 3、omitted 1、duplicate 0。当前输出保持了本轮原提案的三个入口，没有把第二、第三槽偷偷改成第一槽：

| 槽位 / entry_id | 原提案与最终保留范围 | 限定 |
| --- | --- | --- |
| 1 / entry-20579 | `sent_tokenize` → Punkt 句子切分路径 | 加载对象到 Punkt 类的联系仅公告/文档归因，未读证实际对象类型 |
| 2 / entry-00000 | `word_tokenize` → `sent_tokenize` → 相同路径 | `preserve_line=False`；True 分支绕过句子切分 |
| 3 / entry-00001 | `PunktSentenceTokenizer.debug_decisions` 的直接匹配分支 | 返回的是生成器；须实际消费才开始方法体内工作 |

三条共享同一公告、同一模式定义和修复机制；前两条还有嵌套关系。这可以表示三个 API 范围，不能宣称发现三个独立漏洞，亦不能将三个候选当作三份独立测试输入。未选的一个提案不计覆盖成功。

## 2. 每槽证据时序

三槽均在初稿前已保存 E0001–E0016；没有槽间新增源码回执。槽 1 的 draft assessment/draft/self-review assessment/self-review 为调用 5/6/7/8；槽 2 为 9/10/11/12；槽 3 为 13/14/15/16。每次证据截止均为 E0016，各槽 `later_shared_evidence_refs=[]`，`evidence_followup_status=not_requested`。

因此本轮没有把后来补读的证据倒灌给先前候选的问题。但“该次可用”仍不等于模型实际理解了所有字节；三份评估是共享材料上的模型判断，不是三次独立确认。

## 3. 本轮确已支持的内容

- 三条选择父提交 `0b7b076247ec41f9b6b8a94400d48ea299e4b507`，修复提交为 `1405aad979c6b8080dbbc8e0858f89b2e3690341`。E0006/E0007 保存父子关系和逐文件差异；未将修复 SHA 填作旧版本。三条 commit reason 均明确仅 `behavior_at_revision`，未把 SHA 到公告 `<3.6.6` 发布范围的映射说成已证。
- 本轮逐项将 EP、CO、trace 与所选 SHA 的保存 read_file 窗口比较：槽 1 为 8/8、槽 2 为 9/9、槽 3 为 5/5，合计 22/22 字面一致。这只是内容定位检查，不是语义准确率。
- 三个 CO 都完整保留 `punkt.py`:268–275 的模式：前导 `\S*`、句末字符、`after_tok` lookahead 与其中的 `next_tok`。本轮不存在只截后半 lookahead 却称其为前导模式的问题，不能把旧轮次的定位缺陷沿用到这里。
- E0007 的未截断差异显示：删除前导 word-material `\S*`，并让 `_slices_from_text`、`debug_decisions` 转经新增 `_match_potential_end_contexts`。不能概括为删除所有非空白匹配；lookahead 内另一个 `\S+` 仍在。分类及复杂度描述来自公告，本轮没有运行性能测量。
- E0014 支持 `word_tokenize` 的 `preserve_line` 条件，该限定已进入最终 EP/trace 描述；不是本轮仍缺失的条件。

## 4. 当前实质缺口：定位、条件和未读前提分开

### CO 是真实定义，但不是输入被处理的执行点

三条 CO 都选 `_period_context_fmt` 静态模式定义，而不是实际对 text 执行/迭代匹配的位置。它是有价值的机制证据，并非虚构源码；不过按题目“关键操作是问题实际发生的位置”的口径，仍存在锚点偏差。当前保存源码已明确显示句子切分分支的 `finditer(text)` 在 E0010:1338，debug 分支在 E0010:1287。模式定义与编译位置宜作为辅助证据，不能仅因定义恰被修复差异修改，就把它与实际匹配点视为同一类位置。此处是输出定位问题，不需要新增模型请求才能发现。

### 生成器和缓存：已有源码能纠正的遗漏

- E0010 保存 `debug_decisions` 完整方法及 1293 行起的 `yield`。调用该方法只创建生成器；消费者实际推进迭代后，才开始 `period_context_re().finditer(text)` 路径。本轮 EP/trace 描述直接说该方法传入 text 并匹配，没有保留这个执行前提，也没有保存外部消费者。应分别标为“已有源码可确认的惰性前提遗漏”和“实际调用方/消费动作未证”，不能直接写成当前调用即触发。
- 对句子切分，E0010:1334 的列表推导式实际消费 `span_tokenize`；不是外层 `tokenize` 的 `list(...)` 才首次开始消费。`span_tokenize` 在被迭代时创建 `_slices_from_text`，并在默认 `realign_boundaries=True` 时改为迭代 `_realign_boundaries(text, slices)`。当前 trace 的“调用 `_slices_from_text`”是源码事实，但不能省略惰性与默认包装后仍宣称每个消费环节已经直接读证。
- E0015:280–294 先尝试返回缓存 regex，只有该访问失败后才走编译分支。槽 1/2 的描述将编译写成普通必经步骤，槽 3 虽保留完整代码，也概括为编译并返回缓存；应说明“已有缓存则复用，否则编译”。这不是缺源码，而是已读条件没有进入说明。
- 槽 3 的 trace reason 写成“把 text 传给 `period_context_re()`”，但实际该方法无 text 参数；text 传给其返回 regex 的 `finditer(text)`。这是描述层面的接收者混淆，代码片段本身正确。

### 明确尚未读证，不能补成事实的部分

- `sent_tokenize` 的 `load(...)` 实现与加载对象的实际类型不在回执内。槽 1 EP/trace reason 已明确该联系仅来自公告归因，是正确保留；槽 2 trace reason 却把同一段连接列作有序已读调用，未继承这个限定。第二条不应因经过第一条公共 API 就自动升级其证据等级。
- 旧版本 `_realign_boundaries` 在 E0010 中只读到文档字符串；修复侧 E0016 也仅到 `realign = 0`，未读到消费 slices 的循环。E0007 的修改差异不能代替未展示的未变主体。默认 True 路径的内部消费环节尚未完整读证；显式 False 路径可由 E0010:1324–1325 直接看到迭代 slices。不能为补齐链条而默认调用者传 False。
- 未读取实际外部调用者、模型文件/自定义语言变量的运行时配置，也未做触发或复杂度实测；不能把这些缺失说成源码证明了它们不存在。`text_contains_sentbreak` 等后续处理条件影响输出切片，不应混同为在首次 regex 搜索前已经完成的过滤。

## 5. 交验结论及最小下一步

本轮确实完成三份结构齐全、已自检、可导出的候选，并且修复前后源码和正则布局都保存正确；不能继续表述为格式失败。与此同时，静态定义式 CO、生成器/缓存条件遗漏、共享类型前提不一致说明仍不能把 `complete` 解释为内容已获认可。

最小后续应先在交验说明中保留上述条件、按发生点复核 CO，并在确需证明默认完整消费链时仅补缺失的同版本消费主体；不用把同一公告反复拆作更多“独立成功”。本次只新增说明，未修改原 entries/review 或代码，未启动新测试。
