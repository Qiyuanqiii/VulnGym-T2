# NLTK v84：真实编码恢复、CO 定位改善；trace 须注明证据来源与消费条件

日期：2026-09-14。只读核对 `D:\VulnGym-bv2-runtime\t2-representative-20260913\14-nltk-v84-low` 的保存 summary、review、actions、entries，并与[既有 v83 复核](t2_representative_nltk_v83_review_20260914.md)比较。没有新增目标源码读取、目标执行、模型请求或凭证访问，没有改写原始产物。**这是 AI 辅助证据审查，不是人工批准；1 完整候选不等于 1 条已经证明正确。**

## 1. 本次真实验证了什么

- summary 为 completed：1 输入、1 完整候选、0 草稿，10 HTTP、12 本地工具调用，60.716 秒。`prompt_revision=snapshot-guidance-v84`，low、32768 tokens/request；运行上限 12，自动 HTTP 重试为 0。
- `candidate_plan` 为 4 提案、选 1、遗漏 3；`budget_slots_without_reserve=2`、`budget_slots=1`、`encoding_reserve=1`。遗漏的是未执行提案，不能算失败样本或已发现的独立条目。
- call 5 是初稿评估；call 6 编码缺少 7 个根字段，被 `annotation_snapshot_rejected/missing_root_fields` 拒收；call 7 为 `encoding_shape_review`，同时保存 `annotation_encoding_reserve/consumed` 与 `annotation_snapshot_reencoding/recovered`。这是本次实际发生且恢复成功的编码形状失败，不是只在单测中模拟，也不是偷偷重试整个输入。
- 初稿最终 accepted；call 8 followup、call 9/10 自审完成。最后 model/tool/pipeline/annotation 错误均为 0；`encoding_missing_root_rejection_count=1` 与终态无失败并不矛盾：前者记录被恢复的中间事件。不能据一次恢复宣称编码失败已根治。
- 正式输出仍为 15 字段、`verify=0`；7 个位置校验均为 `verbatim_match`，没有坐标纠正。自审完成与源码行码匹配都不是人工语义批准。

本次外层上限 12；v83 外层上限 20、单输入控制器上限 16。两次候选提案数也不同。因此“2 完整变 1 完整”、调用减少或时长变化，都不能当作仅改变 v84 规则的严格单变量效果；本次也没有扩展为新输入成绩。

## 2. 本槽实际拥有的证据

选定 SHA 为 `0b7b076247ec41f9b6b8a94400d48ea299e4b507`。初稿调用的边界为 E0001–E0015，followup 与自审为 E0001–E0016；`later_shared_evidence_refs=[]`，只有一个槽。没有借用 v83 的 E0017 或其他批次的源码。

| 证据 | 本次保存范围 | 作用与限制 |
| --- | --- | --- |
| E0007 | 选定 SHA 到修复 SHA 的 diff | 同时显示删除模式中的前缀、改变匹配处理；hunk 提供类上下文，不是本次运行执行证明 |
| E0008、E0015 | `nltk/tokenize/punkt.py:254–284`、`:280–300` | 保存模式文本与 `period_context_re` 缓存／编译方法；没有 `_lang_vars` 的构造赋值 |
| E0010 | 同版本 `punkt.py:1270–1360` | 保存多个调用、生成器创建、默认 realign 包装与迭代，以及实际 finditer 位置 |
| E0014 | 同版本 `nltk/tokenize/__init__.py:90–132` | 保存公共函数、docstring、load 路径及转发调用；没有读取加载对象自身的类型绑定 |
| E0016 | 同版本 `punkt.py:1361–1440` | 初稿后自动续读 `_realign_boundaries` 函数体及其 `_pair_iter(slices)` 消费路径片段；没有 `_pair_iter` 本体 |

E0016 的动作仍是 `source_window_continuation`、`next-read-v1`、80 行边界窗口，不是新版 40 行 `called_body_continuations` 分支。call 8 本身没有追加工具回执；本次 followup 完成并不能说明“优先补 receiver binding”的新提示已经促成了那个读取。

## 3. 局部 EP/CO 的改善与材料前提

本次 CO 从 v83 的模式静态声明移到 **E0010:1336–1339 的实际 `finditer(text)`**，包含函数头和调用行；trace 的最后一步也抵达同一调用位置。这是明确可核对的定位改善。EP 仍是 E0014:96–107 的真实公共输入边界，而不是凭空生成的接口。

公告 E0002 明确点名 `sent_tokenize`、`word_tokenize` 和 `PunktSentenceTokenizer` 受影响；E0014:96–107 的 docstring 明确推荐类，随后读取对应模型并转发 text。E0007 的修复、E0008 的旧模式、E0015 的编译方法与 E0010 的 finditer 又提供同一机制的源码依据。这是多文档正证，不是对象关联完全未知。**本次 EP/CO 可以作为有多源依据、`verify=0` 的候选保留。**缺少独立对象类型读取，不应自动把这个局部 API 或真实 CO 判错，更不应新增“每一边都必须源码独立证明”、执行反序列化、运行时类型测试或证明每种部署的门槛。

但本轮未新增加载对象绑定，也没有 `_lang_vars` 赋值窗口。E0008 的模式、E0015 的编译方法、E0010 的接收对象调用分别存在；如果将它们表述为“本次源码已经独立证明实际对象必然使用这一模式”，证据强度仍不足。更准确的交验表述是：局部位置真实，机制受公告、patch 与局部源码共同支持，其中对象关联仍有明确的材料前提，不能悄悄升级为已独立读取的调用关系。

`commit` 使用 `behavior_at_revision`，已保留 SHA 到发布范围未映射，不因缺官方版本表而强制降级。关于复杂度的影响来自公告与修复对比，本次没有独立执行计时，不能报告为新测得的复杂度结果。

## 4. 非空 trace 与新 guard 的实际边界

以下为本次保存的公开字段理由原文，不是隐藏推理。

`entry_point.reason`：

> E0014 shows the public boundary reading text and forwarding it to tokenize; the receiver being the Punkt tokenizer is per docstring/load (reported premise). E0010 shows PunktSentenceTokenizer.tokenize, connecting this entry to the operation.

`trace.reason`：

> Consecutive calls visible within E0014/E0010; the load() dispatch binding tokenizer to PunktSentenceTokenizer is per docstring/reported, not independently read, and no runtime mode is claimed.

两者仍为 supported，`support_consistency_checks={}`，动作中没有新支持冲突记录。v6 针对“loaded/returned object identity inferred 且未读＋具体连接断言”的有限词形，本次表达没有命中。因此新检测在合成回归中的覆盖仍成立，但**这次没有真实 guard 拦截成绩**。未命中既不能证明语义正确，也不能自动等同“漏掉了一个必须否定的候选”；当前理由明确归属文档前提，须先评价其正证，不能仅按词形是否命中裁定。

非空 trace 需单独复核两点，不连坐已经真实存在的局部 EP/CO：

1. 第一条到第二条从 `tokenizer.tokenize` 跨到具体类方法，理由自身已说明 load 分派并非独立读取。该关联有公告／docstring 正证，可以保留为有材料前提的说明；应把 `Consecutive calls visible` 勘误为“源码调用与明确文档前提共同支持”，不要概括为所有连接均在源码中直接显示。“未声称 runtime mode”不等于已经准确标示了当前 trace 每一步的证据来源，也不意味着必须新增运行时证明。
2. E0010:1321 创建 `_slices_from_text` 生成器，不等于该语句立即执行生成器里的 finditer。默认 `realign_boundaries=True` 时，1323 先包装 slices，1324 的迭代会经过 E0016:1365 的 `_pair_iter(slices)`；后者本体本轮未读。1334 的列表推导式和 E0016 的消费者片段确实存在，不能说“完全没有消费证据”；但最终 trace 的第三／第四个范围没有交代默认包装与消费条件，理由也没有引用 E0016，不能声称完整默认执行顺序已经建立。

自审公开评估最后称“唯一未知只是 SHA 到发布范围映射”，遗漏了 trace 对默认消费条件的说明局限。后续应优先勘误非空 trace 的证据归属和生成器消费条件；有文档正证的关系不必一概清空，确有必要而完全缺依据的步骤则补证或保留不确定，允许空 trace。不要仅靠继续扩充英语词形检查代替语义核对，也不要把“未新增独立源码绑定读取”误报成“文档前提无效”。

## 5. 收口结论

可交验事实：一次真实缺根字段失败在原预留内恢复，自审完成；CO 确实定位到执行调用；EP/CO 有公告、docstring、patch 与源码共同依据；有限预算下只执行一个提案且公示遗漏；所有正式坐标匹配、`verify=0`。仍不可声称：v84 新增了 receiver／模式绑定的源码读取、完整交代了默认消费、非空 trace 全部独立核实、1 条经人工批准，或完整率相对 v83 已提高。该候选是有依据而待人工确认，不是因为少读某个对象就判为错误。保留本次原始产物；本文只记录验证结果，不改写字段或冒充人工确认。
