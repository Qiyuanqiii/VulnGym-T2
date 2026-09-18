# NLTK 三入口 v73：范围、位置与执行条件复核

## 范围与结论

只读已结束的 `D:\VulnGym-bv2-runtime\t2-representative-20260913\02-nltk-v73` 中 summary/review/actions，并与 `02-nltk-v72` 同输入 `GHSA-F8M6-H2C7-8H9X` 比较。只使用各轮实际保存的公共 receipts，不新增目标源码、网络、模型请求或目标执行；只新增本文，不改原结果、代码或其它文档。

父任务确认会话 74984 退出 0。summary：`completed`，1 输入、3 完整、0 草稿，16 次 HTTP、11 次工具、277.067 秒，终态格式/模型/字段/工具/pipeline 异常均为 0，无协议恢复；全部 `verify=0`。不是人工认可、独立准确率或性能实测。

**三入口范围保持，所有导出代码位置与本轮保存证据吻合；但 trace 变长没有解决加载类型和生成器执行条件。** 部分描述新增了错误的消费位置和正则结构表述，不应将“3完整”解释为本轮已修好全部语义问题。

## 1. 原范围与共享证据边界

两轮三原 scope 仍分别是 `sent_tokenize(text)`、条件调用 sent_tokenize 的 `word_tokenize(text)`、直接使用相同 period-context regex 的 `debug_decisions(text)`。v73 各终稿 EP 与所保存原提案对应，后槽保留前槽提案/位置上下文；没有换成其它入口。

| 槽位 | v72 trace / CO | v73 trace / CO |
| --- | --- | --- |
| sent_tokenize | 5 步；CO 为 _slices_from_text 中 finditer | 5 步；CO 为 punkt.py:268–275 模板 |
| word_tokenize | 空；CO 为 _slices_from_text | 7 步；同一268–275模板 |
| debug_decisions | 空；CO 为本方法的 finditer | 3 步；同一268–275模板 |

这是 **同一正则机制的三个入口/调用路径**，不是3个独立漏洞、3个输入或3个独立机制。v73 将共同 CO 统一到模板声明，不能把重复模板及长 trace 当成新增独立缺陷证据。模板定义与应用位置都需要结合阅读，不能把类属性赋值本身称作已运行的正则匹配。

三槽分别使用 call5–8、9–12、13–16 做初稿与自审，所有边界都是 E0001–E0015；`later_shared_evidence_status=recorded`、refs均为空，没有候选后新增源码。followup 均为 `not_requested`，不是本例成功执行了三次补读。共享16次请求/11次工具不能按三行重复计算；边界记录证据身份可用，不保证每段语义已被理解。

## 2. 实际窗口及位置核对

所选行为 SHA 均为 `0b7b076247ec41f9b6b8a94400d48ea299e4b507`（旧 SHA），修复 SHA 为 `1405aad979c6b8080dbbc8e0858f89b2e3690341`。本轮6次 source read：

- 旧 E0008 `punkt.py:254–284`：268–275 正则模板；旧 E0010 `1270–1360`：tokenize、debug_decisions、span_tokenize、sentences_from_text、_slices_from_text，末尾仅有 _realign_boundaries 声明/docstring。
- 旧 E0014 `nltk/tokenize/__init__.py:90–132`：两公共 API；旧 E0015 `punkt.py:280–300`：period_context_re 的缓存返回/编译分支。
- 修复侧 E0009 `punkt.py:254–283`、E0011 `1270–1400`：模板和消费者对照。另 E0007 保存完整 diff，E0003 是输入的公开 patch。

两轮 source read 数均为6，但并非窗口完全相同：v72额外读过旧200–254；v73以修复侧1270–1400代替，并调整编译窗口证据编号。**没有哪轮因此新增 load 实现、加载对象或旧 _realign_boundaries 主体的证明。**

将3条EP、3条CO、15个trace位置分别与v73自己保存的同SHA/source text切片比较：**21/21逐字一致**（各槽7/9/5）。EP/CO与trace及不同槽之间大量重叠，不能把21称作独立内容样本。所有正式位置在旧SHA；debug理由引用修复侧E0011作对照，不是把修复行号放入旧trace。

## 3. 加载类型与条件性调用链：表达趋同，证据未闭合

E0014:106–107只显示 `load("tokenizers/punkt/...")` 后调用 `tokenizer.tokenize(text)`。两条API的最终reason都承认具体Punkt类型依赖公告、docstring和路径，未读load实现/对象。v72曾对同样前提一条保留trace、另一条留空；v73两条都保留trace并说明相同类型依据，**口径更接近，但不是类型已由源码独立证明**。

单看trace desc仍容易丢掉该限定，应连同reason展示为文档所述Punkt对象前提下的静态局部链。word_tokenize在 `preserve_line=False` 时才调用sent_tokenize；默认false并不等于调用者不能传true。v73 EP保留了默认条件，不能将trace中的“since defaults to False”扩大成所有调用都会进入Punkt。

## 4. 生成器条件没有真正修好，且出现具体描述错误

1. **错误消费位置。** 两条API的tokenize trace称外层 `list(self.sentences_from_text(...))` 在消费“that generator”。但E0010:1334的sentences_from_text实际返回 **list comprehension**；真正消费span_tokenize生成器的是这个列表推导，外层list接收的是已物化列表。整体有消费过程不等于该句对对象/位置的描述正确。
2. **未读 _realign_boundaries 主体。** sent trace说默认分支的切片生成器“is consumed by _realign_boundaries”。E0010只读到该方法1351起的声明/docstring（1360），未读其主体；已见的是调用及随后遍历返回值，不能把调用本身当成已证内部消费。`realign_boundaries=False`时直接遍历slices的局部分支则有实际代码。
3. **debug仍漏惰性前提。** E0010:1293明确含yield；调用debug_decisions本身返回生成器，开始迭代它才执行1287的finditer。v73 EP、trace及最终reason没有补上该消费条件，仍以“debug_decisions(text) consumes...”笼统描述。未部署/未验证外部可达性的免责声明不是这个执行前提的替代。
4. **编译是条件分支。** E0015:283–294先尝试返回缓存，异常分支才编译。debug trace只摘286–293，说法应限定为缓存未成功返回时的编译路径；不能暗示每次finditer前都重新compile。
5. **正则结构说错。** word条目的CO desc称前导 `\S*` 与SentEndChars处于“inside the lookahead alternation”；E0008显示二者在随后 `(?=...)` 之前，只有NonWord/空白后token的选择位于该lookahead内。模板位置正确不使这句结构说明正确。

这些均可从本轮已经保存的源码判定，不需要执行generator、重新请求模型或猜测目标环境。它们不推翻所有局部函数/模板证据，但意味着“生成器消费条件已改善”不能直接作为通过结论。

## 5. 版本、影响与最小剩余项

旧模板、编译/使用位置、前后patch/diff有实际支持，不只依赖修复父关系。三条保留 `behavior_at_revision`，没有把旧SHA映射到发布范围 `<3.6.6`。复杂度、catastrophic backtracking耗时和具体部署可达性均未执行验证；原提案里的强影响措辞只是提案/公告归因，不能当作本项目测得的性能证据。

最小剩余是统一条件性类型/调用链展示，准确区分列表推导消费、生成器创建/迭代、未读helper和缓存分支，并改正正则结构描述。保留三入口与同一机制的计数区别；无需换材料，也不以更多trace条数替代这些语义校对。原始v72/v73条目与验证标志不变。
