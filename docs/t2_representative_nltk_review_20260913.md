# NLTK 新材料 v72：候选范围与内容复核

## 口径与终态

复核目录：`D:\VulnGym-bv2-runtime\t2-representative-20260913\02-nltk-v72`。输入是预选的 `GHSA-F8M6-H2C7-8H9X` 原公告加其公开引用 patch；这是首次生成该材料的代表性运行，但选材时看过公告，不是盲测。

只读已结束运行的 `summary.json`、`entries.jsonl`、`review.jsonl`、`reports.jsonl`；对位置的复核仅与已保存的公共 source receipts 比较。本次没有额外读取目标仓源码、没有网络/付费请求、没有加载 pickle 或执行目标，也没有改写原结果。这里是 AI 辅助静态内容复核，不是人工认可或独立准确率。

父任务确认统一会话 33657 退出 0。保存终态 `completed`：1 输入、3 完整候选、0 草稿，16 次 HTTP、11 次读取工具、318.859 秒；格式/模型/工具/pipeline/当前字段协议异常数均为 0。`reports.jsonl` 在同一个报告下关联这三条 entry，`verify=0`，人工确认数为 0。

## 1. 原提案与实际范围

| 槽位 / entry | 原提案 | 最终 EP / CO | 范围判断 |
| --- | --- | --- | --- |
| 1 / `entry-20579` | `sent_tokenize(text)` 通过加载的 tokenizer 到 Punkt sentence 路径 | `__init__.py:96–107` → `punkt.py:1336–1339` | 保持原提案；trace 5 步，但加载对象的具体类仍为文档/公告前提 |
| 2 / `entry-00000` | `word_tokenize(..., preserve_line)` 在 `preserve_line=False` 时进入 sentence 路径 | `__init__.py:114–132` → `punkt.py:1336–1349` | 保持原提案；明确条件分支，没有错误声称所有调用都进入该路径 |
| 3 / `entry-00001` | `PunktSentenceTokenizer.debug_decisions(text)` 自己使用同一个 period-context regex | `punkt.py:1279–1288` → `1287–1288` | 保持原提案；不是后来从另一范围漂移过来的 tokenization 入口 |

所有位置都属于选定 SHA `0b7b076247ec41f9b6b8a94400d48ea299e4b507`。本轮没有出现 SQL 首轮那种同一 UPDATE 范围被两个近乎相同提案/结果重复计数的问题。

但三条是**同一个公告/CVE、同一正则机制的不同入口记录**：word_tokenize 条件性调用 sent_tokenize，两者共享 `_slices_from_text`；debug_decisions 在另一方法直接使用同一个 pattern。它们不能算三个独立漏洞、三个输入成功或三个独立机制。`reports.jsonl.num_entries=3` 作为入口条目数有意义，作为缺陷数量则没有。

## 2. 证据时间边界已可核对

本轮每条 `candidate_provenance` 都包含原提案、上一槽范围摘要、槽位起止及逐模型调用证据边界：

- 3 个槽位的 `slot_start`、`slot_end` 均准确对应 E0001–E0015，15 个 ID，与最终 evidence 清单逐项相同。
- 槽位 1 的调用 5–8、槽位 2 的 9–12、槽位 3 的 13–16，各调用前记录均为 E0001–E0015。
- 三条 `later_shared_evidence_status=recorded` 且 `later_shared_evidence_refs=[]`。这里不是边界缺失，确实没有后续候选新增 source 又倒算成早期评估证据的情况。
- 上一槽提案及坐标是防止范围漂移的上下文，不是独立证据；“调用前可用”也不等于每字节都进入当时上下文或已成功理解。不能借这些时间标记提升语义置信度。

## 3. 版本与机制支持

证据链不是只有修复父关系：

- E0006 给出修复 `1405aad979c6b8080dbbc8e0858f89b2e3690341` 的父为选定 SHA；该关系仅用于导航。
- E0008 在选定 SHA 的 `punkt.py:254–284` 展示 `_period_context_fmt` 包含 `\S*` 前缀；E0011 `280–300` 展示 `period_context_re` 使用这一模板编译、缓存并返回正则。
- E0010 `1270–1360` 展示 `tokenize`、`sentences_from_text`、`span_tokenize`、`_slices_from_text` 和 `debug_decisions` 的调用/使用位置。
- E0007 是同文件前后完整 diff，E0003 是输入包中的公开 patch；都展示移除该前缀，并调整两个消费位置处理上下文的方式。E0009 还读取了修复后模板片段，不是仅凭补丁标题推断旧行为。
- 原公告 E0002 将此问题归为 ReDoS，报告 `<3.6.6` 受影响。三个候选均使用 `behavior_at_revision`，明确没有把该 SHA 映射到发布范围。

因此“该旧快照包含公告讨论的模式及消费位置”有多种保存材料支持；**运行耗时、复杂度阶数、所有部署均可被外部输入触达**没有经过本运行验证。不要把公告中的性能描述或模型使用的 `catastrophic` 词变成本项目测得的结果。

## 4. 位置和关系核对

按选定 SHA、文件、保存窗口边界取原文，比较 3 条 EP、3 条 CO、槽位 1 的 5 个 trace 位置：**11/11 与对应 source receipts 逐字匹配**。这是保存位置一致性，不是独立仓库重读或语义正确率。

### sent_tokenize

E0014 `__init__.py:90–132` 直接显示接收 text、加载 tokenizer、调用 `tokenizer.tokenize(text)`。E0010 显示 Punkt 实现内 tokenize → sentences_from_text → span_tokenize → _slices_from_text → finditer 的相关语句。保存的 5 步 trace 不是凭空写出的函数名；函数体与各调用位置都存在。

不过，从 `load(...)` 返回对象到 PunktSentenceTokenizer 的运行时类型，原模型仅依赖 docstring/公告归因，没有读取加载实现或对象。导出的 trace 理由承认这个前提。应展示为**在文档所述 Punkt 对象前提下的条件性静态链**，不是完整源码独立闭合的动态链。原始 trace 的各步 desc 自身没有充分重述此限定，交验时需要连同 review reason 使用，不能只拿 entries 的数组宣称所有连接均已独立证明。

此外 `_lang_vars` 的初始化/可替换性没有在这些 receipts 中完整建立；默认 Punkt 模式的归因来自类文档、模板和 patch，而不是对所有自定义 tokenizer 实例的普遍证明。

### word_tokenize

E0014 的 129 行明确 `preserve_line` 为真时直接使用 `[text]`，为假时才调用 sent_tokenize，最终 EP 描述正确保留该条件。CO 与 sent_tokenize 共享 `_slices_from_text`，是同机制的入口差异，不是不同缺陷。

该条 `trace=[]` 的理由是加载对象具体类型未读。这与槽位 1 在相同前提下仍保留 5 步 trace 的严格程度不同：不是两个互相矛盾的源码事实，但**表达/置信口径不一致**。后续最小修正应统一展示条件性链或只展示证实的局部段，不应为使两条看起来一致而编造加载对象类型。

### debug_decisions

E0010 直接显示方法参数 `text` 和同方法内 `period_context_re().finditer(text)`；其范围确实不同于 sentence 路径。原理由还明确没有读取生产调用者，因此不能由 public 方法存在推出任意部署外部可达。

还有一个应补充的执行前提：E0010 中该方法含 `yield`，是 generator；调用方法本身返回生成器，**消费/迭代该生成器时**才执行包含 finditer 的主体。当前 EP/CO desc 只写“传给/应用正则”，没有说明惰性执行。代码位置正确，但若演示说明写成“只要调用即开始执行”就过强。这里建议在用户可读内容说明中明确该条件；不需要运行生成器来补一个数字。

## 5. 结论和最小后续

本轮给出了积极且具体的证据：新输入包能正常处理，原候选范围可回读且没有漂移，多个入口共享机制可从源码关系区分，真实位置齐全，read/assessment/self-review 阶段正常结束。**不是 3/3 独立漏洞准确率，也不能称所有语义前提已经完成。**

需要保留/补充的最小内容限定只有：同一机制多个入口的计数、Punkt 加载对象前提与 trace 口径、debug generator 的消费条件、发布范围未映射及性能未执行。没有发现需要推翻全部输出、换材料或重新大修提取系统的证据；后续若修正机器说明，应另存新结果，保留这一原始成功运行及本复核。
