# SQL 多候选 v79：保存结果内容复核

复核日期：2026-09-13。对象为已终态的 `D:\VulnGym-bv2-runtime\t2-representative-20260913\01-sql-v79-low`。仅阅读其中的 summary、review、actions 及 review 内保存的公共源码回执；没有补读目标源码、联网、调用模型、执行目标或修改原结果。本文是 AI 辅助内容复核，不是人工认可、盲测成绩或整体准确率。

## 结论

本轮解决了“自检阶段没有正常返回”的技术中断，并实际撤回了一个缺乏依据的完整判断；但没有产出可交付的完整 SQL 条目。三条草稿的原因不完全相同：前两条对原提案的缺陷前提保持不确定，有反证依据；第三条的对应操作本体仍未读，是阅读覆盖缺口。不能把三条都说成技术失败，也不能把三条都包装成已完成充分分析后的正确弃答。

## 运行与输出事实

- 统一会话 36377 退出 0；`summary.status=completed`；15 次 HTTP、13 次工具调用、269.516 秒；本轮请求全部成功，`provider.halted=null`。
- 1 份输入、3 个已处理候选，0 完整、3 草稿；三槽均 `initial_draft_status=accepted`、`self_review_status=completed`。`entries.jsonl` 为 0 字节。
- model/tool/pipeline/format/annotation 错误与 read-plan/encoding 拒收均为 0。各槽仍有 `model_uncertain` 字段诊断，不应混称为模型请求错误。
- 三槽最终 `commit`、`entry_point`、`critical_operation` 都为 null，`trace=[]`；值的建议/理由留在复核数据，不冒充正式字段。`verify=0`，没有人审通过声明。
- 本次生成 6 个提案、选取 3 个、遗漏 3 个，控制器记录重复数 0。遗漏槽未被处理，不能计作 3 条失败；该去重计数也不证明已选槽对应 3 个独立漏洞。

## 候选范围与证据时间

三个槽来自同一公告 `GHSA-F3F2-MCXC-PWJX`，不是三份独立公告。原提案的范围保存在 `candidate_provenance.original_proposal`，最终没有偷换为其他操作以补齐结果。

| 槽 | 原提案范围 | 初稿可见证据 | 自检可见证据 | 终态含义 |
|---|---|---|---|---|
| 1 | MySQL deleteTable 的 delete 分支，table / where column 与标识符转义 | calls 4–5，E0001–E0013 | calls 6–7，E0001–E0015 | 初稿曾支持缺陷；见局部修复反证后撤回 |
| 2 | MySQL select 的 table / outputColumns | calls 8–9，E0001–E0015 | calls 10–11，E0001–E0016 | 从初稿即不确认标识符转义缺陷 |
| 3 | PostgreSQL deleteTable 的 delete 分支，table / where column | calls 12–13，E0001–E0016 | calls 14–15，E0001–E0016 | 对应操作文件未读，不借用 MySQL 实现填空 |

E0014 是完整的 MySQL helper 文件前后 diff；E0015 是 fix 侧 helper 的实际窄窗。二者在槽 1 初稿后、该槽自检前加入，不能说初稿已评估它们。E0016 是槽 2 的全库 `execute` 导航搜索；对于槽 1 仅属于 `later_shared`，并未参与其自检。槽 3 没有补入新的源码证据。

与 v78 high/low 的已存失败不同，本轮三个已选槽都完成了自检，没有截断或传输失败。各轮选择的槽和范围并不完全相同，不能用完整数直接计算同题配对准确率提升。

## 前两槽：撤回有依据，但不是证明不存在问题

E0010 保存 base `9ce3ac092cf7339f3c4a416cdea6e5fa2d5b22b9` 的 MySQL `helpers/utils.ts` 1–200；E0012/E0013 分别保存 deleteTable 1–139、select 1–133 的完整操作文件。实际看到了参数读取、SQL 构造、helper 调用及向 `runQueries` 交付查询。

槽 1 初稿把 helper 23–37 解释成“只套反引号，所以可终止引用”，并据此支持 commit、EP、CO、trace。自检在 E0014/E0015 出现后撤回了这个论断；槽 2 同样保留 unknown。撤回有以下具体依据：

- 旧 helper 并非简单给原字符串两端加引号：它用 `` /(`[^`]*`|[^.`]+)/g `` 匹配、trim，保留已加反引号的匹配段，否则加反引号，最后按点连接。原提案省略了这些行为，不能据那一句描述建立缺陷。
- E0014 未截断的文件 diff 没有修改 `escapeSqlIdentifier`。实际变化包括把 sort direction 限制为 ASC/DESC，以及新增 where-clause 类型/condition 允许集合检查；E0015 的可见函数主体与旧侧相同。E0015 到 37 行，未含函数结束花括号，完整文件 diff 才补足“此函数未被该补丁修改”的依据。
- 因而“这个补丁修复了这里的标识符转义”不被保存证据支持；但函数没改也不等于证明任何输入都安全，更不能推翻公告。最终理由中“反引号被切掉”的概括只适用于非引用匹配部分，已引用段会原样保留，不应升级成全面安全结论。

仍未读到 MySQL `runQueries` 的消费实现、相关 helper 的全部调用路径，以及公告 `< 2.4.0` 与所选 SHA 的版本映射。E0005 只证明该 SHA 是 fix 的 parent；最终没有把 fix SHA 当作受影响版本，也没有把 parent 身份直接当成受影响证明。槽 1 的 `revision_basis=behavior_at_revision` 与 `status=uncertain` 并存，理由明确表示该依据未满足，不代表已选定有效 commit。

已见行为的限定也应保留：delete 槽只评 delete 分支，不能扩到 drop/truncate；select 中只有 outputColumns 不含 `*` 才逐列转义，查询之后还经过 where、sort 和可选 limit。登记/dispatch 未读可以列为缺口，但本轮否定完整性的主要原因是原缺陷前提未立住，不是“没有查到注册就必定不是入口”。

若继续围绕 E0014 中 condition/direction 的变化定位，需要明确重提/修订候选范围并保留原范围，不能把 table/outputColumns 槽悄悄改成另一个机制。共享 helper 的多个操作用途也不应自动计作独立漏洞数量。

## 第三槽：诚实保留了未知，但漏读仍在

E0005 已列出 `Postgres/v2/actions/database/deleteTable.operation.ts` 的准确 changed path。E0011 实际读的是 Postgres `helpers/utils.ts` 1–200，而不是该操作文件；其中 `addWhereClauses` 给 column 生成 `$N:name` 占位符并收集 values。这不足以证明提案中借用的 MySQL `escapeSqlIdentifier` 构造存在于 PostgreSQL 路径。

本轮没有读到 PostgreSQL deleteTable 的参数读取、构造与最终消费，也没有针对该文件的未截断 diff。因此将 EP/CO/commit 留空、不把 MySQL 的位置搬给 PostgreSQL，是正确的输出约束；但把“没有读到”当作“材料无法获得”则不正确。已保存的明确文件线索尚未被用完，读取本体后可能支持、否定或修订提案，当前不能预判。

输入公告还有“已认证、可创建/修改工作流、能使用数据库凭据”的条件。它们保留于 E0002，但没有独立验证；三条草稿不能对外简化成无前提的外部入口问题。对数据库侧名称格式化的真实语义，本轮也没有独立读证据。

## 最小下一步

本轮初读关闭记录为 `reserve_annotation_review_context`，当时 `result_allowance_chars=2359`；三槽补读都被 `reserve_review_context` 跳过。槽 2 却进行了全库裸 `execute` 搜索：候选/扫描文件 13837，结果截断，所存窗口主要是 changelog 等无关命中，终止为 `no_usable_reference_hit`。这不是工具失败，也不是有效的操作本体阅读。

最有效的改进是：在现有预算内把一次泛词导航换成已选候选的缺失操作本体或关键消费者窄读，并给该读保留实际可见窗口；遇到明确反证时允许记录范围修订需求，而不是继续堆高否定措辞。优先补第三槽已知路径，再决定是否值得复核其他未证链路。本文未实施这些额外读取，也不据此承诺必能生成完整候选。

交验表述应为：**SQL 多候选流程本轮技术跑通、自检纠正了过强结论；仍无完整 SQL 条目，前两槽存在原提案反证，第三槽存在可继续改善的源码阅读覆盖不足。**
