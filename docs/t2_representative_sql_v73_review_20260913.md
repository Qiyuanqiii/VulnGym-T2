# SQL 多候选 v73：范围、证据时间与内容复核

## 范围与结论

只读已结束的 `D:\VulnGym-bv2-runtime\t2-representative-20260913\01-sql-v73` 中 summary/review/actions，并与 `01-sql-v71` 保存的同输入 `GHSA-F3F2-MCXC-PWJX` 比较。本轮 SQL 的前次基线是 **v71，不是 v72**。没有新增目标源码、网络、模型请求或目标执行；只新增本文，不改代码、原结果或其它文档。

父任务确认会话 95118 退出 0。summary：`completed`，1 输入、3 槽、1 完整、2 草稿，16 次 HTTP、12 次工具、298.168 秒；终态格式/模型/字段/工具/pipeline 异常均为 0，无编码拒收。所有条目 `verify=0`。共享使用量只在首行承载，后两行 `model_calls=0/tool_calls=0` 不表示它们未经过模型判断；须结合各自 model-call 边界，不能逐行重复计算总使用量。

**重复 UPDATE 槽位在本次真实输出中消失，原提案和证据时间也可回读。** 但完整数仍是 1，且由 v71 的 DELETE 换成 v73 的 UPDATE；这是读取窗口和判断发生变化，不是三个数据库节点均提取完成，更不是三项独立漏洞或准确率。

## 1. 三槽原范围与最终操作对应

v73 的 `input_actions.candidate_plan` 记录 proposed=5、selected=3、omitted=2、duplicate=0。三条 `candidate_provenance.original_proposal` 保存了所选提案全文与来源；未保存的两项范围不能从数量推断。

| 槽位 / entry_id | v71 最终操作 | v73 原提案 → 最终操作 | v73 状态 |
| --- | --- | --- | --- |
| 1 / entry-67033 | UPDATE，GenericFunctions 182–195，与槽2重叠 | MSSQL INSERT 的 table/column 标识符 → INSERT 166–168 | 草稿，EP 空 |
| 2 / entry-00000 | 同一 UPDATE，185–195 | MSSQL UPDATE 的 updateKey/columns → UPDATE 185–197 | 完整候选 |
| 3 / entry-00001 | MSSQL DELETE，222–226 | MSSQL DELETE 的 deleteKey → DELETE 222–224 | 草稿，EP 空 |

三条 v73 最终 CO 都与各自已保存提案相符，没有再出现 INSERT 槽漂移成另一个 UPDATE。槽2的 `previous_candidates_context` 保留槽1提案及源码坐标；槽3保留前两槽。同 SHA 的三个不同操作路径可分别描述，但共享标识符处理机制；不是三份独立缺陷证据。

v71 没有 `candidate_provenance`，只留了候选数量，不能重建那轮每个原提案。因此可确认 **v73 本轮原提案保持、v71 最终重复未再出现**，不能冒称已证明两轮最初选题完全相同。`scope_retained=true` 只表示压缩保留范围，不单独构成语义验收。

MySQL/PostgreSQL 在 v73 分别只有 E0010/E0011 的 helper 1–200 阅读，三条所选原提案本来就都是 Microsoft SQL；不能把候选数当成三个数据库节点的覆盖数，也无需为凑数强制每个节点输出一条。

## 2. 证据边界不再靠最终共享列表倒推

| 槽位 | 调用时可用证据边界 | 结束及后续共享 |
| --- | --- | --- |
| 1 | call4/5 初稿到 E0011；call6 followup 到 E0013；call7/8 自审到 E0015 | slot_start=11、slot_end=15；later_shared=[] |
| 2 | call9–12 初稿/自审始终到 E0015 | slot_start=end=15；later_shared=[] |
| 3 | call13–16 初稿/自审始终到 E0015 | slot_start=end=15；later_shared=[] |

槽1初稿之后，自动 E0012 取得同文件完整 diff，E0013 读取修复侧窗口；call6 搜索 insertOperation 得 E0014，再由有界导航真实读取旧 handler E0015。因此槽1自审确实已有 E0015，终稿 EP reason 也明确承认 insert 分支已读，只保留 createTableStruct 缺口。

这不同于 v71 槽1先评估“handler 未读”、后来其它槽新增 handler 后最终 evidence 列表变化。本轮后两槽没有新增 receipts，没有倒算后来证据的空间；每次边界仍只说明保存证据身份可用，不代表所有字节都完整可见，更不代表评估必然正确。

## 3. 真正读到了什么，仍漏了什么

所有候选的行为 SHA 为 `9ce3ac092cf7339f3c4a416cdea6e5fa2d5b22b9`（下称旧 SHA），公告关联修复 SHA 为 `f73fae6fe7fc34907bba102648a9997186aa4385`。

- E0007 旧 `GenericFunctions.ts:77–107`：formatColumns 按逗号拆分、trim 后加方括号。E0009 本轮从 **108** 起读到 260，而 v71 从 150 起；本轮实际补到了 117–124 的 escapeTableName：trim 后若已有首尾方括号则原样返回，否则包装；没有转义嵌入的 `]`。不能省略这个条件写成总会重新包裹。
- E0006 整份 diff 被截断；E0012 按 GenericFunctions 文件得到完整 diff，展示 escapeIdentifier、表名处理及 UPDATE/DELETE 标识符处理变化。E0013 修复侧 186–221 实际覆盖新的 UPDATE。旧操作机制不再仅凭父关系推定，修复后行号也没有拼接到旧 SHA 位置。
- E0015 旧 `MicrosoftSql.node.ts:238–350` 补到 247 的 execute 声明、248 凭据和252输入，v71 255–367 没有这些前文；但新窗口较早结束，**没有 v71 已读到的后续 deleteOperation 调用**。本轮不能拿 v71 的 354 行补到自己的 evidence。
- `createTableStruct` 正文仍没有 source receipt；`executeQueryQueue` 也只在 E0007 看到77起的尾段，而非完整声明/循环。文件已读不等于这些更早的 helper 主体已读。

本次补齐的 handler 入口前文改善了 UPDATE 的边界证据，但请求窗口止于350导致 DELETE 调用连接丢失；E0015 的 `truncated=false` 不表示已经读完函数。草稿不是目标源码不存在，而是本轮实际窗口没有覆盖。

## 4. UPDATE 完整候选：位置和局部语义成立，值传递不能过度宣称

按 v73 自己保存的同 SHA source text 切片比较，EP 323–335、CO 185–197、trace[0] 323–335、trace[1] 182–197 **4/4 逐字一致**。其中 EP 在 trace 重复、CO 被 trace[1] 包含，仅是两段不同源码区域，不是4份独立内容证据。

E0015:323–335 确实读取 node parameter `updateKey`、把相关参数交给 createTableStruct，再调用 updateOperation；E0009:176–201 确实展示 callee 中 `item.updateKey` 与列名被拼入条件/SET，然后 request.query。参数值通过 `request.input` 绑定，与标识符文本插值是不同处理，不能缩写成所有输入均未处理。E0012 的修复 diff 对这些具体插值提供相应对照。

然而 **“外部 updateKey 如何成为 tables 内 item.updateKey”仍取决于未读 createTableStruct**；caller 与 callee 同时存在不证明中间转换原样保留。最终 EP/trace reason 明确承认 helper 未读，所以可据此表达局部参数读取、分派和查询构造，但不能仅展示两步 trace 就宣称外部标识符已独立闭合地流入查询。尚无本轮源码反证推翻所描述的局部插值，也不足以把所有端到端必要前提判为通过。

凭据、pool 连接和相应 operation/循环分支等可见条件应保留；工作流创建/编辑权限和数据库身份来自公告/配置前提，未验证具体部署。`behavior_at_revision` 与发布范围严格分开：当前 receipts 未将旧 SHA 映射到公告 `<2.4.0`，不能宣传为该范围的独立验证。

## 5. 两条草稿及剩余问题

- INSERT：真实 query-build 和局部 identifier helpers 有支持；EP/trace 保留 createTableStruct 的外部 table/columns 读取缺口。最终理由已经根据本槽内新 handler 证据更新，未继续沿用“handler完全未读”。
- DELETE：E0015:340–350 已读取 table/deleteKey 并构造分组，E0009:206/222–226 已有消费；中间 `deleteOperation(tables,pool)` 调用在本轮所有保存窗口之外。留空有真实范围依据，不能用旧轮完整结果强补。
- 范围重复减少和 provenance 可用已获本轮证据；helper/消费者相邻窗口的读取仍需收尾。不能以“1完整2草稿”掩盖进步，也不能据此宣称多候选的输入到关键操作语义全已达标。

本复核只保留事实和缺口，不修改任何原条目、scope、验证状态或调用计数；不启动额外测试。
