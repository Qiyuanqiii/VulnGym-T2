# 新材料结果的有界内容复核（2026-09-13）

## 复核口径

这是对已结束运行的保存材料进行的 **AI 辅助静态内容复核**，不是人工验收、独立准确率评测、目标程序执行或全仓扫描。输入集合在付费生成前固定，但公告已用于选材，因此不是盲测。不得把 `complete`、`supported`、源码逐字匹配或本复核等同于完整语义正确；导出的 `verify` 仍为 `0`。

只读保存的 `summary.json`、`entries.jsonl`、`review.jsonl`、`reports.jsonl`，必要时对其中明确的公共缓存 SHA/文件做普通 `git show`。没有网络、LLM 请求、目标执行；没有读取 benchmark private、gold、selection_lock 或原始 source-map；没有改写运行结果。下文把**模型原本读过的材料**与**本次复核新增查看的片段**分开记录。

## A. SQL 多候选：v71 首轮

运行目录：`D:\VulnGym-bv2-runtime\t2-representative-20260913\01-sql-v71`。

公告：`GHSA-F3F2-MCXC-PWJX`，n8n MySQL/PostgreSQL/Microsoft SQL 标识符处理；输入形式为 URL，经本地缓存和仓库映射读取。`summary.json`：运行 `completed`，1 个输入、3 个 review 槽位、1 条完整导出、2 条草稿，输入状态 `partial`，15 次模型 HTTP 请求、12 次读取工具调用，格式/模型/读取错误均为 0，人工确认数为 0。`reports.jsonl` 仅关联完整的 `entry-00001`，没有把草稿算入已交付条目。

### A1. 候选数量与独立范围：未通过

| 槽位 / 标识 | 实际保存范围 | 结果 | 内容判断 |
| --- | --- | --- | --- |
| 1 / `entry-67033` | MSSQL `updateOperation`，`GenericFunctions.ts:182–195`，EP 空 | 草稿 | 与槽位 2 重复；不是独立的 MySQL 范围 |
| 2 / `entry-00000` | 同一 MSSQL `updateOperation`，同文件 `185–195`，EP 空 | 草稿 | 相同修订、重叠关键位置、相同 `updateKey`/column 标识符机制，没有保存证据支持独立计数 |
| 3 / `entry-00001` | MSSQL delete 分支，`MicrosoftSql.node.ts:340–354` → `GenericFunctions.ts:222–226` | 完整候选 | 与 UPDATE 是不同操作路径；不是 PostgreSQL/MySQL 覆盖证明，也不是独立 CVE 数量 |

三个槽位的选定版本均为 `9ce3ac092cf7339f3c4a416cdea6e5fa2d5b22b9`。槽位 1 和 2 都描述原始 `item.updateKey` 和括号包裹 `col` 被用于 UPDATE 文本；起始行不同不足以证明两个独立候选。保留原始结果，不在本复核中删除草稿；后续应由生成流程记录范围并防止重复/漂移。

`input_actions` 的 `candidate_plan` 只保留 `proposed_count=3`、`selected_count=3`、`duplicate_count=0` 等数量，所读四份产物中没有每槽原始候选范围，不能据此重建最初到底计划拆哪个节点。MySQL、PostgreSQL 各有一个 helper 的前 200 行 receipt（E0010/E0011），但没有形成这两个节点的独立 EP/CO 结果。**本轮只证明多槽流程能运行，不证明拆分质量或三个数据库节点都已覆盖。**

### A2. 完整 delete 候选：局部代码有支持，整体主张有限

保存证据：

- E0002：原始公告；公告描述有工作流创建/修改权限且可访问数据库凭据的背景，标识符来自节点配置，受影响范围 `< 2.4.0`。这些是公告归因，不是本运行独立执行验证。
- E0005：修复 SHA `f73fae6fe7fc34907bba102648a9997186aa4385` 的父为选定 SHA。父关系仅作为导航；不能仅凭父关系证明缺陷。
- E0009：选定 SHA 的 `packages/nodes-base/nodes/Microsoft/Sql/GenericFunctions.ts:150–260`。`deleteOperation` 从 `tables[table]` 的键取得 `deleteKey`（205–206），参数值经 `request.input` 绑定（217–220），标识符直接进入 DELETE 文本（222–224），随后交给 `request.query`（226）。这是参数值绑定与标识符文本处理的区别，不能把两者混为“所有输入都未处理”。
- E0015：同 SHA 的 `packages/nodes-base/nodes/Microsoft/Sql/MicrosoftSql.node.ts:255–367`。分支条件为 `operation === 'delete'`；342–343 读 table/deleteKey，351 按这些键存放 item，354 调 `deleteOperation(tables, pool)`。窗口还显示先连接 pool 并可能在错误时返回/抛出，不能描述成无条件执行。
- E0012：上述 GenericFunctions 文件的完整定向 diff，显示新版本在旧 deleteKey 插值位置加入 `escapeIdentifier`。这与选定旧版本的局部机制一致。

本次普通 `git show` 按选定 SHA 复核了完整候选 EP（340–354）、CO（222–226）和两个草稿 CO（182–195、185–195）：**4/4 保存代码片段与指定文件行逐字匹配**。这只证明位置真实性。

限定与问题：

1. 完整候选的 `commit.revision_basis=behavior_at_revision`，理由明确 `< 2.4.0` 的发布范围与该 SHA 尚未映射。局部旧版本机制有代码支持；不得写成已独立确认全部受影响发布版本。
2. 模型原 source receipt 没有覆盖 `execute` 声明（在 E0015 前方），EP reason 已承认。该完整候选支持“本地分支读节点参数并调用 helper”，不支持独立核实整个框架权限/外部可达链路。公告中的工作流权限、凭据前提需要随交验说明保留，不能把 `entries.jsonl` 单行当成无条件外部入口证明。
3. `trace=[]`，reason 也承认没有给出完整连续链路。空数组不会制造错误，但**本条不能充作 trace 自动构建成功样例**。保存窗口已经覆盖局部 key 传递、调用与消费，可改进这类有证据的局部 trace 构造；不得用未读框架步骤填满它。
4. CO reason 中 “no identifier escaper exists in this parent file” 是超过已读完整文件范围的全称措辞：原 source windows 只有 77–107、150–260。更稳妥的是指明“224 的 deleteKey 插值没有经过标识符转义调用”，不把部分窗口说成全文件无此功能。

### A3. 两条草稿：主要是漏读、重复和共享证据更新问题

- 槽位 2 明确说明 E0015 已读 updateKey 参数及调用（323–335），但 `createTableStruct` 如何把参数传到 `item.updateKey`、以及外层声明未读，因此 EP 为空。这是具体可定位的证据缺口，不是无法取得源仓。
- 槽位 1 的最终 EP reason 仍说“没有 saved read 覆盖 MSSQL handler”，但其最终 `evidence` 已共享包含 E0015。槽位 2/3 后续读取了 handler；槽位 1 的先前判断没有随共享新增材料重审。因此这是**评估时证据与最终共享证据不一致的过时理由**，不能当成当前材料确实不存在。
- 原读取有 `read_context_closed=reserve_annotation_review_context`，后续部分 `evidence_followup_skipped=reserve_review_context`。留空受到运行预算/上下文调度的影响；草稿状态本身没有宣称缺陷不存在。

为核对“缺材料还是漏读”，本次仅追加只读查看同一已保存 SHA/两文件，未加入模型 receipts，也未回填输出：

| 复核新增窗口 | 实际内容 | 与原覆盖关系 |
| --- | --- | --- |
| `MicrosoftSql.node.ts:247–255` | `async execute(this: IExecuteFunctions)`、读取 Microsoft SQL 凭据、`getInputData`、配置 pool | 原 E0015 从 255 起，缺的声明/初始化就在邻近位置 |
| `GenericFunctions.ts:36–61` | `createTableStruct` 读取 table/columns/keyName 参数，经 `itemCopy[keyName] = keyParam` 写入后加入分组 | 原 E0007 从 77 起、E0009 从 150 起，不含该主体 |
| `GenericFunctions.ts:69–87` | `executeQueryQueue` 遍历表/列分组并把 table/columnString/items 交给 buildQueryQueue | 原 E0007 仅见该函数尾部 77 起，未完整覆盖声明/控制范围 |

这三段公开缓存内容存在，支持下一版修正通用补读与证据更新策略；它们**不能追认成原模型已完成的阅读或自动 finalized 成绩**。

### A4. 结论与下一步验收证据

首轮 SQL 不通过“可靠多候选拆分”的内容验收；已获得一个有局部源码支持的完整 delete 候选，但仍为 `verify=0`，不代表人工认可。重复 UPDATE 槽位不能增加覆盖数。

后续应核对：每个候选范围可回读、同范围不重复、原范围未读时不漂移到已熟悉的另一个范围；补读已知 helper/近邻声明并只更新受影响的判断；以新输出目录复测，保留本次失败证据。不是要求强行输出 MySQL/PostgreSQL/MSSQL 各一条，也不是要求所有不确定字段都变完整。

## B. 其他预选新材料

尚待各运行结束后追加内容复核。不得用 A 的局部结论外推 NLTK 共享机制、跨组件依赖或 crawler 输入边界案例。
