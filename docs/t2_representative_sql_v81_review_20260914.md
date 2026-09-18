# SQL v81 代表性回归内容复核

日期：2026-09-14。对象为 `D:\VulnGym-bv2-runtime\t2-representative-20260913\08-sql-v81-low`。本复核只读取保存的公开 summary、review、actions、entries，以及同目录历史 `01-sql-v79-low` 的公开回执作对照；未读取新目标源码，未执行目标代码，未调用模型或联网。它是 AI 辅助内容复核，不是人工认可、独立盲测或漏洞有效性认证。

## 结果与口径

v81 本批 1 份输入、3 个候选：**1 完整候选、2 草稿**，输入状态 partial。16 HTTP、10 个本地工具调用，302.190 秒；summary.status=completed。三个槽位均 initial_draft_status=accepted、self_review_status=completed。

- 模型／流水线／工具／格式／annotation 终态错误均为 0，read_plan_rejection_count=0。
- 编码拒收 1 次：第一槽 draft 缺少根字段，call 6 通过 encoding_shape_review 恢复。不能把终态错误为 0 写成全过程无异常。
- 配置为 deepseek-flash、staged_tool、assessed_tool、plan_tool、thinking enabled、reasoning-effort low、max_tokens 32768、run_request_limit=16、automatic_retries=0；continue_on_format_error=true。
- 本批结束时 summary 记录 2632 次生成；加 1 次历史目录查询为 **2633/3000、余 367**。账本授权字段仍为 3000，但本次 effective_authorization_limit=2999，已限制实际生成总数。
- 旧对照的准确目录是 `01-sql-v79-low`，不是 `03-sql-v79`。旧批为 15 HTTP、13 工具、0 完整＋3 草稿，continue_on_format_error=false。重复材料及单次结果不能当成准确率或泛化提升的证明。

## 读取策略验收：新 probe 没有触发

本批 actions 中没有 candidate_source_probe，也没有 candidate_source_probe_skipped；没有新增 Postgres deleteTable 操作源码。三个槽位的所有 model_call_evidence 都仅有 E0001–E0013，不能宣称新的候选操作补读在实测中成功。

第三槽的原提案确实有 deleteTable 操作名和 E0011、E0005、E0006 引用，但同时写了辅助文件名 `Postgres/v2/helpers/utils.ts`。对保存材料调用纯导航 helper 的结果是 None。仅在内存诊断副本中去掉这段辅助文件名字样后，才能选出既定旧 SHA 的 `packages/nodes-base/nodes/Postgres/v2/actions/database/deleteTable.operation.ts`、1–180 行；没有改变保存材料或运行任何目标读取。

这是导航排序对自然提案措辞的真实边界：已读 helper 的目录接近度高于待读操作，helper 先胜出，随后“已经读过”过滤直接返回 None。此前只复放 v79 的另一种提案措辞，没有覆盖这个表达。应修读取选择，不应靠删改真实提案或把草稿标成完整来绕过。

读取阶段还记录 `read_context_closed / reserve_annotation_review_context / result_allowance_chars=2392`。本次无宽泛 execute 搜索，但也未读到所缺的操作和 helper 后段；这与“没有技术终态错误”是不同的验收项。

## 完整候选：坐标真实，不等于语义正确

唯一完整候选 entry-00000 是 MySQL select 分支，commit 为 `9ce3ac092cf7339f3c4a416cdea6e5fa2d5b22b9`，verify=0。

| 字段 | 保存依据 | 位置核验 |
| --- | --- | --- |
| entry_point | E0013，select.operation.ts 82–86 | 同 SHA，逐字一致 |
| critical_operation | E0013，select.operation.ts 92–97 | 同 SHA，逐字一致 |
| trace[0] | E0013，82–86 | 同 SHA，逐字一致 |
| trace[1] | E0013，92–97 | 同 SHA，逐字一致 |
| trace[2] | E0010，MySql/v2/helpers/utils.ts 23–37 | 同 SHA，逐字一致 |

这 **5/5** 只验证引用窗口。实质问题如下：

1. EP 确实是处理函数读取 table/outputColumns 配置，CO 确实是在同函数内拼装 SELECT 查询，二者有局部参数到查询的关系。但完整候选把缺陷归因于“escapeSqlIdentifier 不转义内部反引号”。E0010 的实际 helper 先用正则分割为内部不含反引号的引用或非引用片段，再逐片段引用、用点连接；不能只看到没有 replace，就推出内部反引号能按所述方式进入 SQL 语法。现有结论缺少对应行为依据。
2. 第一槽对同一 helper 保持 uncertain，并指出未观察到该提案宣称的缺陷；第二槽却将这一前提标为 supported。需要统一证据判断，不能只以第二槽完成导出认定质量提升。
3. E0013:130 的 runQueries 调用本身已经读到，没读到的是其实现。部分 reason 写“query handed to runQueries was not read”，表意不精确。不能把已见调用与未见实现混为一谈。
4. commit 使用 behavior_at_revision，未冒充已有发行版本映射，这是合理的口径区分；但其行为依据正依赖上述尚未证实的 helper 缺陷，因此当前证据不足以确认该字段的 supported 判断。
5. trace 展示的是读取配置、构造查询、所调用 helper 的片段；没有完整展示后续 addWhereClauses、addSortRules、数据库执行关系。记录已经保留了后续关系未建立的说明，但这些说明不能自动抵消前面过强的缺陷断言。

历史 v79 回执 E0014 是同一 MySQL helper 文件的完整路径限定差异，E0015 是修复侧部分源码；该差异没有修改 escapeSqlIdentifier 本体，显示的关键变化是 sort direction 限制和 where clause 验证。它支持“需要检查真实修改位置”的 QA 方向，但**不是 v81 已读到的证据**：v81 只有截断的全局 diff，未读这一完整路径差异，不能将历史内容倒灌为本批能力。

## 两条草稿的剩余缺口

- **MySQL deleteTable，entry-67033**：操作本体 E0012:1–139 已读；helper E0010 只读1–200／总577行，MySQL addWhereClauses 本体未读，当前提案中的缺陷前提未证实。保留草稿有依据，但它仍是已知关键依赖未补读的问题，不是材料完全不存在。
- **Postgres deleteTable，entry-00001**：helper E0011 只读1–200／总657行，覆盖 addWhereClauses 的部分机制；escapeSqlIdentifier、相关查询替换实现和 deleteTable 入口仍未读。它没有错误复用 MySQL 的入口坐标，这是正确的范围隔离；但该已知路径未补读的原始缺口并未解决。

## 结论

本批证明一次初稿编码拒收成功恢复，三个槽位都完成自审；不能证明新的 SQL 操作补读策略已生效，也不能把新增 1 条完整候选算作语义正确性进步。优先修复候选路径选择对“同提案含辅助文件名”的边界，并让真实修改位置、依赖实现进入对应候选的判断。原结果全部保留，不手工改字段，不与其他批次混算成绩。
