# T2 v2 自动运行自评（待人工复核）

本文仅依据已生成的 `summary.json` 与 `review.jsonl` 自动汇总；没有重新访问目标仓库、调用模型或联网。
`supported` 表示带引用的模型判断或控制器事实，**不是独立人工审核或漏洞语义正确的证明**。源码逐字匹配与 schema 通过也不能替代可达性、攻击者可控性和缺陷机制复核。未提供外部独立标签，不计算或宣称 F1、准确率、精确率或召回率。

## 本次实际产出与用量

| 项目 | 已记录结果 |
|---|---|
| 批次执行状态 | completed（执行状态，不是正确性结论） |
| 请求 / 已处理 / 未处理输入 | 1 / 1 / 0 |
| 完整候选 / 草稿 / 输入失败 | 1 / 0 / 0 |
| 模型错误 / 工具错误 / 流程错误总项数 | 0 / 0 / 0 |
| 模型调用 / 仓库工具调用 | 10 / 12 |
| 已记录耗时（秒） | 34.354 |
| 模型 | deepseek-flash |
| 本次 / 同一授权累计 HTTP 尝试 | 10 / 41 |
| 本次 token：输入 / 输出 / 总计 | 58804 / 5799 / 64603 |
| 授权内用量未知的请求数 | 1 |

完整候选仅指通过终检的正式条目；草稿、输入失败与未处理输入不计为完整候选。错误项数可能一份输入含多项，不等于失败公告数。HTTP 尝试包括失败尝试，且不同于模型调用次数。未知用量保持未知，不能把缺失 token 当作零。货币费用未在本报告中独立核算。

逐条 review 实际读取 **1** 条：complete=1，draft=0，input_failure=0。

## 逐报告结果与待解决字段

### 1. GHSA-MQ4R-H2GH-QV7X / entry-75975

- 状态：complete；公告：https://github.com/advisories/GHSA-mq4r-h2gh-qv7x。
- 已知项目 / 标题：Flowise / Flowise Allows Mass Assignment in \`/api/v1/leads\` Endpoint。
- 漏洞 commit：55b6913c03f0dba37cc207975f0c0d0786e0f3c7。
- 入口 EP：packages/server/src/controllers/leads/index.ts，行 22-30；Externally reachable POST handler declared for /api/v1/leads; it only checks that req.body exists and forwards the whole client body unvalidated to the leads service.。
- 关键操作 CO：packages/server/src/services/leads/index.ts，行 28-29；Unfiltered request body is merged onto the Lead entity (attacker-controllable attributes such as chatflowid/chatId/name/email/phone), then persisted via repository.create/save on lines 31-32.。
- 模型 / 工具调用：10 / 12；动作记录中的计划 / 工具 / 草稿 / 自查：8 / 12 / 1 / 1。
- 已记录位置核验：5 / 5 通过（仅为位置与代码的确定性检查）。

| 字段 | 状态 | 已记录理由与证据引用 |
|---|---|---|
| `entry_id` | 已支持（模型/控制器） | Controller-owned input or schema constant; not a model or human verification claim.；引用：controller:entry\_id |
| `report_id` | 已支持（模型/控制器） | Controller-owned input or schema constant; not a model or human verification claim.；引用：controller:report\_id |
| `source_link` | 已支持（模型/控制器） | Controller-owned input or schema constant; not a model or human verification claim.；引用：controller:source\_link |
| `origin` | 已支持（模型/控制器） | Controller-owned input or schema constant; not a model or human verification claim.；引用：controller:origin |
| `project` | 已支持（模型/控制器） | Short repository name from the repository URL.；引用：E0001 |
| `repo_url` | 已支持（模型/控制器） | Controller-owned input or schema constant; not a model or human verification claim.；引用：controller:repo\_url |
| `commit` | 已支持（模型/控制器） | All location evidence was read at this exact SHA; it is the inspected revision whose source carries the defect. No fix commit or vulnerable\_commit was supplied, so this SHA is a locally selected inspected revision, not an advisory-confirmed…（已截短）；引用：E0001, E0005, E0012, E0013, E0014 |
| `vuln_title` | 已支持（模型/控制器） | Advisory title, corroborated by the unvalidated body -&gt; Object.assign -&gt; save path in inspected source.；引用：E0002, E0013, E0014 |
| `vuln_ids` | 已支持（模型/控制器） | CVE then GHSA from advisory metadata, deduplicated.；引用：E0002 |
| `vuln_category_l1` | 已支持（模型/控制器） | Coarse bucket chosen by model assessment for the advisory-named mass-assignment flaw; advisory provides no taxonomy, so this label is inferred, not advisory-sourced.；引用：E0002, E0013, E0014 |
| `vuln_category_l2` | 已支持（模型/控制器） | Advisory title names 'Mass Assignment'; source shows body copied onto the persisted entity.；引用：E0002, E0014 |
| `entry_point` | 已支持（模型/控制器） | createLeadInChatflow is declared in the controller at the inspected commit (E0013 lines 21-30) and is bound to POST / in the leads router (E0012 line 6), which is mounted at /leads (E0011); the /api/v1/leads whitelist string confirms the pa…（已截短）；引用：E0010, E0011, E0012, E0013 |
| `critical_operation` | 已支持（模型/控制器） | Object.assign(newLead, body) at line 27 copies unfiltered client-controlled attributes onto the Lead entity, which create/save then persist; Lead entity fields read at the same commit confirm assignable columns.；引用：E0014, E0015 |
| `trace` | 已支持（模型/控制器） | Ordered connected path for the same entry point, every element read at the inspected commit: POST route binding -&gt; controller forwarding req.body -&gt; service merge/save.；引用：E0012, E0013, E0014 |
| `verify` | 已支持（模型/控制器） | Controller-owned input or schema constant; not a model or human verification claim.；引用：controller:verify |

未解决字段：当前 review 未标注未解决字段；仍不等于独立确认。

## 自动自评与人工复核建议

- **可陈述的结果：** 上述数量、字段状态、引用、用量与错误来自本次公开输出。可追溯性和完整度可以展示；漏洞分析质量仍需按具体证据判断。
- **不能据此陈述的结果：** schema/源码一致不证明 EP 可达、输入可控、CO 确为缺陷，也不证明两者形成利用链。一次同模型自查可能重复原有误判，不是独立审核。
- **人工优先复核：** 项目与标题是否同源；公告影响范围和本地历史是否支持选定漏洞 commit；EP 的触发权限与输入控制；CO 的缺陷机制及其与 EP 的关系；类别是否与实际机制相符。
- **保守处理：** 缺失历史、证据不充分或相互矛盾时保留不确定性和建议值，不用空 SHA、行 0 或推断片段凑完整。合法的 `trace=[]` 不声称已证明数据流。
- **机器与人工分开：** 本报告不改变原始记录，不将自动候选改为人工真值；自动条目仍应为 `verify=0`。人工结论、理由与审核者信息需另行记录。

完整字段理由、证据片段与来源坐标见原始 `review.jsonl`；本文为便于阅读截短部分文字，不替代原始运行产物。
