# T2 v2 自动运行自评（待人工复核）

本文仅依据已生成的 `summary.json` 与 `review.jsonl` 自动汇总；没有重新访问目标仓库、调用模型或联网。
`supported` 表示带引用的模型判断或控制器事实，**不是独立人工审核或漏洞语义正确的证明**。源码逐字匹配与 schema 通过也不能替代可达性、攻击者可控性和缺陷机制复核。未提供外部独立标签，不计算或宣称 F1、准确率、精确率或召回率。

## 本次实际产出与用量

| 项目 | 已记录结果 |
|---|---|
| 批次执行状态 | completed（执行状态，不是正确性结论） |
| 请求 / 已处理 / 未处理输入 | 3 / 3 / 0 |
| 完整候选 / 草稿 / 输入失败 | 2 / 1 / 0 |
| 模型错误 / 工具错误 / 流程错误总项数 | 0 / 0 / 0 |
| 模型调用 / 仓库工具调用 | 12 / 19 |
| 已记录耗时（秒） | 343.974 |
| 模型 | deepseek-v4-pro |
| 本次 / 同一授权累计 HTTP 尝试 | 12 / 29 |
| 本次 token：输入 / 输出 / 总计 | 152959 / 29429 / 182388 |
| 授权内用量未知的请求数 | 0 |

完整候选仅指通过终检的正式条目；草稿、输入失败与未处理输入不计为完整候选。错误项数可能一份输入含多项，不等于失败公告数。HTTP 尝试包括失败尝试，且不同于模型调用次数。未知用量保持未知，不能把缺失 token 当作零。货币费用未在本报告中独立核算。

逐条 review 实际读取 **3** 条：complete=2，draft=1，input_failure=0。

## 逐报告结果与待解决字段

### 1. GHSA-JP4J-Q5FC-58GV / entry-59467

- 状态：draft；公告：https://github.com/advisories/GHSA-jp4j-q5fc-58gv。
- 已知项目 / 标题：未记录 / OpenClaw Discord component interaction ingress skips guild/channel policy enforcement。
- 漏洞 commit：e403decb6e20091b5402780a7ccd2085f98aa3cd。
- 入口 EP：extensions/discord/src/monitor/agent-components.ts，行 498-505；Discord component interaction handler entry point receiving a Discord interaction and parsed component data.。
- 关键操作 CO：extensions/discord/src/monitor/agent-components-helpers.ts，行 282-310；Missing guild/channel policy gates before member access; the patched version inserts channel enabled/allowlist and group policy checks here.。
- 模型 / 工具调用：4 / 8；动作记录中的计划 / 工具 / 草稿 / 自查：2 / 8 / 1 / 1。
- 已记录位置核验：2 / 2 通过（仅为位置与代码的确定性检查）。

| 字段 | 状态 | 已记录理由与证据引用 |
|---|---|---|
| `entry_id` | 已支持（模型/控制器） | Controller-owned input or schema constant; not a model or human verification claim.；引用：controller:entry\_id |
| `report_id` | 已支持（模型/控制器） | Controller-owned input or schema constant; not a model or human verification claim.；引用：controller:report\_id |
| `source_link` | 已支持（模型/控制器） | Controller-owned input or schema constant; not a model or human verification claim.；引用：controller:source\_link |
| `origin` | 已支持（模型/控制器） | Controller-owned input or schema constant; not a model or human verification claim.；引用：controller:origin |
| `project` | 不确定 | The model did not establish this field. |
| `repo_url` | 已支持（模型/控制器） | Controller-owned input or schema constant; not a model or human verification claim.；引用：controller:repo\_url |
| `commit` | 已支持（模型/控制器） | Fix commit parent e403dec... was inspected; parent source shows the missing guild/channel policy checks named by the advisory and added by the fix diff.；引用：E0002, E0004, E0005, E0006 |
| `vuln_title` | 已支持（模型/控制器） | Summarized from advisory summary and affected component description.；引用：E0002 |
| `vuln_ids` | 已支持（模型/控制器） | Advisory lists only the GHSA ID; no CVE was present in the provided evidence.；引用：E0002 |
| `vuln_category_l1` | 已支持（模型/控制器） | Advisory describes bypass of policy enforcement/access control; categorized as Access Control.；引用：E0002, E0005 |
| `vuln_category_l2` | 已支持（模型/控制器） | The defect is missing authorization/policy checks on component interaction ingress.；引用：E0002, E0005, E0006 |
| `entry_point` | 已支持（模型/控制器） | Read source shows handleDiscordComponentEvent as the component interaction handler entry point receiving the Discord interaction.；引用：E0009 |
| `critical_operation` | 已支持（模型/控制器） | Read source shows ensureGuildComponentMemberAllowed at parent lacks the channel enabled/allowlist/group policy checks added by the fix.；引用：E0005, E0006 |
| `trace` | 已支持（模型/控制器） | Empty optional trace makes no asserted source-flow claim; allowed by SCHEMA.md.；引用：controller:optional\_trace |
| `verify` | 已支持（模型/控制器） | Controller-owned input or schema constant; not a model or human verification claim.；引用：controller:verify |

未解决字段：`project`。
- `project` 的建议值（不是已确认字段）：openclaw。

本条已记录错误摘录：
- {"code": "model\_uncertain", "field": "project", "message": "No supported field value was established."}

### 2. GHSA-8C4J-F57C-35CF / entry-04956

- 状态：complete；公告：https://github.com/advisories/GHSA-8c4j-f57c-35cf。
- 已知项目 / 标题：langflow / Authenticated Users Can Read, Modify, and Delete Any Flow via Missing Ownership Check in /api/v1/flow/{flow\_id}。
- 漏洞 commit：73c1f203b0205d00928a0af7fa0e0fc93170f03e。
- 入口 EP：src/backend/base/langflow/api/v1/flows.py，行 287-288；FastAPI GET handler for /api/v1/flow/{flow\_id}, the authenticated external endpoint that reaches the vulnerable \_read\_flow helper.。
- 关键操作 CO：src/backend/base/langflow/api/v1/flows.py，行 277-283；Defective query construction: when AUTO\_LOGIN is False, no ownership filter is applied, so any authenticated user can retrieve flows by ID.。
- 模型 / 工具调用：3 / 3；动作记录中的计划 / 工具 / 草稿 / 自查：1 / 3 / 1 / 1。
- 已记录位置核验：2 / 2 通过（仅为位置与代码的确定性检查）。

| 字段 | 状态 | 已记录理由与证据引用 |
|---|---|---|
| `entry_id` | 已支持（模型/控制器） | Controller-owned input or schema constant; not a model or human verification claim.；引用：controller:entry\_id |
| `report_id` | 已支持（模型/控制器） | Controller-owned input or schema constant; not a model or human verification claim.；引用：controller:report\_id |
| `source_link` | 已支持（模型/控制器） | Controller-owned input or schema constant; not a model or human verification claim.；引用：controller:source\_link |
| `origin` | 已支持（模型/控制器） | Controller-owned input or schema constant; not a model or human verification claim.；引用：controller:origin |
| `project` | 已支持（模型/控制器） | Repository name/langflow inferred from repo\_url.；引用：E0001 |
| `repo_url` | 已支持（模型/控制器） | Controller-owned input or schema constant; not a model or human verification claim.；引用：controller:repo\_url |
| `commit` | 已支持（模型/控制器） | Parent of fix contains the vulnerable AUTO\_LOGIN conditional; actual source read shows unauthenticated ownership filtering when AUTO\_LOGIN is False.；引用：E0004, E0005, E0006 |
| `vuln_title` | 已支持（模型/控制器） | Derived from advisory summary and affected operations.；引用：E0002 |
| `vuln_ids` | 已支持（模型/控制器） | CVE and GHSA are both present in the advisory.；引用：E0002 |
| `vuln_category_l1` | 已支持（模型/控制器） | Missing ownership check is a broken access control issue.；引用：E0002, E0006 |
| `vuln_category_l2` | 已支持（模型/控制器） | The advisory explicitly describes IDOR via /api/v1/flow/{flow\_id}.；引用：E0002 |
| `entry_point` | 已支持（模型/控制器） | Actual FastAPI route handler read from parent commit; this is the external ingress point, not merely a patched helper.；引用：E0006 |
| `critical_operation` | 已支持（模型/控制器） | Actual \_read\_flow query code read from parent commit; conditional ownership filter is the core defect.；引用：E0006 |
| `trace` | 已支持（模型/控制器） | Empty optional trace makes no asserted source-flow claim; allowed by SCHEMA.md.；引用：controller:optional\_trace |
| `verify` | 已支持（模型/控制器） | Controller-owned input or schema constant; not a model or human verification claim.；引用：controller:verify |

未解决字段：当前 review 未标注未解决字段；仍不等于独立确认。

### 3. GHSA-MQ4R-H2GH-QV7X / entry-19628

- 状态：complete；公告：https://github.com/advisories/GHSA-mq4r-h2gh-qv7x。
- 已知项目 / 标题：Flowise / Mass Assignment in /api/v1/leads endpoint permits unauthenticated overwrite of id, createdDate, and chatId fields。
- 漏洞 commit：c045ceb872c01a583e817480de4fc1a0a4cbf57f。
- 入口 EP：packages/server/src/controllers/leads/index.ts，行 22；Express handler invoked by POST /api/v1/leads; reads and forwards req.body。
- 关键操作 CO：packages/server/src/services/leads/index.ts，行 28；Copies all request body properties to the Lead entity, including id, createdDate, and chatId。
- 模型 / 工具调用：5 / 8；动作记录中的计划 / 工具 / 草稿 / 自查：3 / 8 / 1 / 1。
- 已记录位置核验：6 / 6 通过（仅为位置与代码的确定性检查）。

| 字段 | 状态 | 已记录理由与证据引用 |
|---|---|---|
| `entry_id` | 已支持（模型/控制器） | Controller-owned input or schema constant; not a model or human verification claim.；引用：controller:entry\_id |
| `report_id` | 已支持（模型/控制器） | Controller-owned input or schema constant; not a model or human verification claim.；引用：controller:report\_id |
| `source_link` | 已支持（模型/控制器） | Controller-owned input or schema constant; not a model or human verification claim.；引用：controller:source\_link |
| `origin` | 已支持（模型/控制器） | Controller-owned input or schema constant; not a model or human verification claim.；引用：controller:origin |
| `project` | 已支持（模型/控制器） | Repository is FlowiseAI/Flowise.；引用：E0001 |
| `repo_url` | 已支持（模型/控制器） | Controller-owned input or schema constant; not a model or human verification claim.；引用：controller:repo\_url |
| `commit` | 已支持（模型/控制器） | Fix parent c045ceb872c01a583e817480de4fc1a0a4cbf57f is the revision read and contains the vulnerable Object.assign behavior.；引用：E0004, E0005, E0009 |
| `vuln_title` | 已支持（模型/控制器） | Derived from advisory summary and endpoint.；引用：E0002 |
| `vuln_ids` | 已支持（模型/控制器） | Advisory lists CVE-2026-30822 and GHSA-MQ4R-H2GH-QV7X, upper-cased and CVE-first as required.；引用：E0002 |
| `vuln_category_l1` | 已支持（模型/控制器） | CWE-915 falls under improper input/attribute control.；引用：E0002 |
| `vuln_category_l2` | 已支持（模型/控制器） | Advisory explicitly identifies Mass Assignment.；引用：E0002 |
| `entry_point` | 已支持（模型/控制器） | createLeadInChatflow is the route callback and initial user input handler.；引用：E0011, E0008 |
| `critical_operation` | 已支持（模型/控制器） | Object.assign(newLead, body) is the unprotected field copy enabling mass assignment.；引用：E0009 |
| `trace` | 已支持（模型/控制器） | Shown source provides connected route to controller to service path for the same entry point.；引用：E0011, E0008, E0009 |
| `verify` | 已支持（模型/控制器） | Controller-owned input or schema constant; not a model or human verification claim.；引用：controller:verify |

未解决字段：当前 review 未标注未解决字段；仍不等于独立确认。

## 自动自评与人工复核建议

- **可陈述的结果：** 上述数量、字段状态、引用、用量与错误来自本次公开输出。可追溯性和完整度可以展示；漏洞分析质量仍需按具体证据判断。
- **不能据此陈述的结果：** schema/源码一致不证明 EP 可达、输入可控、CO 确为缺陷，也不证明两者形成利用链。一次同模型自查可能重复原有误判，不是独立审核。
- **人工优先复核：** 项目与标题是否同源；公告影响范围和本地历史是否支持选定漏洞 commit；EP 的触发权限与输入控制；CO 的缺陷机制及其与 EP 的关系；类别是否与实际机制相符。
- **保守处理：** 缺失历史、证据不充分或相互矛盾时保留不确定性和建议值，不用空 SHA、行 0 或推断片段凑完整。合法的 `trace=[]` 不声称已证明数据流。
- **机器与人工分开：** 本报告不改变原始记录，不将自动候选改为人工真值；自动条目仍应为 `verify=0`。人工结论、理由与审核者信息需另行记录。

完整字段理由、证据片段与来源坐标见原始 `review.jsonl`；本文为便于阅读截短部分文字，不替代原始运行产物。
