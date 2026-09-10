# T2 v2 自动运行自评（待人工复核）

本文仅依据已生成的 `summary.json` 与 `review.jsonl` 自动汇总；没有重新访问目标仓库、调用模型或联网。
`supported` 表示带引用的模型判断或控制器事实，**不是独立人工审核或漏洞语义正确的证明**。源码逐字匹配与 schema 通过也不能替代可达性、攻击者可控性和缺陷机制复核。未提供外部独立标签，不计算或宣称 F1、准确率、精确率或召回率。

## 本次实际产出与用量

| 项目 | 已记录结果 |
|---|---|
| 批次执行状态 | completed（执行状态，不是正确性结论） |
| 请求 / 已处理 / 未处理输入 | 3 / 3 / 0 |
| 完整候选 / 草稿 / 输入失败 | 3 / 0 / 0 |
| 模型错误 / 工具错误 / 流程错误总项数 | 1 / 0 / 1 |
| 模型调用 / 仓库工具调用 | 18 / 23 |
| 已记录耗时（秒） | 525.471 |
| 模型 | deepseek-v4-pro |
| 本次 / 同一授权累计 HTTP 尝试 | 18 / 51 |
| 本次 token：输入 / 输出 / 总计 | 200646 / 44449 / 245095 |
| 授权内用量未知的请求数 | 0 |

完整候选仅指通过终检的正式条目；草稿、输入失败与未处理输入不计为完整候选。错误项数可能一份输入含多项，不等于失败公告数。HTTP 尝试包括失败尝试，且不同于模型调用次数。未知用量保持未知，不能把缺失 token 当作零。货币费用未在本报告中独立核算。

逐条 review 实际读取 **3** 条：complete=3，draft=0，input_failure=0。

## 逐报告结果与待解决字段

### 1. GHSA-8C4J-F57C-35CF / entry-04956

- 状态：complete；公告：https://github.com/advisories/GHSA-8c4j-f57c-35cf。
- 已知项目 / 标题：langflow / Langflow: Authenticated Users Can Read, Modify, and Delete Any Flow via Missing Ownership Check。
- 漏洞 commit：73c1f203b0205d00928a0af7fa0e0fc93170f03e。
- 入口 EP：src/backend/base/langflow/api/v1/flows.py，行 288；GET /api/v1/flow/{flow\_id} handler; path parameter flow\_id is attacker-controlled resource identifier。
- 关键操作 CO：src/backend/base/langflow/api/v1/flows.py，行 276-283；Defective ownership check: when AUTO\_LOGIN is False, no user\_id filter is applied, allowing any authenticated user to retrieve any flow by UUID。
- 模型 / 工具调用：5 / 4；动作记录中的计划 / 工具 / 草稿 / 自查：2 / 4 / 1 / 1。
- 已记录位置核验：2 / 2 通过（仅为位置与代码的确定性检查）。

| 字段 | 状态 | 已记录理由与证据引用 |
|---|---|---|
| `entry_id` | 已支持（模型/控制器） | Controller-owned input or schema constant; not a model or human verification claim.；引用：controller:entry\_id |
| `report_id` | 已支持（模型/控制器） | Controller-owned input or schema constant; not a model or human verification claim.；引用：controller:report\_id |
| `source_link` | 已支持（模型/控制器） | Controller-owned input or schema constant; not a model or human verification claim.；引用：controller:source\_link |
| `origin` | 已支持（模型/控制器） | Controller-owned input or schema constant; not a model or human verification claim.；引用：controller:origin |
| `project` | 已支持（模型/控制器） | Short repository name from the repository URL.；引用：E0001 |
| `repo_url` | 已支持（模型/控制器） | Controller-owned input or schema constant; not a model or human verification claim.；引用：controller:repo\_url |
| `commit` | 已支持（模型/控制器） | Fix commit parent read directly and contains the vulnerable code shown in E0007；引用：E0004, E0007 |
| `vuln_title` | 已支持（模型/控制器） | Advisory summary title；引用：E0002 |
| `vuln_ids` | 已支持（模型/控制器） | CVE and GHSA from advisory metadata, deduplicated；引用：E0002 |
| `vuln_category_l1` | 已支持（模型/控制器） | Missing ownership/authorization check is broken access control；引用：E0002 |
| `vuln_category_l2` | 已支持（模型/控制器） | Advisory explicitly labels IDOR on flow\_id UUID；引用：E0002 |
| `entry_point` | 已支持（模型/控制器） | GET handler declaration read from vulnerable parent commit; line corrected to 288 based on E0007 exact source read；引用：E0007 |
| `critical_operation` | 已支持（模型/控制器） | Exact defective query logic at parent commit showing no ownership filter when AUTO\_LOGIN is False；引用：E0007 |
| `trace` | 已支持（模型/控制器） | Empty optional trace makes no asserted source-flow claim; allowed by SCHEMA.md.；引用：controller:optional\_trace |
| `verify` | 已支持（模型/控制器） | Controller-owned input or schema constant; not a model or human verification claim.；引用：controller:verify |

未解决字段：当前 review 未标注未解决字段；仍不等于独立确认。
- `trace` 的建议值（不是已确认字段）：\[\]。

本条已记录错误摘录：
- Expected action=tools or action=draft

### 2. GHSA-MQ4R-H2GH-QV7X / entry-19628

- 状态：complete；公告：https://github.com/advisories/GHSA-mq4r-h2gh-qv7x。
- 已知项目 / 标题：Flowise / Flowise Allows Mass Assignment in \`/api/v1/leads\` Endpoint。
- 漏洞 commit：c045ceb872c01a583e817480de4fc1a0a4cbf57f。
- 入口 EP：packages/server/src/controllers/leads/index.ts，行 22；External Express route handler for POST /api/v1/leads; receives attacker-controlled req.body and is reachable without authentication due to the endpoint being whitelisted.。
- 关键操作 CO：packages/server/src/services/leads/index.ts，行 28；Copies all properties from the request body onto the new Lead entity, allowing attacker-supplied id, createdDate, and chatId to override server-generated fields before save.。
- 模型 / 工具调用：5 / 8；动作记录中的计划 / 工具 / 草稿 / 自查：3 / 8 / 1 / 1。
- 已记录位置核验：5 / 5 通过（仅为位置与代码的确定性检查）。

| 字段 | 状态 | 已记录理由与证据引用 |
|---|---|---|
| `entry_id` | 已支持（模型/控制器） | Controller-owned input or schema constant; not a model or human verification claim.；引用：controller:entry\_id |
| `report_id` | 已支持（模型/控制器） | Controller-owned input or schema constant; not a model or human verification claim.；引用：controller:report\_id |
| `source_link` | 已支持（模型/控制器） | Controller-owned input or schema constant; not a model or human verification claim.；引用：controller:source\_link |
| `origin` | 已支持（模型/控制器） | Controller-owned input or schema constant; not a model or human verification claim.；引用：controller:origin |
| `project` | 已支持（模型/控制器） | Short repository name from the repository URL.；引用：E0001 |
| `repo_url` | 已支持（模型/控制器） | Controller-owned input or schema constant; not a model or human verification claim.；引用：controller:repo\_url |
| `commit` | 已支持（模型/控制器） | Parent of fix commit c045ceb872c01a583e817480de4fc1a0a4cbf57f is the vulnerable revision; actual read\_file at this SHA shows the vulnerable Object.assign behavior.；引用：E0004, E0005, E0006 |
| `vuln_title` | 已支持（模型/控制器） | Advisory title describes the vulnerability and affected endpoint.；引用：E0002 |
| `vuln_ids` | 已支持（模型/控制器） | CVE and GHSA IDs present in advisory metadata; deduplicated and ordered CVE first.；引用：E0002 |
| `vuln_category_l1` | 已支持（模型/控制器） | Advisory describes unauthenticated users controlling internal fields and cites OWASP API6:2023 Unrestricted Access to Sensitive Business Flows, placing this mass assignment issue under access control/authorization.；引用：E0002 |
| `vuln_category_l2` | 已支持（模型/控制器） | Advisory explicitly labels Vulnerability Type as Mass Assignment.；引用：E0002 |
| `entry_point` | 已支持（模型/控制器） | Read controller source confirms the Express callback declaration for POST /api/v1/leads; route file confirms it is wired to POST '/'.；引用：E0010, E0011 |
| `critical_operation` | 已支持（模型/控制器） | Read service source confirms Object.assign(newLead, body) is the unsafe dynamic property copy at line 28.；引用：E0006 |
| `trace` | 已支持（模型/控制器） | Read controller and service files show an ordered, same-entry-point call path from handler body pass to vulnerable assignment.；引用：E0010, E0006 |
| `verify` | 已支持（模型/控制器） | Controller-owned input or schema constant; not a model or human verification claim.；引用：controller:verify |

未解决字段：当前 review 未标注未解决字段；仍不等于独立确认。

### 3. GHSA-CM35-V4VP-5XVX / entry-16602

- 状态：complete；公告：https://github.com/advisories/GHSA-cm35-v4vp-5xvx。
- 已知项目 / 标题：open-webui / Open WebUI Affected by an External Model Server (Direct Connections) Code Injection via SSE Events。
- 漏洞 commit：9762ef3ef6f230bfed8d550dde69df6187f6267d。
- 入口 EP：backend/open\_webui/utils/middleware.py，行 2321；Ingress read of streaming chunks from untrusted Direct Connection model server。
- 关键操作 CO：src/lib/components/chat/Chat.svelte，行 441；Arbitrary JavaScript code from attacker-controlled SSE execute event is evaluated in browser。
- 模型 / 工具调用：8 / 11；动作记录中的计划 / 工具 / 草稿 / 自查：6 / 11 / 1 / 1。
- 已记录位置核验：5 / 5 通过（仅为位置与代码的确定性检查）。

| 字段 | 状态 | 已记录理由与证据引用 |
|---|---|---|
| `entry_id` | 已支持（模型/控制器） | Controller-owned input or schema constant; not a model or human verification claim.；引用：controller:entry\_id |
| `report_id` | 已支持（模型/控制器） | Controller-owned input or schema constant; not a model or human verification claim.；引用：controller:report\_id |
| `source_link` | 已支持（模型/控制器） | Controller-owned input or schema constant; not a model or human verification claim.；引用：controller:source\_link |
| `origin` | 已支持（模型/控制器） | Controller-owned input or schema constant; not a model or human verification claim.；引用：controller:origin |
| `project` | 已支持（模型/控制器） | Short repository name from the repository URL.；引用：E0001 |
| `repo_url` | 已支持（模型/控制器） | Controller-owned input or schema constant; not a model or human verification claim.；引用：controller:repo\_url |
| `commit` | 已支持（模型/控制器） | Fix commit parent 9762ef... contains vulnerable frontend new Function handler and unguarded backend event forwarding; advisory range &lt;=0.6.34 corresponds to pre-fix versions.；引用：E0004, E0006, E0009, E0005 |
| `vuln_title` | 已支持（模型/控制器） | Matches advisory title.；引用：E0002 |
| `vuln_ids` | 已支持（模型/控制器） | Deduped CVE and GHSA IDs from advisory metadata.；引用：E0002 |
| `vuln_category_l1` | 已支持（模型/控制器） | Advisory classifies as CWE-95 code injection; source confirms eval style execution.；引用：E0002, E0009 |
| `vuln_category_l2` | 已支持（模型/控制器） | Specific unsafe new Function() evaluation of untrusted SSE execute code.；引用：E0009 |
| `entry_point` | 已支持（模型/控制器） | Backend response.body\_iterator reads untrusted SSE chunks from Direct Connection; supported by parent source read.；引用：E0006 |
| `critical_operation` | 已支持（模型/控制器） | Line 441 constructs new Function with attacker-controlled data.code.；引用：E0009 |
| `trace` | 已支持（模型/控制器） | Connected path: backend forwards event at line 2353, frontend socket listener at line 534 routes to handler, critical eval at line 441. Each location has read\_file evidence.；引用：E0006, E0013, E0009 |
| `verify` | 已支持（模型/控制器） | Controller-owned input or schema constant; not a model or human verification claim.；引用：controller:verify |

未解决字段：当前 review 未标注未解决字段；仍不等于独立确认。

## 自动自评与人工复核建议

- **可陈述的结果：** 上述数量、字段状态、引用、用量与错误来自本次公开输出。可追溯性和完整度可以展示；漏洞分析质量仍需按具体证据判断。
- **不能据此陈述的结果：** schema/源码一致不证明 EP 可达、输入可控、CO 确为缺陷，也不证明两者形成利用链。一次同模型自查可能重复原有误判，不是独立审核。
- **人工优先复核：** 项目与标题是否同源；公告影响范围和本地历史是否支持选定漏洞 commit；EP 的触发权限与输入控制；CO 的缺陷机制及其与 EP 的关系；类别是否与实际机制相符。
- **保守处理：** 缺失历史、证据不充分或相互矛盾时保留不确定性和建议值，不用空 SHA、行 0 或推断片段凑完整。合法的 `trace=[]` 不声称已证明数据流。
- **机器与人工分开：** 本报告不改变原始记录，不将自动候选改为人工真值；自动条目仍应为 `verify=0`。人工结论、理由与审核者信息需另行记录。

完整字段理由、证据片段与来源坐标见原始 `review.jsonl`；本文为便于阅读截短部分文字，不替代原始运行产物。
