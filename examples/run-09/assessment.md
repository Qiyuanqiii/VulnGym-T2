# T2 v2 自动运行自评（待人工复核）

本文仅依据已生成的 `summary.json` 与 `review.jsonl` 自动汇总；没有重新访问目标仓库、调用模型或联网。
`supported` 表示带引用的模型判断或控制器事实，**不是独立人工审核或漏洞语义正确的证明**。源码逐字匹配与 schema 通过也不能替代可达性、攻击者可控性和缺陷机制复核。未提供外部独立标签，不计算或宣称 F1、准确率、精确率或召回率。

## 本次实际产出与用量

| 项目 | 已记录结果 |
|---|---|
| 批次执行状态 | completed\_with\_errors（执行状态，不是正确性结论） |
| 请求 / 已处理 / 未处理输入 | 3 / 3 / 0 |
| 完整候选 / 草稿 / 输入失败 | 1 / 2 / 0 |
| 模型错误 / 工具错误 / 流程错误总项数 | 2 / 1 / 3 |
| 格式失败输入数 | 1 |
| 模型调用 / 仓库工具调用 | 15 / 29 |
| 已记录耗时（秒） | 56.259 |
| 模型 | deepseek-flash |
| 本次 / 同一授权累计 HTTP 尝试 | 15 / 60 |
| 本次 token：输入 / 输出 / 总计 | 180749 / 10548 / 191297 |
| 授权内用量未知的请求数 | 1 |

完整候选仅指通过终检的正式条目；草稿、输入失败与未处理输入不计为完整候选。错误项数可能一份输入含多项，不等于失败公告数。HTTP 尝试包括失败尝试，且不同于模型调用次数。未知用量保持未知，不能把缺失 token 当作零。货币费用未在本报告中独立核算。

逐条 review 实际读取 **3** 条：complete=1，draft=2，input_failure=0。

**批次已处理完但含格式错误：全部输入已处理，至少一项格式失败；不是全成功。失败输入仍是草稿，不因生成报告而补成完整候选。**

已记录逐项格式失败：
- 公告：GHSA-8C4J-F57C-35CF；错误：deepseek\_response\_invalid\_json；失败后是否继续批次：false。

## 逐报告结果与待解决字段

### 1. GHSA-JP4J-Q5FC-58GV / entry-59467

- 状态：complete；公告：https://github.com/advisories/GHSA-jp4j-q5fc-58gv。
- 机器自查状态：已完成机器自查；机器自查不等于独立人工审核。
- 已知项目 / 标题：openclaw / OpenClaw's Discord component interaction ingress skips guild/channel policy enforcement。
- 已记录 commit（不代表已确认漏洞版本）：e403decb6e20091b5402780a7ccd2085f98aa3cd。
- 版本判断依据（已记录机器声明）：影响范围+源码；机器声明不等于人工审核。缺少旧字段不会改变原有状态，也不会补造版本依据。
- 入口 EP：extensions/discord/src/monitor/agent-components.ts，行 567-577；Anonymous guild-component interaction handler's authorization call; the handler declaration sits above the read window, so this is the gated ingress call site rather than a verified external handler declaration.。
- 关键操作 CO：extensions/discord/src/monitor/agent-components-helpers.ts，行 306-310；Member-only decision: allowed solely from resolveDiscordMemberAccessState; the disabled-channel, denied-channel and groupPolicy checks that the fix adds are absent. Line corrected to the exact read location; fix/parent roles kept distinct.。
- 模型 / 工具调用：4 / 6；动作记录中的计划 / 工具 / 草稿 / 自查：2 / 6 / 1 / 1。
- 已记录位置核验：2 / 2 通过（仅为位置与代码的确定性检查）。

| 字段 | 状态 | 已记录理由与证据引用 |
|---|---|---|
| `entry_id` | 已支持（模型/控制器） | Controller-owned input or schema constant; not a model or human verification claim.；引用：controller:entry\_id |
| `report_id` | 已支持（模型/控制器） | Controller-owned input or schema constant; not a model or human verification claim.；引用：controller:report\_id |
| `source_link` | 已支持（模型/控制器） | Controller-owned input or schema constant; not a model or human verification claim.；引用：controller:source\_link |
| `origin` | 已支持（模型/控制器） | Controller-owned input or schema constant; not a model or human verification claim.；引用：controller:origin |
| `project` | 已支持（模型/控制器） | Short repository name from the repository URL.；引用：E0001 |
| `repo_url` | 已支持（模型/控制器） | Controller-owned input or schema constant; not a model or human verification claim.；引用：controller:repo\_url |
| `commit` | 已支持（模型/控制器） | Fix parent, read directly at this SHA. Source shows ensureGuildComponentMemberAllowed (agent-components-helpers.ts) returning allow based only on resolveDiscordMemberAccessState, with no channelConfig.enabled/allowed or groupPolicy gate — t…（已截短）；引用：E0002, E0004, E0005, E0008 |
| `vuln_title` | 已支持（模型/控制器） | Advisory summary.；引用：E0002 |
| `vuln_ids` | 已支持（模型/控制器） | Advisory lists only the GHSA id; no CVE assigned.；引用：E0002 |
| `vuln_category_l1` | 已支持（模型/控制器） | Missing authorization gate on component interactions.；引用：E0002 |
| `vuln_category_l2` | 已支持（模型/控制器） | Component ingress did not reapply guild/channel policy gates.；引用：E0002, E0005 |
| `entry_point` | 已支持（模型/控制器） | Verbatim window read at the cited SHA (E0009) at corrected lines 565-577; enclosing function declaration not shown, so reachability is inferred from the visible call chain only.；引用：E0009 |
| `critical_operation` | 已支持（模型/控制器） | Verbatim window read at the cited SHA (E0008) at corrected lines 297-310.；引用：E0008 |
| `trace` | 已支持（模型/控制器） | Empty optional trace makes no asserted source-flow claim; allowed by SCHEMA.md.；引用：controller:optional\_trace |
| `verify` | 已支持（模型/控制器） | Controller-owned input or schema constant; not a model or human verification claim.；引用：controller:verify |

未解决字段：当前 review 未标注未解决字段；仍不等于独立确认。

### 2. GHSA-MQ4R-H2GH-QV7X / entry-75975

- 状态：draft；公告：https://github.com/advisories/GHSA-mq4r-h2gh-qv7x。
- 机器自查状态：已完成机器自查；机器自查不等于独立人工审核。
- 已知项目 / 标题：Flowise / Flowise Allows Mass Assignment in \`/api/v1/leads\` Endpoint。
- 已记录 commit（不代表已确认漏洞版本）：未记录。
- 版本判断依据（已记录机器声明）：仅检查过；机器声明不等于人工审核。缺少旧字段不会改变原有状态，也不会补造版本依据。
- 入口 EP：未建立；以字段状态和建议值为准。
- 关键操作 CO：未建立；以字段状态和建议值为准。
- 模型 / 工具调用：6 / 13；动作记录中的计划 / 工具 / 草稿 / 自查：4 / 13 / 1 / 1。
- 已记录位置核验：0 / 0 通过（仅为位置与代码的确定性检查）。

| 字段 | 状态 | 已记录理由与证据引用 |
|---|---|---|
| `entry_id` | 已支持（模型/控制器） | Controller-owned input or schema constant; not a model or human verification claim.；引用：controller:entry\_id |
| `report_id` | 已支持（模型/控制器） | Controller-owned input or schema constant; not a model or human verification claim.；引用：controller:report\_id |
| `source_link` | 已支持（模型/控制器） | Controller-owned input or schema constant; not a model or human verification claim.；引用：controller:source\_link |
| `origin` | 已支持（模型/控制器） | Controller-owned input or schema constant; not a model or human verification claim.；引用：controller:origin |
| `project` | 已支持（模型/控制器） | Short repository name from the repository URL.；引用：E0001 |
| `repo_url` | 已支持（模型/控制器） | Controller-owned input or schema constant; not a model or human verification claim.；引用：controller:repo\_url |
| `commit` | 不确定 | Only resolvable ref in this repo (no HEAD). read\_file at this exact SHA shows the lead creation path and mass assignment, so the mechanism exists at this revision; however no fix commit, no advisory version range (description withheld), and…（已截短）；引用：E0004, E0006, E0013, E0014, E0015 |
| `vuln_title` | 已支持（模型/控制器） | Advisory summary title.；引用：E0001, E0002 |
| `vuln_ids` | 已支持（模型/控制器） | Identifiers listed in advisory metadata, CVE first.；引用：E0001, E0002 |
| `vuln_category_l1` | 不确定 | Advisory supplies only the title and identifiers; the class is named in the title ('Mass Assignment'). Coarse grouping is a model inference with no CWE given.；引用：E0002 |
| `vuln_category_l2` | 不确定 | Term comes directly from the advisory title; no separate advisory detail or CWE was supplied, and the observed Object.assign(newLead, body) is inspected-source support for the same term.；引用：E0002, E0015 |
| `entry_point` | 不确定 | No cited successful actual file read matches every location at the selected vulnerable commit. read\_file at the selected SHA shows this handler declaration, a route file mapping POST '/' to it, and constants.ts listing '/api/v1/leads'; the …（已截短）；引用：E0011, E0013, E0014 |
| `critical_operation` | 不确定 | No cited successful actual file read matches every location at the selected vulnerable commit. read\_file at the selected SHA shows createLead(body: Partial&lt;ILead&gt;) doing Object.assign(newLead, body) before repository save; combined with the…（已截短）；引用：E0015, E0016, E0013 |
| `trace` | 已支持（模型/控制器） | Empty optional trace makes no asserted source-flow claim; allowed by SCHEMA.md.；引用：controller:optional\_trace |
| `verify` | 已支持（模型/控制器） | Controller-owned input or schema constant; not a model or human verification claim.；引用：controller:verify |

未解决字段：`commit`、`vuln_category_l1`、`vuln_category_l2`、`entry_point`、`critical_operation`。
- `commit` 的建议值（不是已确认字段）：55b6913c03f0dba37cc207975f0c0d0786e0f3c7。
- `vuln_category_l1` 的建议值（不是已确认字段）：Input Validation。
- `vuln_category_l2` 的建议值（不是已确认字段）：Mass Assignment。
- `entry_point` 的建议值（不是已确认字段）：packages/server/src/controllers/leads/index.ts，行 21；Express handler bound to POST '/' in packages/server/src/routes/leads/index.ts (verbatim read at this SHA); reads req.body and forwards it to the leads service.。
- `critical_operation` 的建议值（不是已确认字段）：packages/server/src/services/leads/index.ts，行 27；Untrusted request body is copied wholesale onto a new Lead entity (createLead) without any field allow-list, then persisted via repository.save.。
- `trace` 的建议值（不是已确认字段）：\[{"code": "router.post('/', leadsController.createLeadInChatflow)", "desc": "POST route registration (router mounted at /leads, prefix /api/v1 per constants.ts) -&gt; controller,", "file": "packages/server/src/routes/leads/index.ts", "line": 6…（已截短）。

本条已记录错误摘录：
- {"code": "model\_uncertain", "field": "commit", "message": "No supported field value was established."}
- {"code": "model\_uncertain", "field": "critical\_operation", "message": "No supported field value was established."}
- {"code": "model\_uncertain", "field": "entry\_point", "message": "No supported field value was established."}
- {"code": "model\_uncertain", "field": "vuln\_category\_l1", "message": "No supported field value was established."}
- {"code": "model\_uncertain", "field": "vuln\_category\_l2", "message": "No supported field value was established."}
- 另有 1 项，完整内容见本条 `review.jsonl`。

### 3. GHSA-8C4J-F57C-35CF / entry-79305

- 状态：draft；公告：https://github.com/advisories/GHSA-8c4j-f57c-35cf。
- 机器自查状态：未请求（不是失败）；机器自查不等于独立人工审核。
- 已知项目 / 标题：langflow / Langflow: Authenticated Users Can Read, Modify, and Delete Any Flow via Missing Ownership Check。
- 已记录 commit（不代表已确认漏洞版本）：未记录。
- 版本判断依据（已记录机器声明）：未建立；机器声明不等于人工审核。缺少旧字段不会改变原有状态，也不会补造版本依据。
- 入口 EP：未建立；以字段状态和建议值为准。
- 关键操作 CO：未建立；以字段状态和建议值为准。
- 模型 / 工具调用：5 / 10；动作记录中的计划 / 工具 / 草稿 / 自查：4 / 10 / 0 / 0。
- 已记录位置核验：0 / 0 通过（仅为位置与代码的确定性检查）。

| 字段 | 状态 | 已记录理由与证据引用 |
|---|---|---|
| `entry_id` | 已支持（模型/控制器） | Controller-owned input or schema constant; not a model or human verification claim.；引用：controller:entry\_id |
| `report_id` | 已支持（模型/控制器） | Controller-owned input or schema constant; not a model or human verification claim.；引用：controller:report\_id |
| `source_link` | 已支持（模型/控制器） | Controller-owned input or schema constant; not a model or human verification claim.；引用：controller:source\_link |
| `origin` | 已支持（模型/控制器） | Controller-owned input or schema constant; not a model or human verification claim.；引用：controller:origin |
| `project` | 已支持（模型/控制器） | Short repository name from the repository URL.；引用：E0001 |
| `repo_url` | 已支持（模型/控制器） | Controller-owned input or schema constant; not a model or human verification claim.；引用：controller:repo\_url |
| `commit` | 缺失 | Not established from available evidence. |
| `vuln_title` | 已支持（模型/控制器） | Title supplied by matching advisory metadata; not a model inference.；引用：E0002 |
| `vuln_ids` | 已支持（模型/控制器） | Identifiers supplied by matching advisory metadata; not a model inference.；引用：E0002 |
| `vuln_category_l1` | 缺失 | Not established from available evidence. |
| `vuln_category_l2` | 缺失 | Not established from available evidence. |
| `entry_point` | 缺失 | Not established from available evidence. |
| `critical_operation` | 缺失 | Not established from available evidence. |
| `trace` | 已支持（模型/控制器） | Empty optional trace makes no asserted source-flow claim; allowed by SCHEMA.md.；引用：controller:optional\_trace |
| `verify` | 已支持（模型/控制器） | Controller-owned input or schema constant; not a model or human verification claim.；引用：controller:verify |

未解决字段：`commit`、`vuln_category_l1`、`vuln_category_l2`、`entry_point`、`critical_operation`。

本条已记录错误摘录：
- {"code": "missing\_value", "field": "commit", "message": "No supported field value was established."}
- {"code": "missing\_value", "field": "critical\_operation", "message": "No supported field value was established."}
- {"code": "missing\_value", "field": "entry\_point", "message": "No supported field value was established."}
- {"code": "missing\_value", "field": "vuln\_category\_l1", "message": "No supported field value was established."}
- {"code": "missing\_value", "field": "vuln\_category\_l2", "message": "No supported field value was established."}
- 另有 2 项，完整内容见本条 `review.jsonl`。

## 自动自评与人工复核建议

- **可陈述的结果：** 上述数量、字段状态、引用、用量与错误来自本次公开输出。可追溯性和完整度可以展示；漏洞分析质量仍需按具体证据判断。
- **不能据此陈述的结果：** schema/源码一致不证明 EP 可达、输入可控、CO 确为缺陷，也不证明两者形成利用链。一次同模型自查可能重复原有误判，不是独立审核。
- **人工优先复核：** 项目与标题是否同源；公告影响范围和本地历史是否支持选定漏洞 commit；EP 的触发权限与输入控制；CO 的缺陷机制及其与 EP 的关系；类别是否与实际机制相符。
- **保守处理：** 缺失历史、证据不充分或相互矛盾时保留不确定性和建议值，不用空 SHA、行 0 或推断片段凑完整。合法的 `trace=[]` 不声称已证明数据流。
- **机器与人工分开：** 本报告不改变原始记录，不将自动候选改为人工真值；自动条目仍应为 `verify=0`。人工结论、理由与审核者信息需另行记录。

完整字段理由、证据片段与来源坐标见原始 `review.jsonl`；本文为便于阅读截短部分文字，不替代原始运行产物。
