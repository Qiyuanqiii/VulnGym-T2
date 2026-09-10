# T2 v2 自动运行自评（待人工复核）

本文仅依据已生成的 `summary.json` 与 `review.jsonl` 自动汇总；没有重新访问目标仓库、调用模型或联网。
`supported` 表示带引用的模型判断或控制器事实，**不是独立人工审核或漏洞语义正确的证明**。源码逐字匹配与 schema 通过也不能替代可达性、攻击者可控性和缺陷机制复核。未提供外部独立标签，不计算或宣称 F1、准确率、精确率或召回率。

## 本次实际产出与用量

| 项目 | 已记录结果 |
|---|---|
| 批次执行状态 | provider\_stopped（执行状态，不是正确性结论） |
| 请求 / 已处理 / 未处理输入 | 1 / 1 / 0 |
| 完整候选 / 草稿 / 输入失败 | 0 / 1 / 0 |
| 模型错误 / 工具错误 / 流程错误总项数 | 2 / 0 / 2 |
| 模型调用 / 仓库工具调用 | 2 / 4 |
| 已记录耗时（秒） | 4.712 |
| 模型 | deepseek-flash |
| 本次 / 同一授权累计 HTTP 尝试 | 2 / 20 |
| 本次 token：输入 / 输出 / 总计 | 19374 / 501 / 19875 |
| 授权内用量未知的请求数 | 0 |

完整候选仅指通过终检的正式条目；草稿、输入失败与未处理输入不计为完整候选。错误项数可能一份输入含多项，不等于失败公告数。HTTP 尝试包括失败尝试，且不同于模型调用次数。未知用量保持未知，不能把缺失 token 当作零。货币费用未在本报告中独立核算。

逐条 review 实际读取 **1** 条：complete=0，draft=1，input_failure=0。

## 逐报告结果与待解决字段

### 1. GHSA-JP4J-Q5FC-58GV / entry-59467

- 状态：draft；公告：https://github.com/advisories/GHSA-jp4j-q5fc-58gv。
- 已知项目 / 标题：openclaw / OpenClaw's Discord component interaction ingress skips guild/channel policy enforcement。
- 漏洞 commit：未记录。
- 入口 EP：未建立；以字段状态和建议值为准。
- 关键操作 CO：未建立；以字段状态和建议值为准。
- 模型 / 工具调用：2 / 4；动作记录中的计划 / 工具 / 草稿 / 自查：1 / 4 / 0 / 0。
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
