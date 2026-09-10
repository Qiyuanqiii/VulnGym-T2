# V4.1 Flash：真实回归与减线索诊断

日期：2026-09-10。用户授权最多 500 次请求并指定 V4.1 Flash；上限不是必须花完的配额。旧模型运行和旧样例保持原样，本页只报告这一轮。

## 模型、输入和预算

- [DeepSeek 当日更新](https://api-docs.deepseek.com/updates/#date-2026-09-10)将 V4.1 Flash 对应到 `deepseek-flash`；一次官方 `/models` 查询也确认账号可用该标识。所有生成请求显式使用它，响应名称检查一致，不切回 Pro。
- CLI 新增 `--model`，请求、响应检查、摘要和授权账本绑定同一模型。为兼容旧脚本，省略时仍是旧 Pro 默认；本轮命令均明确传入 Flash。
- 模型目录查询 1 次；生成账本上限 499 次，四个实际运行复用同一账本，失败请求也计数。**实际 41 次生成 + 1 次目录查询 = 42/500 次请求**，零自动重试，没有为后续批次重置额度。
- 已报告用量为 **432,465 tokens**（prompt 378,679，completion 53,786）；另有 1 次响应读取断线，用量未知。因此这个数字不是包括断线请求在内的精确总 token，货币费用也未独立测量。
- 共四份完整公告和两份减线索变体，涉及同样四个已见开发案例，**独立新样本数为 0**。没有给模型旧预测、人工答案或隐藏评测材料。
- 完整公告来自随包四份公开缓存，均有资料本身提供的修复候选。减线索变体去掉详细描述、修复链接/候选和代码摘录，只保留原摘要、编号和来源；仍使用同一批已提供的本地 Git 对象，不能称为陌生仓库或盲测。

## 每次实际运行

计数顺序为请求输入 / 已处理 / 完整候选 / 草稿 / 未开始。完整候选不是人工确认；所有导出条目均为 `verify=0`。

| 随包目录 | 输入与结果 | 计数 | HTTP / 秒 | 已报告 tokens |
|---|---|---|---|---|
| `examples/run-04` | 完整公告：Langflow、Flowise 完整；Open WebUI 正文 JSON 错误；OpenClaw 未开始 | 4 / 3 / 2 / 1 / 1 | 18 / 150.486 | 239,679 |
| `examples/run-05` | 仅接上未开始的 OpenClaw；正文 JSON 错误，保留草稿 | 1 / 1 / 0 / 1 / 0 | 2 / 4.712 | 19,875 |
| `examples/run-06` | 减线索：Langflow 已形成不确定草稿，自查时响应读取断线；Flowise 未开始 | 2 / 1 / 0 / 1 / 1 | 11 / 91.337 | 108,308，另 1 次未知 |
| `examples/run-07` | 仅接上未开始的减线索 Flowise；完成，0 模型/工具/流程错误 | 1 / 1 / 1 / 0 / 0 | 10 / 34.354 | 64,603 |

完整公告四份合计 **2 完整候选、2 失败草稿**；减线索两份合计 **1 完整候选、1 不确定草稿（自查未完成）**。不要把四个运行的 requested_input_count 相加重复统计那些后来接上的输入，也不要把重叠变体当成六份独立公告。

四个运行耗时合计 280.889 秒，只是各自 CLI 记录的运行时间之和，不含输入准备、检查与打包。与旧 Pro 运行相比，代码、提示、预算和成功数量均不完全相同，不能据此宣布模型优劣或固定加速倍数。

## 具体获得了什么

### 完整材料：两处旧问题有改善，仍保留措辞疑点

开发助手对照了 run-04 保存的字段与证据，不是独立人工验收：

- Langflow `entry-04956`：完整路由和权限前提明确归于公告 E0002，源码 E0006 支持的相对路由另行说明，不再将局部源码当成完整挂载路径的证据。所选版本与修复线索的父提交关系、公告影响范围也分开表述。
- Flowise `entry-19628`：commit 理由正确区分修复 `1738fa9…` 与所选父提交 `c045…`，可对照该案例 E0004/E0005/E0007；入口说明收窄为 leads router 的相对路由，不凭局部文件宣称完整前缀及无需认证。
- 两条均有 15 个预期字段，entries 与相应 review.draft_fields 一致，没有缺失必填值，终检 errors 为空。这些是完整性和一致性事实，不是准确率。
- **仍有疑点：** Langflow trace 写了 “unterminated query”。保存的 E0006 展示的是条件性的 user_id 过滤及查询执行，不支持将其解释成 SQL/字符串未终止问题。交验应标记这处措辞不清，复核其实际想表达的过滤条件缺失；原 JSON 不改写。

### 减线索：不再只有工具合成测试，但尚不能宣称普遍成功

- Langflow `entry-79305` 实际调用 `list_refs` 1 次、`search_history` 2 次、`inspect_commit` 2 次、`read_file` 6 次、`search_code` 2 次，13 次工具读取均未报错。commit、EP、CO 留为 uncertain；自查前的有用字段和证据保留，没有以猜测填成完整记录。
- Flowise `entry-75975` 在未提供详细公告和修复候选时形成完整候选，实际调用 `list_refs` 1 次、`inspect_commit` 3 次、`search_code` 3 次、`read_file` 5 次，未调用 `search_history`，共 12 次工具读取且无错误。仓库初始 HEAD 不可解析，模型先列 refs 再检查提交，没有明显把固定 HEAD 当答案的证据。**commit 理由把所选 `55b6913c…` 定义为本地检查到相关行为的候选版本，并非已由公告确认的受影响版本；这一关键前提仍待人工判断。** 具体字段和源码摘录见 run-07 的 review/actions，完整候选不等于该前提已经解决。
- 减线索不是完全无线索：摘要本身仍可含主题、组件或路由名称，本地 refs/提交说明也可能提示修复位置。这是预先记录的输入删减诊断，不是严格控制的独立基准。

## 失败解释：不把格式错误当作安全拒绝

两次 JSON 错误的记录均显示 `model_matches=true`、`finish_reason=stop`、`refusal_present=false`，外层响应可解析，错误发生在 assistant 正文。请求已开启官方 `json_object` 模式，参见 [JSON Output 文档](https://api-docs.deepseek.com/guides/json_mode/)。

| 累计生成请求 | 错误 | 已保存的结构诊断 |
|---|---|---|
| 18，Open WebUI | `deepseek_response_invalid_json` | 行 1 列 5364：Unterminated string；正文 6419 字符，以对象开始，没有代码围栏。 |
| 20，OpenClaw | `deepseek_response_invalid_json` | 行 1 列 407：Extra data；正文 650 字符，以数组开始，没有代码围栏。 |
| 31，减线索 Langflow | `deepseek_transport_error` | `phase=read_body`，未得到完整响应，用量未知；自查没有完成。 |

未发现本地解析误报依据；没有补字符、猜填 JSON、扩大根类型或重试同一失败项。由于未保存原始错误响应正文，不能进一步断言哪段文本丢失、为何供应商没有满足格式约束，或定位断线的具体网络根因。后续只处理预定但尚未开始的输入，并保留原失败。前三个运行的外层 shell 观察到非零退出，第四个为 0；以实际 summary 的 `provider_stopped/completed` 和错误记录解释状态。

## 交验与下一步

离线阅读，不需要 key，也不会修改原模型记录：

```powershell
python -m vulngym_t2.review_export --run-dir examples/run-04 --output flash-full-review.md
python -m vulngym_t2.review_export --run-dir examples/run-06 --output flash-draft-review.md
python -m vulngym_t2.review_export --run-dir examples/run-07 --output flash-reduced-review.md
```

下一优先级是结构化响应稳定性和人工语义复核，而不是继续重复这四份直到全成功：先以短小的协议请求隔离新模型格式问题，任何格式兼容改动都独立记录，不能偷偷修复失败正文；再选择少量新公开输入扩充代表性。选择与运行都需明确授权，旧 key 已通知可撤销，不再复用。

本次只做模型选择相关的针对性离线检查及真实流程验证，没有再跑旧大规模门禁。程序接口、失败样例、公开输入、自评和开发记录均随包；设计 PDF 仍是首次交付快照，最新行为以 Markdown 和源码为准。未录制视频、未人工签字、未声称通过导师最终验收。

## 后续代码修复：不是又一轮实测成绩

用户要求继续修后，基于上述保存的故障做了以下更改，**没有再次使用临时 key，也没有重算或覆盖 run-01 至 run-07**：

1. 可选 `--response-mode strict_tool` 使用官方 Beta 的严格函数 schema，返回结构化 `submit_step` 容器；未知值不塞进 JSON 字符串、不补字符、不新增执行工具。保留原 thinking 设置，用 API 支持的 auto 工具选择；只接受一个正确容器。旧 json 模式保留兼容。它针对自由 JSON 生成这一故障来源，但尚未用真实服务验证支持情况或成功率。
2. 批次默认仅隔离经过完整外层、模型、结束原因及无拒绝检查的正文 JSON 错误。失败项只处理一次，账本和费用计数不断开；下一项必须是此前未处理的不同输入。`--stop-on-format-error` 可恢复旧行为。遍历完但含此类错误为 `completed_with_errors` / 退出 2，未完成和错误数量都保留。鉴权、权限、拒绝、模型不符、网络、截断和未知错误不会因此恢复。
3. commit review 新增 `revision_basis`。`inspected_only/unknown` 或缺声明不再满足 supported；`behavior_at_revision/affected_range_and_source` 还需该 SHA 实际源码引用及简短关联理由。没有修复链接也可以依据实际源码提出有根据的候选；这不是强制唯一版本答案，更不是程序自动理解了全部语义。
4. 新 `self_review_status` 明确区分未请求、完成、失败。初稿即使字段完整，只要已请求的自查失败，就留在草稿和复核材料，不进入正式完整条目。原稿字段不丢失，成功自查且有早期恢复错误的条目不会因此误降级。
5. 复核包和自评显示以上状态；旧记录缺声明时标明旧协议，而非替旧模型补写依据。离线 pending 也识别新终态，全部遍历完成时不会再提出重复输入。

离线验证使用合成模型响应、合成仓库及独立临时账本，检查严格参数、失败隔离、全局停机、预算不重置、版本降级、自查失败保留和导出兼容。这些只能证明代码处理符合预期，不能填上真实效果一栏。下一步应使用仍有效且明确授权的凭据做少量定向实测，先检验严格输出协议，再检验实际字段判断；不默认复用已通知可撤销的旧 key。

## 再次明确授权后的严格输出定向复测：阶段记录

用户随后明确确认继续使用同一 key，并沿用同一份最多 500 次请求的授权与累计预算，没有另开额度。前文“不再复用”“尚未真实服务验证”是此前阶段截止时的记录；本节追加再次获准后的实际进展，不改写 run-01 至 run-07，也不将尚未完成的后续安排列为成功。

### 协议短测成功，但不是任务提取结果

累计生成请求 42 使用 `strict_tool`、`thinking=enabled`、`tool_choice=auto`，完成一次仅返回空 draft 的短协议检查：**1 次 HTTP、3,199 tokens、1.674 秒**。该请求没有产出漏洞任务结果，不计完整候选或独立样本。它只说明这一次短请求能够通过所测协议；不能证明同一配置在真实任务中稳定，更不能说明版本判断或源码字段已经正确。

### run-08：真实任务在第一项停止

运行名为 `targeted-run-01`，六份公开产物已原样归档到 `examples/run-08`。计数仍按请求输入 / 已处理 / 完整候选 / 草稿 / 未开始排列：

| 随包目录 | 批次状态与结果 | 计数 | HTTP / 秒 | 已报告 tokens |
|---|---|---|---|---|
| `examples/run-08` | `provider_stopped`；第一项保留草稿，后三项未开始 | 4 / 1 / 0 / 1 / 3 | 2 / 7.456 | 26,763 |

累计生成请求 44 记录 `deepseek_completion_incomplete`，触发全局停止；本批 `format_failure_count=0`，不是可隔离后继续批次的正文 JSON 格式错误。保存的诊断为 `finish_reason=stop`、`refusal_present=false`、`model_matches=true`。这不是额度用尽或安全拒绝；也没有 `finish_reason=length` 支持输出长度截断的解释。现有记录只支持说明响应未满足控制器的完成条件，不据此猜测供应商内部原因。原失败和草稿保留，不因前述短探针成功而改记为成功。

### 显式关闭 thinking 后，仅接上未开始的三项

依据官方 [API 参数](https://api-docs.deepseek.com/api/create-chat-completion/)和 [Tool Calls](https://api-docs.deepseek.com/guides/tool_calls/)：thinking 下不能强制 required，而 strict 支持非 thinking。增加 `--thinking disabled` 显式选项，仅与 strict_tool 配合：发送 `tool_choice=required`，省略 reasoning_effort。默认 enabled 仍保留 auto；不会故障后静默切换，也不接收普通正文作为备用答案。该更改改变了推理配置，不能把新旧结果当严格控制的模型对比。34项限定离线测试通过，不替代真实效果证据。

累计生成请求45以 disabled/required 完成第二次空draft协议检查，1 HTTP、3,147tokens、1.631秒，同样不算任务结果。之后仅处理前批从未开始的 OpenClaw、减线索Flowise、减线索Langflow，材料及顺序未变，不重跑Open WebUI。相应四项原输入的可携带模板为 `examples/t2_v2_input/v41/strict-targeted-inputs.example.jsonl`，实际续批只取末三行；仓库路径需用户自行配置。

| 随包目录 | 批次状态与结果 | 输入 / 已处理 / 完整 / 草稿 / 未开始 | HTTP / 秒 | 已报告 tokens |
|---|---|---|---|---|---|
| `examples/run-09` | `completed_with_errors`；OpenClaw完整、Flowise证据不足、Langflow技术失败 | 3 / 3 / 1 / 2 / 0 | 15 / 56.259 | 191,297 |

三项分别使用4、6、5次模型调用，共29次只读工具调用；Flowise另有1次 `search_history failed: ValueError` 工具错误，后续继续。零未开始不等于零失败。最后一项累计请求60的原生函数参数仍非合法JSON：`Expecting ':' delimiter`，行1列3499，参数5799字符；`finish_reason=tool_calls`、模型匹配、无refusal，错误阶段为 `parse_completion_json`。这次严格schema并未消除语法失败；原始坏参数未保存，无法进一步定位供应商生成原因，未猜补或重试。

该错误满足既有格式隔离条件，`format_failure_count=1`；但它是最后一项，`continued=false`，没有实际发生“错误后继续下一输入”。因此这批也不能当作错误隔离分支的真实继续成功证据。所有输入已遍历但含错，保留 `completed_with_errors` 及非零退出，终态不是全成功。

### 逐条质量核对：完整候选也存在缺口

以下是开发助手对保存的公开字段与源码片段的只读核对，不是独立人工签字，不改写模型JSON：

- **OpenClaw：** 机器完整候选，15字段、verify=0、自查completed、无模型/工具错误。commit理由包含所选SHA实际源码与机制，但basis写 `affected_range_and_source`，同时理由承认受影响范围对应只来自公告、未检查本地版本表，不能称范围映射已确认。EP选了内部授权调用参数尾段567–577，理由承认外部handler声明未读、可达性为推断，却保持supported。**必需入口字段的实质依据仍有缺口；不能把这条机器完整候选当作交验已通过。**
- **减线索Flowise：** 自查completed，但commit最终 `inspected_only/uncertain`，建议SHA保留，EP/CO/分类随版本未建立而留待复核。它不是自查失败，也不是一次完整提取。E0013–E0015保存相关机制，模型仍以没有fix/范围作不足理由，有过度弃答疑点；“唯一可解析ref”措辞也与E0007/E0008成功检查其他SHA不一致。自查总结称恢复EP/CO supported，不取代最终review中的uncertain状态。
- **减线索Langflow：** 5次调用均在plan_and_read，未取得模型字段初稿，自查not_requested，而不是“自查失败”或“没有缺陷”。保留10个输入/默认字段、13条证据、10次工具读取，commit/EP/CO/分类missing。E0010–E0013保存源码窗口，E0013有截断标记；没有建立位置终检结果。
- **前批Open WebUI：** 同样未取得模型字段初稿，自查not_requested。保留10个字段、9条证据、6次成功工具读取；公告E0002有截断标记。技术失败不能当作模型已完成判断后的保守弃答。

所以这轮四个预定输入的真实结果是 **1个待语义复核的机器完整候选、1个证据不足草稿、2个技术失败草稿**。不是四条都完成提取，也不能与旧run的最好结果拼成新配置全成功。严格模式与版本声明修复只解决了一部分问题；主要剩余缺口是供应商结构输出稳定性、入口定义/可达性证据和过度弃答之间的校准。

### 本轮收尾与账本

本轮新增19 HTTP：2个纯协议检查、17个任务请求；新增已报告224,406tokens。原授权累计 **60个生成请求 + 1个目录查询 = 61/500**，已报告prompt591,190、completion65,681、总656,871tokens，仍另有此前1请求用量未知，费用未独立测量。没有重置账本、自动重试、换模型或追加独立样本；本轮调用已结束。

run-01至run-07原样保留，新run-08/run-09各六个公开文件随包。没有把密钥、账本、原始响应、隐藏推理、本地仓库路径或目标Git对象搬进交付包。两次协议检查的脱敏统计见本节，不作为额外样例目录。代码、CLI、自评、复核导出和当前说明一并更新；设计PDF仍是旧快照。下一步优先缩短/简化结构输出并补入口证据判断，而不是反复付费重跑这四题直到全绿。
