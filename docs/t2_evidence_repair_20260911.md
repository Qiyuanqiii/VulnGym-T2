# T2 证据导航与字段重判记录（2026-09-11）

第五轮 v6 已结束，原始机器结果为 1 完整、2 草稿；完整项的 EP 支持状态误放已修正，并通过零 HTTP 保存结果回放转为待审。原始运行记录不回写；工程修复已验证，外部入口证据和总体语义验收仍未完成。本轮付费调用已停止。

## 范围与统计口径

本记录只涉及同一份既有 OpenClaw 开发输入 `GHSA-JP4J-Q5FC-58GV` 的连续复测。独立新输入为 **0**；不同轮次、不同 slot、同链路的不同位置不等于独立漏洞或独立评测样本。旧输出保留，不用历史完整候选回填当前草稿。

五轮均使用 `deepseek-flash`、`staged_tool`、`thinking=disabled`，wire 为 `candidate-serial-snapshot-v2`。v3/v4/v5/v6 是 `prompt_revision` 的版本，不是不同模型；第四轮仍为 v5，另加入窄范围 JSON 边界兼容。输入、候选及调用分别计数；HTTP/工具预算由输入共享，不能按 review 行重复累加。

运行目录在 `D:/VulnGym-bv2-runtime/t2-evidence-repair-20260911/`。下表由各目录的 `summary.json` 核对，并结合其 `review.jsonl`、`actions.jsonl` 区分过程与字段状态。

| 轮次 / 目录 | summary 状态 | 输入 / review | 完整 / 草稿 | HTTP / 读工具 | 已报告 tokens | 耗时 | 当前字段协议错误 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| v3 / `openclaw-live` | `completed` | 1 / 3 | 0 / 3 | 14 / 8 | 246230 | 39.876 s | 0 |
| v4 / `openclaw-context-live` | `completed` | 1 / 4 | 0 / 4 | 15 / 8 | 292166 | 47.937 s | 1 |
| v5 / `openclaw-recovery-live` | `completed_with_errors`，进程 exit 1 | 1 / 1 | 0 / 1 | 5 / 9 | 73048 | 15.648 s | 0（尚未成稿） |
| v5 边界兼容后 / `openclaw-boundary-live` | `completed`，进程 exit 0 | 1 / 4 | 0 / 4 | 15 / 9 | 306782 | 50.153 s | 0 |
| v6 / `openclaw-field-guidance-live` | `completed`，进程 exit 0 | 1 / 3 | 1 / 2（原始机器结果） | 13 / 8 | 251333 | 45.759 s | 0（历史 1 项已恢复） |

这五轮合计 **62 HTTP、1169559 已报告 tokens**，同一旧输入 5 次开发复测，共 15 行 review，原始机器结果为 1 完整、14 草稿；唯一完整项仍有 EP 误放，不据此计算独立准确率或成功率。第五轮结束时累计 319 次生成加 1 次目录查询，即 **320/500**，剩余 180 次。历史仍有 1 次用量未知，不能将累计已报告 tokens 称为精确总消耗；币费未测。

## v3：引用越界未重现，但补证与版本理解仍有缺口

[v3 摘要](D:/VulnGym-bv2-runtime/t2-evidence-repair-20260911/openclaw-live/summary.json) 中模型、工具、pipeline、输入级格式错误均为 0。三个初稿均 `accepted`，自查均 `completed`。本次最终记录和自查反馈未再出现 `source_ref_out_of_bounds`，不等于所有描述已获语义确认。

三个候选分别进入 followup（第 7、10、13 次调用），状态均完成，但此时没有新增读工具或证据；全部 8 次工具读取发生在成稿前。因此“3 次 followup”不能写成“3 次实际补读”。

- slot 1 仅 EP 待审：保存理由承认外部回调/注册到内部 handler 的关系未读；commit/CO 可单独保留其局部行为判断。
- slot 2、3 的 commit 理由已描述该 SHA 的机制，却仍把缺少 release mapping 当作 `behavior_at_revision` 不能成立的理由。不能把这些草稿统称为正确弃答。
- slot 2 的可选 trace 建议还混用了另一 SHA，保留 `source_ref_commit_mismatch`；空 trace 不证明该链路，也不自动否定独立 EP/CO。

## v4：两次真实前缀补读，最后自查仍留下坏字段

[v4 摘要](D:/VulnGym-bv2-runtime/t2-evidence-repair-20260911/openclaw-context-live/summary.json) 仍无模型、工具、pipeline 或输入级格式失败，但有 1 个未解决字段协议异常，不能写成“没有格式问题”。初稿为 3 个 `accepted`、1 个 `partial`；4 个自查和 4 个 followup 均完成。

保存 actions 明确记下两次成功 `entry_context_read`：slot 1 的 E0010 请求 `agent-components.ts` 440–559，slot 2 的 E0011 请求同文件 320–439，均在已知 parent SHA。两次读取计入原 8 次工具总量，不另加模型 HTTP；后续 followup 阶段完成也不代表再次读取。前缀窗口用于找上下文，不自动证明外部注册、调用关系或漏洞事实。

slot 3 初稿的 `vuln_title / unexpected_properties` 经原自查恢复；slot 1 第 6 次调用（self-review）却留下 `critical_operation / unexpected_properties / $[0].arguments.critical_operation.value`。有效兄弟字段、建议和证据均保留，坏 CO 阻止完整导出。旧记录只保存该定位，不能倒推当时多出的具体属性名或值。

slot 2 的 commit 采用 `behavior_at_revision` 并明确没有 release mapping；其他 slot 仍有版本依据混淆、外部 EP 关系未证和分类判断不稳定。即使补读到了声明，调用/注册关系仍需按实际证据限定。4 个草稿不是 4 个已确认独立缺陷。

## 当前代码修正：三类动作不能混称“自动修复”

| 动作 | 允许做什么 | 不做什么 |
| --- | --- | --- |
| 安全形状诊断 | 保存固定字段、schema code/path、有限白名单 `known_extra_keys` 和 `unknown_extra_count`，给出声明形状提示 | 不记录任意原始属性名/值，不从未保存内容猜测答案，不将诊断当证据 |
| 无损冗余属性清理 | 仅当保留的核心通过既有校验，且允许位置的额外属性与合法字段值类型和值完全相同时，移除冗余并记录 `annotation_normalizations` | 不补必需值，不转换类型；不删除未知、不同值或可能包含限定语的属性；不是容忍重复 JSON 键 |
| 有界字段语义重判 | 原自查后仍有 `annotation_errors` 时，对目标非 commit 字段至多请求一次 `field_recovery`；同时重判证据支持与结构，合法提交才可清除当前错误 | 不是盲重试或纯格式修补；不改健康兄弟，不靠删改措辞解除支持矛盾，不保证恢复、准确或人工确认 |

字段重判仍提交同一个完整八字段 snapshot，但控制器只应用 `targeted_field_review` 指定字段。commit 涉及跨字段版本判断，不走局部恢复。未知保持 `uncertain`，无新读工具，只有原总调用预算内的余量可用；必须预留后续候选各一次 draft 和 self-review。没有余量就保留草稿，不能偷用后续候选额度。

此外，固定 `revision_basis_review` 清单把“所选 SHA 的源码与机制必要前提”和“SHA 到 affected release/range 的映射”分开：前者适用于 `behavior_at_revision`，后者是 `affected_range_and_source` 的附加要求。缺 release mapping 本身不自动否定局部 CO；若另有必要前提未证，应具体说明，不能自动提升状态。前缀读取也接入已记录的外部入口支持矛盾，但不以任意理由关键词推断源码。

新增 `completion_json.py` 的窄范围兼容与上述字段重判不同：仅在已验证响应 envelope 中的 `submit_annotation` / `propose_candidates` arguments，允许一个已经完整解析的 dict 后只有单个冗余 `}`（边界 JSON 空白除外）。正常 JSON 原样解析；其他尾部字符或不完整对象不修改。仍使用同一严格 decoder，重复 JSON 键、非有限数字、大小/资源界限及后续 schema 校验不放松；read 工具参数、外层响应 envelope 和 refusal 处理不受影响。无新增 HTTP 或 retry，命中时保存受控 `completion_json_normalizations` 审计，代码为 `redundant_object_close_removed`、数量 1，不保存回答正文。此前请求 291 的实际尾部字符未留存，不能仅凭 `Extra data` 追认它满足此规则，也不回写旧结果。

对应入口为 `annotation_rules.py`、`source_refs.py`、`staged_protocol.py`、`pipeline.py` 和 `completion_json.py`。除上述明确定义的尾部兼容外，整体非法 JSON、控制容器、候选规划及工具权限/预算限制仍严格；不因单字段恢复放松全局协议。

## v5：候选规划前置解析失败，恢复分支尚未真实触发

[运行计划](D:/VulnGym-bv2-runtime/t2-evidence-repair-20260911/recovery-live-plan.json) 限定同一输入、最多 16 次 HTTP/生成、32 次只读工具、零自动 HTTP 重试，不将旧预测作为输入。[实际摘要](D:/VulnGym-bv2-runtime/t2-evidence-repair-20260911/openclaw-recovery-live/summary.json) 已结束。

第 5 次请求处于 `candidate_selection`，`deepseek_response_invalid_json` 阻止规划被接受；保存 1 行技术失败草稿和已有证据，不伪造候选。`initial_draft_status=not_received`，自查/followup 均 `not_requested`，未进入 `field_recovery`，故不能声称局部重判已真实成功。

公共 `model_failure` 诊断为 `phase=parse_completion_json`、`JSONDecodeError: Extra data`、第 1 行第 1615 列、回答长度 1615，`finish_reason=tool_calls`、`refusal_present=false`；主线程受控诊断另确认 1 个 `propose_candidates` 调用。不是权限拒绝，不应凭错误名推断幻觉或删除尾部内容。此后增加的窄范围兼容不改变这一历史失败，后续运行单列如下。

本次 `format_failure_count=1` 表示 1 个已处理输入出现格式失败。summary 的 `model_error_count=2`、`pipeline_error_count=2` 对应请求失败及“没有候选规划”的后续过程记录，不是 2 次额外失败 HTTP；工具错误为 0。

## 第四轮：流程无技术错误，版本依据与待审理由仍未统一

[第四轮摘要](D:/VulnGym-bv2-runtime/t2-evidence-repair-20260911/openclaw-boundary-live/summary.json) 已结束：4 个初稿均 `accepted`，4 个自查及 followup 均 `completed`，format/annotation/model/tool/pipeline 错误均为 0。候选规划提出 5 个范围，按预算/槽位上限选择 4 个、略去 1 个；这不是 4 个独立缺陷成立的证明。

公共 actions 没有字段拒收/恢复、`annotation_field_recovery` 或任何 normalization 审计。因此这次没有实际触发局部字段重判，也没有观察到 `completion_json_normalizations` 尾部兼容命中；正常完成只能证明该次响应通过当前链路，不能证明这两个异常分支真实恢复成功。

最终阻断均为 `model_uncertain`，不是技术失败。以下只比较保存的状态和理由，不重新分析目标源码或调用关系：

| slot / entry_id | 待审字段 | 保存理由仍需澄清之处 |
| --- | --- | --- |
| 1 / `entry-59467` | commit、EP、CO | commit/CO 均称机制已被读取，剩余缺口只是 release mapping；CO 还明确说机制本身不是缺失前提。仍将映射缺失绑定到 `behavior_at_revision`/局部 CO。 |
| 2 / `entry-00000` | commit、EP、CO、L1、L2 | commit 理由称机制 established，CO 理由却称只读局部窗口、机制细节 uncertain；需统一限定范围。分类理由因没有明确 CWE 而保留 uncertain。 |
| 3 / `entry-00001` | commit、EP、CO | commit 仍称 `behavior_at_revision` 有未映射的 affected-range 前提；CO 混合了 release mapping 与没有查其他路径的更广泛缺口，不能只靠换措辞解决。 |
| 4 / `entry-00002` | commit、EP、CO | commit 仍因缺 release mapping 保留建议；CO 理由从局部机制已见转向外部 EP 未读，局部判断与完整路径的界限仍需说明。 |

四个 EP 都明确保留外部回调/注册或 dispatch 未证的限制。四个可选 trace 均为空，原 uncertain 说明保留在 `omitted_assessment`；不能把空 trace 的外层 supported 理解为链路通过。`reason_citation_checks`、`support_consistency_checks` 均为空，不等于理由语义已获批准，也不能把 4 个草稿统称为正确弃答。

## v6：版本依据表述改善、字段恢复实触发，但机器完整项仍有 EP 误放

v6 在成稿函数的 commit/CO schema description 中加入假设条件示例，将关键区分放在模型填写字段的位置：**如果**所选 SHA 的源码和所述机制必要前提已经成立，缺少 release mapping 本身不是 `behavior_at_revision` 的缺口；`affected_range_and_source` 仍需实际映射证据。局部 CO 与官方 affected-release 归属分开陈述，不能因外部 EP 未证就自动否定已经独立建立的局部操作，也不能补造其必要前提。

这些是假设条件示例，不是对当前输入事实的断言。此次只补充函数 schema 描述，不改字段类型、已有规则或证据要求，不自动升级状态，也不新增请求上限。

[第五轮摘要](D:/VulnGym-bv2-runtime/t2-evidence-repair-20260911/openclaw-field-guidance-live/summary.json) 为 1 个输入部分完成（`partial_input_count=1`）：三个候选初稿均 `accepted`，自查和 followup 均 `completed`，当前 format/annotation/model/tool/pipeline 错误均为 0。规划提出并选择 3 个范围，无略去项。三槽 commit 均 `supported / behavior_at_revision`，理由明确将已观察机制与未映射 release membership 分开；三槽局部 CO 也均 supported。这是本次保存理由相对第四轮的具体改善，不是对所选版本或机制的独立语义批准。

| slot / entry_id | 原始终态 | 实际保存的限制 |
| --- | --- | --- |
| 1 / `entry-59467` | draft，仅 EP uncertain | EP 理由保留 `source_ref_commit_mismatch`：引用中的 dispatch/call-site 属于 fix SHA，未建立所选 parent SHA 的外部入口角色；没有让 EP 缺口自动抹去局部 CO。 |
| 2 / `entry-00000` | complete，`verify=0`，未人审 | EP 选了局部访问 gate/helper，status 却 supported；同一理由明确承认外部回调角色仅见于 diff callers（E0006），没有 dispatch 的 read receipt。trace 的原始 missing 说明同样承认缺少外部 dispatch→helper 的读取证据。此为已发现的 EP 支持状态误放，不能作为可信成功。 |
| 3 / `entry-00001` | draft，仅 EP uncertain | EP 明确保留 fix/parent SHA 不符与选定版本缺 handler 读取的限制；CO 经一次局部重判恢复后，EP 仍未被升级。 |

第五轮确实进入新恢复分支：slot 3 第 12 次 self-review 的 CO 被拒，定位为 `unexpected_properties / $[0].arguments.critical_operation.value`；安全形状记录仅指出 `known_extra_keys=["evidence_refs"]`、`unknown_extra_count=0`，不含被拒原始值。第 13 次 `field_recovery` 仅重判 CO，随后保存 `annotation_field_recovered` 和 `annotation_field_recovery: recovered`。这次真实完成了字段协议恢复，仍在原 16 次总调用上限内，无新工具、无自动 HTTP 重试；恢复字段不是人工确认，整条也仍因 EP 待审而是草稿。

没有 `annotation_normalizations` 或 `completion_json_normalizations` 审计命中，不能将这次恢复归因于无损属性清理或 JSON 尾部兼容。原始完整项的 `support_consistency_checks={}` 未捕获上述 EP 限定表达；该实际漏检随后由 `declared-support-v2` 修正。新规则只在 EP 自身当前句子同时声明“外部派发角色”“仅由 diff 支持”“不是该派发的读取回执”时转为待审，不因提到 diff 就否定字段，不扩散到 CO 或可选 trace。

[保存结果回放脚本](D:/VulnGym-bv2-runtime/t2-evidence-repair-20260911/replay_v6_candidate.py) 已通过：slot 2 / `entry-00000` 从 complete 转为 draft，EP 从 supported 转为 uncertain，错误为 `supported_reason_conflict / entry_dispatch_diff_only`；commit、CO、原理由、引用和建议全部保留。回放只检查保存的公开读取文本，0 HTTP、0 目标仓库读取，旧文件逐字节未变，输入状态未被修改。它验证这次漏放修正，不是新的模型成绩或人工批准，也不能证明有限表达检查已覆盖所有语义矛盾。原始 entries.jsonl 里的 1 条机器完整项仍作为历史保留，不应拿去冒充本轮可信成品。

## 离线验证与交接边界

主线程最终全仓检查为 532 项：531 通过、1 跳过，37.914 s；独立冒烟 11 项通过，18.057 s。局部恢复预算合成测试覆盖：三个候选无余量时不恢复首项，保留后两项 draft/self-review；恰好多一额度时仅恢复一次，不增加工具量或自动重试。这些是程序行为验证，不是模型准确率。

请求账本最终为 319 started / 319 finished，无 pending 或重复请求号；加历史目录查询共 320/500，剩 180。五轮共 62 HTTP，其中 1 次格式错误；零自动 HTTP 重试。本轮用 key 已结束，可撤销。[机器摘要](D:/VulnGym-bv2-runtime/t2-evidence-repair-20260911/repair-summary.json) 保存最终核验与边界。

第五轮提供了真实字段恢复记录和版本依据表述改善，但唯一机器完整项仍有 EP 误放，JSON 尾部兼容也未实测命中，不能宣称导师验收或准确率提高。后续以少量代表性输出的语义抽查和可演示交接说明缺口；没有人工评估就明确未评，不升级 `verify=0`，不把空人工表当确认，也不额外要求所有条目自动 complete 或逐条签字。本记录不产生 ZIP、不执行 Git 发布，也不修改历史运行材料。
