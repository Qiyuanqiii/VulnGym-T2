# T2 健壮性修复与验收记录（2026-09-11）

后续更新：本页保留当时离线修复过程；随后[真实复测](t2_snapshot_v2_retest_20260911.md)已完成，4 输入 / 42 HTTP / 1 完整 / 8 草稿，仍有 1 份全局格式失败。不能把本页离线通过解释为整道 T2 或真实服务效果已验收。

## 本轮目标与范围

本轮按用户要求修复当前代码的健壮性、可读性与测试方向，并在发现新问题后继续修复、重跑全仓测试和端到端冒烟。不是重新运行旧 finalizer，也不是新的真实模型效果评测。

工作仓库：`D:/GitProjects/VulnGym-T2`，分支 `codex/t2-core-v2`，开始时 HEAD 为 `4e86882`。保留原有未提交修改及历史结果；不修改旧主仓库、不提交或推送、不提供新 ZIP。本轮没有真实模型 HTTP 请求。测试临时目录放在 D 盘；这不代表能阻止 Codex 应用自身保存会话日志。

T2 主目标不变：公告材料与已提供的本地仓库 → 自主查阅 → 有证据的 VulnGym 条目。不确定应保留给人工复核，不能为了提高完整数而错标。正式条目仍为原 15 字段且 `verify=0`。

## 修复了什么

1. **单个漏字段不再导致整个成稿响应作废。** snapshot-v2 对八个字段分别检查；缺省与坏字段有明确 field/code/path，合法兄弟保留。最终复核漏掉的字段不能继承初稿的 supported；空对象是八条缺失错误，不是成功。未知控制键、坏 JSON、重复键、越阶段调用和资源超限仍拒绝。
2. **主流程按阶段组织。** `_ProductionSession` 显式持有输入状态、证据、预算与候选作用域，拆分准备、读取、成稿、补读、自查。移除大闭包的跨函数 nonlocal 修改；候选状态在请求前挂入结果，中断时保留已完成候选及当前草稿。
3. **为最终自查预留上下文。** 读取前预算包含下一份最大结果和完整快照/复核的预留空间；达到上限会结束探索，而不是先读满再发现没法自查。可选补读/预览不能占掉原一次自查。超大输入仍有明确上限，不保证任意长度材料都能完整读入。
4. **不静默丢掉解释尾部。** 保存允许的 2000 字符理由；旧模式超长理由或程序前缀造成的截短带 `reason_truncated`，报告和预览保留警告。trace 建议展示原 `omitted_assessment`，不能把“省略可选 trace”的 supported 当成对建议链路的支持。
5. **失败状态不会被裁剪和汇总变成成功。** 在裁剪仓库回执前判定 error/ok/success；缺历史等错误保留白名单代码、不透传任意异常原文。输入级格式失败按 typed event 统计，是否允许下一输入是另一个判断；字段错误另计，不混同技术失败与有用未知。
6. **请求与账本有明确生命周期。** 已关闭的客户端/账本不能继续请求/写入；不重复 finish，不在写盘失败后继续。发送中断保留 unfinished 请求和未知用量，不伪造 finished，不自动重发；重开账本遇到不确定现场必须停下检查。
7. **保存和读回更可靠。** 完成导出先序列化、暂存再替换，summary 最后发布；写入失败保留现场且不生成假完成摘要。重复草稿 ID、entry/review 不一致、坏 JSON/actions 明确报错。合法唯一 slot 中的坏 child 保留独立错误草稿，不丢合法兄弟；非法或重复身份不猜补。
8. **CLI 的取消和坏输入可解释。** 合作式 Ctrl+C 保存已经取得的部分结果并退出 130；不继续下一输入。重复键、非有限数、深嵌套和畸形 URL 记为当前坏输入，不拖垮后续有效输入。强杀进程/断电仍不保证当前写入完成。

## 验收标准与证据

| 验收内容 | 实际要求 | 检查入口 |
|---|---|---|
| 字段隔离 | 八字段逐一遗漏；原一次复核可显式恢复；仍缺失则不能 complete | `test_t2_v2_annotation_recovery.py`、`test_t2_v2_snapshot_protocol.py` |
| 证据与状态 | 坏引用、失败读、不同 SHA 不补造源码；建议 trace 不假标 supported | `test_t2_v2_source_refs.py`、`test_t2_v2_pipeline_resilience.py`、`test_t2_v2_trace_preview.py` |
| 原预算有效 | 同输入/候选不重置授权，无自动重试；大历史仍保留原一次自查 | `test_t2_v2_llm.py`、`test_t2_v2_context_budget.py`、`test_t2_v2_staged_multi.py` |
| 中断保全 | 当前请求不冒充已结束；前候选不因后候选失败而消失；CLI 停止 | `test_t2_v2_resilience_smoke.py`、`test_t2_v2_llm.py` |
| 写入/读回 | 输出失败无假 summary；完成前不截断已写条目；错误有稳定诊断 | `test_t2_v2_output_resilience.py`、`test_t2_v2_report_review.py` |
| 真正串联组件 | 实际 CLI、临时 Git、读取、协议、管线、写入、复核导出，只有模型 HTTP 替身 | `test_t2_v2_resilience_smoke.py` |
| 正式格式不变 | 完整条目仍 15 字段、来源关联一致、verify=0；review 不混入 entries | 输出测试与端到端冒烟 |

这里的合成资料用于检验工程行为，不能给出模型语义准确率。对应 run-25 漏 entry_point、run-26 漏 vuln_title 的测试是基于保存诊断构造的等价异常，不是原始模型响应重放。

测试方向分为：协议/状态负例、跨模块生命周期、CLI + Git 端到端故障注入、独立的真实模型效果评审。前三类可离线重复；第四类不能用前三类替代。

## 执行结果

- 修复前全仓：308 项，307 通过、1 跳过；说明旧测试变绿并未覆盖最近实测故障。
- 首轮修复后全仓：364 项，363 通过、1 跳过。
- 独立复核随后复现“大历史挤掉自查”和“建议 trace 误标 supported”，已补修及回归测试。
- 最终全仓：**377 项，376 通过、0 失败、0 错误、1 跳过，21.492 秒，退出 0**；收尾两次全仓结果一致。跳过项为当前 Windows 环境不允许创建符号链接的复核导出检查，不隐报为通过。
- 独立端到端冒烟：**11 项，全部通过，13.181 秒，退出 0**；包含正常成稿、未知、遗漏、坏引用、缺历史、第二候选失败、格式计数、预算耗尽、取消、输出写入失败，以及 help/prepare-only 子进程。
- 大上下文回归用原 6 次上限，在 4 次模型替身调用内完成初稿和一次自查，保留同 SHA 的原始源码回执；不靠扩大预算或重试通过。
- API 请求：0；不增加真实批次、准确率或“已独立验证”条目。

可复跑（仓库根目录，Python 标准库 + Git）：

```powershell
$env:PYTHONDONTWRITEBYTECODE='1'
$env:PYTHONUTF8='1'
$env:TEMP='D:\VulnGym-bv2-runtime\tmp'
$env:TMP=$env:TEMP
python -B -m unittest discover -s tests -p 'test*.py' -q
python -B scripts/smoke_t2_v2.py --temp-root D:\VulnGym-bv2-runtime\tmp
```

上述临时父目录需要已经存在；非 Windows 环境可换成自己的临时目录。smoke 不读取真实 key、不联网、不执行目标代码；临时合成工作目录由测试清理，不清理历史运行。当前可选打包脚本为避免发布半包，使用同目录暂存与不覆盖发布，目标文件系统需支持硬链接；本轮只测合成打包失败行为，不生成用户交付 ZIP。

## 仍然不能宣称的部分

截至本页离线修复阶段，最近真实结果是 **snapshot-v1 的 run-23～26：4 个既有输入、1 完整候选、6 草稿、2/4 输入协议失败**。它们保留不动；v2 的工程修复不能追改这些结果为成功，也不能证明真实服务不再漏字段。其后的真实复测另见页首链接。

后续效果工作应单独进行：在有效授权、原账本与小批预算内复测旧失败形态；随后使用独立输入并人工核对版本、外部入口、关键操作及其关系。报告完整候选、保留未知、技术失败三类结果，不将重复开发案例算成新样本。自动覆盖多个入口、语义准确性及导师验收仍未证明，本轮工程验收不是整道 T2 的最终验收。

## 委托审阅覆盖

使用 Open Code Review delegate 仅选取变更文件和加载 Python 审阅规则；没有调用其外部模型。初始精确范围 **36 个 (path,status)，36 reviewed、0 skipped，覆盖 100%**，124 个文档/示例等路径在选取阶段明确排除；这不是全仓代码覆盖率。各代理更小范围的 preview 不作为全仓统计。随后新增或纳入的 7 个实现/测试文件也完成检查；未改动 vendor 的当前 T2 调用路径另作上下文核对。

| 初始范围路径 | 初始状态 | 结论 |
|---|---|---|
| `scripts/package_t2_v2.py` | modified | reviewed |
| `tests/test_t2_v2_cli.py` | modified | reviewed |
| `tests/test_t2_v2_intake_repo.py` | modified | reviewed |
| `tests/test_t2_v2_llm.py` | modified | reviewed |
| `tests/test_t2_v2_output.py` | modified | reviewed |
| `tests/test_t2_v2_protocol.py` | modified | reviewed |
| `tests/test_t2_v2_transport.py` | modified | reviewed |
| `vulngym_t2/cli.py` | modified | reviewed |
| `vulngym_t2/intake.py` | modified | reviewed |
| `vulngym_t2/llm.py` | modified | reviewed |
| `vulngym_t2/output.py` | modified | reviewed |
| `vulngym_t2/pending.py` | modified | reviewed |
| `vulngym_t2/pipeline.py` | modified | reviewed |
| `vulngym_t2/protocol.py` | modified | reviewed |
| `vulngym_t2/report.py` | modified | reviewed |
| `vulngym_t2/review_export.py` | modified | reviewed |
| `vulngym_t2/source_refs.py` | modified | reviewed |
| `vulngym_t2/transport.py` | modified | reviewed |
| `tests/test_t2_v2_annotation_error_output.py` | added | reviewed |
| `tests/test_t2_v2_annotation_recovery.py` | added | reviewed |
| `tests/test_t2_v2_claim_review.py` | added | reviewed |
| `tests/test_t2_v2_multi_cli.py` | added | reviewed |
| `tests/test_t2_v2_multi_consumers.py` | added | reviewed |
| `tests/test_t2_v2_multi_entry.py` | added | reviewed |
| `tests/test_t2_v2_package_conflicts.py` | added | reviewed |
| `tests/test_t2_v2_report_review.py` | added | reviewed |
| `tests/test_t2_v2_revision_feedback.py` | added | reviewed |
| `tests/test_t2_v2_serial_output.py` | added | reviewed |
| `tests/test_t2_v2_snapshot_protocol.py` | added | reviewed |
| `tests/test_t2_v2_staged_multi.py` | added | reviewed |
| `tests/test_t2_v2_staged_pipeline.py` | added | reviewed |
| `tests/test_t2_v2_staged_protocol.py` | added | reviewed |
| `tests/test_t2_v2_staged_read_batch.py` | added | reviewed |
| `vulngym_t2/annotation_rules.py` | added | reviewed |
| `vulngym_t2/multi_entry.py` | added | reviewed |
| `vulngym_t2/staged_protocol.py` | added | reviewed |

新增/额外检查：`vulngym_t2/repository.py`、`scripts/smoke_t2_v2.py`、`tests/test_t2_v2_resilience_smoke.py`、`tests/test_t2_v2_output_resilience.py`、`tests/test_t2_v2_pipeline_resilience.py`、`tests/test_t2_v2_context_budget.py`、`tests/test_t2_v2_trace_preview.py`。这些均 reviewed，不将历史存在的 dirty 改动全部算作本轮新增。
