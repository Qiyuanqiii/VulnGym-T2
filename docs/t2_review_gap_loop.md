# 可选的自审缺口补读循环

当前控制器策略为 `review-gap-loop-v1`；沿用原 `snapshot-guidance-v84` 系统规则、阶段 schema、十五字段输出和 `verify=0`。这是默认关闭的、同一次输入处理内的有限补读机制，不是完整任务编排框架，也不表示 T2 内容目标已经完成。

## 开关与预算

CLI 参数为 `--review-read-cycles 0|1|2`，默认 `0`。只有非零值要求 `--response-mode staged_tool`；不符合模式时，在读取输入、凭据或打开账本之前拒绝。`--prepare-only` 的 `configuration.review_read_cycles` 会显示选定值。默认 0 保持原调用路径，不向 `produce` 传入额外配置，也没有新增 GUI 控件。

参数表示最多允许几次额外“定向读取决策＋完整自审”，不是保证执行次数，也不是新的请求额度：

- 仍共用输入的 `--max-calls-per-report`、`--max-tool-calls`、本次 `--max-requests`、provider 剩余额度和原累计授权账本。CLI 原可设上限仍是每份资料 16 次模型调用、64 次本地工具调用；不因开关而将用户选定的更低上限抬高。工具、读取范围及 100000 字符上下文边界不变。
- 单输入预算足够时，探索阶段让出“一次读决策＋完整自审”的空间，只提前安排一个循环；设为 2 不预先扣出两份，第 2 次只使用实际剩余空间。启用时，探索预算按单输入上限与 provider 剩余额度的较小值计算，不能以 16 次单输入配置替代实际仅余 12 次的可用空间；默认 0 不改旧规划。`assessed_tool` 的完整自审包含评估和编码两次调用，其他 staged 格式按原自审费用计算。编码纠正及后续候选等既有预留仍受保护，因此上述最小费用不是全部可用性条件。
- 这是 opt-in 的质量/覆盖取舍，多候选也可进入补读自审循环。预算充足时，多候选探索同样让出“一次读决策＋完整自审”，assessed 模式另留一次共享编码纠正余量；候选接纳阶段仅在仍能完成至少一个候选及额外循环时，先保护输入级的一份循环预算，可能因此少选一个提案。`omitted_count` 如实保留，未选不算失败；不是逐槽发放新额度，也不保证每个候选都有循环余量。后续候选和原总模型/工具/账本上限继续受保护，条件不足就停止，不自动 HTTP 重试或花满循环数。

## 何时补读，何时重新自审

原有初稿与第一次完整自审先执行。只有自审已完成，控制器才按实际字段、引用和最终校验结果整理仍未建立支持的必要字段缺口；不能只看模型写了 supported 就忽略被拒位置。缺口理由是可能出错的任务资料，不是新的源码事实或执行指令。

每个可用循环依次执行：

1. 检查真实必要字段缺口与剩余预算。只有可选 trace 未补齐，不构成追加读取的理由；必要字段已无缺口时停止。
2. 将缺口及既有来源交给一次定向读决策。模型可请求一个允许的窄读取，也可 `finish_reading`；不要求补造答案或重读已经覆盖的窗口。既有有界导航仍受原工具和上下文限制。
3. 只有本轮新增了成功保存的实际工具回执，才重新做一次工具关闭的完整自审。成功回执不等于证明了字段：空搜索、版本线索或局部源码仍需按实际含义判断，未知可以继续保留。
4. 若没有新增成功回执，不购买一次重复自审；若已有新回执，旧的 completed 自审状态不能认证新状态。后续完整自审未完成或失败时不能沿用旧自审把该候选导出为 complete。额外循环仍遵守原整份编码拒收、受限纠正与字段校验，不复用被拒对象。

再次自审后仍有必要缺口且剩余条件允许，才考虑第 2 个循环。停止理由包括没有必要缺口、provider 已停止、模型/工具/上下文预算不足或没有新证据。合理未知、工具/模型故障和未执行循环应分别解释，不能把“未执行两轮”当作失败，也不能把多做自审当作语义成功。

## 如何查看过程回执

复核输出 `review.jsonl` 在存在循环策略记录时附带 `review_cycle_history`，对应动作仍保留在 actions 中，正式 entries 的十五字段不增加：

- `review_cycle_policy` 标明 `review-gap-loop-v1` 与申请的循环数；`review_cycle_planning_reserve` 记录实际采用的探索预留。这里的 `requested_calls` 必须按动作含义解释，不与真实 HTTP 次数相加。
- `review_cycle_gap` 保存该轮必要缺口、状态和来源引用；`review_cycle_started` 记录实际进入的循环。
- `review_cycle_result` 保存新增成功回执 ID 及后续自审状态；`review_cycle_stopped` 保存停止原因。这些动作中的 `slot` 是循环序号，不是新增候选条目。

默认 0 不伪造循环历史。判断是否真实发生补读/重新自审，应联看成功工具回执、阶段状态与这些动作；不能仅凭配置为 1 或 2，便声称完成了对应循环。回执保留原有公开过滤与错误边界，不新增私有 provider 响应或隐藏推理导出。

## CLI 示例：在既有运行配置上增加开关

已有 staged 命令只需增加 `--review-read-cycles 1`；保留原输入、输出、调用上限和同一授权账本。下面沿用[打包与运行说明](t2_v2_packaging.md)的 low 配置及 12 次示例上限，没有提升到允许的最大 16。路径是占位符，须换成已有材料、本地仓库及原授权账本；输出目录必须是新的。

先做无凭据、无模型 HTTP 的配置检查：

```powershell
& 'D:\python314\python.exe' -B -m vulngym_t2 --advisory 'D:\materials\advisory.json' --repo 'D:\repos\project' --model deepseek-flash --response-mode staged_tool --annotation-format assessed_tool --read-format plan_tool --thinking enabled --reasoning-effort low --max-tokens 32768 --max-calls-per-report 12 --max-tool-calls 64 --max-requests 12 --review-read-cycles 1 --prepare-only
```

只有另获真实运行授权后，才可使用对应运行模板；本说明没有执行下面命令，也不提供或读取 key：

```powershell
& 'D:\python314\python.exe' -B -m vulngym_t2 --advisory 'D:\materials\advisory.json' --repo 'D:\repos\project' --output 'D:\results\review-gap-run-001' --request-ledger 'D:\results\authorization.jsonl' --authorization-limit 3000 --effective-request-limit 2999 --model deepseek-flash --response-mode staged_tool --annotation-format assessed_tool --read-format plan_tool --thinking enabled --reasoning-effort low --max-tokens 32768 --max-calls-per-report 12 --max-tool-calls 64 --max-requests 12 --stop-on-format-error --review-read-cycles 1
```

3000/2999 是已有授权的累计账本/执行上限组合，不是新预算；不要新建账本清零，也不要把上述 12 次模板当作新的付费授权。`--review-read-cycles 2` 仅改变最多可尝试的循环数；是否有机会执行仍由原预算和实际缺口决定。

## 当前边界与验证状态

该机制只使用本次处理已经保存的输入、证据、字段判断和新增回执；没有断点续跑、跨运行恢复或外部选择性 memory，也不自动接入 T1 反馈、执行目标代码或改变 GUI 默认流程。

本功能尚无真实效果证明，本次实现与说明没有新增付费调用。已保存的 v83/v84 真实运行发生在这项控制器扩展之前，不因继续使用 v84 系统/schema 标识便成为 `review-gap-loop-v1` 的效果成绩。

生产代码冻结后的离线验证为：全仓 unittest **1186 项，1185 通过、1 既有 Windows 符号链接能力跳过，26.455 秒**；冒烟 **11/11，10.055 秒**；本轮 Node 假 DOM 交互 **27/27，169.0556 毫秒**，均退出 0。相对此前 1151 项基线新增 35 项 unittest：循环 21、CLI 11、回执 3；不是新增真实模型样本。明细与前基线见[代表性验证](t2_representative_validation_20260913.md)，不以测试通过或新增回执直接宣称字段准确、完整率提高或全任务完成。

另沿现有演示的 `inputs/02-nltk-bundle/record.jsonl` 命令追加 `--review-read-cycles 1`，在 multi/staged/assessed/plan_tool/low、每份 16 次／本次 12 次请求／64 次工具配置下，实际 prepare-only 退出 0：`http_attempts=0`、`repo_available=true`、`document_count=2`、`input_error=null`、`configuration.review_read_cycles=1`；未读取 key、打开账本或检查模型。这只证明免费输入预检与配置回读，不证明循环真实效果。
