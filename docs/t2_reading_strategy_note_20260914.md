# 读取策略机制记录：历史 v79/v80 与后续 v81/v82

## 2026-09-14 后续状态

下文原记录保留为 v79/v80 历史，不代表当前所有机制均未修。当前唯一工作区为 `D:\VulnGym-T2-work`；v81 四批真实复测共 53 HTTP，累计 2659/3000，余 341。完整候选与语义验收分开，详见[代表性验证](t2_representative_validation_20260913.md)。

v81 的可逆回执表示压缩在 Airflow 实际运行中已发生，但仍有必要代码未读；SQL 候选预读未触发，不能将其完整数增加认作改进。新的真实回执定位了两个程序边界，随后在 v82 分别修正：

- 已提出的 staged `read_file` 在 1024–4095 字符结果空间内可执行整行小窗；搜索仍用 4096 门槛，68k 探索、100k 总上限与最终评审预留均未放宽。超长行/元数据仍明确失败，不造可见源码。
- 候选按明确提到的文件 basename 分别排名；已读文件仍参与各组竞争，组内歧义拒绝，只有一个未读组赢家才补读。已读辅助文件不再跨名称压住操作本体，同时避免跳到同名兄弟文件。

这些是本地工程修正。SQL 保存回执的纯选择回放由 None 变为原提案对应路径，不代表已执行该读取；v82 尚无真实模型成绩。不新增重试、不降低字段证据要求、不改原结果。本轮 key 使用已结束，不继续付费。完整终态、自审完整性和剩余条件以各版本独立记录为准。

## 历史原始记录（v79/v80）

日期：2026-09-14。对象为 2026-09-13 v79 三批代表运行的读取策略账目（`D:\VulnGym-bv2-runtime\t2-representative-20260913` 下 `03-chain-v79-low`、`regression-airflow-v79-10`、`01-sql-v79-low`），以及分支 `codex/t2-core-v2` 工作副本 `D:\VulnGym-T2-work` 的代码行号。

**本文区分已实施与未实施；未实施项需要单独批准。** 第 1 节的窗口预留经人工批准后已于本工作副本实施并附离线用例；第 2、3 节仅依据已保存回执与代码静态阅读记录机制与候选方向，任何一个候选方向的实施都需单独设计批准后另行提交。本文未联网、未调用模型、未修改运行目录（只读）；除第 4 节列出的改动外未触碰 `llm.py`、`output.py`、prompt 文本、`PROMPT_REVISION` 及任何预算上限。

## 1. chain：followup 决策窗口被探索挤占（已修，本次实施）

### 1.1 回执账目（全部为已保存事实，已对照 actions.jsonl 复核）

- `run_request_limit=12`，assessed 单输入（`multi_entry=false`、`annotation_format=assessed_tool`），故 `annotation_call_cost=2`（`pipeline.py:293`）。
- 调用 1–7 全部为 `plan_and_read`；第 7 次的工具处理触发 `read_context_closed`（reason=`reserve_annotation_review_context`，`result_allowance_chars=0`）——探索本就被上下文预留截断，未用满规划调用上限。
- 调用 8/9 为初稿评估/编码（draft 快照对）；调用 10/11 为最终自审评估/编码。全程无 `evidence_followup` 模型调用，`evidence_followup_status` 停留 `not_requested`。
- 初稿后已用 9/12，剩 3 次。`finish_draft` 的补读决策准入（`pipeline.py:1634`，本次未改动）要求 `remaining >= 1 + annotation_call_cost + reserved_calls + encoding_reserve`；单输入 `run()` 以 `reserved_calls=0` 调用 `finish_draft`，单输入 assessed 恒有 `encoding_reserve=1`（`pipeline.py:1599-1600`），即需 `1 + 2 + 0 + 1 = 4` 次。剩 3 次 → 循环在首次决策前 break。**缺口恰为 1 次，即 encoding_reserve。** 工具上限（23 次）与授权余量均未触界。

### 1.2 实施的修复（`vulngym_t2/pipeline.py` `read_and_draft`，改动后 1841-1860 行）

在既有规划调用算术（multi 路径与单输入 assessed 的 encoding 纠正预留，原样保留）之后新增一段：对 **staged 单输入** 运行，当 `max_calls >= 2 * annotation_call_cost + 5` 时再把规划上限 `planning_calls` 减 1，给草稿与最终评审之间的 followup 决策留出一次调用的窗口。

- 效果（按 chain 的 12 次预算）：`planning_calls` 9→8，强制草稿轮从 `model_calls >= 7` 提前到 `>= 6`，探索调用上限 7→6；草稿对用 2 次后剩 4 = 门槛 4，决策窗口可用。窗口内至多发生一次决策后剩余回落到 3，同一门槛自然封顶后续决策（`followup_limit=3` 与逐轮复查均未改）。
- 两种停止机制下都成立：若探索先被 `read_context_closed` 截断（回执情形），草稿轮同样提前，剩余同样为 4；若上下文未截断，则由新上限封顶。预留只降低探索上限，不发起任何请求。
- 阈值含义：assessed（cost=2）下 `2*2+5=9`，默认 `max_calls=8` 的 `produce()` 运行不满足、路径与改动前逐位相同（含 assessed 既有 `-1` 预留仍要求 `>=8`）；非 assessed staged 单输入（cost=1）阈值为 7，同样只让出窗口、不改任何门。12≥9 满足，8≥9 不满足。
- 红线复核：`finish_draft` 门槛、`followup_limit`、全部 prompt/`prompt_revision`、multi 路径、单输入 assessed 既有 `encoding_reserve`、被拒值零复用原则、drafts 15 字段契约均未改动；无新增请求、重试或预算上限；预留未被决策消费时不补花（剩余调用仍按既有门供评审/纠正使用）。

### 1.3 离线验证（tests/test_t2_v2_followup_window_reserve.py，沿用 scripted-send 模式）

- **翻转用例**（`max_calls=12`，chain 形状脚本）：6 轮探索 + 草稿对 + 一次真实 `evidence_followup` 决策（search_code 新回执）+ 自审对；断言 stage 序列恰含一个 `evidence_followup` 模型调用、`evidence_followup_status=completed`、`self_review_status=completed`、11/12 次调用、`finalize` 条目非空、无 `budget_unavailable`。
- **小预算不变用例**（`max_calls=8` 同构脚本）：3 轮探索 + 草稿对 + 自审对，7/8 次调用，`not_requested`——与改动前逐位一致（chain 账目的缩影：剩 3、需 4）。
- **阈值钉死**（`max_calls=8` vs `9`）：两档规划上限同为 5、探索轮数同为 3，唯一差异是 9 档出现决策窗口（`finish_reading` 决策即完成）；各自剩 1 次调用未补花。
- **翻转复核**：临时还原旧算术后，12 档与 9 档用例如期失败（脚本尾段未消费＝决策未发生），8 档用例两侧通过；随后恢复。
- **既有测试调整（唯一一处，逐条理由）**：`tests/test_t2_v2_final_encoding_and_source.py` 的 `test_exploration_leaves_initial_encoding_correction_and_review_budget` 直接钉死旧规划算术（草稿轮起点剩 5、探索 7 轮、草稿后剩 2）。该测试目的（探索不得吃掉纠正+评审预留）不变，按新事实把锚点平移：草稿轮起点剩 6（原 5 次必需阶段 + 1 次预留决策窗）、探索 6 轮、草稿后剩 3（评审对 + 决策窗）。无其他既有测试锚定旧值；全量 `python -m unittest discover -s tests -q` **1044 项 OK、1 跳过**（实施前基线 1041 项 OK、1 跳过，净增 3 项新测试）。

### 1.4 本修复不解决的事

窗口只保证"草稿后还有一次决策机会"；决策读什么、能否闭合关键关系仍取决于模型与已存证据质量（chain 回执的核心缺口是必要 helper 本体与 Git 侧消费者未读）。这不属于本改动目标。另如实记录机会成本：在上下文未截断的运行里，被新上限封顶的第 7 轮探索可能是有效读取；本预留的代价总量有界（最多 1 轮探索，未消费不补花），换来的是草稿后基于已识别缺口的定向决策读。

## 2. Airflow：上下文容量机制（未修，需单独设计批准）

### 2.1 回执账目（v79，run_request_limit=16）

- 11/16 次 HTTP 即停，远未用完调用预算；最后一次补读后的第三次模型决策未发生，保存动因为 `evidence_followup_skipped: reserve_review_context`，此前 `read_context_closed: reserve_annotation_review_context`（call 5 内）。停止原因是**保留最终自审上下文**，不是调用数耗尽。
- 复核文档以冻结 v79 预算函数代入保存字符数得到 `100000 - 81902 - (476 + 1514 + 512) - 14964 - 2048 = -1416`（见 `docs/t2_representative_airflow_v79_review_20260913.md`），补读 allowance=0，低于最低 4096。瓶颈是 **100k 上下文字符**，不是调用数；自动另快照/测试链导航（E0016–E0020）消耗可见上下文却未闭合核心机制。
- 机制缺口（`_build_metrics` 后半与最终 logger 未读）属于上下文分配问题：E0024 只读到 helper 的 158 行 `else:`，装配与最终消费者窗口从未进入上下文。其中 E0019 前后 compact 字符数 62226→68008（+5782），与从 -1416 恢复到最低 4096 所需的 5512 字符同量级——说明单次自动测试窗口的占用与下一轮实读余量同量级。

### 2.2 候选方向（均未实施、需单独设计批准）

1. **草稿前更早的证据压缩**：把候选上下文重打包的时机从"每轮之后"提前到探索中期，减少历史信封对可见窗口的占用。风险：压缩-重读循环可能迫使更多 read 轮次，把字符瓶颈换成热调用数瓶颈；重打包必须保持无损（回执不丢、只省信封开销），否则与"零复用/不丢回执"红线冲突。
2. **大文件默认窗口收窄**：对超长源文件按锚点给更窄的默认窗口，腾出后续续读余量。风险：同一机制需要更多续读才能覆盖（Airflow 的命令文件本轮读了三段仍缺尾部），可能加剧"多段拼读"；且收窄不能成为变相抬高 100k 上限的对价，总上限不动。
3. **`planning_read_allowance` 对大窗口的分段**：探索期大 `read_file` 窗口改为显式分段预算（首段 + 显式续段），为草稿前上下文留出缓冲。风险：分段会在探索期消耗更多模型轮次来完成原本一次窗口可覆盖的范围，与本次刚保护的决策窗口形成新的竞争；分段边界的选择本身也需要回执验证，避免制造新的 `reserve_annotation_review_context` 提前截断。

以上三项都会改变读取策略行为，任一实施前需独立设计 note + 批准 + 离线用例；在未批准前，Airflow 类输入的兜底仍是人工按复核材料包补读。

## 3. SQL：模型语义选择机制（未修，需单独设计批准）

### 3.1 回执账目（v79，三槽多候选）

- 三槽草稿均接受、自审均完成、无技术中断；但槽 3 的 PostgreSQL `deleteTable` 操作本体从未被读：E0011 实际读的是 Postgres `helpers/utils.ts` 1–200，而 E0005 已列出准确 changed path。
- 槽 2 的导航搜索用泛词 `execute` 全库检索：候选/扫描文件 13837、结果截断，所存窗口主要是 changelog 等无关命中，终止 `no_usable_reference_hit`。这不是工具失败，是一次无效的语义选择。
- 初读关闭为 `reserve_annotation_review_context`（`result_allowance_chars=2359`），三槽补读都被 `reserve_review_context` 跳过——调用预算同样不是首要约束。

### 3.2 为什么程序侧不实施机械规则

控制器没有可靠的语言学/语义判断来"替模型选对搜索词"：从保存回执看，能区分"已选候选的 changed path"与"全库泛词"的唯一可靠信号是提案里的路径/文件名（E0005 已含准确路径），但把"优先用提案路径"写成硬规则（如禁词表、强制路径限定）会在提案本身缺路径或路径拼写与库内不一致的输入上制造新的**可避免留空**——比当前的无效搜索更差，因为它把一次可能无效但无害的探索直接变成零证据。机械规则也与"被拒值零复用"同类的原则冲突：控制器只保存与呈现回执，不代替模型做语义取舍。

### 3.3 候选方向（均未实施、需单独设计批准）

1. **未来 prompt 修订**：在 followup/探索指令中引导模型优先核对已选提案的 changed path 与关键消费者，再考虑泛词检索。必须 bump `PROMPT_REVISION` 并经人工批准，且需与运行目录标签、代码版本共同对账（当前工作副本 `staged_protocol.py` 的 `PROMPT_REVISION` 已是 `snapshot-guidance-v80`，与 v79 回执不同源，任何对比须先核对两版提示词文本）。
2. **保持现状 + 人工审核兜底**：槽 3 型缺口由人工依据 saved-evidence 复核材料包离线补读；零代码风险，代价是每次出现都需人工介入。

本文不实施上述任何一项；在获得批准前，现状（诚实留空 + 人工兜底）是正确行为。

## 4. 本次实施清单与边界重申

- 改动文件：`vulngym_t2/pipeline.py`（`read_and_draft` 预留算术，8 行注释 + 3 行判断，改动后位于 1850-1860 行）；新增 `tests/test_t2_v2_followup_window_reserve.py`（3 项）；按事实最小调整 `tests/test_t2_v2_final_encoding_and_source.py` 既有 1 项的锚点数字；新建本文。
- 未改动：`finish_draft` 准入门槛与 `followup_limit`、`llm.py`/`output.py`/prompt 文本/`PROMPT_REVISION`、multi 路径、单输入 assessed 既有 encoding_reserve、任何预算上限、drafts 15 字段契约、被拒值零复用原则。
- 全量测试：1044 项 OK、1 跳过（基线 1041 + 3）。
- 运行标签规范：本改动后的真实运行必须使用新的运行目录标签（延续既有顺延规则），不得与 2026-09-13 v79 各批目录及产物混写、回填或覆盖；对比 v79 与后续运行时以运行目录标签 + 代码版本区分，不能以 `prompt_revision` 单一字段断言两轮提示词一致。
