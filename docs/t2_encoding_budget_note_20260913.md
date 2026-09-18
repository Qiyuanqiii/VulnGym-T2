# NLTK 槽 2 `budget_unavailable` 成因与最小修复选项（设计 note，不改行为）

日期：2026-09-13。对象为已结束的 `D:\VulnGym-bv2-runtime\t2-representative-20260913\02-nltk-v79-low`（分支 `codex/t2-core-v2` 工作副本 `D:\VulnGym-T2-work` 的代码行号）。

**本 note 不改任何行为。** 全部内容仅依据已保存回执（summary/actions/review/drafts）与现有代码静态阅读；文中所有"修复选项"均未实施，任何一项的实施都需人工批准后另行提交。本文未联网、未调用模型、未修改 `pipeline.py` / `llm.py` / `output.py` 及运行目录（只读）。

## 1. 回执依据（全部为已保存事实）

- `summary.json`：`status=completed`，`model_calls=15`、`tool_calls=12`、`review_count=3`、输入 1 个（partial：2 完整候选 + 1 草稿）；provider 段 `run_request_limit=16`、`http_attempts=15`、`automatic_retries=0`、`encoding_rejection_count=1`、`encoding_missing_root_rejection_count=1`、`multi_entry=true`、`annotation_format=assessed_tool`、`requests_per_snapshot=2`。
- `actions.jsonl` 共 65 条事件，关键时点：
  - 事件 23：`candidate_plan`，`proposed_count=4 / selected_count=3 / budget_slots=3`（4 次读计划调用之后的候选规划）。
  - 事件 40/42：槽 2 `entry-00000` 的调用 9（draft_assessment）与调用 10（draft 编码）。
  - 事件 43：`annotation_snapshot_rejected`，`code=missing_root_fields`，`path=$[0].arguments`，缺失 7 个根字段（critical_operation / entry_point / trace / vuln_category_l1 / vuln_category_l2 / vuln_ids / vuln_title）。
  - 事件 44：`annotation_snapshot_reencoding`，`stage=draft`，`summary=budget_unavailable`。**此时槽 3 尚未开始**（槽 3 的第一条事件是事件 45 的 `evidence_context_compacted`）。
  - 事件 45–65：槽 3 `entry-00001` 完整跑完（调用 11/12 初稿、13 补读、14/15 自检）。
- 对账说明：回执中只有**一次**格式拒收事件（事件 43；provider 计数 `encoding_rejection_count=1`）。所谓"两次拒收"记忆与回执不符——重编码从未发出请求，因此不可能产生第二次拒收回执；实际序列是"一次拒收 → 一次未启动的重编码"。

## 2. `budget_unavailable` 的账目成因

### 2.1 判定点与预留链

判定代码 `vulngym_t2/pipeline.py:1051-1052`（`reencode_rejected_snapshot`）：

```python
"budget_unavailable" if self.max_calls - self.result["model_calls"] < 1 + reserved_calls
  or getattr(self.client, "remaining_requests", 1) < 1 else
```

`reserved_calls` 的传参链（快照串行候选路径）：

1. `pipeline.py:283`：`max_calls = min(16, ...)` —— 16 来自 `run_request_limit=16`；`pipeline.py:293`：assessed 模式 `annotation_call_cost = 2`（每次快照 = 1 次评估 + 1 次编码）。
2. `pipeline.py:1986`：候选槽位 `slots = min(MAX_ENTRIES, (max_calls - model_calls) // (2 * annotation_call_cost))`。规划时 `model_calls=4`，`(16-4)//4 = 3`，与事件 23 的 `budget_slots=3` 一致。
3. `pipeline.py:2027`：每个候选开始前，为**后续**候选预留 `remaining_reserve = 2 * annotation_call_cost * (len(entries) - index - 1)`。
4. `pipeline.py:2028`：`complete("draft", reserved_calls=remaining_reserve)`。
5. `pipeline.py:963-964`：draft 阶段快照被拒收后，`reencode_rejected_snapshot(outgoing, stage, reply, reserved_calls + (self.annotation_call_cost if stage == "draft" else 0))` —— 在后续候选预留之上再叠加**本候选尚未运行的自查预留**（assessed 自查 = 评估 + 编码 = 2 次）。
6. `pipeline.py:1051-1052`：要求 `1（本次编码修正）+ reserved_calls <= 剩余`，否则记 `budget_unavailable`，不发请求。

### 2.2 事件 44 时点的具体数字

- 调用 10 刚完成，`model_calls=10`，`剩余 = 16 - 10 = 6`。
- 传入的 `reserved_calls = 4（槽 3 的初稿 2 + 自检 2，见第 3 步）+ 2（槽 2 自己的自查预留，见第 5 步）= 6`。
- 判定：`6 < 1 + 6 = 7` → `budget_unavailable`。第二个子句（授权层 `remaining_requests`）远未触界，不是成因。

### 2.3 为什么"槽 2 被跳过、槽 3 却完整跑完"

- 槽 3 的 4 次调用（初稿 2 + 自检 2）在上面的 6 里被**整块预留**，这是串行候选设计的既有保证，事件 45–65 证明它被完整兑现。
- 槽 2 自己的 2 次自查预留成了"死预留"：初稿被拒收后 `accept_snapshot` 返回 False、`self.drafted=False`，`finish_draft` 的自查门（`pipeline.py:1685` 要求 `self.drafted`）永不打开——这 2 次预留既没被花掉，也不允许被挪给重编码。
- 槽 3 实际花了 5 次：预留 4 之外，`extra_read_fits`（`pipeline.py:2029`）发现补读后仍有 `4 >= 1+2+0` 的空间，追加了一次 `evidence_followup`（调用 13）。
- 终态：15/16，**剩 1 次调用未用**。事后看 `1（重编码）+ 5（槽 3 实耗）= 6 <= 6` 似乎装得下；但判定是前瞻性的：若重编码成功，槽 2 仍欠 2 次自查、槽 3 仍需 4 次，`1+2+4=7 > 6`，在"不降低任何保证"的前提下确实装不下。缺口恰好等于槽 2 被作废的 2 次自查预留——这是本 note 讨论的最小修复空间。
- 后果：槽 2 `initial_draft_status=not_received`、`self_review_status=not_requested`，drafts.jsonl 仅一行 15 字段占位（缺失标量为 `""`、trace/vuln_ids 为 `[]`、verify=0，值只来自输入元数据，**被拒收对象的任何字段值从未被应用**，model_errors 原文亦如此声明）。该 15 字段契约不变。

## 3. 最小修复选项（供人工审批；本 note 一概未实施）

三个选项都满足：总预算上限（`max_calls = run_request_limit`）**影响为零**；每快照仍最多一次编码修正；无 HTTP 重试；不新增门禁或阈值。离线验证统一采用现有 Stub/scripted-send 模式（见 3.4）。

### 选项 1（推荐）：多候选 draft 拒收时不再叠加本候选的自查预留

- **改动点**：`vulngym_t2/pipeline.py:963-964` —— 当 `stage == "draft"` 且处于多候选路径（`self.multi_mode`）时，传给 `reencode_rejected_snapshot` 的 `reserved_calls` 不再加 `self.annotation_call_cost`（单输入路径保持原样，`tests/test_t2_v2_snapshot_reencoding.py:124` 的 `test_required_later_phases_keep_their_request_reserve` 必须继续通过）。自查是否运行改由既有门 `pipeline.py:1685` 按剩余预算裁决。
- **预算影响**：零。上限不变；后续候选的 `remaining_reserve` 原样保留；修正调用本身仍计入 `model_calls`。
- **效果**（按本轮数字）：判定变为 `1 + 4 = 5 <= 6` → 重编码启动。若恢复：槽 2 变成"有真实字段但自查被推迟"的草稿（`self_review_status=not_requested`，finalize 记 `self_review_required`，导出仍为 draft，绝不为 complete；字段值来自**已接受**的快照，与红线不冲突）；若再失败：槽 2 与现状完全一致，剩余 5 仍覆盖槽 3 的 4。最坏情况（恢复后剩余 < 自查 2 次）也只是该候选推迟自查，不会波及后续候选的启动门（`pipeline.py:2021` 仍要求 `>= 2*cost`）。
- **代价**：多候选运行中可能出现"字段已填、自查未跑"的中间候选草稿——这正是把 2 次死预留换成 1 次修正机会的对价；人工复核时需按 `self_review_required` 与机器自查状态行识别。改动必须严格限定在 multi+draft+被拒收的分支，避免影响单输入语义。
- **离线验证**：见 3.4 用例 A/B。

### 选项 2：候选规划时为每个候选预留 1 次修正窗口（减少选中候选数）

- **改动点**：`vulngym_t2/pipeline.py:1986` 槽位公式改为先扣除 1 次修正窗再整除，例如 `(self.max_calls - self.result["model_calls"] - 1) // (2 * self.annotation_call_cost)`。
- **预算影响**：上限为零；但本轮 `(16-4-1)//4 = 2`，第三个候选整个不再被选中，槽 2 成为末位候选（`remaining_reserve=0`，现有代码同样会尝试修正：`1+2=3 <= 6`）。
- **代价**：以候选覆盖换取每候选修正窗；`candidate_plan` 计数变化会牵动既有测试断言；对"中间候选在预算尾部被拒收"的一般场景保护有限（候选多时中间槽仍可能被预留压住）。不推荐作为首选。

### 选项 3：不改 pipeline（仅记录）

- 依赖本次已完成的展示层改进（`vulngym_t2/review_export.py` 新增"初稿未接收说明"节：声明、16 条已保留证据计数与 EID 清单、不自动填充边界），人工依据材料包即可离线补齐该行，不重跑。
- 若同类输入必须机器完成，可对该输入单独提高 `run_request_limit` 重跑——这是运行参数选择，不属于代码预算扩大，也不在本 note 范围内实施。
- 代价：每次出现都需人工介入；只要"非末位候选 + 快照拒收 + `剩余 < 1 + 2*cost*后续数 + cost`"重演，同样账目会重演。

### 3.4 通用离线验证方法（不联网、不调用模型）

沿用 `tests/test_t2_v2_snapshot_reencoding.py` 的 scripted-send + `DeepSeekClient(send=...)` / `_ProductionSession` 模式与 `tests/test_t2_v2_staged_multi.py` 的串行多候选脚本（`proposals()` + `full_for_scope()`）：

- **用例 A（现状翻转验证）**：3 个合成候选、`max_calls=16`；脚本让槽 2 的首次 `submit_annotation` 返回缺根字段快照（触发 `missing_root_fields`）、其唯一一次重编码返回有效快照。实施选项 1 后断言：`annotation_snapshot_reencoding.summary == "recovered"`（不再是 `budget_unavailable`）、槽 3 仍完整跑完初稿+自检、`model_calls <= 16`、槽 2 终态为带 `self_review_required` 的草稿。
- **用例 B（"槽 2 拒收 + 剩余 1 次调用"）**：同一脚本、`max_calls=11`（拒收时点剩余 = 1）。断言无论是否实施选项 1，`budget_unavailable` 仍被记录（`1 + 后续预留 4 > 1`，后续候选保证不被侵蚀），且槽 3 因 `pipeline.py:2021` 门被 `candidate_skipped / draft_review_budget_unavailable` 跳过——证明修复不会牺牲"后续候选保证"这条底线。
- **回归**：单输入路径的预留语义由 `tests/test_t2_v2_snapshot_reencoding.py:124`（`required_later_phases_keep_their_request_reserve`）与 `tests/test_t2_v2_duplicate_location_encoding.py:266` 等现有用例守护，实施后须全量 `python -m unittest discover -s tests -q` 通过。

## 4. 边界重申

- 本 note 与其描述的展示层改进均不自动填充任何字段；被拒收快照对象的任何字段值从未被应用（pipeline 既有保证，展示层只读已保存记录）。
- drafts.jsonl 15 字段契约、`no values from the rejected object were applied` 原则、0 HTTP 的 inert 导出性质均不变。
- 以上任一选项的实施都是行为变更，需人工批准后另行提交并附对应离线用例。

## 实施记录（2026-09-13/14）

选项 1 经人工批准后实施于工作副本 `D:\VulnGym-T2-work`（分支 `codex/t2-core-v2`）。改动仅限 `vulngym_t2/pipeline.py`、新增测试文件与本文本节；未触碰 `llm.py`、`output.py`、prompt 文本、prompt_revision、任何预算上限与运行目录。

### 账目复核

实施前按第 2 节独立复核，代码与回执逐项一致：`max_calls=min(16,…)`（`pipeline.py:283`）、assessed 模式 `annotation_call_cost=2`（`:293`）、`slots=(16-4)//4=3`（`:1986`）、`remaining_reserve=2*2*(3-1-1)=4`（`:2027`）；只读回执 `02-nltk-v79-low` 证实事件 42 为调用 10（draft 编码），事件 43 拒收、事件 44 `budget_unavailable`，即 `model_calls=10`、剩余 6、旧预留 `4+2=6`、判定 `6 < 1+6`（`:1051-1052`）。

一处与本文 3.4 用例 B 字面数字不符：**"槽 2 拒收时剩余恰为 1 次调用且后续预留 4"这一状态在现有公式下不可达**。`slots=(max_calls-model_calls)//(2*cost)` 与候选启动门（`:2021` 要求 `>=2*cost`）共同保证拒收点剩余至少为 2，且 `max_calls=11` 在同一 3 请求前奏下只选出 1 个候选（无槽 2/3 可言）。实施不改用例 B 想保护的性质，改用等价边界用例（见下）。

### 实际改动点

`vulngym_t2/pipeline.py` `complete()` 的快照拒收分支（原 963-964 行；改动后含守卫行为位于 963-971 行）：`stage == "draft" and not self.multi_mode` 时才把 `self.annotation_call_cost` 叠入 `reserved_calls`；多候选路径只传后续候选的 `remaining_reserve`，并加注释说明"本候选自查预留在此分支不可兑现，不计入 reserved"。单输入路径行为等价（共享行文本有变，真值逻辑与改动前恒等，已由回归测试钉死）。与选项 1 描述无差异；补充一点语义注记：所谓"死预留"指拒收分支中该预留必然不可兑现（自查仅在重编码被接受后可能运行，且其可行性由既有 `finish_draft` 门 `pipeline.py:1685` 连同后续候选预留一并裁决），并非该候选自查被取消。

### 新增测试（tests/test_t2_v2_multi_draft_reencode_budget.py，4 项）

- `test_mid_slot_rejection_starts_the_sole_reencoding_and_later_slots_keep_their_review`：3 候选、`max_calls=15`，槽 2 拒收时剩余 6（与回执同数）→ 重编码启动且 `summary=recovered`，无 `budget_unavailable`；槽 2 终态为 `initial_draft_status=accepted` 且 `self_review_status=not_requested` 的草稿（finalize 记 `self_review_required`，`entry=None`）；槽 1、槽 3 自查完整跑完（槽 3 的 followup 按既有规则另计）；全程 15/15 次调用；被拒对象的标记值不出现在任何回执/合并字段，槽 2 字段来自已接受的重编码。
- `test_last_slot_rejection_spends_the_remaining_tail_on_the_correction`：2 候选、`max_calls=11`，末位候选拒收时剩余 2（该路径可达的最小值）→ 修正启动（旧判定需 3 会拒绝），槽 1 自查不受影响。
- `test_later_candidate_reserve_still_caps_the_correction`：直接以 `complete("draft", reserved_calls=4)` 钉死判定边界——剩余 4 时 `budget_unavailable` 仍记录（后续候选预留继续否决修正），剩余 5（恰为 `1+4`）时启动；证明被移除的只是本候选自身的死预留。
- `test_single_input_draft_keeps_its_own_review_reserve`：单输入下同场景边界不变——剩余 2 拒绝、剩余 3 启动（自查预留仍保留）。

既有测试**零修改**：无既有用例组合 `multi_entry` 与快照拒收（不锚定旧死预留语义）；各处 `budget_unavailable` 断言均在 `self_review` 阶段，不受本改动影响。翻转验证：临时还原旧逻辑后，上述 4 项中 3 项如期失败、单输入回归如期两侧通过，随后恢复。

### 全量测试

`python -m unittest discover -s tests -q`：**1041 项 OK、1 跳过**（实施前基线 1037 项 OK、1 跳过；净增 4 项新测试，无既有测试改动）。

### 运行标签规范

- 本改动后的真实运行必须使用**新的运行目录标签**（建议 v80 序，如 `03-nltk-v80-low`），不得与 2026-09-13 v79 四批的目录及产物混写、回填或覆盖。
- 本次实施不触碰 prompt 文本与 `PROMPT_REVISION`。需注意：当前工作副本 `vulngym_t2/staged_protocol.py` 的 `PROMPT_REVISION` 在本次实施前已是 `snapshot-guidance-v80`（v79 回执记录为 `snapshot-guidance-v79`；该文件属未提交工作副本状态，差异非本次改动造成）。因此对比 v79 与后续运行时，必须以**运行目录标签 + 代码版本**区分，不能以 prompt_revision 单一字段断言两轮提示词一致；如需按 prompt_revision 对账，须先单独核对两版提示词文本。
