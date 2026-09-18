# T2 v2 五分钟现场演示与人工复核

本指南用于五分钟结果回放，展示时间不含模型等待，不代表现场新生成或导师认可。另已制作[五分钟字幕视频与说明](../output/demo-replay-20260914/README.md)：使用真实工作台截图编排，无配音、不是连续操作录屏，全程标注保存结果回放。首选 NLTK v84 的有依据候选、实际编码恢复和 trace 勘误，再展示 SQL v83 保留未知的草稿；回放无需 key。当前批次及限制见[代表性验证](t2_representative_validation_20260913.md)。

本轮用[代表性验证的 v83/v84 矩阵及四份 QA](t2_representative_validation_20260913.md)解释证据与失败边界。四批 entries/drafts/summary 的副本与索引在 `output/real-results-20260914/`（12 文件、29549 字节）；它不是完整 run，不能直接交给 GUI/review_export，副本 summary 的 files 仍描述原批次七个文件。完整 review/actions 仍在原 D 盘运行目录；NLTK v84 的可读报告已另存 `14-nltk-v84-review-export.md`，该次导出 0 HTTP。下方占位参数与 v69/examples 结果属于历史演示材料，不是当前可直接收费执行的命令；CLI low 与 GUI 固定 high 分开说明。

## 演示前准备，不占五分钟

### 本机当前批次回放（首选，无模型请求）

用 **NLTK v84 展示有依据的完整候选与真实编码恢复，用 SQL v83 展示诚实保留的草稿**。两批都已结束，已有可读报告，不需要重新导出、启动网页或输入 key。当前代码为 v84；SQL 是 v83 的保存结果，不把它标成 v84 新运行。

在无配置文件的 PowerShell 中设置本机路径；以下命令只设置变量：

```powershell
Set-Location -LiteralPath 'D:\VulnGym-T2-work'
$env:PYTHONUTF8 = '1'
$t2Python = 'D:\python314\python.exe' # 本机实际为 Python 3.13.12
$t2Root = 'D:\VulnGym-bv2-runtime\t2-representative-20260913'
$t2Inputs = Join-Path $t2Root 'inputs'
$t2Run = Join-Path $t2Root '14-nltk-v84-low'
$t2SqlRun = Join-Path $t2Root '12-sql-v83-low'
```

演示前在编辑器里打开这四份已有文档，直接使用对应完整 run 的 summary/entries/drafts/review/actions；**不要把 `output/real-results-20260914/` 摘录目录当作 run**：

- [NLTK v84 可读报告](D:/VulnGym-bv2-runtime/t2-representative-20260913/14-nltk-v84-review-export.md) 与 [NLTK v84 内容勘误](t2_representative_nltk_v84_review_20260914.md)。
- [SQL v83 可读报告](D:/VulnGym-bv2-runtime/t2-representative-20260913/12-sql-v83-review-export.md) 与 [SQL v83 内容复核](t2_representative_sql_v83_review_20260914.md)。

NLTK 的真实输入是 `inputs\02-nltk-bundle\record.jsonl`，SQL 的真实输入是 `inputs\01-sql-url.txt`；本机公告缓存为 `inputs\cache`，仓库映射为 `inputs\repo-map.json`，均位于上述 `$t2Root`。映射指向已经准备好的本地仓库，不是让接收者现场下载或填写答案。

如要现场展示免费预检，只执行下面这一条 **带 `--prepare-only`** 的 NLTK 命令。它显式采用本轮 32768 / plan_tool / low 配置和 12 请求上限；没有输出目录、账本路径或 key，不会生成新模型结果。预检检查材料与仓库可用性，不验证服务额度或内容正确性；**不得为了演示删除 `--prepare-only`，也不默认执行后面的历史收费模板**。

```powershell
$t2PrepareArgs = @(
    '--input', (Join-Path $t2Inputs '02-nltk-bundle\record.jsonl'),
    '--cache-dir', (Join-Path $t2Inputs 'cache'),
    '--repo-map', (Join-Path $t2Inputs 'repo-map.json'),
    '--multi-entry', '--model', 'deepseek-flash',
    '--response-mode', 'staged_tool', '--thinking', 'enabled',
    '--annotation-format', 'assessed_tool', '--read-format', 'plan_tool',
    '--reasoning-effort', 'low', '--max-tokens', '32768',
    '--max-calls-per-report', '16', '--max-tool-calls', '64',
    '--max-requests', '12', '--authorization-limit', '3000',
    '--effective-request-limit', '2999', '--prepare-only'
)
& $t2Python -B -m vulngym_t2 @t2PrepareArgs
```

### 当前批次的五分钟展示顺序

| 时间 | 打开什么 | 只讲当前证据支持的结论 |
| --- | --- | --- |
| 0:00–0:40 | NLTK 输入 `record.jsonl`，说明 cache / repo-map 位置 | 输入提供公告与本地仓库资料，不指定 EP/CO 答案；本次是已结束结果回放。 |
| 0:40–1:10 | 上面的免费预检 | 看 `http_attempts=0`、`repo_available`、`input_error` 和配置；不把预检说成模型分析成功。 |
| 1:10–2:00 | NLTK 可读报告中的 EP/CO 与版本 | 1 输入、10 HTTP、1 完整候选、60.716 秒、verify=0。EP 是 E0014 的 sent_tokenize 96–107；CO 是 E0010 的实际 finditer 调用 1336–1339，不再把模式声明当执行行。 |
| 2:00–2:55 | 同份报告的 trace，旁边对照 v84 QA 第 3、4 节 | 公告/docstring/patch/源码共同支持 EP/CO，不要求所有运行对象独立证明；但“全部连接在源码直接显示”过强，需注明加载对象的材料前提及默认生成器包装/消费条件。保留原报告，口头说明勘误，不冒称原字段已修改或已人工批准。 |
| 2:55–3:45 | SQL 可读报告的 MySQL select 草稿；再扫一眼 Postgres 草稿 | 1 输入、16 HTTP、3 草稿；helper 会分割并重新引用，不能凭没有 replace 就认定缺陷。Postgres 操作只读到 68 行、尚未到 execute；未知保留为空，不冒充 3 次格式失败。 |
| 3:45–4:35 | NLTK 报告的过程记录与 QA 第 1 节 | call 6 缺 7 个根字段，call 7 消费共享预留后恢复；call 8 是补读决策，没有新增源码工具读取，call 9/10 自审完成。4 提案选 1、未选 3，不把遗漏算失败或独立漏洞；一次恢复不等于格式问题根治。 |
| 4:35–5:00 | 两批 summary / entries / drafts 与结果目录索引 | 完整和草稿分开交付，所选行码真实不等于完整语义已确认；下一步是 trace 表述及必要读取，不凑完整数。本机结果摘录不是完整 run；新字幕视频采用另列的 10×30 秒编排，本轮真实 GUI 核验另见[工作台记录](t2_web_gui.md)。 |

预检若因本机环境未准备好而失败，展示原错误后继续打开已有报告；不要借此新建收费批次。上述回放不需要运行目标代码或追加 API 请求。

<details>
<summary>历史随包回放与通用命令模板（非首选；收费命令不默认执行）</summary>

**历史随包无费用回放：** 在项目根目录执行 `python -m vulngym_t2.review_export --run-dir examples/run-03 --output review-complete.md`，另用 `examples/run-02` 导出 `review-failure.md`。打开两份 Markdown 即可按下述节奏展示，不必现场拼接 JSONL。输出需是新文件且在原运行目录之外。先看 `docs/t2_case_notes.md` 中的已发现勘误；复核包保留原模型措辞，不会自动修正旧产物。回放只展示已有结果，不是模型现场重跑、录屏视频或已完成的人工审核。

使用无配置文件的 PowerShell（例如 `powershell -NoProfile`），切到包含完整 `vulngym_t2/` 的项目目录。当前实查解释器为 Windows / Python 3.13.12，`D:\python314` 只是安装目录名，不代表 Python 版本；未验证最低版本。还需 `PATH` 中的 Git；运行路径只有标准库依赖，不必安装第三方 Python 包。准备 UTF-8 公告、包含相关历史的独立本地 clone 或 bare 仓库；程序不 clone/fetch，不支持 linked worktree、partial clone 或仓库外对象存储。

五分钟是**展示时间，不包含模型等待时间**。严格限时可直接选择“已有结果回放”路线，准备一份已经结束的真实输出，说明运行时间和输入；若尚无真实输出，就现场展示准备检查、运行进度与限制，不预演成已成功完成。回放不冒称现场新运行，stub 不冒充真实模型结果；本稿也不表示已有录屏视频。

以下变量仅在本地终端使用，不把本地绝对路径当作公开报告的证据：

```powershell
New-Item -ItemType Directory -Force 'D:\T2\tmp', 'D:\T2\budget' | Out-Null
$env:TEMP = 'D:\T2\tmp'
$env:TMP = 'D:\T2\tmp'
$t2Advisory = 'D:\T2\materials\advisory.md'
$t2Repo = 'D:\T2\repos\project'
$t2Source = 'https://github.com/advisories/GHSA-2222-3333-4444'
# 必须替换成同一授权已有账本的实际路径，不要用占位路径重置次数。
$t2Ledger = 'D:\T2\budget\temporary-authorization.jsonl'
# 以下仅对应本任务现有授权；其他使用者填自己的已批准限额。
$t2AuthorizationLimit = 3000
$t2EffectiveLimit = 2999
```

同一授权始终复用原账本，不能并发占用、另建或清空以重置次数。示例的 24 次只是批次上限，不是新授权；历史查询和失败尝试都要计入总额。本任务后续每次执行须同时传 `--authorization-limit 3000 --effective-request-limit 2999`，Web 再加 `--historical-requests 1`；账本 header 仍为 3000，2999 是本进程累计生成上限，不是单批额度。不能把示例的 500、旧 2599 或未传新参数的 3000 当成正确的合计门禁；总用量以[代表性验证](t2_representative_validation_20260913.md)为准。以下新提取命令仅说明接口，不在本次文档收尾中执行，也不要求为了演示重新付费。有效授权和适配的账本参数由实际运行时明确核对；密钥不写入命令、历史或文档。

## 0:00—0:40：给评审看输入边界

打开实际公告，指出项目、问题描述和可用的修复链接；说明本地仓库已经准备好，但**未指定源码路径、候选代码 ID 或内部任务编号**。材料可是一份文件，也可是平铺材料目录。公告中的 fix、仓库 HEAD 或 fix parent 都不是自动确认的漏洞版本。

若需要说明批量格式，展示 README 中这类简单 JSONL 行即可，不必为演示另造复杂任务配置：

```json
{"source_link":"https://github.com/advisories/GHSA-2222-3333-4444","repo_path":"../repos/project","repo_url":"https://github.com/example/project","advisory":"advisory.md"}
```

路径相对于 JSONL 所在目录；URL 列表模式需要公告缓存和本地仓库映射，程序不会自动下载 URL 或补全仓库历史。

## 0:40—1:15：执行无模型的准备检查

```powershell
python -m vulngym_t2 --advisory $t2Advisory --repo $t2Repo --source-link $t2Source --authorization-limit $t2AuthorizationLimit --effective-request-limit $t2EffectiveLimit --model deepseek-flash --response-mode staged_tool --thinking enabled --annotation-format assessed_tool --reasoning-effort low --max-tokens 16384 --max-calls-per-report 12 --max-tool-calls 32 --stop-on-format-error --prepare-only
```

现场检查 `http_attempts` 是否为 `0`、`configuration` 是否与正式命令一致，以及每条输入的 `repo_available`、`document_count`、`fix_candidates` 和 `input_error`。准备检查不读 key/账本、不连接服务，故不能据此宣称额度足够或供应商可用，也不是内容分析成功。

若选择 JSONL 或 URL 列表批次，用对应命令代替即可，不需要现场执行三遍。URL 模式的缓存名、repo-map 格式见 README；两者都必须提前准备：

```powershell
python -m vulngym_t2 --input D:\T2\materials\reports.jsonl --prepare-only
python -m vulngym_t2 --input D:\T2\materials\urls.txt --cache-dir D:\T2\cache --repo-map D:\T2\materials\repo-map.json --prepare-only
```

## 1:15—1:50：选择现场执行或真实结果回放

有有效授权且时间允许时，新建一次运行；`--output` 指向尚不存在的目录，`--max-requests` 是上限而不是必须花完的配额：

```powershell
$t2Run = Join-Path 'D:\T2\runs' ('demo-' + (Get-Date -Format 'yyyyMMdd-HHmmss'))
python -m vulngym_t2 --advisory $t2Advisory --repo $t2Repo --source-link $t2Source --output $t2Run --request-ledger $t2Ledger --authorization-limit $t2AuthorizationLimit --effective-request-limit $t2EffectiveLimit --model deepseek-flash --response-mode staged_tool --thinking enabled --annotation-format assessed_tool --reasoning-effort low --max-tokens 16384 --max-calls-per-report 12 --max-tool-calls 32 --stop-on-format-error --max-requests 24
```

这是前台命令，需等待返回后才在同一终端执行下一条命令；可看到 `report_started`、HTTP 进度、`report_finished` 和末尾汇总。严格五分钟时，不必启动上面的请求，直接选择下列**已结束真实结果的只读回放**，不要为追求成功画面反复运行：

```powershell
$t2Run = 'D:\T2\runs\single-001'
```

此处替换为实际输出目录。后续读取命令仅用于已经生成 `summary.json` 的已结束运行；新运行仍在等待、尚无汇总时，先展示进度，不照抄读取不存在的文件。没有完整条目仍可以展示真实草稿。鉴权、网络或格式错误会停止后续请求，已处理结果尽量保留；不要换账户、模型或账本绕过停止状态。

## 1:50—3:10：读结果，先统计再看字段

```powershell
$t2Summary = Get-Content -Raw -Encoding UTF8 -LiteralPath (Join-Path $t2Run 'summary.json') | ConvertFrom-Json
$t2Summary | Select-Object status, requested_input_count, input_count, unprocessed_input_count, candidate_count, draft_count, input_failure_count, model_error_count, tool_error_count, elapsed_seconds | Format-List
$t2Summary.provider | Select-Object model, http_attempts, authorization_http_attempts, usage, unknown_usage_attempts, currency_cost_measured | Format-List
```

说明三个逐条状态：`review.status=complete` 是完整自动候选，计入 `candidate_count`；`draft` 保留未完成字段，计入 `draft_count`；`input_failure` 是材料/仓库准备错误，计入 `input_failure_count`。`unprocessed_input_count` 是另外尚未处理的输入。批次 `summary.status=completed` 不代表每条都是 complete，更不代表字段都正确。模型调用不等于 HTTP 次数，token 也不是货币账单。

在工作台演示时，先分清“份资料”和“条结果”，再展开“候选提案覆盖”：提出、选中、未选的提案数按每份资料记录，未选包含去重，不是已确认漏洞数。未选提案尚未逐条处理，但不等于 `unprocessed_input_count` 中尚未开始的资料，也不算已有草稿或完整结果；编码预留不代表实际消费或恢复成功。旧记录缺失时说明“未记录”，不要补成 0 或宣称全部覆盖。

完整条目存在时，展示第一条的版本和两个关键位置：

```powershell
$t2Entry = Get-Content -Encoding UTF8 -LiteralPath (Join-Path $t2Run 'entries.jsonl') -TotalCount 1 | ConvertFrom-Json
if ($null -ne $t2Entry) {
    $t2Entry | Select-Object entry_id, report_id, project, vuln_title, commit, entry_point, critical_operation, trace, verify | ConvertTo-Json -Depth 10
} else {
    Write-Output '本次没有完整候选；下面查看仍然保留的草稿与错误。'
}
```

选取与刚展示的 entry **同一个 entry_id** 的 review；没有完整 entry 时才改选草稿或第一份输入结果。不要把不同案例的位置、理由和证据混起来：

```powershell
$t2Reviews = @(Get-Content -Encoding UTF8 -LiteralPath (Join-Path $t2Run 'review.jsonl') | ForEach-Object { $_ | ConvertFrom-Json })
$t2Review = $null
if ($null -ne $t2Entry) { $t2Review = $t2Reviews | Where-Object { $_.entry_id -eq $t2Entry.entry_id } | Select-Object -First 1 }
if ($null -eq $t2Entry) { $t2Review = $t2Reviews | Where-Object status -eq 'draft' | Select-Object -First 1 }
if ($null -eq $t2Entry -and $null -eq $t2Review) { $t2Review = $t2Reviews | Select-Object -First 1 }
if ($null -eq $t2Review) { Write-Output '没有可匹配的 review；请核对未处理数量或产物是否一致。' }
$t2Review | Select-Object report_id, status, draft_fields, suggested_values, field_reviews, errors, model_errors | ConvertTo-Json -Depth 12
```

若 entry 存在却没有同 ID 的 review，应报告产物不一致，不继续套用另一条证据。正常情况下，现场指出一个字段：引用了什么、为什么 `supported` 或 `uncertain/missing/conflicting`。原始 `review.jsonl` 的未知必需字段保持 `null`，建议值单独放在 `suggested_values`，不能口头说成事实。新批次另有 `drafts.jsonl`，使用相同的 15 个正式字段名：未知标量/整个位置为 `""`，数组为 `[]`，`verify=0`；它是待补充导出，不是完整条目或满足完整非空 schema 的数据集，不会把建议值补成事实。可选 trace 未建立时可为 `[]`，原建议和疑点仍保留。所有自动条目为 `verify=0`，`entries.jsonl` 和 `reports.jsonl` 只收录、聚合完整候选。若本次有另一条草稿，可另选并说明其 ID 后展示部分结果；没有草稿就不虚构缺失案例。

## 3:10—4:20：展示工具、自查和可人工检查的证据

```powershell
$t2Actions = @(Get-Content -Encoding UTF8 -LiteralPath (Join-Path $t2Run 'actions.jsonl') |
    ForEach-Object { $_ | ConvertFrom-Json } |
    Where-Object { $_.entry_id -eq $t2Review.entry_id })
$t2Actions | ForEach-Object { $_.action } | Select-Object action, tool, evidence_ref, stage, call | Format-Table
$t2Actions | ForEach-Object { $_.action } | Where-Object { $_.action -in @('plan', 'draft', 'draft_validation', 'self_review') } | ConvertTo-Json -Depth 6
$t2Refs = @($t2Review.field_reviews.entry_point.evidence_refs) + @($t2Review.field_reviews.critical_operation.evidence_refs)
$t2Review.evidence | Where-Object { $_.id -in $t2Refs -and $_.tool -eq 'read_file' } | Select-Object -First 1 | ConvertTo-Json -Depth 10
$t2Review | Select-Object location_checks, location_corrections | ConvertTo-Json -Depth 10
```

这里只展示当前案例的动作和 EP/CO 引用的一份源码证据，避免把整批长文本刷满终端。讲清楚模型怎样根据公告/差异读取 commit/相对路径，再形成草稿、自查与回改。当前流程把本地 schema/源码预检查反馈给原有一次自查，不增加额外 HTTP；旧一些运行若无 `draft_validation`，就按它实际记录说明。随包旧运行使用五种只读工具；后续已增加本地 refs/历史搜索，但不要把新增能力冒称在旧运行中已发生。工具不是任意 shell；未进入自查或没有引用源码证据时，也不补讲成已发生。

入口与缺陷位置需引用同一选定 commit 的实际 `read_file` 行，再由 `location_checks` 核验逐字一致。`location_corrections` 若非空，只允许原坐标也在已读窗口内、同版本同路径片段唯一逐字匹配时修正行号，不改变代码或语义置信度。公告、diff 或搜索命中不能替代源码读取。**这些检查不证明入口可达、攻击者可控、类别正确或漏洞可利用；同模型自查不是独立 T1 或人工审计。**

## 4:20—5:00：回答验收问题，明确剩余工作

请评审就屏幕中的实际案例提问，而不是只问“是否全部绿色”：

- 只给公告和已有仓库，模型是否自行发现了源码路径？若没有，卡在材料、历史、搜索还是模型判断？
- 为何选择这个漏洞 commit，而不是修复提交或当前 HEAD？两处位置是否确实在同一版本？
- 入口为何能被攻击者触发，缺陷操作为何构成该漏洞？现有证据支持到哪一步，哪里仍是推断？
- 一个字段不确定后，其余已知字段是否保留？草稿是否被排除在完整候选数量之外？
- 能否用实际文件说明处理量、未处理量、失败原因、耗时和 HTTP/token 用量，而不把格式通过或自查通过当成准确率？

历史随包示例可直接展示 `examples/run-03`：GHSA-8C4J-F57C-35CF、GHSA-MQ4R-H2GH-QV7X、GHSA-CM35-V4VP-5XVX；完整 3、草稿 0、输入失败 0、未处理 0，525.471 秒、18 次 HTTP、245,095 tokens，含 1 项已恢复的协议动作错误。`examples/run-02` 可展示空白响应停止及未处理计数。这不是 v69、v79 或 v80 的成绩；对应历史原始运行及限制见 `docs/t2_v2_results.md`。现场另行实跑时填写本次实际值，不照搬示例；人工认可的判断与疑点仍待评审。没有独立人工复核时，结论应写“自动候选/待复核”，不写“高置信 ground truth”。

</details>

## 评审人工复核清单

这是一份帮助定位问题的检查单，不新增运行门槛，不要求为了填满表格重复调用模型。

- **项目与标题：** 公告、repo URL 与实际代码是否属于同一项目？标题描述的机制是否与选中入口一致，是否把公告级影响误写成另一子功能？
- **版本：** 公告的受影响范围、修复说明和本地历史能否共同支持该 commit？“修复父提交”只是候选；缺历史、分支差异或多提交修复应明确保留疑点。
- **入口 EP：** 这是不是实际可达的入口，而非仅一个看起来相关的内部函数？攻击者控制什么输入、需要什么权限、由哪些调用或路由证据支撑？
- **关键操作 CO：** 该操作是否真是缺陷发生处，而非测试、日志、已修复分支或仅同名 API？缺少的校验/授权/隔离条件如何与公告机制对应？
- **两者关系：** EP 与 CO 是否处于同一漏洞版本，是否有合理的数据或控制关系？不应因为两个片段都逐字匹配，就默认存在可利用链；非空 trace 的每一步也需同样复核。
- **字段与证据：** project、title、类别和漏洞版本的引用是否真正相关？`supported` 是有依据的模型判断，不是引用存在即真；确认不够时保留 `uncertain/missing/conflicting` 与具体原因。
- **输出诚实性：** 人工分别记录“格式/源码字节正确”和“漏洞语义有依据”，注明未验证的前提。保留有用部分，建议值不冒充事实；没有人工确认就不把 `verify` 说成 1。

现场追问无法解决的语义问题应记入后续复核，不通过临时编造版本、行号或结论来完成演示。
