# T2 v2 五分钟现场演示与人工复核

目的：让评审看到“公告材料＋已有本地仓库 → 自主读历史和源码 → 自动候选或有用草稿”的实际过程，并能指出结果中的一个可靠判断和一个未解决问题。**不是展示一个预设成功画面，也不以 schema 通过代替漏洞分析正确。**

本指南的输入示例来自交付包 `README.md`（开发目录为 `README_T2_V2.md`）。`GHSA-2222-3333-4444`、`example/project` 和以下路径都是格式占位符；演示前必须替换为实际公开公告和已准备的本地仓库。后文提供真实随包结果的位置与统计，不预填质量分数或人工验收结论。

## 演示前准备，不占五分钟

使用无配置文件的 PowerShell（例如 `powershell -NoProfile`），切到包含完整 `vulngym_t2/` 的项目目录。建议使用 Python 3.13（实测 Windows / Python 3.13.12，未验证最低版本）和 `PATH` 中的 Git；运行路径只有标准库依赖，不必安装第三方 Python 包。准备 UTF-8 公告、包含相关历史的独立本地 clone 或 bare 仓库；程序不 clone/fetch，不支持 linked worktree、partial clone 或仓库外对象存储。

五分钟是**展示时间，不包含模型等待时间**。严格限时可直接选择“已有结果回放”路线，准备一份已经结束的真实输出，说明运行时间和输入；若尚无真实输出，就现场展示准备检查、运行进度与限制，不预演成已成功完成。回放不冒称现场新运行，stub 不冒充真实模型结果；本稿也不表示已有录屏视频。

以下变量仅在本地终端使用，不把本地绝对路径当作公开报告的证据：

```powershell
New-Item -ItemType Directory -Force 'D:\T2\tmp', 'D:\T2\budget' | Out-Null
$env:TEMP = 'D:\T2\tmp'
$env:TMP = 'D:\T2\tmp'
$t2Advisory = 'D:\T2\materials\advisory.md'
$t2Repo = 'D:\T2\repos\project'
$t2Source = 'https://github.com/advisories/GHSA-2222-3333-4444'
$t2Ledger = 'D:\T2\budget\temporary-authorization.jsonl'
```

同一临时授权始终复用原有 `$t2Ledger`，不可并发占用或另建账本重置次数。累计授权上限最多 500 次 HTTP，失败也计数；本次示例的 24 次只是额外上限。没有有效授权就仅演示离线准备和已有结果。未设置 `DEEPSEEK_API_KEY` 时，在交互终端直接运行正式命令，会出现 `Temporary DeepSeek key (hidden):`；此时输入临时密钥，不回显。不把密钥写进赋值命令、参数或历史，不展示环境变量内容；已有环境配置须属于本次授权。

## 0:00—0:40：给评审看输入边界

打开实际公告，指出项目、问题描述和可用的修复链接；说明本地仓库已经准备好，但**未指定源码路径、候选代码 ID 或内部任务编号**。材料可是一份文件，也可是平铺材料目录。公告中的 fix、仓库 HEAD 或 fix parent 都不是自动确认的漏洞版本。

若需要说明批量格式，展示 README 中这类简单 JSONL 行即可，不必为演示另造复杂任务配置：

```json
{"source_link":"https://github.com/advisories/GHSA-2222-3333-4444","repo_path":"../repos/project","repo_url":"https://github.com/example/project","advisory":"advisory.md"}
```

路径相对于 JSONL 所在目录；URL 列表模式需要公告缓存和本地仓库映射，程序不会自动下载 URL 或补全仓库历史。

## 0:40—1:15：执行无模型的准备检查

```powershell
python -m vulngym_t2 --advisory $t2Advisory --repo $t2Repo --source-link $t2Source --prepare-only
```

现场检查 `http_attempts` 是否为 `0`，每条输入的 `repo_available`、`document_count`、`fix_candidates` 和 `input_error` 是否合理。`status: prepared` 只说明准备检查执行了；仍需检查具体错误，不能据此宣布漏洞分析成功。

若选择 JSONL 或 URL 列表批次，用对应命令代替即可，不需要现场执行三遍。URL 模式的缓存名、repo-map 格式见 README；两者都必须提前准备：

```powershell
python -m vulngym_t2 --input D:\T2\materials\reports.jsonl --prepare-only
python -m vulngym_t2 --input D:\T2\materials\urls.txt --cache-dir D:\T2\cache --repo-map D:\T2\materials\repo-map.json --prepare-only
```

## 1:15—1:50：选择现场执行或真实结果回放

有有效授权且时间允许时，新建一次运行；`--output` 指向尚不存在的目录，`--max-requests` 是上限而不是必须花完的配额：

```powershell
$t2Run = Join-Path 'D:\T2\runs' ('demo-' + (Get-Date -Format 'yyyyMMdd-HHmmss'))
python -m vulngym_t2 --advisory $t2Advisory --repo $t2Repo --source-link $t2Source --output $t2Run --request-ledger $t2Ledger --max-requests 24
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

若 entry 存在却没有同 ID 的 review，应报告产物不一致，不继续套用另一条证据。正常情况下，现场指出一个字段：引用了什么、为什么 `supported` 或 `uncertain/missing/conflicting`。未知必需字段保持 `null`，建议值单独放在 `suggested_values`，不能口头说成事实。可选 trace 未建立时可为 `[]`，原建议和疑点仍保留。所有自动条目为 `verify=0`，`reports.jsonl` 只聚合完整条目。若本次有另一条草稿，可另选并说明其 ID 后展示部分结果；没有草稿就不虚构缺失案例。

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

这里只展示当前案例的动作和 EP/CO 引用的一份源码证据，避免把整批长文本刷满终端。讲清楚模型怎样根据公告/差异读取 commit/相对路径，再形成草稿、自查与回改。当前流程把本地 schema/源码预检查反馈给原有一次自查，不增加额外 HTTP；旧一些运行若无 `draft_validation`，就按它实际记录说明。工具只有上述五种只读能力，不是任意 shell；未进入自查或没有引用源码证据时，也不补讲成已发生。

入口与缺陷位置需引用同一选定 commit 的实际 `read_file` 行，再由 `location_checks` 核验逐字一致。`location_corrections` 若非空，只允许原坐标也在已读窗口内、同版本同路径片段唯一逐字匹配时修正行号，不改变代码或语义置信度。公告、diff 或搜索命中不能替代源码读取。**这些检查不证明入口可达、攻击者可控、类别正确或漏洞可利用；同模型自查不是独立人工审计。**

## 4:20—5:00：回答验收问题，明确剩余工作

请评审就屏幕中的实际案例提问，而不是只问“是否全部绿色”：

- 只给公告和已有仓库，模型是否自行发现了源码路径？若没有，卡在材料、历史、搜索还是模型判断？
- 为何选择这个漏洞 commit，而不是修复提交或当前 HEAD？两处位置是否确实在同一版本？
- 入口为何能被攻击者触发，缺陷操作为何构成该漏洞？现有证据支持到哪一步，哪里仍是推断？
- 一个字段不确定后，其余已知字段是否保留？草稿是否被排除在完整候选数量之外？
- 能否用实际文件说明处理量、未处理量、失败原因、耗时和 HTTP/token 用量，而不把格式通过或自查通过当成准确率？

随包可直接展示 `examples/run-03`：GHSA-8C4J-F57C-35CF、GHSA-MQ4R-H2GH-QV7X、GHSA-CM35-V4VP-5XVX；完整 3、草稿 0、输入失败 0、未处理 0，525.471 秒、18 次 HTTP、245,095 tokens，含 1 项已恢复的协议动作错误。`examples/run-02` 可展示空白响应停止及未处理计数。对应原始运行及限制见 `docs/t2_v2_results.md`。现场另行实跑时填写本次实际值，不照搬示例；人工认可的判断与疑点仍待评审。没有独立人工复核时，结论应写“自动候选/待复核”，不写“高置信 ground truth”。

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
