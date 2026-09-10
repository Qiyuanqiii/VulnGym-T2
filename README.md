# T2 v2：从公告与本地仓库生成可复核记录

本产品独立维护于私有仓库 [Qiyuanqiii/VulnGym-T2](https://github.com/Qiyuanqiii/VulnGym-T2)。首次导入仅包含重做版交付文件，不包含旧工程的 Git 历史、Issue、目标仓库、密钥或请求账本；旧工程保持不动。

当前目标与勘误解释见 [目标、验收边界和推进顺序](docs/t2_goals.md)。以 T2 提取质量和可用性为主，不把 T1、GUI、固定 70 题或评分示例当作前置门槛。

这是独立重建入口 `python -m vulngym_t2`，不经过旧 sealed/orchestrator 流程。输入公告材料和已经准备好的本地 Git 仓库，由模型读取历史与真实源码、提出字段，并在预算允许且形成草稿后最多进行一次自查。不要求用户提供 `source_paths`、候选代码编号或内部任务 ID。

状态：隔离实现已完成代表性真实开发运行。最近一次 GHSA URL 列表批次处理 3 份输入，导出 3 条完整候选，耗时 525.471 秒、18 次 HTTP；另一次批次因首条模型空白正文停止，失败和草稿也保留。**这不是盲测、总体准确率或导师验收通过的声明。** 逐项结果与质量边界见 `docs/t2_v2_results.md`；交付包同时包含真实结果、自评和失败示例。

## 不用 key，先看真实结果

在项目根目录运行以下命令，将已有真实结果整理成便于评审阅读的 Markdown。输出必须是尚不存在的新文件，且不能放进原运行目录；不会读取目标仓库、联网或修改原 JSONL。

```powershell
python -m vulngym_t2.review_export --run-dir examples/run-03 --output review-complete.md
python -m vulngym_t2.review_export --run-dir examples/run-02 --output review-failure.md
```

打开生成的文件即可看批次统计、逐条字段、模型判断、引用目录和空白人工复核栏。`complete` 仍是自动完整候选，`verify=0` 不变；导出不是新的模型运行或人工批准。来源内容作文本显示，不是要执行的命令。最新[案例勘误](docs/t2_case_notes.md)已记录一处修复/父提交角色文字错误及描述超出所引证据的情况；读旧样例时应同时查看，不能只展示成功数量。

## 运行前

建议使用 Python 3.13（当前实测为 Windows / Python 3.13.12），以及已加入 `PATH` 的 Git；未单独验证最低可用 Python 版本。独立运行路径只使用 Python 标准库，**不需要 pip 安装第三方包，也不需要旧 `vulngym_agent` 包**。保留完整 `vulngym_t2/` 目录（包括 `_vendor/` 和 `transport.py`），在其上一级、本项目根目录运行命令；不要只拷贝 `cli.py`。

目标仓库须提前准备为包含相关历史的独立本地 clone 或 bare 仓库。程序不会 clone、fetch 或联网补全缺失对象；浅克隆即使准备检查通过，也不代表包含漏洞与修复版本。不支持 linked worktree、使用外部 gitdir 的 submodule 工作目录、partial clone、外部 alternate object store。目标源码只作为数据读取，不安装目标依赖、不执行目标代码。

建议在无配置文件的 PowerShell（`powershell -NoProfile`）中先确认入口可用；以下检查不请求模型：

```powershell
python --version
git --version
python -m vulngym_t2 --help
```

临时文件、账本和运行输出放在 D 盘。例如在 PowerShell 中先准备运行目录：

```powershell
New-Item -ItemType Directory -Force 'D:\T2\tmp', 'D:\T2\budget' | Out-Null
$env:TEMP = 'D:\T2\tmp'
$env:TMP = 'D:\T2\tmp'
```

以下路径和 `GHSA-2222-3333-4444` 均为格式示例，需换成实际公开材料与本地路径；包含空格的路径须加引号。文本、JSONL 和缓存文件使用 UTF-8 保存。每次 `--output` 必须指向不存在的新目录；不会覆盖已有运行。下列账本父目录已在准备命令中创建，账本本身由程序创建或读取。

## 单份公告 + 本地仓库

先做完全离线的输入检查，不需要密钥，也不会请求模型：

```powershell
python -m vulngym_t2 --advisory D:\T2\materials\advisory.md --repo D:\T2\repos\project --source-link https://github.com/advisories/GHSA-2222-3333-4444 --prepare-only
```

公告正文已有真实 GHSA 标识时可省略 `--source-link`。正式 schema 要求 GHSA 来源；只有 CVE 或无 GHSA 的本地文字可以保留部分分析，但不能用示例 GHSA 补成正式来源。`--advisory` 也可接受平铺材料目录，读取至多 8 份 `.txt/.md/.json/.html/.patch/.diff` 文件，不递归搜集材料。每份文件最多 256 KiB，较长正文还有显式截断；把原始 GitHub 公告 JSON 当作单份材料时也用 `--advisory`，不是多行 JSONL。

`--prepare-only` 不需要 `--output`，不会生成运行输出或自评。它返回 `http_attempts: 0` 和逐输入检查；全部输入准备正常时退出码为 0，含输入错误时为 1。准备通过不等于所需历史齐全、schema 已完整或漏洞已确认。

确认材料与授权后运行：

```powershell
python -m vulngym_t2 --advisory D:\T2\materials\advisory.md --repo D:\T2\repos\project --source-link https://github.com/advisories/GHSA-2222-3333-4444 --output D:\T2\runs\single-001 --request-ledger D:\T2\budget\temporary-authorization.jsonl --max-requests 24
```

密钥优先从已配置的 `DEEPSEEK_API_KEY` 环境变量读取；若未配置，在交互式终端直接运行上面的正式命令，会出现 `Temporary DeepSeek key (hidden):`，此时输入临时授权密钥，字符不回显。不要为了设置环境变量而把真实密钥写进一条可进入 Shell 历史的赋值命令，也不要放进参数、脚本或文档。若已有环境配置，先确认它属于本次授权，不要打印其内容。

非交互环境应使用已授权的环境变量注入；`--key-stdin` 仅接收来自受控管道的一行密钥，不能在普通终端直接加此参数。程序不会把密钥写进输出文件，不自动响应原生权限弹窗。只有正式模型运行需要模型服务网络；输入检查和仓库读取始终不联网。

## 简单报告 JSONL

例如把以下一行保存为 `D:\T2\materials\reports.jsonl`。每行一个 JSON 对象，不是整个文件一个 JSON 数组；记录内的路径相对于 JSONL 所在目录。

```json
{"source_link":"https://github.com/advisories/GHSA-2222-3333-4444","repo_path":"../repos/project","repo_url":"https://github.com/example/project","advisory":"advisory.md"}
```

```powershell
python -m vulngym_t2 --input D:\T2\materials\reports.jsonl --prepare-only
python -m vulngym_t2 --input D:\T2\materials\reports.jsonl --output D:\T2\runs\jsonl-001 --request-ledger D:\T2\budget\temporary-authorization.jsonl --max-requests 80
```

同仓库批次可用 `--repo` 指定默认仓库；该命令行路径相对于当前工作目录，而非 JSONL 目录。`repo_url` 可省略并从本地 GitHub `origin` 推导；若没有可用的 GitHub origin，就在 JSONL 或 repo-map 中明确提供真实 `repo_url`，否则可能保留为不完整草稿。不要编造 GitHub 仓库 URL。

可选 `documents`（例如 `[{"name":"note","kind":"advisory","text":"补充正文"}]`）、正文/描述、`fix_commits` 或 `vulnerable_commit` 用于补充材料，但不替代实际源码核验。每条记录独立处理，格式错误保留为输入失败；输入清单上限 4 MiB、最多 500 条，超限会明确报错。

## GHSA URL 列表 + 缓存 + 仓库映射

`D:\T2\materials\urls.txt` 每行一个 GHSA URL，空行和 `#` 注释会被忽略：

```text
https://github.com/advisories/GHSA-2222-3333-4444
```

把已获得的公告保存为 `D:\T2\cache\GHSA-2222-3333-4444.md`。缓存文件名支持**整段 GHSA ID 全小写或全大写**，扩展名为 `.json/.md/.txt/.html`；有字母的 ID 不应只把 `GHSA-` 前缀大写而后缀保留小写。工具本身不会下载 URL，缺缓存会记为输入失败。

`D:\T2\materials\repo-map.json` 按公告 ID 映射到本地仓库：

```json
{
  "GHSA-2222-3333-4444": {
    "repo_path": "D:/T2/repos/project",
    "repo_url": "https://github.com/example/project"
  }
}
```

```powershell
python -m vulngym_t2 --input D:\T2\materials\urls.txt --cache-dir D:\T2\cache --repo-map D:\T2\materials\repo-map.json --prepare-only
python -m vulngym_t2 --input D:\T2\materials\urls.txt --cache-dir D:\T2\cache --repo-map D:\T2\materials\repo-map.json --output D:\T2\runs\batch-001 --request-ledger D:\T2\budget\temporary-authorization.jsonl --max-requests 80
```

repo-map 中的相对路径以映射文件所在目录为基准。上面三种输入路线任选一种即可，不需要同时准备 JSONL、URL 列表和材料目录。

## 如何读结果

| 文件 | 含义 |
|---|---|
| `entries.jsonl` | 通过完整 schema、来源与精确源码位置检查的自动候选条目；全部 `verify=0`。 |
| `reports.jsonl` | 仅对上述完整条目按公告聚合，不把草稿伪装成完整报告。 |
| `review.jsonl` | 每条已处理输入的字段状态、已知 `draft_fields`、独立 `suggested_values`、证据、源码核验结果和错误。 |
| `actions.jsonl` | 有界的计划、读工具、草稿、自查记录，不保存隐藏推理或密钥。 |
| `summary.json` | 完整条目/草稿/输入失败数量、未处理数量、耗时、模型与 HTTP 用量。 |

每条已处理输入的 `review.status` 有三种结果，不能与批次 `summary.status` 混淆：

| `review.status` | 读法与统计 |
|---|---|
| `complete` | 进入正式 `entries.jsonl` 的自动候选，计入 `candidate_count`，仍需人工判断语义。 |
| `draft` | 必需内容未全部建立，已知字段和建议值仍可复核，计入 `draft_count`，不计完整候选。 |
| `input_failure` | 材料或本地仓库准备失败，原因保留，计入 `input_failure_count`。 |

`supported` 表示有引用依据的模型判断或控制器输入事实及适用的确定性检查，不是人工确认。`uncertain/missing/conflicting` 保留原因；未知必需字段在 `draft_fields` 中为空，建议值单独存放。缺失 SHA 或位置时不会补空 SHA、行 0 或猜测代码。可选 trace 未建立时可导出 `[]`，原建议和疑点仍留在 review；行号若经已读窗口内唯一逐字匹配修正，会记录 `location_corrections`，不改变片段、版本或语义置信度。

首次草稿先做本地 schema/字段与源码位置预检查，把实际错误和行号修正反馈给原有的那一次 self-review，让模型据已读证据回改或保留未知；这不会额外增加模型自查轮次或 HTTP 请求。最后仍做终检，本地检查和模型回改都不替代语义复核。

批次逐条保存结果。`summary.status: completed` 仅表示批次走完，可能没有任何完整候选；网络、鉴权或响应格式失败通常得到 `provider_stopped` 并停止继续请求，已写出的结果保留，剩余输入计入 `unprocessed_input_count`。启动或参数错误可能尚未生成目录。强制终止进程仍可能使当前输入或汇总尚未落盘，不能把不存在的 summary 当成一次已完成运行。

已结束的目录可离线生成便于提交和人工复核的中文自动自评，不用密钥，也不产生新模型请求：

```powershell
python -m vulngym_t2.report --run-dir D:\T2\runs\single-001
```

它仅读取 `summary.json` 和 `review.jsonl`（合计最多 20 MB），新建 `assessment.md`，已有同名文件时拒绝覆盖；不修改原 JSON。自评引用实际统计与疑点，不提供无独立标签支撑的准确率或 F1。

## 预算、安全与已知边界

同一临时授权的所有运行必须复用同一个 `--request-ledger`，且不能并发占用它。`--authorization-limit` 默认且最多为 **500 次累计 HTTP 尝试**，已有账本须继续使用创建时相同的授权上限；失败尝试也计数。`--max-requests` 是本次运行上限，默认 80，不是必须花完的配额。不得另建或清空账本重置授权；锁定、损坏或发现未结束请求时保留现场并检查。

默认每份公告最多 8 次模型调用、24 次仓库读调用，可用 `--max-calls-per-report` 和 `--max-tool-calls` 调低；硬上限分别为 16/64。模型调用次数和实际 HTTP 次数不是同一口径，以账本的 `http_started` 为授权用量准绳。当前实现固定使用传输模块配置的 `deepseek-v4-pro`，零自动重试，不自动换账户或模型；未测量货币费用，不能把 token 数当成实际账单。

模型可请求七种有界只读工具：`inspect_commit`、`list_files`、`read_file`、`search_code`、`read_diff`，以及探索已有本地版本的 `list_refs` / `search_history`。修复父提交、tag、HEAD 或提交说明命中只是待检线索，不自动成为漏洞版本；历史查询无命中也不证明不存在。源码精确一致不证明入口可达、攻击者可控或漏洞可利用；长材料截断、多入口、复杂跨文件逻辑和历史缺失仍需人工判断。当前每个输入最多产出一个条目；T1 集成和非空 trace 属可选扩展。新增历史探索已有离线功能检查，尚未进行新的真实模型评估。

历史搜索默认从 HEAD 开始；若提供的对象仓库没有有效 HEAD，模型应先用 `list_refs`，再显式指定返回的 commit。程序不会静默挑选“漏洞版本”。

### 批次停止后，离线列出尚未开始的 URL

```powershell
python -m vulngym_t2.pending --input examples/t2_v2_input/urls.txt --run-dir examples/run-02 --output D:\T2\remaining.txt
```

工具只读取原 URL 列表和已结束运行的汇总/逐条结果，不联网、不读 key/账本、不请求模型。它核对已处理前缀后写入新清单；失败但已产生草稿的当前项也算已处理，不会偷偷重试。上面随包失败示例会得到三份尚未开始的 URL；它们之后已经在 `examples/run-03` 运行，**这里只演示清单生成，不要把它们再当成未见案例重跑**。

只支持不重复的 GHSA URL 列表，以及可核对的 `completed` / `provider_stopped` 运行。中断状态、计数/身份不符或已有输出文件会拒绝，不猜测哪一项曾发出请求；不保证源材料未变，也不恢复模型 checkpoint。若后来又分批运行过这些 URL，使用者还需核对后续记录，不能把单个旧运行的剩余清单当成全局待办。真正处理剩余输入需要明确授权和有效 key，并使用新输出目录、同一授权原有账本。

可携带公开输入见 `examples/t2_v2_input/`，需按其说明配置自己的本地仓库路径。交付包的 `examples/run-01`、`run-02`、`run-03` 分别保留混合结果、停止结果、最新 URL 列表结果，不能把它们相加当成独立案例数。

短设计见 `docs/t2_v2_design.md`，交付 ZIP 另含三页 `docs/T2-design.pdf`；现场操作和人工复核见 `docs/t2_v2_demo.md`，支持现场演示，并不表示已经录制视频。官方字段定义以 `SCHEMA.md` 为准。
