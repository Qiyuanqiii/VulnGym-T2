# T2 v2 standalone packaging

## Current state

The current explicit runtime manifest contains **43 files: 30 product Python
modules + 5 vendored Python files + 8 local Web assets**. These are separate from
the README, schema, licenses, documentation, tests and selected example outputs.
It does not require the legacy project, orchestrator, finalizers or benchmark
packages. CLI and local Web share the same product implementation.

The four vendored implementations and their package initializer carry source
provenance; this packaging update does not change them. The HTTP/JSON transport
is a separate module, without legacy prompts or backend orchestration.

This is a standalone **source archive**, not a wheel or a claim that vulnerability
quality acceptance is complete. The builder is `scripts/package_t2_v2.py`; it
selects these runtime files explicitly, including HTML/CSS/JavaScript, branding
and the bundled font/license. On 2026-09-14 the two packaging test modules passed
**7 tests**: they check relative-import coverage, import the selected Python
modules in an isolated temporary directory, and exercise small synthetic archive
publication/conflict cases. They do not prove a user delivery archive was built,
that every UI interaction works after extraction, or that extraction quality has
passed acceptance. The v84 full suite also passed the isolated checks with the
current 43-file manifest. A real user archive and its extracted CLI/Web checks remain
separate work; **no new user ZIP was built in this update**.

The working-copy `DELIVERY.json` runtime list has been updated, but
`source_files=143` and `example_runs=13` retain the last actual archive's historical
counts. They are not current tree counts, test counts or a newly packaged result.
The builder computes new counts only when it actually creates an archive.

## Exact runtime source manifest

### Product Python modules: 30 (`MODULES`)

```text
vulngym_t2/__init__.py
vulngym_t2/__main__.py
vulngym_t2/annotation_rules.py
vulngym_t2/candidate_navigation.py
vulngym_t2/cli.py
vulngym_t2/completion_json.py
vulngym_t2/entry_navigation.py
vulngym_t2/evidence_context.py
vulngym_t2/evidence_focus.py
vulngym_t2/evidence_navigation.py
vulngym_t2/imported_call_navigation.py
vulngym_t2/intake.py
vulngym_t2/llm.py
vulngym_t2/multi_entry.py
vulngym_t2/output.py
vulngym_t2/pending.py
vulngym_t2/pipeline.py
vulngym_t2/prompt_evidence.py
vulngym_t2/protocol.py
vulngym_t2/read_plan_protocol.py
vulngym_t2/report.py
vulngym_t2/repository.py
vulngym_t2/review_export.py
vulngym_t2/revision_navigation.py
vulngym_t2/source_refs.py
vulngym_t2/staged_protocol.py
vulngym_t2/support_consistency.py
vulngym_t2/transport.py
vulngym_t2/web.py
vulngym_t2/web_runtime.py
```

### Vendored Python files: 5 (`VENDOR`)

```text
vulngym_t2/_vendor/__init__.py
vulngym_t2/_vendor/bounded_process.py
vulngym_t2/_vendor/git_repository.py
vulngym_t2/_vendor/models.py
vulngym_t2/_vendor/schema_adapter.py
```

### Local Web assets: 8

```text
vulngym_t2/web_assets/index.html
vulngym_t2/web_assets/app.css
vulngym_t2/web_assets/app.js
vulngym_t2/web_assets/brand/vulngym.png
vulngym_t2/web_assets/brand/README.md
vulngym_t2/web_assets/fonts/jetbrains-mono-latin-wght-normal.woff2
vulngym_t2/web_assets/fonts/OFL.txt
vulngym_t2/web_assets/fonts/README.md
```

Do not distribute only the 35 Python files if the local Web interface is part
of the hand-off. Its scripts, styles, icon and bundled font are served locally;
they are not supplied by a Node build or a CDN fallback.

Support provenance:

| Current module | Origin and purpose |
| --- | --- |
| `_vendor/git_repository.py` | Original low-level Git reader; immutable object reads, safe argument arrays and local-storage checks. Imports only the local bounded-process helper. |
| `_vendor/bounded_process.py` | Original process helper; output ceilings, timeouts and process-tree containment. |
| `_vendor/schema_adapter.py` | Original schema adapter; normalization and semantic schema checks. Imports the local models. |
| `_vendor/models.py` | Original schema/evidence data classes; standard library only. |
| `transport.py` | Extracted official HTTP and bounded JSON/error primitives; no legacy package dependency. |
| `protocol.py` | Typed strict function-output schema and pure normalization into existing T2 actions; no function execution. |
| `report.py` | Chinese assessment generation from completed public run outputs; no new model analysis. |
| `pending.py` | Offline remaining-URL list from an exact completed-prefix comparison; no model, target or credential access. |
| `review_export.py` | Offline reviewer Markdown from saved public results, joined by entry ID; no approval or source edits. |

Also distribute the existing `LICENSE`, `SCHEMA.md`, a product-specific README,
and selected design, limitations, self-assessment, iteration-history and public
demonstration artifacts. Preserve source attribution in the vendored files.
The schema document is for users; the adapter does not load a schema file at
runtime. Exclude credentials, authorization ledgers, private transcripts, target
Git objects, benchmark datasets and unrelated legacy source.

The builder includes `tests/__init__.py` and the current `tests/test_t2_v2_*.py`
modules, not an obsolete short list. Test modules share synthetic fixtures, so
do not select individual test files without their dependencies. Tests are not
runtime dependencies. The packaging-specific checks are:

```powershell
python -B -m unittest tests.test_t2_v2_package_runtime tests.test_t2_v2_package_conflicts -q
```

The runtime check covers Python relative imports and clean-tree imports. The
conflict/publication checks use synthetic temporary archives, not the user's
saved results. Neither is a substitute for extracted Web asset/interaction QA.

## Dependencies and usage

Third-party Python runtime dependencies: **none**. HTTP/TLS, JSON, path handling,
process management and locking use the standard library, including `ctypes`
and `msvcrt` on Windows, or `fcntl` for locking on POSIX. No provider SDK,
`requests`, `httpx`, `jsonschema`, Docker or Node runtime is required.

Git must be installed on an absolute PATH entry outside the inspected target
repository. Target repositories must be complete standalone clones or bare
repositories. Linked worktrees, alternate object stores, partial/promisor
clones and SHA-256 Git repositories are unsupported; no fetching is performed.

The interpreter actually used is **Python 3.13.12 on Windows**, verified with
`D:\python314\python.exe --version`. The directory name is not the Python
version. An oldest-supported-version claim and POSIX compatibility remain
unverified.

From the standalone product root, using existing example input locations:

```powershell
$env:TMP = 'D:\VulnGym-bv2-runtime\tmp'
$env:TEMP = 'D:\VulnGym-bv2-runtime\tmp'
& 'D:\python314\python.exe' -B -m vulngym_t2 --help
& 'D:\python314\python.exe' -B -m vulngym_t2.web --help
& 'D:\python314\python.exe' -B -m vulngym_t2 --advisory 'D:\materials\advisory.json' --repo 'D:\repos\project' --prepare-only
& 'D:\python314\python.exe' -B -m vulngym_t2 --input 'D:\materials\advisories.txt' --cache-dir 'D:\materials\cache' --repo-map 'D:\materials\repos.json' --prepare-only
```

These are local command templates; input/repository paths and the temporary
directory must already exist and be adjusted for the receiving machine.
Preflight needs no credential and sends no HTTP request. For explicitly
authorized live operation, use a new output directory and the existing shared
ledger for that authorization. The following live template matches the current
generation-ledger ceiling of 3000 but additionally enforces cumulative generation
at 2999, leaving the already used historical request inside the total 3000:

```powershell
& 'D:\python314\python.exe' -B -m vulngym_t2 --advisory 'D:\materials\advisory.json' --repo 'D:\repos\project' --output 'D:\results\run-001' --request-ledger 'D:\results\authorization.jsonl' --authorization-limit 3000 --effective-request-limit 2999 --model deepseek-flash --response-mode staged_tool --annotation-format assessed_tool --read-format plan_tool --thinking enabled --reasoning-effort low --max-tokens 32768 --max-calls-per-report 12 --max-tool-calls 64 --max-requests 12 --stop-on-format-error
& 'D:\python314\python.exe' -B -m vulngym_t2.report --run-dir 'D:\results\run-001'
```

This template does not grant authorization or create a replacement budget.
The receiver must supply their own authorized limits/ledger. Do not reuse the
numeric limits as permission, and do not omit the effective cap when continuing
the current authorization. It is process-local, not a rewrite of ledger history.

For the local Web workbench, the same current authorization can be configured as:

```powershell
& 'D:\python314\python.exe' -B -m vulngym_t2.web --runs-root 'D:\results\web-runs' --request-ledger 'D:\results\authorization.jsonl' --authorization-limit 3000 --effective-request-limit 2999 --historical-requests 1 --port 8765
```

Starting the server alone sends no model request. The existing ledger must match
the selected model/authorization. Extraction still requires the separate GUI
confirmation and a valid runtime key; it invokes the same CLI. The Web fixed
`high` profile is not the CLI `low` template above. See [Web operation](t2_web_gui.md)
for interaction checks and per-version evidence rather than equating the profiles.

The hidden terminal prompt or an already configured `DEEPSEEK_API_KEY` supplies
the credential. Never put a real key in a command, package, test or log. Reuse
the same ledger across one authorization; failed HTTP attempts count, and the
ceiling is not a target. Existing output directories are not overwritten.

Source execution with `python -m` needs no packaging tool. An installable wheel
would additionally need packaging metadata and a clean installation check;
do not advertise `pip install` support before that work is complete.

## 打包、解压与交给其他使用者

在源码项目根目录运行下面命令；`D:\T2\delivery` 应已存在，ZIP 文件名必须是新的。
默认不带任何真实运行输出，适合先验证独立交付能力：

```powershell
python -B scripts/package_t2_v2.py --output D:\T2\delivery\vulngym-t2-v2.zip
Expand-Archive -LiteralPath D:\T2\delivery\vulngym-t2-v2.zip -DestinationPath D:\T2\standalone
Set-Location D:\T2\standalone
python -E -s -B -m vulngym_t2 --help
```

解压目录必须与原工程分离，且不需要复制 `vulngym_agent`。`-E -s` 忽略 Python
环境路径和用户 site 包，避免原工程或本机扩展包意外补齐缺失依赖。压缩包根目录含
`README.md`、`SCHEMA.md`、`LICENSE`、35 个运行 Python 文件及 8 个 Web 资源、选定文档与离线测试，以及
`examples/t2_v2_input/` 中的四份公开公告输入；
`DELIVERY.json` 记录准确运行文件清单、打包 Python 版本和示例数量。
打包器优先使用 `README_T2_V2.md`；当前独立工作副本以 `README.md` 与产品
`DELIVERY.json` 标识回退选择。归档统一命名为 `README.md`，随附的
`DELIVERY.json` 标识本产品，因此可在解压目录再次运行同一打包脚本。缺少产品 README
和交付标识的普通旧工程不会被静默当作本产品打包。

原公开输入目录采用七个文件的显式清单：四份 `cache/GHSA-....json`、`urls.txt`、
`repo-map.example.json` 和该目录的 `README.md`。JP4J、8C4J、MQ4R、CM35 四份均为
公开开发样本，公告 JSON 和 URL 列表保留原文，不含预测答案或另行预选的源码位置。
映射仅使用 `repos/...` 相对占位路径；接收者须修改成本机仓库路径，或准备对应目录。
相对路径以映射文件为基准，详细离线预检查命令见该目录 README。打包脚本不会递归
收集 runtime、实际 repo-map、目标仓库、密钥、账本或未选择的运行输出。

当前 `PUBLIC_INPUT_FILES` 明列 12 个文件：上述原7个加 `v41/` 的5个文件
（完整批次URL列表、减线索JSONL、严格定向JSONL与两份公告）。这不是目录递归收集。
历史 `run-04` 至 `run-07` 分别为完整材料首批、首批未开始项、减线索首批、减线索未开始项，
含失败和自查未完成的草稿，详见 `docs/t2_v41_results.md`。早期“七示例、100个文件、
18个运行源码”仅属于旧归档，不是当前清单；最后实际归档的143个source_files/13个example_runs
也不因这次源码与清单更新而重算。历史示例不能作为当前版本成绩。

接收者自行提供已经准备好的本地 Git 仓库和公开公告；包不包含目标仓库、Git 对象、
私有基准或答案数据。以 `D:\materials\advisory.md` 和 `D:\repos\project` 为例：

```powershell
python -E -s -B -m vulngym_t2 --advisory D:\materials\advisory.md --repo D:\repos\project --source-link https://github.com/advisories/GHSA-2222-3333-4444 --prepare-only
```

上面的 GHSA ID 是格式占位符，请替换成真实公告；正文已有 GHSA ID 时可省略
`--source-link`。单公告可用 UTF-8 Markdown、文本或 JSON，也可提供平铺材料目录。
无需给程序 `source_paths`、候选编号或标准答案。若采用 URL 列表批次，则自行准备
`advisories.txt`、按 GHSA ID 命名的公告缓存，以及如下仓库映射（路径改为本机实际值）：

```json
{"GHSA-2222-3333-4444":{"repo_path":"D:/repos/project","repo_url":"https://github.com/example/project"}}
```

预检查不读密钥、不发模型请求。真实调用需要使用者另行授权，在运行时通过隐藏提示或
已配置的 `DEEPSEEK_API_KEY` 提供密钥；账本和新输出目录放在压缩包之外。**不得把密钥、
授权账本、原始响应、隐藏推理或私有数据加入交付包。** CLI授权参数默认500，但不是当前
用户累计上限，也不是自动授权。当前总3000包含历史1，继续运行使用账本3000与有效生成
上限2999；所有运行复用原账本，失败也计数。不要把包内示例当成额外授权或盲测结果。

需要演示产物时才重复传入 `--example-run`。脚本只选 `entries.jsonl`、`reports.jsonl`、
`review.jsonl`、`actions.jsonl`、`summary.json` 和存在时的 `assessment.md`，并保留存在时的
`drafts.jsonl`、`report_conflicts.jsonl`；拒绝明显仍在运行
或最终计数不完整的目录；完成但含错误/草稿的运行会如实保留其状态。文件名白名单与
完成标记不是数据公开性证明，发布者还须确认这些文件已经完成脱敏与公开授权检查。
首次交付包选择已经结束的 development-run-04、url-batch-run-05、url-batch-run-06，
依次放入 `examples/run-01`、`run-02`、`run-03`。失败和未处理数量不隐藏；详细统计见
`docs/t2_v2_results.md`。附带三页设计 PDF 时使用 `--design-pdf` 指定已渲染文件：

```powershell
python -B scripts/package_t2_v2.py --output D:\T2\delivery\vulngym-t2-v2.zip --example-run D:\T2\runs\development-run-04 --example-run D:\T2\runs\url-batch-run-05 --example-run D:\T2\runs\url-batch-run-06 --design-pdf D:\T2\delivery\T2-design.pdf
```

这些路径是运行位置示例，应替换为实际已结束目录；不要为了打包重新请求模型。

### 设计说明与已生成的 PDF 快照

`docs/t2_v2_design.md` 与新生成的三页 `output/pdf/T2-design-v84.pdf` 对应，
经过三页 PNG 逐页检查与全部文本核对，记录当前实现、真实恢复和内容复核限制。
`output/pdf/T2-design-v83.pdf` 保留为 v83 复测前设计快照，
`output/pdf/T2-design-v81.pdf` 保留为 v81 真实复测前快照，旧
`docs/T2-design.pdf` 保留为早期设计，不要混为同一版本。
以后获准生成新包时，应将新 PDF 明确传给 `--design-pdf`；包内仍按
`docs/T2-design.pdf` 命名，内容版本以所选文件为准。当前没有制作新用户 ZIP。

开发用生成器为 `scripts/render_t2_design.py`，需要 ReportLab、pypdf 和可用字体，
不在产品运行依赖或运行清单中。它要求 Markdown 恰分三页并拒绝覆盖已有 PDF；
修改设计后应指定新的输出位置、检查文本，再用 Poppler 渲染检查每页。
PDF 说明其生成时的架构和已知限制，不把旧真实运行升级为当前成绩。生成器从 Markdown 的版本/日期生成页眉和默认文件名，不再硬编码 v81，仍拒绝覆盖已有文件；正文 10.1 pt，不靠缩小字号挤入三页。三份 v83 与一份 v84 QA 已加入显式打包文档清单，当前为 **58 份且全部存在**；运行文件仍为 43 个，包含 `evidence_navigation.py`。生成 PDF 与更新清单不等于生成了新归档。

四批最新 entries/drafts/summary 的可读副本在 `output/real-results-20260914/`，
共 12 文件、29549 字节，目录索引另列来源与限制。它不包含完整 review/actions；
后两者仍在原 D 盘运行目录，四份 QA 位于 docs。摘录不能直接传给 GUI/review_export，
其中 summary 的 files 仍描述原批次完整七文件；副本不替代原始回执，也不是用户 ZIP。

## Release verification and lesson

2026-09-14 的 v81 隔离启动核对覆盖当时 42 个运行文件：fresh Python `-I -B`
逐模块确认只从新临时树导入，实际执行 CLI `--help`；8 个 Web 资产均复制齐全，
首页及 6 个公开静态路由返回 HTTP 200，内容/MIME/长度匹配。字体说明 README
只随包保存，不是公开路由。未构造模型或授权账本，未调用业务 API 或外网，临时服务已关闭。
相关 7 项测试通过；这证明所选源文件可独立启动，不冒充尚未制作的新用户 ZIP 已验收。

v84 的 43 文件清单隔离运行检查已随全仓通过：1151 项中 1150 通过、
1 项既有符号链接能力跳过（25.769 秒），最终冒烟 11/11（9.563 秒），本轮 Node VM
合成交互 24/24，均退出 0。这不是本轮浏览器验收，也不重算历史
`source_files=143` / `example_runs=13`，没有制作新用户 ZIP、提交或推送。
这些打包相关离线检查不调用模型；另行授权的三批 v83 与一批 v84 共 50/52 HTTP，
累计 2708 次生成加历史 1 次为 2709/3000、余 291，本轮余 2 次不补花。
两个驱动均退出 0、临时 key 已释放，无付费进程；不同上限与重复输入不合并成质量评分。

Before distributing an archive, stage the 43 runtime files listed above plus explicitly
selected delivery/test files in a new D-drive directory, with no legacy checkout
on `PYTHONPATH`. Run `--help`, a synthetic local preflight and the explicitly
named focused tests. Check that importing the CLI and report module leaves no
`vulngym_agent` entries in `sys.modules`. Provider tests must use stubbed
transport, never an incidental credential; do not execute inspected target code.
The no-example extraction check must run from the extracted directory, not from
the original checkout. Inspect archive member names and confirm there are no
`vulngym_agent/`, credential, ledger, target-repository or private-data trees.
No paid/live HTTP check is needed to validate source-package independence.

The first implementation's seemingly small legacy imports expanded to 70 files
because package initializers eagerly imported unrelated workflows. Vendoring
the four low-level helpers and extracting the transport removed that dependency.
The lesson is to verify package initialization as well as direct imports; the
obsolete 70-file tree is not a distribution manifest.
