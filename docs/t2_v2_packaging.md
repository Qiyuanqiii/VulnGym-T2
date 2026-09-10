# T2 v2 standalone packaging

## Current state

The product is isolated: all production imports remain inside `vulngym_t2` or
Python's standard library. A fresh import of `vulngym_t2.cli` loads **zero
`vulngym_agent` modules**. The source distribution now needs the **18 Python files**
below, not the legacy project, orchestrator, finalizers or benchmark packages.

The four vendored implementations preserve their original behavior. Mechanical
comparison verified that their only changes were provenance comments and two
relative dependency imports. The HTTP/JSON transport is a separate extracted
module, without legacy prompts, backend orchestration or replay machinery.

This is a standalone **source archive**, not a wheel or a claim that vulnerability
quality acceptance is complete. The builder is `scripts/package_t2_v2.py`; it
selects the 18 runtime files explicitly. A fresh-process CLI check after
extraction is still required: a source manifest alone does not prove the full
import path.

## Exact runtime source manifest

```text
vulngym_t2/__init__.py
vulngym_t2/__main__.py
vulngym_t2/cli.py
vulngym_t2/intake.py
vulngym_t2/llm.py
vulngym_t2/output.py
vulngym_t2/pending.py
vulngym_t2/pipeline.py
vulngym_t2/protocol.py
vulngym_t2/report.py
vulngym_t2/repository.py
vulngym_t2/review_export.py
vulngym_t2/transport.py
vulngym_t2/_vendor/__init__.py
vulngym_t2/_vendor/bounded_process.py
vulngym_t2/_vendor/git_repository.py
vulngym_t2/_vendor/models.py
vulngym_t2/_vendor/schema_adapter.py
```

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

Optional focused tests are `tests/__init__.py` and these modules:

```text
tests/test_t2_v2_cli.py
tests/test_t2_v2_intake_repo.py
tests/test_t2_v2_llm.py
tests/test_t2_v2_output.py
tests/test_t2_v2_pipeline.py
tests/test_t2_v2_source_coordinates.py
tests/test_t2_v2_transport.py
tests/test_t2_v2_history.py
tests/test_t2_v2_pending.py
tests/test_t2_v2_review_export.py
tests/test_t2_v2_protocol.py
tests/test_t2_v2_report.py
tests/test_t2_v2_batch_recovery.py
```

The intake/repository and output tests now import the vendored schema adapter.
Keep the pipeline test beside the CLI test because the latter reuses its
synthetic fixtures. Tests are not runtime dependencies.

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
$env:TMP = 'D:\Temp'
$env:TEMP = 'D:\Temp'
& 'D:\python314\python.exe' -B -m vulngym_t2 --help
& 'D:\python314\python.exe' -B -m vulngym_t2 --advisory 'D:\materials\advisory.json' --repo 'D:\repos\project' --prepare-only
& 'D:\python314\python.exe' -B -m vulngym_t2 --input 'D:\materials\advisories.txt' --cache-dir 'D:\materials\cache' --repo-map 'D:\materials\repos.json' --prepare-only
```

Preflight needs no credential and sends no HTTP request. For explicitly
authorized live operation, replace `--prepare-only` with a new output
directory and an absolute ledger path whose parent already exists:

```powershell
& 'D:\python314\python.exe' -B -m vulngym_t2 --advisory 'D:\materials\advisory.json' --repo 'D:\repos\project' --output 'D:\results\run-001' --request-ledger 'D:\results\authorization.jsonl' --max-requests 20
& 'D:\python314\python.exe' -B -m vulngym_t2.report --run-dir 'D:\results\run-001'
```

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
`README.md`、`SCHEMA.md`、`LICENSE`、18 个运行源码文件、选定文档与离线测试，以及
`examples/t2_v2_input/` 中的四份公开公告输入；
`DELIVERY.json` 记录准确运行文件清单、打包 Python 版本和示例数量。
开发目录使用 `README_T2_V2.md`；解压后该文件命名为 `README.md`，随附的
`DELIVERY.json` 标识本产品，因此可在解压目录再次运行同一打包脚本。缺少产品 README
和交付标识的普通旧工程不会被静默当作本产品打包。

原公开输入目录采用七个文件的显式清单：四份 `cache/GHSA-....json`、`urls.txt`、
`repo-map.example.json` 和该目录的 `README.md`。JP4J、8C4J、MQ4R、CM35 四份均为
公开开发样本，公告 JSON 和 URL 列表保留原文，不含预测答案或另行预选的源码位置。
映射仅使用 `repos/...` 相对占位路径；接收者须修改成本机仓库路径，或准备对应目录。
相对路径以映射文件为基准，详细离线预检查命令见该目录 README。打包脚本不会递归
收集 runtime、实际 repo-map、目标仓库、密钥、账本或未选择的运行输出。

V4.1 迭代另显式加入四个 `v41/` 输入文件：完整批次 URL 顺序、两份减线索公告、使用相对仓库占位路径的 JSONL。新公开结果按顺序追加为 `run-04` 至 `run-07`，分别为完整材料首批、首批未开始项、减线索首批、减线索未开始项。含失败和自查未完成的草稿，不筛掉错误；详见 `docs/t2_v41_results.md`。后续格式/版本修复增加 protocol.py 和3个针对性测试文件，当前七示例交付含 100 个文件，运行源码为 18 个；七个真实示例仍是修复前的记录。

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
授权账本、原始响应、隐藏推理或私有数据加入交付包。** 同一授权累计最多 500 次 HTTP
尝试，所有运行复用同一账本，失败也计数；不要把包内示例当成额外授权或盲测结果。

需要演示产物时才重复传入 `--example-run`。脚本只选 `entries.jsonl`、`reports.jsonl`、
`review.jsonl`、`actions.jsonl`、`summary.json` 和可选 `assessment.md`，拒绝明显仍在运行
或最终计数不完整的目录；完成但含错误/草稿的运行会如实保留其状态。文件名白名单与
完成标记不是数据公开性证明，发布者还须确认这些文件已经完成脱敏与公开授权检查。
首次交付包选择已经结束的 development-run-04、url-batch-run-05、url-batch-run-06，
依次放入 `examples/run-01`、`run-02`、`run-03`。失败和未处理数量不隐藏；详细统计见
`docs/t2_v2_results.md`。附带三页设计 PDF 时使用 `--design-pdf` 指定已渲染文件：

```powershell
python -B scripts/package_t2_v2.py --output D:\T2\delivery\vulngym-t2-v2.zip --example-run D:\T2\runs\development-run-04 --example-run D:\T2\runs\url-batch-run-05 --example-run D:\T2\runs\url-batch-run-06 --design-pdf D:\T2\delivery\T2-design.pdf
```

这些路径是运行位置示例，应替换为实际已结束目录；不要为了打包重新请求模型。

## Release verification and lesson

Before distributing an archive, stage only the 18 runtime files plus explicitly
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
