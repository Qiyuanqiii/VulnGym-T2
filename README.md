<img src="vulngym_t2/web_assets/brand/vulngym.png" alt="VulnGym" width="240">

# VulnGym T2 · 漏洞条目提取工作台

在本机运行的 T2 工作台。你给它一份公开漏洞公告和一个开源仓库，它让模型自己去读公告、翻提交历史、在源码里定位入口和关键操作，产出符合 VulnGym schema 的 15 字段条目，以及每个字段“凭什么这么填”的依据。依据不够的字段留成待补充草稿，不拿模型的猜测冒充核实过的事实。

提供网页工作台和命令行两种入口，共用同一套处理逻辑。日常使用只需要浏览器。

本仓库是独立实现，**不是腾讯官方产品，也不代表腾讯认可其输出**。上方图标的来源、字节校验值与署名见[图标说明](vulngym_t2/web_assets/brand/README.md)。

[下载最新 Windows x64 交付包](https://github.com/Qiyuanqiii/VulnGym-T2/releases/latest) · [解压启动说明](README_START.md) · [输出字段参考](SCHEMA.md) · [效果与缺口](docs/t2_representative_validation_20260913.md) · [工程说明](ENGINEERING_README.md)

## 三条设计约束

- **不运行目标代码。** 目标仓库只按 git 对象读取，不 checkout、不安装依赖、不执行任何目标项目的脚本。
- **出处必须落在真实读过的源码上。** 入口点和关键操作要求同一 commit、同一路径、并且是程序确实向模型展示过的连续行，逐字比对。对不上就把该字段留成待补充，不做“看起来合理”的补全，也不为缺失位置编造出处。
- **自动产物一律 `verify=0`。** 程序校验的是结构、来源一致性和位置是否真的存在，漏洞事实是否成立由人判断。

这三条都是代码级检查，不是文档承诺。

## 它能做什么

输入有三条路，任选一条：

- **粘贴公告链接。** 一次贴 GHSA 和 OSV 的链接（每批最多 20 条，支持换行、空格、Markdown 链接和混合来源）。程序按链接来源下载公开公告，找到唯一可确定的公开源码仓库后拉取 Git 历史，你不用填仓库路径、缓存目录或映射文件。这一步不花钱。
- **粘贴或上传本地资料。** 公告正文、补丁、已有的本地仓库路径，全程离线。
- **本地批次文件。** 报告 JSONL，或每行一个 GHSA URL 的列表配上公告缓存和仓库映射。

模型阶段逐份处理，整个批次共用你在确认时填写的一次请求上限。

| 主要输出 | 内容 |
| --- | --- |
| `entries.jsonl` | 字段齐全、通过结构与出处检查的机器候选。`verify=0`，不是人工确认也不是标准答案 |
| `drafts.jsonl` | 依据不足、字段待补充或未能完整成稿的记录，缺失标量写 `""`、缺失数组写 `[]` |
| `review.jsonl` | 每个字段的状态、依据、建议值和疑点，人复核看这份 |

另有按公告聚合的 `reports.jsonl`、字段冲突旁车、过程记录 `actions.jsonl` 和用量统计 `summary.json`，都能从工作台“更多文件”导出。字段定义在 [SCHEMA.md](SCHEMA.md)。

准备资料、检查输入、查看已保存的结果都不调用模型。只有在工作台里输入自己的 key、设定本批次请求上限并明确同意之后，才会开始付费提取。

## 五分钟上手（免安装）

1. 从 [Releases 页下载 ZIP](https://github.com/Qiyuanqiii/VulnGym-T2/releases/latest)，**完整解压**到一个可写目录，不要在压缩软件里直接运行。包内自带 CPython 3.13.12 便携运行时，不需要另装 Python、Git 或 Node。
2. 只想看成品：双击 `start-demo.cmd`，只读回放三个已保存的开发案例，不需要 key，也不会创建或重置请求账本。
3. 想自己提取：双击 `start.cmd`，浏览器自动打开本机工作台。点“添加资料并提取”，贴链接，点“获取资料并检查”，再输入 key、设置本批上限并确认。
4. 在结果页核对源码位置和依据，导出 `entries.jsonl`、草稿和复核报告。重要字段请人工复核。

`start-extraction.cmd` 与 `start.cmd` 打开的是同一个完整工作台。`start-direct.cmd` 在本机具备直连条件时显式选择直连获取公开资料；遇到拒绝访问或限流，程序只记录原始错误，不换出口、不换来源、不重复请求。历史结果回放不能发起模型请求。

包内的 `demo/T2-demo.mp4`（约 1 分 21 秒，1920×1200）演示了本地资料输入、确认提取、查看依据和导出，配套的输入材料在 `演示数据/NLTK`。

## 从源码运行

GitHub 仓库保存的是源码，不含交付 ZIP 里的便携 Python 运行时和演示视频。准备 Python 3.13 和已加入 `PATH` 的 Git：

```powershell
python launch_workbench.py          # 打开本地网页工作台
python -m vulngym_t2 --help         # 命令行参数
python launch_workbench.py --check --no-browser   # 只做起启动检查，不下载资料、不调用模型
```

零第三方依赖，不需要 pip install。`python -m vulngym_t2` 是 CLI 入口，用法见[工程说明](ENGINEERING_README.md)的命令行一节。

在 Windows 上克隆源码建议保留 LF：`git -c core.autocrlf=false clone …`。开启 `core.autocrlf=true` 时，`web_assets` 下的静态资源会被转成 CRLF，导致 `tests/test_t2_v2_package_runtime.py` 的逐字节资源比对失败（1287 项中会多 1 项 failure），功能本身不受影响。

## 工作原理

模型不参与它不该参与的事，程序不参与它做不到的事。

**职责划分。** 15 个字段里，8 个由模型判断，7 个由程序维护：

| 谁负责 | 字段 |
|---|---|
| 模型判断 | `commit`、`vuln_title`、`vuln_category_l1`、`vuln_category_l2`、`entry_point`、`critical_operation`、`trace`、`vuln_ids` |
| 程序维护 | `entry_id`、`report_id`、`source_link`、`origin`、`project`、`repo_url`、`verify` |

**读取阶段。** 模型只能请求七种有界只读工具，参数逐个校验，输出按上界裁剪（`repository.py:123`）：

| 工具 | 用途 | 上界 |
|---|---|---|
| `inspect_commit` | 解析版本、读提交信息与父提交 | 变更路径 ≤200，说明截到 8000 字符 |
| `list_refs` | 列出本地已有版本 | ≤100 个引用 |
| `search_history` | 在提交说明里搜字面量 | ≤50 命中 |
| `list_files` | 列某个 commit 下的文件 | 每页 ≤200，树读取 ≤4 MiB |
| `read_file` | 按行读源码 | ≤300 行且 ≤24 000 字符，blob ≤1 MiB |
| `search_code` | 在源码里搜字面量 | ≤100 命中 |
| `read_diff` | 读两个版本间的差异 | 输入 2 MiB，输出约 96 000 字节 |

每次 git 子调用 10 秒超时，参数按 argv 传递，不经过 shell。一次读取计划最多 4 个调用；`finish_reading` 独占一步，表示“读够了，可以成稿”。

**成稿与自查。** 模型先用一次公开简短判读写清思路，再用一次原生函数提交八个字段的 decision，每项带取值、状态、理由和引用的证据 ID。程序接着做本地预检：schema、类型、来源一致性、SHA 合法性、位置逐字匹配。行号只有在原读取窗口内且片段唯一匹配时才自动纠正，并留下 `location_corrections`。真实错误反馈给同一模型做一轮自查，允许它降级字段状态，这一轮禁止再读工具。全部机械检查通过才进 `entries.jsonl`。

commit 还必须交代 `revision_basis`：`behavior_at_revision`（该版本源码的机制依据）、`affected_range_and_source`（影响范围与源码关联）、`inspected_only`（只是检查过）或 `unknown`。后两类以及不声明的保留为 uncertain，候选 SHA 放进建议值。这一项是逼着模型说明“凭什么认定这个 commit 是漏洞版本”，而不是抄一个哈希。

**出错时不猜补。** 坏 JSON、重复键、未知工具、非法控制参数整份拒收；网络、鉴权、权限拒绝、模型名不符、截断一律停下该批次，HTTP 自动重试次数为 0。填表形状错误允许在同一份判读基础上重编码一次，仍消耗原预算。已确认的正文格式错误默认只把当前输入留成草稿，同一授权内未开始的输入继续处理。

## 读结果时的口径

`review.status` 三种取值分开统计：`complete` 是进入正式条目的候选，`draft` 是必需内容未全部建立，`input_failure` 是材料或仓库准备失败。

批次状态 `completed` 只表示走完了，可能一条完整候选都没有；含已隔离的格式失败时为 `completed_with_errors`（退出码 2）；故障导致中断时为 `provider_stopped`，剩余输入计入未处理。强制终止时当前输入或汇总可能还没落盘，不存在的 `summary.json` 不算一次已完成的运行。

多候选模式下 summary 带 `counting_version="input-review-v2"`：一份输入产生两条完整候选仍只算一份输入。工作台还能展开“候选提案覆盖”，查看每份资料提出、选中、未选的提案数；提案不是已确认漏洞，未选提案也不等于未处理的输入。

## 预算、密钥与用量

模型只连 `api.deepseek.com`；获取公开资料的下载只连 GitHub 与 OSV 的公开接口，两条路径互不相干，下载阶段不会产生模型请求。

工作台把累计用量记在本机用户配置里（Windows 下是 `%LOCALAPPDATA%\VulnGymT2`），换解压目录或换 key 都不会清零，程序自己延续原有累计并检查上限；不要通过删除或修改这个配置来重置用量。命令行用 `--request-ledger` 指向同一个账本文件，同一授权的所有运行必须复用它，不能并发占用。失败尝试同样计数，软件接受的 3000 上限不是自动获准的额度，`--max-requests` 是天花板不是配额。

key 只在确认批次的那一刻经 stdin 传给子进程，不入库、不写日志、不进输出文件。CLI 侧可以用已配置的 `DEEPSEEK_API_KEY`、交互式隐式输入，或 `--key-stdin` 接收受控管道的一行密钥。网页里的请求次数上限不是金额硬限额，请同时在模型服务平台设置费用上限。

## 结果边界

工具能证明的是：字段齐了、schema 合法、位置在同 commit 的真实源码上逐字成立。工具不能证明的是：这个 commit 确实是受影响版本、这个入口真的可达、这段操作真的是漏洞关键所在、这条调用链确实是攻击路径。

修复的父提交、tag、HEAD、提交说明里的关键字都只是待检线索，命中不等于受影响版本已确认，历史搜索无命中也不等于不存在。`supported` 表示有引用依据并通过了适用的确定性检查，仍是机器判断。一次同模型自查只是自查，不是独立评审。长材料截断、多入口、跨文件逻辑和历史缺失是这类任务的固有困难。

包里三个结果批次来自已见开发案例，不是盲测，也不能当总体准确率；独立新样本为 0。本次交付不包含 T1 自动反馈迭代。

## 当前状态

代码标为 `snapshot-guidance-v85`（v85 修正了网页运行配置与入口判据）。离线状态：全量测试 1287 项通过、1 项因环境跳过，冒烟 11 项通过。真实模型侧，v84 的四批回归（三个输入加一次 NLTK 重复复测）共 50/52 次 HTTP 已逐批 QA，v85 尚未取得真实复测成绩，保存的 v84 及更早结果未改写。请求账本累计 2709/3000，余 291，本轮保留剩余不追加付费。

逐批耗时、工具调用次数、拒收恢复次数和内容缺口以 [代表性验证记录](docs/t2_representative_validation_20260913.md) 为准；历史额度与配置数字散落在 `ENGINEERING_README.md` 与按日期命名的文档里，保留当时的口径，不重算也不当作当前成绩。

## 仓库导览

```
launch_workbench.py     网页工作台启动入口（--check 自检、--read-only 回放、--live 提取）
start*.cmd              Windows 双击入口：完整工作台 / 只读回放 / 直连下载
configure_launch.py     保留的高级兼容工具，日常不需要
vulngym_t2/             产品源码，37 个 Python 文件、约 1.9 万行，只用标准库
  acquisition.py        公开公告获取与目标仓库裸克隆（唯一联网下载入口）
  pipeline.py           读取、成稿、自查、补读主循环
  repository.py         七种只读工具与位置上界
  output.py             终检、聚合、批次落盘
  llm.py transport.py   请求账本与 DeepSeek 传输
  web.py web_runtime.py web_portable.py  回环工作台、子进程批次与本机用量
  _vendor/              只读 git 对象读取、argv-only 子进程、官方 entry 校验
vulngym_t2/web_assets/  工作台 HTML/CSS/JS、品牌图标与字体
examples/               run-01..03 是 v12 交付内的三个公开结果，run-04..09 为历史开发批次
docs/                   按日期命名的设计、验证与过程记录
tests/                  131 个测试文件，全部标准库 unittest
```

## 测试

测试不联网、不需要 key，用桩仓库和桩连接：

```powershell
python -B -m unittest discover -s tests -p 'test*.py' -q   # 1287 项，约 25 秒
python scripts/smoke_t2_v2.py                              # 11 项冒烟
```

Web 界面的交互另有一份 Node 测试：`node --test tests/web_ui_interactions.cjs`（需要 Node，主流程不需要）。

## 文档

- [解压启动说明](README_START.md)：ZIP 用户手册，联网方式、演示顺序、包内清单
- [工程说明](ENGINEERING_README.md)：CLI 全部参数、各响应模式、按日期的复测与勘误
- [字段定义](SCHEMA.md)：15 个字段与类型口径
- [标注契约](docs/t2_annotation_contract.md)：字段规则 R1–R8 与阶段划分
- [代表性验证](docs/t2_representative_validation_20260913.md)：最新批次的真实数字与缺口，以此为准
- [目标与验收边界](docs/t2_goals.md)：什么算做完，什么明确不要求
- [URL 批次说明](docs/t2_url_batch_20260914.md)：链接输入链路的实现与限制
- [本地工作台](docs/t2_web_gui.md)、[五分钟演示](docs/t2_v2_demo.md)、[打包说明](docs/t2_v2_packaging.md)

## 许可与第三方资源

VulnGym 上游以 CC-BY-4.0 发布，全文见 [LICENSE](LICENSE)。本仓库沿用该许可，是其 T2 环节的独立重做实现，不含旧工程的提交历史、Issue、目标仓库、密钥或原请求账本。

- 品牌图标 `vulngym.png` 未修改地取自上游 README，含署名与校验值，不构成商标授权。
- 界面字体 JetBrains Mono 以 OFL 许可随包提供，见 `vulngym_t2/web_assets/fonts/`。
- 静态资源和字体全部本地服务，不使用远程图片服务或任何跟踪请求。
