# T2 v2：从公告与本地仓库生成可复核记录

联网方式可在启动时明确选择：`start.cmd` 保留系统默认，`start-direct.cmd` 让公开公告与源码下载直连。工作台显示本次选择，不修改系统代理，也不自动切换出口；模型连接和预算规则不变。详见 [启动说明](README_START.md)。

交付入口更新：Web 默认支持一次粘贴多条 GitHub GHSA / OSV 链接，自动获取公开公告和 Git 仓库，再按一个批次确认模型用量；原本地资料模式仍然可用。OSV 保留原始来源；当前正式输出要求唯一真实 GHSA 且已审核，不能满足时明确报告。OSV 是用户选择的来源，不是 GitHub 403 后的自动替代重试。联网获取限制、测试范围和操作说明见 [URL 批次说明](docs/t2_url_batch_20260914.md) 与 [解压启动说明](README_START.md)。下方既有模型运行记录保留原日期与配置，不作为本次资料获取功能的准确率证明。

当前代码为 `snapshot-guidance-v85`，提供 CLI 与本地 Web。v85 修正网页运行配置与文档佐证的入口判据；相关离线回归已通过，尚未取得 v85 真实模型复测成绩。保存的 v84 及更早结果未改写，不能当作新版成绩。完整候选不等于人工认可；版本、验证及剩余缺口统一见[代表性验证](docs/t2_representative_validation_20260913.md)。

本机 Web 已实际核验保存结果切换、免费输入检查、编辑后预检失效、依据跳转、键盘返回及窄屏布局；同公告多条结果已有区分标识。该轮未调用模型，导出到浏览器的反馈不等于已确认文件落盘，详细范围见[工作台记录](docs/t2_web_gui.md)。

CLI 新增默认关闭的 [`--review-read-cycles 0..2`](docs/t2_review_gap_loop.md)：仅 staged_tool 可启用，在原预算内根据自审的必要缺口定向补读，有新增成功回执才再次完整自审。控制器策略为 `review-gap-loop-v1`，沿用 v84 系统/schema；尚无该功能的真实效果证明，不把下面已保存的 v84 成绩追记为新循环成果。

CLI 与本地 Web、批量/多候选、15 字段及独立草稿导出已具备，不含独立 T1 自动反馈。当前交付可运行产品与明确缺口，**尚未完全完成内容质量收尾**；原题百分比不是硬门槛，完整状态和同模型自审不等于人工认可。唯一最新明细见[代表性验证](docs/t2_representative_validation_20260913.md)。

| 本轮已结束批次 | HTTP / 工具 | 完整 / 草稿 | 秒 | 内容与技术限制 |
| --- | --- | --- | --- | --- |
| [11-nltk-v83-low](docs/t2_representative_nltk_v83_review_20260914.md) | 13 / 13 | 2 / 0 | 110.934 | 无编码拒收、两个自审完成；对象关联与默认消费的证据表述仍待核，不是 2 条人工认可 |
| [12-sql-v83-low](docs/t2_representative_sql_v83_review_20260914.md) | 16 / 11 | 0 / 3 | 363.853 | 共享预留恢复一次初稿编码失败，三个自审完成；未证实的 MySQL 提案保留未知；无 probe，Postgres 规划读取只到 68 行 |
| [13-airflow-v83-low](docs/t2_representative_airflow_v83_review_20260914.md) | 11 / 23 | 0 / 1 | 51.238 | 仍有必要读取缺口；新 40 行续读分支未触发，不能算已真实生效 |
| [14-nltk-v84-low](docs/t2_representative_nltk_v84_review_20260914.md) | 10 / 12 | 1 / 0 | 60.716 | 一次初稿编码失败由共享预留恢复；CO 移至实际 finditer 调用；EP/CO 有多源依据，非空 trace 仍须限定证据来源与消费条件 |

四批均退出 0，共 **50/52 HTTP**。这是三个输入及一次 NLTK 重复复测，NLTK 两次的上限和提案数不同，不能用“2 完整变 1 完整”或合计条数计算质量变化。跨组件本轮未重测，最新仍是 [10-chain-v81-low](docs/t2_representative_chain_v81_review_20260914.md)，不计入本轮。当前累计 **2709/3000，余 291**；原账本须传 `--authorization-limit 3000 --effective-request-limit 2999`，Web 另加 `--historical-requests 1`。2999 是累计生成上限，不是单批额度。

v83 的共享编码纠正预留已在 SQL 和 v84 NLTK 各真实恢复一次；NLTK v83 没有拒收，不冒称验证了纠正。候选覆盖如实保留提出、选中及未选数，预留可能减少处理槽位，未用不补花。v84 补充了有限的必要关系声明检查，但本次没有该 guard 的真实拦截记录；不能仅凭词形或未独立读取每个运行对象就判错。公告、docstring、patch 和源码共同支持的 EP/CO 可保留为待人工确认候选，非空 trace 须明确材料前提和生成器消费条件，不概括为全部连接均已源码独立证明。没有提高总 HTTP、工具或 100000 上下文上限。

本轮已结束，剩余 2 次不补花。后续优先处理 QA 中已确认的表述与读取缺口，不重启原运行、不追求凑高完整数；本次不生成 ZIP、不提交或推送。

四批 entries/drafts/summary 已复制到 [本轮结果目录](output/real-results-20260914/README.md)，共 **12 文件、29549 字节**；这是摘录，不是可直接传给 GUI/review_export 的完整 run，完整 review/actions 仍在原 D 盘运行目录，四份 QA 见上表。7 条数据投影均为 15 字段、verify=0，3 条完整候选的 formal_t2 校验无问题；仅证明格式，不代表全部语义正确。原 JSONL 不变。包装清单为 **58 份文档、43 个运行文件**（30 个产品 Python、5 个 vendored Python、8 个本地 Web 资产），所列文档均存在；这不代表已制作新 ZIP。当前三页设计稿为 [T2-design-v84.pdf](output/pdf/T2-design-v84.pdf)，已检查全部文本和三页 PNG；该 PDF 未重生成，描述新增循环前的版本，新可选循环以[补充说明](docs/t2_review_gap_loop.md)为准。旧 PDF、运行与测试保留为历史。

## 从这里开始

- 使用者：打开 [工作台启动与操作](docs/t2_web_gui.md)，点击“添加资料并提取”，先免费检查输入，再确认请求上限并开始。
- 看数据：`entries.jsonl` 是完整候选，`drafts.jsonl` 是空值待补充条目，`review.jsonl` 解释字段依据及问题；均不是人工确认的数据。
- 看验收：[本轮收尾与结果](docs/t2_closeout_20260913.md)、[字段定义](SCHEMA.md)、[五分钟演示](docs/t2_v2_demo.md)。CLI 与 GUI 共用处理逻辑；GUI 固定使用已实测的 `deepseek-flash` 分阶段配置。
- 历史兼容 CLI 的默认参数不是本轮实测配置。复用本轮 CLI low 配置时须显式指定 `--model deepseek-flash --response-mode staged_tool --thinking enabled --annotation-format assessed_tool --read-format plan_tool --reasoning-effort low --max-tokens 32768 --max-tool-calls 64`，并设置已批准的有效请求额度；它不等于 GUI 固定 high 配置的实测。

<details>
<summary>历史开发与复测记录（不代表当前成绩）</summary>

### v79 回归历史

v79 冻结 low 配置的四批真实回归均已退出 0，实耗 **52 HTTP（11 + 15 + 11 + 15）**；四份可读报告离线导出均退出 0、新增 0 HTTP。

| v79 批次 | 完整 / 草稿 | HTTP / 工具 | 时长（秒） | 技术状态 |
| --- | --- | --- | --- | --- |
| Airflow `regression-airflow-v79-10` | 0 / 1 | 11 / 21 | 117.910 | 终态错误 0；1 次读取计划拒收恢复 |
| NLTK `02-nltk-v79-low` | 2 / 1 | 15 / 12 | 115.590 | 1 次编码缺根字段拒收；model/pipeline 各 2 为同槽失败及后果的重复记录 |
| 跨组件 `03-chain-v79-low` | 0 / 1 | 11 / 23 | 80.299 | 终态错误及读取/编码拒收 0，最终自审完成 |
| SQL `01-sql-v79-low` | 0 / 3 | 15 / 13 | 269.516 | 终态错误及读取/编码拒收 0 |

[Airflow QA](docs/t2_representative_airflow_v79_review_20260913.md) 确认相关旧版、metrics 后半和最终 logger 仍缺，第三次补读受上下文预留限制而非请求用尽。[NLTK QA](docs/t2_representative_nltk_v79_review_20260913.md) 确认两个完整候选的 CO 已改到实际匹配点，但生成器/类型等条件仍有限制；另一个 word_tokenize 草稿来自编码失败，不是主动弃答。跨组件及 SQL 内容 QA 尚在进行，不将完整数、位置匹配或不同版本/范围合并为准确率。

v79 四批结束时累计 2580/2600、余 20；其工程验证为 1028 项（1027 通过、1 环境跳过）和冒烟 11/11。以上是 v79 当时状态，后续 v80 与当前修正见页首。

### v78 回归历史（v79 前的独立记录）

v78 Airflow `regression-airflow-v78-09` 退出 0：11 HTTP、17 工具、216.626 秒，0 完整、1 草稿，终态技术/格式/字段错误为 0，含 1 次读取计划拒收恢复。四个源码窗口中，自动导入导航读到 `action_cli` 及 `_build_metrics` 开头；最终 logger、旧版本和完整值构造仍缺，独立 `--conn-password` 遮蔽不能扩为全部敏感参数安全。该版工程验证为 1022 项（1021 通过、1 环境跳过），冒烟 11/11。

v78 SQL 高档因输出上限截断退出 2（6 HTTP、12 工具）；同代码低档 `01-sql-v78-low` 也退出 2（6 HTTP、13 工具、127.969 秒），原因为 call 6 自审评估读取响应正文时的 `deepseek_transport_error`，不是鉴权/格式拒绝或低档质量结论。两档均保存 0 完整、3 草稿，未运行槽不算独立语义失败，原结果分别保留；两份报告离线导出未增加 HTTP。

v78 NLTK `02-nltk-v78-low` 退出 0：16 HTTP、12 工具、182.575 秒，3 完整、0 草稿，终态技术/格式/字段错误及读取计划/编码拒收全为 0。[该版内容复核](docs/t2_representative_nltk_v78_review_20260913.md)：22/22 位置字面匹配，但三个 CO 都是静态定义，生成器/缓存条件与未读类型前提仍有限制；不是独立准确率或语义全部通过。

v78 low 跨组件 `03-chain-v78-low`（会话 75241）provider_stopped／退出 2：9 HTTP、21 工具、0 完整、1 草稿。[专项 QA](docs/t2_representative_chain_v78_review_20260913.md) 确认第三次补读的一次传输失败及后续停止说明在 model/pipeline 字段重复计数，不是四次独立故障或语义失败。该时点累计 2527 次生成 + 1 次历史查询 = 2528/2600、余 72，当时停止付费，随后先完成 v79 离线修正才开始新版回归。

> **本地 Web GUI 已实现（2026-09-12）：** Python 标准库服务 + 原生 HTML/CSS/JavaScript，复用现有 CLI；不需要 Node 构建或新增前端依赖。支持粘贴/上传资料、免费检查输入、受额度限制的单批运行、当前条目完成后停止、证据复核和六文件导出。仅监听 `127.0.0.1`，不存储 key、不记录轮询日志。启动与完整验证记录见 [本地工作台](docs/t2_web_gui.md)。当前提供 CLI + Web GUI，没有 TUI。

> **历史 v68 修正版真实复测：** MLflow/NLTK/ONNX 三份材料不再传 `repo_url` 或仓库映射，主公告身份和修复线索仍正确恢复。通过 GUI 后端启动原 CLI，25 次请求、3 完整候选、0 草稿、0 终态技术错误；填表位置形状拒收后重编码恢复 1 次，已包含在 25 次请求内；16 处源码引用一致。MLflow 原“只拒绝空字符串”已改为准确的 falsiness 描述。当时累计 **2192/2300，剩余 108**，不是当前额度。这些仍是已见开发材料与 `verify=0` 候选，不是盲测、总体准确率或导师验收。旧 v67 发现与原输出保留在[跨项目实验](docs/t2_cross_project_20260912.md)，该次编码计数勘误见[收尾内容复核](docs/t2_closeout_content_review_20260913.md)。

该历史阶段离线检查：837 项（836 通过、1 环境跳过），冒烟 11/11；该轮模型调用已结束。界面分栏、即时状态反馈、键盘焦点和 reduced-motion 支持以清晰复核为目标，不增加动画或构建依赖。

> **此前四例回归（v67）：** 同四例真实复测退出 0，4 完整候选、0 草稿、0 终态技术错误，17 处源码引用一致；当时全仓 815 项（814 通过、1 环境跳过）和 11 项冒烟通过。原始结果及限制见 [四例记录](docs/t2_real_retest_20260912.md)，不与上面的 v68 成绩拼接。

> 判读和填表分开，正式十五字段及 `verify=0` 不变。限定的填表编码错误整份拒收后，至多按同一判读重编码一次；显式 `plan_tool` 对单个已知函数的有界 JSON 语法或根容器形状错误，共享每输入最多一次读取计划重编码。错误原文不修补、不复用，错误操作不执行；校正仍占原预算并保留必要自查。未知操作、权限拒绝、传输及信封错误继续停止，HTTP 自动重试为 0。所有纠正另计，不能把已纠正错误说成模型从未出错。完整候选不是人工批准；不同配置不拼接成绩，独立新样本 0。

主公告身份检查、报告冲突旁车及复核表继续有效，不重写历史结果。多候选独立性、完整自动恢复及语义正确性仍未证明。[离线修复验收](docs/t2_robustness_20260911.md)与真实效果分别报告；历史对照见[导师差距](docs/t2_mentor_gap_20260911.md)及[实跑记录](docs/t2_v41_results.md)，不能用历史最好结果或离线测试替代当前成绩。

本产品独立维护于仓库 [Qiyuanqiii/VulnGym-T2](https://github.com/Qiyuanqiii/VulnGym-T2)。首次导入仅包含重做版交付文件，不包含旧工程的 Git 历史、Issue、目标仓库、密钥或请求账本；旧工程保持不动。

当前目标与勘误解释见 [目标、验收边界和推进顺序](docs/t2_goals.md)。以 T2 提取质量和可用性为主，不把 T1、GUI、固定 70 题或评分示例当作前置门槛。

这是独立重建入口 `python -m vulngym_t2`，不经过旧 sealed/orchestrator 流程。输入公告材料和已经准备好的本地 Git 仓库，由模型读取历史与源码、提出字段。当前 staged 单条采用一份初稿和一次自查；显式多条按预算选择候选后逐条执行同一流程，不扩大输入总预算。不要求用户提供 `source_paths`、候选代码编号或内部任务 ID。

早期 Flash 阶段（run-04～07）：显式 `--model deepseek-flash`（2026-09-10 官方 V4.1 Flash），完整材料四份得到 Langflow、Flowise 两条完整候选，Open WebUI、OpenClaw 两份无效 JSON 失败草稿；减线索两份中 Flowise 完整，Langflow 因传输失败保留不确定草稿。两套实验重叠使用既有四个案例，独立新样本为 0。这些是历史配置结果，不是本轮成绩。**核心仍未达到广泛效果验收；不是盲测、总体准确率或导师验收通过的声明。** 逐批记录见 [V4.1 实跑记录](docs/t2_v41_results.md)，更早结果见 [v2 结果与自评](docs/t2_v2_results.md)；旧 3/3 不代表最新结果。

随后经用户再次确认，用同一授权完成严格协议定向复测：Open WebUI 技术失败；仅接上未开始的三项后，OpenClaw 为机器完整候选，减线索 Flowise 为证据不足草稿，减线索 Langflow 为函数参数 JSON 失败草稿。OpenClaw 仍有入口位置及版本依据措辞需要复核，不能当作已验收正确；新结果见 `examples/run-08`、`run-09`，旧失败不覆盖。这轮没有独立新样本。

以下是历史 snapshot-v1 复测：合计 **42 HTTP、729,647 个已报告 tokens**；当时原授权累计 **188 次生成请求 + 1 次目录查询 = 189/500 次**，剩余 **311 次**。零重试、不重置授权，旧结果保留。修复后的最新 v2 实测另见页首链接；历史仍有 1 次请求用量未知，货币费用未测，密钥不在交付材料中。

| 原始结果 | 原有输入 | HTTP | 完整 / 草稿 | 退出码与限制 |
|---|---|---:|---|---|
| [run-23](examples/run-23) | Open WebUI | 7 | 0 / 1 | 0；草稿不是完整候选 |
| [run-24](examples/run-24) | OpenClaw | 12 | 1 / 2 | 0；完整候选仍待复核 |
| [run-25](examples/run-25) | Flowise | 11 | 0 / 1 | 2；初稿缺 `entry_point`，技术失败草稿 |
| [run-26](examples/run-26) | Langflow | 12 | 0 / 2 | 2；第二候选自查缺 `vuln_title` |

该历史批次中 3 份输入获得初稿并至少完成一次自查，不等于每个候选均已完成。旧 `summary.format_failure_count=0` 不能解释为零协议错误：上述 2 份输入的失败与安全诊断均原样保留。多候选是否语义独立仍未证明，1 条机器完整候选不能当作已人工认可。

此前 run-20～22 使用旧单 v5 / 多 v4：4 个原有输入、0 完整、9 草稿、29 HTTP、402,571 tokens；当时累计 147/500、剩余 353，均为历史阶段数字。

此前 run-14～19 阶段为 26 HTTP、254,007 tokens、6 次已处理输入尝试（4 个旧案例），0 完整、6 草稿；当时累计 118/500、剩余 382，均为历史阶段数字，不是本轮余额。

分阶段模式 `staged_tool` 将读取函数与八字段成稿分开，七个固定字段由程序维护，所有阶段共用 [标注契约](docs/t2_annotation_contract.md)（语义v2，run-12为v1）。run-12 有历史完整候选；run-15 是此前补读/自查完成但必需字段未建立的草稿。本轮部分候选仍未建立必需字段；Flowise、Langflow 的技术失败不应解释为主动保守弃答。借鉴 Open Code Review 的阶段工具与确定性校验分工，不引入其模型调用、JSON 修补或额外预算。正式 entries/reports 保持原字段，历史结果不重算；独立新样本仍为 0。

</details>

## 不用 key，先看真实结果

在项目根目录运行以下命令，将已有真实结果整理成便于评审阅读的 Markdown。输出必须是尚不存在的新文件，且不能放进原运行目录；不会读取目标仓库、联网或修改原 JSONL。

```powershell
python -m vulngym_t2.review_export --run-dir examples/run-04 --output review-v41-mixed.md
python -m vulngym_t2.review_export --run-dir examples/run-05 --output review-v41-failure.md
```

打开生成的文件即可看批次统计、逐条字段、模型判断、引用目录和空白人工复核栏。`complete` 仍是自动完整候选，`verify=0` 不变；导出不是新的模型运行或人工批准。来源内容作文本显示，不是要执行的命令。[旧案例勘误](docs/t2_case_notes.md)记录了旧运行中的修复/父提交角色文字错误及描述超出所引证据的情况；新一轮是否改进见 [V4.1 实跑记录](docs/t2_v41_results.md)，不能只展示成功数量。

需要结构化记录人工意见时，可在仓库根目录运行（输出文件必须不存在）：

```powershell
python -m vulngym_t2.report --run-dir examples/run-12 --review-template review-run-12.json
# 人工填写 JSON 的 overall/checks 后，再汇总；不要修改 source_snapshot。
python -m vulngym_t2.report --run-dir examples/run-12 --human-review review-run-12.json --output human-summary-run-12.md
```

支持、合理替代、反证、不确定、未评分开记录，非未评意见须有审核者和理由。表格与实际候选完整内容绑定，不因相同ID而复用旧结果的意见。工具不验证审核者身份、引用内容或判断真伪，不自动升级verify，也不把空表计为已审核。

人工复核工具不是逐条签字的交验硬门槛。可选择少量代表性输出做语义抽查，其余附可交接的待审说明；没人评的明确标未评，不升级verify。导师强调宁缺勿错，不要求所有输出自动complete或全部条目经签字才可展示。

## 运行前

当前修复及真实复测使用 Windows / Python 3.13.12（`python -VV` 输出；`D:\python314` 只是安装目录名，不是版本号）；未单独验证最低可用版本。还需已加入 `PATH` 的 Git。独立运行路径只使用 Python 标准库，**不需要 pip 安装第三方包，也不需要旧 `vulngym_agent` 包**。保留完整 `vulngym_t2/` 目录（包括 `_vendor/` 和 `transport.py`），在其上一级、本项目根目录运行命令；不要只拷贝 `cli.py`。

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

下面单条/批量示例使用 `assessed_tool` 两步配置，保留 low / 16K 的示例参数；不是本轮 Web 使用的 high / 32K / plan_tool 固定配置，CLI 兼容默认值没有更改。最新配置与实测结论见文首收尾链接，不应把可运行示例当作广泛效果验收。复用本次现有账本时，每条正式命令都须追加 `--authorization-limit 3000 --effective-request-limit 2999` 并将 `--request-ledger` 换成原账本的实际路径；省略授权参数会使用兼容默认值 500，与本任务原账本不匹配。不要照抄占位路径另建账本。其他用户须使用自己的有效授权，付费运行均需足额许可。

## 单份公告 + 本地仓库

先做完全离线的输入检查，不需要密钥，也不会请求模型：

```powershell
python -m vulngym_t2 --advisory D:\T2\materials\advisory.md --repo D:\T2\repos\project --source-link https://github.com/advisories/GHSA-2222-3333-4444 --model deepseek-flash --response-mode staged_tool --thinking enabled --annotation-format assessed_tool --reasoning-effort low --max-tokens 16384 --max-calls-per-report 12 --max-tool-calls 32 --stop-on-format-error --prepare-only
```

公告正文已有真实 GHSA 标识时可省略 `--source-link`。正式 schema 要求 GHSA 来源；只有 CVE 或无 GHSA 的本地文字可以保留部分分析，但不能用示例 GHSA 补成正式来源。`--advisory` 也可接受平铺材料目录，读取至多 8 份 `.txt/.md/.json/.html/.patch/.diff` 文件，不递归搜集材料。每份文件最多 256 KiB，较长正文还有显式截断；把原始 GitHub 公告 JSON 当作单份材料时也用 `--advisory`，不是多行 JSONL。

`--prepare-only` 不需要 `--output`，不会生成运行输出或自评。它返回 `http_attempts: 0`、逐输入检查及 `configuration`，后者显示实际选择的模型、格式、推理和上限；不会读取 key、打开账本或连接供应商，`authorization_checked/provider_checked` 均为 false。全部输入准备正常时退出码为 0，含输入错误时为 1，非法选项组合或过小输出上限为 2。准备通过不等于额度够用、服务可用、历史齐全、schema 完整或内容正确。

确认材料与授权后运行：

```powershell
python -m vulngym_t2 --advisory D:\T2\materials\advisory.md --repo D:\T2\repos\project --source-link https://github.com/advisories/GHSA-2222-3333-4444 --output D:\T2\runs\single-001 --request-ledger D:\T2\budget\temporary-authorization.jsonl --model deepseek-flash --response-mode staged_tool --thinking enabled --annotation-format assessed_tool --reasoning-effort low --max-tokens 16384 --max-calls-per-report 12 --max-tool-calls 32 --stop-on-format-error --max-requests 24
```

### 选择模型

`--model` 接收准确的 DeepSeek API 标识。2026-09-10 [官方更新说明](https://api-docs.deepseek.com/updates/#date-2026-09-10)将 V4.1 Flash 对应为 `deepseek-flash`；本次账号的 `/models` 也返回该标识。不要猜写 `v4.1flash` 或把名称相近的模型当成已授权模型。

为兼容旧脚本，省略参数时仍使用旧默认 `deepseek-v4-pro`；本次 V4.1 运行必须显式传 `--model deepseek-flash`。请求、响应名称校验、用量摘要与账本头绑定同一模型，不静默降级或改别名。供应商可能更新服务端别名所指版本，运行报告应同时记录日期、API 标识和当时官方版本说明，不靠客户端字符串声称永远锁定权重。

同一授权继续运行时复用同一账本。不同模型与旧账本不匹配会在请求前失败；不要通过另建账本重置已消费次数。若本轮还进行了模型目录查询，应从总授权中扣除其次数，例如总 500 次且目录查询已用 1 次，模型账本上限设为 499。`--max-requests` 仍只是单批额外上限，不是必须用完的配额。

### 当前开发接口：完整 snapshot

以下是显式选择开发模式的命令示例，不代表已获新的付费运行授权：

```powershell
python -m vulngym_t2 --advisory D:\T2\materials\advisory.md --repo D:\T2\repos\project --source-link https://github.com/advisories/GHSA-2222-3333-4444 --output D:\T2\runs\staged-001 --request-ledger D:\T2\budget\temporary-authorization.jsonl --model deepseek-flash --response-mode staged_tool --thinking enabled --annotation-format assessed_tool --reasoning-effort low --max-tokens 16384 --max-calls-per-report 12 --max-tool-calls 32 --stop-on-format-error --max-requests 12
```

需要有效的明确授权，并继续使用原账本。`staged_tool` 读取阶段允许 1～4 个合法读调用，整批校验后按剩余工具预算执行；finish_reading 独占，补读、候选提议和成稿各收一个函数容器。上述显式配置的单条 wire 为 `assessed-snapshot-v1`：初稿和自查各先用一次公开简短判读，再用一次 required 原生函数提交八个 decision，包含 value/status/reason/evidence_refs，只有 commit 另含 revision_basis。位置用单个 source_id 与实际范围，理由仍用 evidence_refs 数组；旧模式保留 snapshot-v2 的位置键。漏项局部标错，程序不为缺失位置补造出处。详见 [标注约束说明](docs/t2_annotation_contract.md)。

API schema 的直接对象解决单字段多 decision 的形状歧义，不保证所有本地语义或资源约束。typed unknown、supported 与值的关系、引用/文本上限、同版本实际源码证据仍由本地检查，缺陷与入口关系仍需语义判断。坏字段作为 `annotation_errors` 保留，不能沿用旧 supported；原预算内一次完整自查可更正，合法 uncertain 仍不是语义确认。坏 JSON、重复键、外层、未知工具与非法控制参数不猜补或回退；范围内的已知读取参数错误/finish 混用可返回零执行反馈，由下一原预算内规划步纠正，非自动 HTTP 重试。当前 snapshot 候选须自查 completed 且通过终检才可完整导出。

`review.initial_draft_status` 只描述初稿格式接收，不表示事实已确认。历史 run-20～22 的旧 v5/v4 仍有 `decision_limit` 或全局协议失败；这些记录原样保留，不套用新 snapshot 的解释。控制器的所选 commit/read_file 回执 SHA 对照也只反映一致性，不自动选 parent 或证明缺陷。旧 run-23～26 曾有 2/4 输入协议失败；最新开发复测见页首，不能用旧数字指代当前状态，也不能把两个旧案例的成功视为广泛可靠性达标。

### 一份公告的多个独立入口

需要一份输入提出多条候选时，在上述 staged 命令末尾显式加入 `--multi-entry`；要求 `--response-mode staged_tool`，省略该参数为单条 snapshot。历史多条成绩使用 disabled + native_tool，不能借给其他配置。

```powershell
python -m vulngym_t2 --input D:\T2\materials\reports.jsonl --output D:\T2\runs\multi-001 --request-ledger D:\T2\budget\temporary-authorization.jsonl --model deepseek-flash --response-mode staged_tool --thinking disabled --multi-entry --max-requests 24
```

多条 wire 为 `candidate-serial-snapshot-v2`。共享读取后，模型只用 `propose_candidates` 提议 scope 和 evidence_refs；空列表合法，不分配 slot/entry_id 或直接塞入成稿字段。程序精确去重并按剩余预算选择最多 4 个候选，再逐个执行完整八字段初稿和一次完整自查。候选可能多于 4 个，但不会自动扩额；预算不足明确省略/不处理，不强凑 4 条。不同入口不能拼成一条 trace，精确去重也不是语义同一性证明。

各候选共享原 HTTP、模型调用和读取预算，不重启读取 job；某条未知独立保留草稿，全局停止则不继续请求并明确记未处理。控制器维护 run-local ID 和复核侧车 slot，模型 wire 中没有这些键。无可处理候选仍保存元数据草稿。旧 `annotation_multi` / `submit_annotations` 多槽容器已停用；历史 OpenClaw 4 槽、Langflow 3 槽草稿仍属旧 v4，不证明独立入口数或新模式效果。

本轮开发实测显式选择 `--response-mode staged_tool --thinking enabled --annotation-format assessed_tool --read-format plan_tool --reasoning-effort low --max-tokens 32768`：读取与函数填表阶段关闭推理，公开判读阶段开启推理；每份初稿/自查分别花两次请求。不是格式失败后的回退，旧 snapshot_json / native_tool / snapshot_tool 的结果不混算；具体成效与未完成项见页首记录。提供 strict/required 不代表供应商一定返回有效参数，真实无效回答仍拒收。high 的历史输出预算失败也不能借用 low 的结果。

以下 strict_tool 为兼容保留的旧混合容器模式，与 staged_tool 的成绩必须分开记录：

在正式命令末尾添加 `--response-mode strict_tool`，可显式启用 [DeepSeek 严格函数输出（Beta）](https://api-docs.deepseek.com/guides/tool_calls/)：通过官方 `/beta/chat/completions` 返回 `submit_step` 的结构化参数，不再把自由正文当成动作 JSON。该函数只是回答容器，仍只能经原控制器使用七种只读工具，不执行模型自造函数。保留 thinking 与原 reasoning_effort；使用 `tool_choice=auto`，因为供应商不支持 thinking 下强制 required/指定函数。客户端只接受单个正确容器，未调用容器、多函数或无效参数都会明确失败，不猜补、不静默切回旧模式。

如需强制回答容器，显式添加 `--response-mode strict_tool --thinking disabled`。这会关闭供应商 thinking，使用 `tool_choice=required` 并省略不适用的 `reasoning_effort`；并非同一推理配置的等价替换，实际设置记在 summary。它不会增加执行能力，仍只接受一个合法 `submit_step`；鉴权、权限、拒绝、网络等错误仍停止，没有正文回退或自动重试。官方说明见 [Chat Completions 参数](https://api-docs.deepseek.com/api/create-chat-completion/)。

当前 strict_tool 的内部位置值是 `{evidence_ref,start_line,end_line,desc}`，不再要求模型抄写 file/code。只允许从同SHA、成功read_file、实际展示的连续行中展开，单处最多200行；未知引用、版本不符或未展示的行会留作未验证建议，不猜填源码。程序最终仍输出标准 `{file,line,code,desc}`，不存在把证据ID塞进正式样本替代源码的情况。旧 json 模式继续兼容展开位置格式。

省略参数仍为 `json` 和 `thinking=enabled`，兼容旧脚本；`json + disabled` 会在读取密钥前明确拒绝。两种严格配置已各通过一次短协议实测，但 `enabled + auto` 在真实 run-08 第二个响应返回 `stop`，导致停止。**短协议成功不证明真实任务稳定或语义正确**；各配置的后续实际结果见实跑记录，旧样例不冒充新模式成绩。

密钥优先从已配置的 `DEEPSEEK_API_KEY` 环境变量读取；若未配置，在交互式终端直接运行上面的正式命令，会出现 `Temporary DeepSeek key (hidden):`，此时输入临时授权密钥，字符不回显。不要为了设置环境变量而把真实密钥写进一条可进入 Shell 历史的赋值命令，也不要放进参数、脚本或文档。若已有环境配置，先确认它属于本次授权，不要打印其内容。

非交互环境应使用已授权的环境变量注入；`--key-stdin` 仅接收来自受控管道的一行密钥，不能在普通终端直接加此参数。程序不会把密钥写进输出文件，不自动响应原生权限弹窗。只有正式模型运行需要模型服务网络；输入检查和仓库读取始终不联网。

## 简单报告 JSONL

例如把以下一行保存为 `D:\T2\materials\reports.jsonl`。每行一个 JSON 对象，不是整个文件一个 JSON 数组；记录内的路径相对于 JSONL 所在目录。

```json
{"source_link":"https://github.com/advisories/GHSA-2222-3333-4444","repo_path":"../repos/project","repo_url":"https://github.com/example/project","advisory":"advisory.md"}
```

```powershell
python -m vulngym_t2 --input D:\T2\materials\reports.jsonl --model deepseek-flash --response-mode staged_tool --thinking enabled --annotation-format assessed_tool --reasoning-effort low --max-tokens 16384 --max-calls-per-report 12 --max-tool-calls 32 --stop-on-format-error --prepare-only
python -m vulngym_t2 --input D:\T2\materials\reports.jsonl --output D:\T2\runs\jsonl-001 --request-ledger D:\T2\budget\temporary-authorization.jsonl --model deepseek-flash --response-mode staged_tool --thinking enabled --annotation-format assessed_tool --reasoning-effort low --max-tokens 16384 --max-calls-per-report 12 --max-tool-calls 32 --stop-on-format-error --max-requests 80
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
python -m vulngym_t2 --input D:\T2\materials\urls.txt --cache-dir D:\T2\cache --repo-map D:\T2\materials\repo-map.json --model deepseek-flash --response-mode staged_tool --thinking enabled --annotation-format assessed_tool --reasoning-effort low --max-tokens 16384 --max-calls-per-report 12 --max-tool-calls 32 --stop-on-format-error --prepare-only
python -m vulngym_t2 --input D:\T2\materials\urls.txt --cache-dir D:\T2\cache --repo-map D:\T2\materials\repo-map.json --output D:\T2\runs\batch-001 --request-ledger D:\T2\budget\temporary-authorization.jsonl --model deepseek-flash --response-mode staged_tool --thinking enabled --annotation-format assessed_tool --reasoning-effort low --max-tokens 16384 --max-calls-per-report 12 --max-tool-calls 32 --stop-on-format-error --max-requests 80
```

repo-map 中的相对路径以映射文件所在目录为基准。上面三种输入路线任选一种即可，不需要同时准备 JSONL、URL 列表和材料目录。

## 如何读结果

| 文件 | 含义 |
|---|---|
| `entries.jsonl` | 通过完整 schema、来源与精确源码位置检查的自动候选条目；全部 `verify=0`。 |
| `drafts.jsonl` | 新运行的待补充条目，保留 15 个正式字段名；缺失标量及整个位置为 `""`，缺失数组为 `[]`，`verify=0`。仅投影 `draft_fields`，不采纳建议值；不是完整 schema 数据集，不计完整候选。旧批次可能没有此文件。 |
| `reports.jsonl` | 完整条目按公告聚合；依 SCHEMA 对标量取多数值，并列取最小 entry_id 对应值，标题先去文件名后缀，编号取并集。草稿不参与聚合。 |
| `report_conflicts.jsonl` | 保留同公告字段冲突的原值及 entry IDs；规范聚合报告照常生成，聚合值不等于冲突事实已获确认。旧运行可能没有此文件。 |
| `review.jsonl` | 每条候选或输入失败的字段状态、已知 `draft_fields`、独立 `suggested_values`、证据、源码核验结果和错误；多条模式附 input_id/slot。 |
| `actions.jsonl` | 有界的计划、读工具、草稿、自查记录，不保存隐藏推理或密钥。 |
| `summary.json` | 完整条目/草稿/输入失败数量、未处理数量、耗时、模型与 HTTP 用量。 |

每条复核记录的 `review.status` 有三种结果，不能与输入级状态或批次 `summary.status` 混淆：

| `review.status` | 读法与统计 |
|---|---|
| `complete` | 进入正式 `entries.jsonl` 的自动候选，计入 `candidate_count`，仍需人工判断语义。 |
| `draft` | 必需内容未全部建立，已知字段和建议值仍可复核，计入 `draft_count`，不计完整候选。 |
| `input_failure` | 材料或本地仓库准备失败，原因保留，计入 `input_failure_count`。 |

多条模式的 summary 带 `counting_version="input-review-v2"`：`input_count` 是已处理输入数，分为 `complete_input_count`（子条目全完整）、`partial_input_count`（完整与草稿并存）、`draft_input_count`（无完整子条目）和 `input_failure_count`。`candidate_count/entry_count` 是完整条目数，`draft_count` 是草稿复核行数，`review_count` 是全部复核行数；一份输入产生两条完整候选仍只算一份输入。`input_reviews` 保存输入到子条目 ID 的映射，未开始数量也按输入计算。旧无计数版本的单条结果沿用原口径，不重新解释历史分母。

工作台分别显示“份资料”和“条结果”，另可展开“候选提案覆盖”，查看每份资料提出、选中、未选的提案数（未选含去重）及编码预留。提案不是已确认漏洞；未选提案没有逐条处理，不等于尚未处理的输入资料，也不会自动算成草稿或完整结果。预留不等于实际请求或成功恢复；旧记录缺失时显示“未记录”，不按 0 补算。

新模式使用 `process_metadata_scope="candidate_with_shared_usage"`：每个候选独立记录初稿、自查、补读三项状态，以及自身 errors/actions；后一个候选失败不降级此前已独立完成的候选。slot 1 仅集中承载共享调用/费用和单列的 `input_errors` / `input_actions`，其余候选关联同一 input_id 查共享用量，不重复计费，也不把输入级记录泛化为所有候选的错误。历史 `shared_input` 产物仍按原来的共享过程解释，不回写为新结构。

`report_linkage_complete` 只检查 entries/reports 的真实关联；`report_conflict_count` 单列元数据冲突，二者均不证明语义正确。此前“冲突组不进入 reports”的实现/说明不符合 SCHEMA，已恢复规范聚合并保留警告。

`supported` 表示有引用依据的模型判断或控制器输入事实及适用的确定性检查，不是人工确认。`uncertain/missing/conflicting` 保留原因；内部 `review.jsonl` 的未知必需字段在 `draft_fields` 中仍为 `null`，建议值单独存放。面向题面 missing 风格的 `drafts.jsonl` 将缺失标量或整个位置表示为 `""`、数组为 `[]`；不造行 0、空位置对象或猜测代码，也不混入正式 `entries.jsonl`。可选 trace 未建立时可导出 `[]`，原建议和疑点仍留在 review；行号若经已读窗口内唯一逐字匹配修正，会记录 `location_corrections`，不改变片段、版本或语义置信度。

`draft_export_count` 统计 `drafts.jsonl` 中的草稿与输入失败占位，包含 `input_failure`；`draft_count` 不包含输入失败，二者不能混用。复核报告会分别展示空值导出、原始草稿及建议；旧结果不自动回填新文件。

新运行的 commit 须给出 `revision_basis`：`behavior_at_revision`（该版本源码机制依据）、`affected_range_and_source`（影响范围与源码关联）、`inspected_only`（仅检查过）或 `unknown`。后两类及缺声明保留为 uncertain，候选 SHA 放入建议；前两类还需简短理由及所选 SHA 的实际源码读取引用。不强制修复链接或官方版本表，不按理由关键词猜测语义。通过检查仍是机器判断。旧记录缺字段只显示“旧记录未声明”，不重算旧结果。

### 旧 strict_tool 的兼容流程（非 snapshot）

以下两段仅说明保留兼容的旧混合容器模式，不适用于当前 staged 完整快照。strict_tool 首次草稿后，若原模型预算还余至少2次且读工具预算未耗尽，可进行一次聚焦补证：专看外部入口/所属handler是否真的读过，以及源码机制与版本范围是否被混淆。该步骤最多增加1次模型调用和2次有界读取，仍计入原有总预算；只允许read_file/search_code/inspect_commit/read_diff，不另开探索循环。模型也可以不补读、只返回更正/降级或空增量。预算不足时不请求，明确显示not_requested。

随后进行本地 schema/字段与源码位置预检查，把实际错误和行号修正反馈给原有的一次最终 self-review。这一步禁止再读工具，只返回修改字段；strict历史也使用源码引用，不回传一份重复的大段code。最后仍做终检，本地检查、补证完成及模型自查均不替代语义复核。该流程给模型补足依据的机会，不保证它一定能正确判断入口或版本。

### 运行状态与历史读回

旧 json / strict_tool 及历史产物继续兼容读回，不把旧记录补写成 snapshot 状态。批次逐条保存结果；`summary.status: completed` 仅表示批次走完，可能没有完整候选。新版默认把已确认的单条正文格式错误留在当前草稿，随后继续同一授权内尚未开始的不同输入，不重试失败项、不重置账本；`--stop-on-format-error` 恢复旧全停方式。全部输入遍历完但含此类失败时为 `completed_with_errors`，退出码 2，`case_failures` 记录失败及是否继续下一项。这不是全成功，也不表示后台仍有剩余任务。

网络、鉴权、权限、拒绝、模型不符、截断或未知故障仍为 `provider_stopped` 并停下，不利用错误隔离绕过访问限制；剩余输入计入 `unprocessed_input_count`。已请求自查却未完成时，`self_review_status=failed`；未请求为 `not_requested`，不伪称失败或完成。当前 snapshot 两者都不能完整导出，必须自查 completed 并通过独立终检。启动错误可能尚无输出目录；强制终止仍可能使当前输入或汇总未落盘，不能把不存在的 summary 当成一次已完成运行。

`evidence_followup_status` 独立记录聚焦补证的not_requested/completed/failed；失败保留草稿和证据，不导出完整候选，旧样例缺字段显示旧记录未声明。源码在提示中仅发送一份带行号表示；同SHA/路径且已完整展示的子区间可复用原证据，不重复读取。完整的已读证据仍在复核产物中保存。

### 正式样本与复核材料的区别

对当前run-01至run-09做的离线格式核对通过：合计9条entry、9条report、34处location，15字段、类型、来源/ID/SHA、report关联、字段序和行序均符合本仓库 `SCHEMA.md`。这些是重复开发运行，不是9个独立案例；格式正确不等于入口或机制已确认，所有自动entry的verify仍为0。

正式数据交 `entries.jsonl` 和 `reports.jsonl`。`review.jsonl`、`actions.jsonl`、`summary.json`、`assessment.md` 及冲突旁车是辅助复核/过程材料，允许保存未知值、建议和额外状态，不能将 review 直接拼进 entries。SCHEMA 中的184/408是原始数据集发布条数，不是本工具每次必须生成的数量；默认每份输入最多一个 entry，显式多条模式最多四个独立候选，但不保证覆盖公告所有入口。

已结束的目录可离线生成便于提交和人工复核的中文自动自评，不用密钥，也不产生新模型请求：

```powershell
python -m vulngym_t2.report --run-dir D:\T2\runs\single-001
```

它仅读取 `summary.json` 和 `review.jsonl`（合计最多 20 MB），新建 `assessment.md`，已有同名文件时拒绝覆盖；不修改原 JSON。自评引用实际统计与疑点，不提供无独立标签支撑的准确率或 F1。

## 预算、安全与已知边界

同一临时授权必须复用原 `--request-ledger`，不并发占用、另建或清空账本重置用量。`--authorization-limit` 是生成请求账本的上限，历史目录查询等账本外请求也要计入总授权；默认值或软件可接受上限都不是新增授权。后续每次须显式传 `--authorization-limit 3000 --effective-request-limit 2999`，Web 再加 `--historical-requests 1`；历史账本 cap 仍是 3000，新参数限制本进程累计生成次数，不是本批请求数，未传时不自动生效。当前冻结版本与验证见页首。`--max-requests` 只是单批上限，不是必须花满的配额；错误尝试也计数，锁定、损坏或未结束请求须保留现场处理。

默认每份公告最多 8 次模型调用、24 次仓库读调用，可用 `--max-calls-per-report` 和 `--max-tool-calls` 调低；硬上限分别为 16/64。模型调用次数和实际 HTTP 次数不是同一口径，以账本的 `http_started` 为授权用量准绳。模型由显式 `--model` 选择；旧默认仍为 `deepseek-v4-pro`，本次新运行明确使用 `deepseek-flash`。零自动重试，不自动换账户或模型；未测量货币费用，不能把 token 数当成实际账单。

模型可请求七种有界只读工具：`inspect_commit`、`list_files`、`read_file`、`search_code`、`read_diff`，以及探索已有本地版本的 `list_refs` / `search_history`。修复父提交、tag、HEAD 或提交说明命中只是待检线索，不自动成为漏洞版本；历史查询无命中也不证明不存在。源码精确一致不证明入口可达、攻击者可控或漏洞可利用；长材料截断、多入口、复杂跨文件逻辑和历史缺失仍需人工判断。默认单条、多条模式最多四条的数量上限不等于覆盖证明；非空 trace 可选，独立 T1 自动反馈不在本轮范围内，也未接入。同模型自查不等于 T1。历史 V4.1 减线索 Langflow 记录中有 1 次 `list_refs` 和 2 次 `search_history` 调用；该条仍因传输失败保留为草稿，不能把工具成功调用当成端到端成功，也不构成广泛提取效果评估。

历史搜索默认从 HEAD 开始；若提供的对象仓库没有有效 HEAD，模型应先用 `list_refs`，再显式指定返回的 commit。程序不会静默挑选“漏洞版本”。

### 批次停止后，离线列出尚未开始的 URL

```powershell
python -m vulngym_t2.pending --input examples/t2_v2_input/urls.txt --run-dir examples/run-02 --output D:\T2\remaining.txt
```

工具只读取原 URL 列表和已结束运行的汇总/逐条结果，不联网、不读 key/账本、不请求模型。它核对已处理前缀后写入新清单；失败但已产生草稿的当前项也算已处理，不会偷偷重试。上面随包失败示例会得到三份尚未开始的 URL；它们之后已经在 `examples/run-03` 运行，**这里只演示清单生成，不要把它们再当成未见案例重跑**。

只支持不重复的 GHSA URL 列表，以及可核对的 `completed` / `completed_with_errors` / `provider_stopped` 运行。中断状态、计数/身份不符或已有输出文件会拒绝，不猜测哪一项曾发出请求；不保证源材料未变，也不恢复模型 checkpoint。若后来又分批运行过这些 URL，使用者还需核对后续记录，不能把单个旧运行的剩余清单当成全局待办。真正处理剩余输入需要明确授权和有效 key，并使用新输出目录、同一授权原有账本。

可携带公开输入见 `examples/t2_v2_input/`，需按其说明配置自己的本地仓库路径。`examples/run-01`、`run-02`、`run-03` 原样保留历史混合结果、历史停止结果和旧 URL 列表结果；V4.1 完整材料首批及仅未开始项续批分别见 `examples/run-04`、`run-05`，减线索首批及仅未开始项续批分别见 `examples/run-06`、`run-07`。严格协议首批和仅未开始三项续批见 `examples/run-08`、`run-09`；原四项顺序及材料组合见 `examples/t2_v2_input/v41/strict-targeted-inputs.example.jsonl`。这些批次含重复案例和不同配置，不能相加当独立样本或拼出一次全成功。逐项说明见 [V4.1 实跑记录](docs/t2_v41_results.md)。

```powershell
python -m vulngym_t2.review_export --run-dir examples/run-09 --output strict-review.md
```

短设计见 `docs/t2_v2_design.md`，当前三页 PDF 见 [T2-design-v84.pdf](output/pdf/T2-design-v84.pdf)；旧交付 ZIP 中的 `docs/T2-design.pdf` 是历史版本，本轮未重建 ZIP。现场操作和人工复核见 `docs/t2_v2_demo.md`；另提供[五分钟字幕回放视频](output/demo-replay-20260914/README.md)，由真实工作台截图编排、无配音，不是连续操作录屏或现场新生成。官方字段定义以 `SCHEMA.md` 为准。
