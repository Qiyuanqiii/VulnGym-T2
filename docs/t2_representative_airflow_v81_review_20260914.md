# Airflow v81 首轮真实复测：与 v79 保存回执的只读对比

日期：2026-09-14。只读以下终态目录中的公开 `summary.json`、`review.jsonl`、`actions.jsonl`；actions 包装记录按 `.action` 展开。未读取目标仓库、私有 gold、source-map 或任何密钥，未联网、调用模型、执行目标代码，也未修改原候选或结果。

- 新轮：`D:\VulnGym-bv2-runtime\t2-representative-20260913\07-airflow-v81-low`
- 旧轮：`D:\VulnGym-bv2-runtime\t2-representative-20260913\regression-airflow-v79-10`
- 旧轮详细内容复核见 [Airflow v79 复核](t2_representative_airflow_v79_review_20260913.md)。

结论：v81 正常完成并保留了一份有实际证据的草稿；不是全失败。命令文件现已完整读取，工具文件的参数遮蔽分支覆盖也有推进。但上下文预留仍阻断下一次模型补读，`_build_metrics` 的字典装配/返回、最终日志消费者及相关历史版本仍缺证据。核心字段保持 uncertain 有依据，**不能因此把所有缺口都包装成合理弃答，也不能把草稿状态当作理由内容全部正确**。读取目的与关键边界的先后次序仍有可改进空间；最终理由仍存在历史命中误称 fix commit、局部遮蔽被扩大成报告反证的问题。

## 1. 终态、调用与停止原因

| 项目 | v79 | v81 |
| --- | --- | --- |
| summary 终态 | completed | completed |
| HTTP / 工具 | 11 / 21 | 11 / 21 |
| 耗时 | 117.910 秒 | 69.813 秒 |
| profile / 单轮请求上限 | low / 16 | low / 16 |
| 完整条目 / 草稿 | 0 / 1 | 0 / 1 |
| 读取计划拒收 / 整份编码拒收 | 1 / 0 | 1 / 0 |
| 初稿 / followup / 自审 | accepted / completed / completed | accepted / completed / completed |
| 模型 followup 决策次数 | 2 | 1 |
| 最后重打包上下文 | 81,902 字符 | 78,783 字符 |
| selected_location_review | 因上下文省略 | attached |

两轮 model/tool/pipeline/format/annotation 终态错误均为零，自动 HTTP 重试均为零。v81 call 3 的读取计划因 `path` 类型错误被拒收，call 4 为一次有界重编码并恢复；不能写成全程没有拒收。0 完整并不表示没有产物：项目、公告身份、标题、分类和实际回执仍保留，必要字段未建立支持。

新轮实际阶段顺序为：call 1-6 规划/读取（含 call 4 重编码），call 7/8 初稿评估/编码，call 9 一次模型 followup，call 10/11 最终评估/编码。旧轮在 call 6/7 初稿之后有 call 8/9 两次 followup。两轮工具数相同，不能写成 v81 靠更多工具取得成功；读取顺序、内容和提示版本均不同，也不能把耗时差单独归因于压缩。

新轮有两处明确的上下文停止：

1. call 6 实际完成 E0021 后，下一项 `read_file` 被 `read_context_closed: reserve_annotation_review_context` 截止，`result_allowance_chars=2080`。被停止项没有成功回执，不能推定其目标、内容或阴性结果。
2. call 9 完成 E0024 后，保存 `evidence_followup_skipped: reserve_review_context`。当时仅用到 9/16 次请求，仍余 7 次；因此不是 HTTP 上限耗尽。随后 call 10/11 自审正常完成。未出现第二次新轮 followup 或主动 `finish_reading`。

## 2. 压缩确实发生，但没有解除瓶颈

新轮保存四次 `evidence_context_compacted`：

| evidence_count | before_chars | after_chars |
| --- | ---: | ---: |
| 21 | 68,077 | 64,486 |
| 22 | 65,521 | 65,229 |
| 23 | 71,283 | 70,991 |
| 24 | 79,566 | 78,783 |

这些是整个候选上下文重打包的实际动作，不是单独的表格编码节省计数。最后上下文较旧轮少 3,119 字符，但仍触发原有评审预留门槛；不能说原容量问题已经修复完毕。

另作纯表示离线核对：只把公开 review 中每份 `read_file.text` 按保存的 `start_line/end_line` 在内存恢复行对象，逐一核对行数；再比较既有 `display_record(compact=True)` 与新增 `compact_record`。不读取源仓库、不重建或发送模型请求。

| 保存证据集 | 原紧凑 evidence 数组 | 加无损表格后的数组 | 净节省 |
| --- | ---: | ---: | ---: |
| v79 | 65,429 | 59,688 | 5,741 |
| v81 | 68,341 | 62,400 | 5,941 |

新轮节省来自 E0004 28、E0007 763、E0008 714、E0009 1,640、E0010 1,323、E0017 1,342、E0018 126、E0022 5 字符；所有回执可逐字段往返还原，源码未删减。上述数字是**保存证据的离线表示投影**，不是动作日志独立记录的模型输入节省，更不是语义成功率。

## 3. 实际源码覆盖与读取目的

两个实际 source-read SHA：

- A：`19c1a16dc8b44ba470198c300b25defc7848576f`
- B：`df4cb30b116c8628afc465876e08d58f2bcb897b`

A/B 只是回执身份简称，不是漏洞版本、修复版本或先后顺序标签。

| 回执 | SHA / 实际文件与范围 | 实际来源与作用 |
| --- | --- | --- |
| E0014 | A / `airflow-core/src/airflow/cli/commands/connection_command.py` / 1-112 | call 4 恢复后的模型读；请求 1-200，实际只显示 1-112。含真实导入头部。 |
| E0015 | A / 同命令文件 / 112-218 | call 5 模型读；请求 112-382，实际只显示 112-218。含 decorated `connections_add` 的开头。 |
| E0020 | A / `airflow-core/src/airflow/utils/cli.py` / 54-158 | call 5 后自动 imported_context_source；E0019 的真实 `def action_cli` 搜索给出位置。wrapper 完整，helper 起始可见。 |
| E0021 | A / 同 utils 文件 / 158-200 | call 6 模型续读；新增等号密码、conn-json、conn-uri 处理，但在 metrics 字典开头结束。 |
| E0023 | B / 同 utils 文件 / 48-160 | 初稿后的自动 alternative_snapshot_read；E0022 为路径限定 `_build_metrics` 搜索。只建立这一个窗口的实际比较。 |
| E0024 | A / 同命令文件 / 218-382 | call 9 模型 followup；覆盖添加函数后部及后续 delete/import/test 函数，已到文件结尾。 |

共六个成功 read_file 窗口、两个不同路径、两个 SHA，与旧轮同为六个源码窗口。新轮命令文件三段的并集覆盖 1-382 全文，不能再称其添加消息尾部未读。旧轮测试文件 E0019 的窗口本轮没有出现；这是本轮实际覆盖差异，不是全局禁止测试的证明。

新轮 E0014/E0015 已包含头部导入和 decorator，因而在初稿前便触发了 E0019/E0020 的 imported_context_search/source；这两项均成功且 `semantic_approval=false`。没有把词名命中当作字段支持。

E0017 的全局 `action_log` 搜索扫描 11,327 个候选/扫描文件，结果截断，显示命中主要位于 FastAPI 路由中的导入与依赖声明。它仍是实际的搜索证据，但不等于 CLI 日志消费者已经读取。E0016 在命令文件搜索 `Log` 为空，只约束该文件的这次字面查询，不能扩展成仓库中没有日志写入。

## 4. 已推进的内容与仍未闭合的必要关系

### 4.1 真实推进

E0020:95-97 显示 wrapper 先调用 `_build_metrics`，再将返回的 `metrics` 传入 `on_pre_execution`；117-119 显示 finally 中调用 `on_post_execution`。E0021:158-162 新增等号密码参数处理，165-173 显示 conn-json 分支，175-197 显示 conn-uri 的 URI 重组分支。这些是比旧轮只到 `else:` 更充分的局部源证据。

E0024:280-295 现在再次明确保留添加消息构造与 `print(msg)`：283 行优先使用 `args.conn_uri`，287 行的密码替换位于另一 fallback 构造。它不能直接证明审计日志写入，也不能被局部遮蔽一笔覆盖。

新轮 `reason_citation_checks` 中保存的引用均为 `covered`，没有旧轮 EP 将 search 回执当 read_file 引用的 `reason_citation_read_required`。这只说明所引范围真实可读，不验证理由语义。

### 4.2 仍然真实未知

- **metrics 装配和返回仍未读。** E0021:199 是 `metrics = {`，200 只到 `"sub_command": func_name,`；尚未看到 `full_command` 的字典装配、返回或后续处理。局部变量的形成，加上 wrapper 接收 helper 返回值，不足以证明未读的完整数据连接。
- **最终日志消费者仍未读。** 本轮没有任何 read_file 覆盖 `cli_action_loggers` 回调实现、配置分发、日志对象构造或最终持久化。docstring 对 logger 参数的描述不能替代实现读取。
- **相关旧版本仍未建立。** A/B 均有实际源码窗口，但没有本报告机制在某 SHA 上成立的充分证据，也没有受影响发布范围到 SHA 的映射。不是要求必须有官方版本表或 fix parent；问题是两种可接受依据目前都未建立。
- **B 的比较仍有限。** E0023 只到 160 行，未见 B 的 161 行以后等号判断、conn-json/conn-uri 处理或 metrics 装配。不能把 A 新读到的全部遮蔽逻辑自动映射到 B。

## 5. 最终理由仍须勘误，不能用 uncertain 标签免责

1. **历史命中被误称 fix commit。** E0012 只保存 SHA `144aab6a9191c17963da262590830d72dafdcab5`、其 parent 及标题 `Bugfix/mask sensitive values in cli (#58659)`；它没有后续 inspect/read/diff。公告 E0002 引用 `#61882`，并提示与另一个 CVE 类似但并非同一问题。当前证据不足以把 E0012 候选称为本报告的 fix commit。最终 commit.reason 和自审 assessment 的这一称呼应改成“相关历史候选尚未读取”。
2. **局部遮蔽被扩大成报告反证。** 最终 commit.reason 使用 `contradicting the reported missing-masking mechanism`；初次 assessment 还称读到的是 masking fix。已见分支只能说明这些条件下存在局部处理，尚未建立全部相关参数形式、消费者和历史差异，不能据此反证整份报告或断言当前 SHA 不受影响。保守可说“尚未在已读范围建立报告中的未遮蔽审计写入”。
3. **helper 到回调的数据连接仍有未读部分。** CO 建议及描述把 `_build_metrics` 构造 full_command 和传给回调概括为一条完成关系，但 metrics 字典与 return 尚未显示。wrapper 确实把 helper 的返回对象传给回调；该对象是否以及如何携带已处理 full_command 仍需下一段源证据，不能由常识补齐。

因此，commit、EP、CO 的 uncertain/null 终态具有事实依据；但当前未读部分同时暴露读取选择和上下文分配的可避免缺口。不能只说“谨慎留空是正确结果”便结束内容复核，更不能把所有缺失归为外部材料不足。

## 6. 后续可修机制与边界（仅建议，未执行）

call 9 前后保存的 compact 字符数由 70,991 增至 78,783，增加 7,792。E0024 的 218-295 确实补了添加函数的必要后部，不应称整次读取无用；但 301-382 已进入兄弟 delete/import/test 函数，与仍在 200 行断开的必要 helper、未读消费者竞争同一上下文。随后评审预留使下一次模型决策不可用。

可继续针对一般机制评估：在已有明确必要依赖和边界缺口时，是否先完成该边界与消费者，再展开同文件无关尾段或另一个快照；读取窗口与后续最小可用补读余量能否一起规划。必须由可泛化的证据和预算规则支持，不能硬编码 Airflow、SHA、函数答案或禁词，不能禁止新路径、把测试一刀切排除，也不能偷偷提高 100k 字符或 HTTP 上限。

就本轮实际证据而言，最清晰的后续方向是 A 的 utils/cli.py:200 后 metrics 装配/返回、真实 logger 消费者，以及对 E0012 已观察历史候选的 inspect 后再决定是否比较源代码；均不自动证明漏洞、修复或字段支持。本文没有执行这些读取，没有修改原模型理由或终态候选，也没有据一次复测宣布准确率提升。
