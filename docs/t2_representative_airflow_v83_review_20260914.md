# Airflow v83 真实复测：读取覆盖与内容 QA

日期：2026-09-14。仅核对 `D:\VulnGym-bv2-runtime\t2-representative-20260913\13-airflow-v83-low` 的公开 summary/review/actions/entries/drafts，以及既有 [Airflow v81 QA](t2_representative_airflow_v81_review_20260914.md)。下文 EID 均指 **v83 本轮**；旧 QA 只用于覆盖和行为对比，不把旧批源码补进本轮证据。未读取目标仓库、私有材料或密钥，未联网、调用模型、执行目标代码，也未修改原结果。

结论：本轮正常完成并保留一条有真实证据的草稿，不是全失败。新增 40 行 `called_body_continuations` 分支没有实际发生，不能宣称已通过本次真实验证。本轮读通了另一条 FastAPI 日志持久化路径，却未读到 CLI 的 `action_cli` 函数体，旧版本关系也未建立。核心字段保持未知有依据，但最终理由仍遗漏已读事实、扩大局部遮蔽效果；不能把全部缺口包装成合理弃答。

## 1. 终态与阶段

| 项目 | v81（既有 QA） | v83（本轮回执） |
| --- | --- | --- |
| 终态 / HTTP / 工具 | completed / 11 / 21 | completed / 11 / 23 |
| 耗时 / 单轮请求上限 | 69.813 秒 / 16 | 51.238 秒 / 12 |
| 完整条目 / 草稿 | 0 / 1 | 0 / 1 |
| 读取计划拒收 / 整份编码拒收 | 1 / 0 | 0 / 0 |
| 初稿 / followup / 自审 | accepted / completed / completed | accepted / completed / completed |
| 模型 followup 次数 | 1 | 2 |
| 实际 read_file 窗口 / SHA 数 | 6 / 2 | 5 / 1 |

v83 的 model/tool/pipeline/format/annotation 终态错误、自动 HTTP 重试均为 0，provider 未 halted。实际顺序是 call 1–5 规划读取，call 6/7 初稿评估/编码，call 8/9 两次 followup，call 10/11 自审评估/编码；`selected_location_review` 已 attached。读取选择、提示和请求上限均不同，不能把耗时或工具数差异单独归因于某项修复，更不能视为语义成功率。

`entries.jsonl` 为空；`drafts.jsonl` 保留一行 15 字段资料，commit、EP、CO 为空字符串，trace 为 `[]`，verify 为 0。review 中这三个必要字段各有一个 `model_uncertain`，原值为 null；EP 的 E0022:205–298 仅保留为 suggestion，没有偷偷提升为完整条目。空 optional trace 的 controller supported 也不是完整调用链得到支持。

## 2. 40 行分支未触发，上下文瓶颈仍有实证

actions 中没有 `source_window_continuation`，本轮也没有任何 `utils/cli.py` 的 read_file。直到 call 9 的 E0026 才用路径限定搜索得到 `def action_cli`，命中第 62 行；这只是位置线索，不含函数体，更没有形成 v81 那种已经读到 helper 前半、可继续向后补 40 行的证据状态。因此，本轮只能说明新增分支未被覆盖，不能据此判定该分支自身成功或失效。

更早的阻断已经保存：call 5 完成 E0023 后出现 `read_context_closed: reserve_annotation_review_context`，`result_allowance_chars=0`；随后 `imported_context_skipped` 引用 E0018/E0022，理由为 `context_budget`，`semantic_approval=false`。被停止的 read_file 没有保存成功回执或目标参数，不能替它指定路径，也不能把停止当成阴性搜索结果。这发生在初稿前，不能解释成最终 HTTP 次数耗尽。

三次 `evidence_context_compacted` 分别为 70,321→66,557、76,404→75,331、76,711→75,952 字符（证据数 23/25/26）。它们证实上下文重打包发生，不是独立表格节省计数，不能相加当作累计释放量。后续仍成功完成自动入口补读和两次 followup，说明并非所有后续读取被封死；但第一次导入导航已被上下文门槛挡住，压缩尚未消除这种读取时序问题。

## 3. 本轮实际版本和窗口

A=`19c1a16dc8b44ba470198c300b25defc7848576f`；B=`df4cb30b116c8628afc465876e08d58f2bcb897b`。这只是身份简称，不代表漏洞/修复版本或先后顺序。

| 回执 | 实际源码范围（均为 A） | 作用与边界 |
| --- | --- | --- |
| E0018 | `airflow-core/src/airflow/cli/commands/connection_command.py`:1–112 | 初始模型读；请求 1–200，实际缩至 112。 |
| E0022 | 同文件:200–382 | 初始模型读；覆盖添加函数主体和后续兄弟函数。 |
| E0024 | 同文件:113–199 | 初稿后自动 `entry_context_read`；三段并集覆盖全文 1–382。 |
| E0023 | `airflow-core/src/airflow/api_fastapi/logging/decorators.py`:1–78 | 初始模型读；请求 1–180，实际只到 action_logging 开头。 |
| E0025 | 同文件:77–174 | call 8 followup；补到文件结尾，两段并集覆盖全文 1–174。 |

E0005/E0006 分别 inspect A/B；其标题是 SQLAlchemy 类型迁移和 Execution API security 重构，不是本报告漏洞机制的源码证明。B 只有 inspect 和路径限定 `audit_log` 查询（E0017，零命中），没有源码窗口；字面查询为空不能证明该版本不存在 CLI 日志机制。既没有受影响发布范围到 SHA 的映射，也没有某 SHA 上该机制成立的充分源码链。不能从改动标题无关推出整个快照不受影响，也不能把 B 称为本轮已读源码版本。

与 v81 相比，命令文件全文覆盖得以保留；本轮新增了完整 FastAPI 日志消费者的实际读取。但 CLI helper 及第二个 SHA 的源码覆盖没有保留。不能用旧轮已读的 wrapper、参数处理或 metrics 片段补齐本轮。

## 4. 消费者确实读到了，但 CLI 连接仍未建立

E0022:205 的 decorator 和 207–298 的 `connections_add` 是实际入口线索；255–275 从 URI、JSON 或各参数构造 Connection，279 有 `session.add(new_conn)`。这是连接对象持久化，不等于公告要求的审计 Log 写入。

E0025:77–84 明示 FastAPI Request/SessionDep/GetUserDep 和 endpoint/event 来源；126–129 仅在 event_name 包含 connection 时选择 `_mask_connection_fields`。146–155 构造 `Log`，151 将 `extra_fields` JSON 放入 extra；169/172 分别执行 `session.add(log)`、`session.commit()`。因此本轮不是“完全没读到最终 Log 写入”。但是 CLI→该 FastAPI 路径的调用/注册关系没有建立，`action_cli` 函数体也没有读取，不能凭命名相似把两条路径连接起来。

此外，已读 API 分支调用 `secrets_masker.redact` 不等于其实现或所有参数形式均已核验。公告所述 CLI 参数进入审计表的具体值、条件及相关旧版本仍然未知；不要求必须找到 fix commit 才能标注，但版本依据或实际漏洞机制至少需要有充分证据。

## 5. 最终理由的具体勘误

1. **把条件遮蔽概括为全部消息已遮蔽。** commit.reason 称 `connections_add` 只构造 Connection 并打印 masked message，遗漏 E0022:279 的连接对象持久化；更关键的是 283 优先采用 `args.conn_uri`，287 的密码替换仅在 fallback URI 构造中。现有窗口不能保证所打印消息一律遮蔽，也不能把 stdout 输出直接视为审计 Log。v83 没有再使用 v81 的整机制 `contradicting` 断言，这是措辞改善，但上述局部概括仍不准确。
2. **把 CLI 链未读扩大成任何 Log 写入未读。** trace.omitted_assessment 的 `any Log write remain unread` 与 E0025:146–155、169/172 直接冲突。CO 理由虽明确说 API 路径不是 CLI 写入，但应保留“已读 API 持久化、CLI 连接尚未建立”的区别，而不是笼统说期待操作未读。自审 completed 并未纠正这处事实错误。
3. **版本证据称呼仍不严谨。** commit.reason 的 `Neither read SHA` 把仅 inspect/search 的 B 也称为已读源码 SHA。E0005/E0006 可说明本次 inspect 的改动主题，不能独立支持受影响/不受影响结论。最终保持 commit unknown 有依据；这不使其全部理由自动正确。

EP 理由中的 `source_ref_invalid_commit` 是未建立 commit 后的坐标解析约束，不是本轮模型协议失败；同一理由仍保存了真实覆盖的 E0022:205–298 建议。E0026:62 出现 `reason_citation_read_required` warning，但模型已明确注明 search-only、函数体未读，不应改称它伪造了一次源码读取。

## 6. 尚未解决的边界

本轮可确认的改善是没有读取计划/编码拒收、完整读取了 API 日志持久化实现，并保留草稿和已读入口建议；尚不能确认 CLI 漏洞链、相关历史版本或新增 40 行分支的真实效果。最明确的剩余读取缺口是 E0026 已定位但未读的 CLI decorator 及其真实消费者连接；这是读取选择与上下文分配仍可检查的具体边界，不是现有公开材料已证明无法获得的外部未知。

因此，0 完整不能叫作全失败；也不能因正常退出、工具增加或保守留空宣布内容质量达标。技术终态没有失败，不代表没有可避免的取证缺口和语义错误。本文仅记录这些事实与待验证边界，没有执行新读取、改变模型理由、重标字段或新增真实调用。
