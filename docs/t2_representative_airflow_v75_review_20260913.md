# Airflow v75：补读完成，但审计日志链仍未闭合

## 范围与终态

只读已结束的 `D:\VulnGym-bv2-runtime\t2-representative-20260913\regression-v75-06` 中 summary、review 第二行及对应 actions；结合本产品冻结代码解释调度，不新增目标源码、网络、模型请求或目标执行。原结果不改。

会话 21954 退出 0；整批 21 HTTP、26 工具、319.599 秒，1 完整候选、1 草稿，0 模型/格式/字段错误及读取计划/编码拒收。2 个工具错误与 2 个 pipeline 计数是同事件，来自另一条输入。**Airflow 实际是草稿，不是完整候选**：10 模型调用、11 工具调用，自身无工具或 pipeline 错误；`evidence_followup_status=completed`、`self_review_status=completed`。commit、EP、CO 均为 null，trace 为空，`verify=0`。本批结束时累计 2450 次生成 + 1 次历史查询 = 2451/2600，余 149；这不是后续批次实时余额。

与 [v74](t2_representative_regression_v74_review_20260913.md) 相比，三次补读及自审确实执行，未再保留失败前未自审的旧稿；但 source 从三个窗口缩为一个，最终 logger、日志值构造和相关旧版本仍未读到。不能把流程恢复称为语义目标完成。

## 1. 实际覆盖：只有一个命令主体窗口

- E0005/E0006 inspect 的仍是 `19c1a16dc8b44ba470198c300b25defc7848576f`（19c）及 `df4cb30b116c8628afc465876e08d58f2bcb897b`（df4）。父 SHA 和变更路径是导航事实，不是受影响版本映射。
- E0009 在 19c 搜裸词 `audit_log`，`complete=true`、30 命中；自动 E0011 原样转到已 inspect 的 df4，确有 `initial_snapshot_search`。后者保存 25 个命中、`complete=false/context_truncated=true`，没有自动 source read。说明“完整但无已识别声明”的跨快照探查实际发生，不证明找到审计 logger。
- E0010 的 `Log` 搜索包含 `airflow-core/src/airflow/models/log.py:36` 类声明，但没有读取该文件。搜索命中不算连续源码窗口，更不等于实际写入点。
- **唯一 read_file 是第三次补读 E0014**：19c 的 `airflow-core/src/airflow/cli/commands/connection_command.py:200–300`，请求与显示边界一致，`truncated=false`、`has_more=true`、文件共 382 行。

E0014 显示 205 行 `@cli_utils.action_cli`、207 行 `connections_add`；209–253 校验 URI/JSON/type 的组合，255–275 按 URI、JSON 或分离参数构造 Connection，277–298 查重、`session.add(new_conn)` 及成功提示/重复项异常。**Connection 写入不是 Log/audit 写入**。本轮没有 wrapper、`_build_metrics`、`cli_action_loggers.py`、发布版本文件、相关历史主体或修复 diff 的 receipt。

## 2. 没有主动 finish：三次机会分别用于两次搜索和一次源码读取

| 模型调用 | 实际动作 | 保存结果 |
| --- | --- | --- |
| 1–2 | 两次 inspect、两次 history、两次 source 搜索及一次自动探查 | E0005–E0011；尚无 read_file |
| 3 | 提交 3 操作计划，首项是 search_history | `read_context_closed`，`result_allowance_chars=0`，首项及后续操作均未执行 |
| 4–5 | 初稿评估与编码 | 无源码，commit/EP/CO 未确定 |
| 6 | 搜 CLI 路径的 `set_connection` | E0012，完整、0 命中 |
| 7 | 在 connection_command.py 搜 `connection` | E0013，含 207 行函数声明；显示搜索已截断 |
| 8 | 读 connection_command.py:200–300 | E0014，唯一连续源码窗口 |
| 9–10 | 自审评估与编码 | 识别已读 handler，保留未知审计链 |

actions 没有 `finish_reading`、失败、`no_new_evidence` 或后续 `evidence_followup_skipped`。`pipeline.py:1515` 对 staged 单输入设三次 followup 决策；本次三次均成功且产生新回执，因此循环到上限后进入自审。不是模型主动选择 finish，也不是每输入 12 次 HTTP 已用满。补读中的工具只有 search_code/read_file，**本例没有实际执行 followup search_history**；协议名单修复的本地测试不能替代该通路的真实调用证据。

### 初读关闭的开销边界

`pipeline.py:1700` 的初读可用量是 `68,000 - 已有消息字符 - 当前 responses 序列化字符 - 1,024`。非 read_file 操作必须再容纳完整 16,000 字符结果，否则返回 0；所以 call 3 的 `allowance=0` 只证明 search_history 未获该预留，**不证明上下文物理剩余为零或目标历史不可用**。当时完整消息包未保存在公开回执中，不能精确重建真实剩余量，也不能断言换成窄 read_file 一定能执行。

保存的随后压缩指标是初稿后 54,936 → 52,946 字符；三次补读后分别 54,201 → 53,451、62,216 → 61,439、66,976 → 66,193。这些是不同阶段的实测消息开销，不是 call 3 的精确上下文。早期历史/宽词搜索确实用了读取阶段空间；最终只有一次源码读取，属于实际选择与有界调度留下的漏读，不能归因为缺资料或权限失败。

## 3. history 返回了可继续调查的 SHA，不是版本证据

本产品 `repository.py:274` 的 search_history 是本地可达历史中区分大小写的字面 **commit message** 检索（`git log --fixed-strings --grep`）；返回 SHA、parents、subject，不读正文、diff、tag 或发布版本。E0007 的 `audit log` 和 E0008 的 `sensitive` 均在 19c 起搜、limit=20，均 20 命中、`has_more=true/truncated=true`、`negative_result_conclusive=false`。

已保存结果并非全部无关：

- E0008：`144aab6a9191c17963da262590830d72dafdcab5`，题为 `Bugfix/mask sensitive values in cli (#58659)`，附 parent `84110f44b73ac9ee8383d9066001e0ee17c9b5e8`。
- E0007：`826f3bd3803ecc0c9aad17e549735ad0e7b6b0ee`，题为 `Properly test that audit log secrets are masked for connection objects (#29011)`，附 parent `481f27170673cb1e4fc8210341c8d341b11925e9`。

这些是模型实际看到的相关导航线索，但本轮未 inspect、按文件比较或读取其源码，不能认作本公告修复、受影响旧版本或已存在的完整机制。初稿将 history 概括为“only older unrelated commits”过宽；最终理由改为审计链未读、版本 unknown，没有据此选定 SHA。已检查提交没有相关 changed_paths，也只能说明该次差异，不是否定整个快照含相关行为的理由。这里是未跟进已有线索，不是已经证明旧材料不存在。

## 4. 遮蔽、位置与 v73 误概括

E0014:280–295 的成功提示采用 `args.conn_uri or urlunsplit(...)`；287 行仅在派生 URI 分支、password truthy 时替换成星号。最终理由明确限定为 derived-URI branch，局部描述有支持；它不能证明所有打印输入均遮蔽，更不能证明尚未读取的审计日志值已遮蔽。日志 full_command 的生产与遮蔽仍未读，不能用当前 Connection 构造或 print 代替。

本轮没有 EP/CO/trace 选定位置，故不存在“位置全部匹配”的成绩。理由的 E0014:280–295 引用确在可见范围内；256/270 的参数读取也在窗口内。自审称 200–300“ends at print(msg)”不够精确：295 是 print，296–298 仍有 else/异常；不影响“窗口没有 Log 写入”，但不得把成功分支结尾当整个窗口终点。

[v73](t2_representative_regression_v73_review_20260913.md) 实际读过最终 logger，却在 `_build_metrics` 正文缺失时将“消费者未再脱敏”扩成“全链未脱敏”。v75 最终没有重复该 supported 断言，并明确未读路径不作否定，保留草稿是合理的；但它也未重读 producer/consumer 或相关旧版本，**这是不确定性表述改善，不是旧缺陷路径已被证明或修复验证已通过**。原完整候选、草稿和 `verify=0` 均保持原样。
