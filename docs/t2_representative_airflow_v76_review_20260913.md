# Airflow v76：命令文件完整覆盖，日志链与旧版本仍未读取

## 范围、终态与结论

只读已结束的 `D:\VulnGym-bv2-runtime\t2-representative-20260913\regression-airflow-v76-07` 中 summary/review/actions，以及 [v75 同例保存复核](t2_representative_airflow_v75_review_20260913.md)。输入是原回归第二条 URL，不新增目标源码、网络、模型调用或目标执行；原 JSONL 不改。本产品协议代码仅用于解释阶段边界，不充当目标证据。

会话 17144 退出 0：10 HTTP、12 工具、72.131 秒；0 完整候选、1 草稿。终态模型/工具/pipeline/格式/字段错误及读取计划/编码拒收均为 0，followup、自审均 `completed`。commit、EP、CO 为 null，trace 为空，`verify=0`；字段 `model_uncertain` 是未确定原因，不是终态技术失败。累计 2468 次生成 + 1 次历史查询 = 2469/2600，余 131。

**本轮增加的是同一命令文件的完整可见覆盖，不是自动导入导航或完整审计链的真实验证。** 三次 source 均由模型请求、都在同一 SHA 的同一文件；没有新的模块定义、日志值构造、最终 logger 或相关旧版本源码。保持草稿合理，但不能把流程无错误或文件读全当效果验收通过。

## 1. 真实窗口与逐行一致性

三次 read_file 都在 `19c1a16dc8b44ba470198c300b25defc7848576f`（19c）的 `airflow-core/src/airflow/cli/commands/connection_command.py`，回执 `total_lines=382`。

| 回执/阶段 | 请求范围 | 实际可见范围 | 保存边界 |
| --- | --- | --- | --- |
| E0012，初读 call 3 | 1–200 | 1–112，112 行 | truncated/context_truncated=true；不能当已读到 200 |
| E0014，补读 call 6 | 112–300 | 112–287，176 行 | truncated/context_truncated=true、has_more=true；不能当已读到 300 |
| E0015，补读 call 7 | 288–382 | 288–382，95 行 | truncated=false、has_more=false |

在内存中仅按回执文本与行号核对：去重后覆盖 **382/382 行、无间隙**，重复的第 112 行相同；与 v75 E0014 的同 SHA 200–300 行比较，**101/101 行逐字一致**。这是保存证据之间的一致性，不是重新读取目标、独立验真或准确率。

- E0012:39 已有 `from airflow.utils import cli as cli_utils, helpers, yaml`；46 起 mapper、96 起 dict helper、109 起默认连接入口可见。
- E0014 包含 export/格式化逻辑、205 行 `@cli_utils.action_cli`、207 行 `connections_add`，以及 URI/JSON/type 参数条件和 Connection 构造、查重、`session.add(new_conn)`。
- E0015 补齐成功提示尾部与异常分支，还显示 delete/import/test；301 与 317 的 action_cli decorators、import helper 的 session.merge/commit 也可见。

这些是命令局部行为。**Connection 表操作不是审计 Log 写入；显示 import/decorator 不等于读取其定义。** 没有 `airflow/utils/cli.py`、`_build_metrics`、`cli_action_loggers.py`、版本文件、相关历史主体或按文件 diff 的 receipt。不得用 v73 当时读过的 logger 或 v72 的 masking 正文回填本轮。

## 2. 实际调度：两次补读工具，第三次决策结束读取

call 1 inspect 两个已有 refs；call 2 执行两次 history、一次 `audit_log` 搜索和一次 CLI 路径 list_files，并自动进行 E0011 跨快照同词搜索。call 3 的三操作计划先执行 E0012 源码读取及 E0013 定向 history，随后首个未执行的 search_code 记录 `read_context_closed/result_allowance_chars=0`；不能把整份三操作计划都计为已执行，也不能称初读没有源码。

call 4–5 初稿时仅 E0012 可见，因此“add/import handler 未读”符合当时边界。call 6、7 分别实际执行 E0014、E0015；call 8 是第三次 followup 决策，保存 completed，但没有新工具回执。call 9–10 自审完成，理由已承认后来读到的 handler 和 decorator，没有沿用初稿的“handler 未读”。

正常 staged 协议允许一次窄工具或 finish_reading；call 8 的无工具 completed 与结束读取分支一致，公开 actions 未保留具体 finish reason，不能断言模型因何认为足够。准确计数是 **三次 followup 决策、两次实际源码工具**，不是三次工具读取，也不是 12 次请求已耗尽。没有 followup failure 或 context-skipped 事件。

初稿后保存压缩 55,352 → 53,270 字符；两次补读后分别 62,084 → 61,301、66,678 → 65,895；第三次决策后 66,292 → 65,895。这些是对应阶段的实测消息字符，不是初读关闭时精确剩余量。初读 search_code 的 allowance=0 是未取得该操作预留，不是目标内容不可用的证据。

### 不把既有探查当 v76 新导航验证

E0009 在 19c 搜 `audit_log`，完整、30 命中；自动 E0011 转到已 inspect 的 `df4cb30b116c8628afc465876e08d58f2bcb897b`（df4），保存 25 命中、截断。这与 v75 已有的首次跨快照搜索相同，不是 v76 decorator/import 定义导航。所有 read_file 的 action 均 `automatic=false`，且没有新模块读取回执。

本轮未观察到新导航实际读取模块定义，不能称自动导入增强已真实通过。未触发的代码级原因另行离线诊断；本文不先归因为 tokenizer、窗口语法或缺失模块头，也不把这些猜测当模型证据。

## 3. 旧版本仍未验证，不能归因为仓库不可读

E0003 的初始化 metadata 确有 `head=null/commit_unavailable`，但 E0004 随后成功列 refs，E0005/E0006 成功 inspect，19c 三次源文均成功。因此该 metadata 不能概括为仓库或所有 SHA 不可读取；它也不同于本轮的终态工具错误计数。

E0007/E0008 是本地字面 commit-message 搜索，各 20 命中、has_more/truncated=true；再次显示 v75 已见的 CLI masking SHA `144aab6a9191c17963da262590830d72dafdcab5` 和 connection audit masking 测试 SHA `826f3bd3803ecc0c9aad17e549735ad0e7b6b0ee`。新增 E0013 在当前 connection_command.py 字面路径搜 `connection`，返回四条消息、has_more=false；它没有读取正文，也不穷尽其它消息或旧路径。

所有 history 均 `negative_result_conclusive=false`。本轮没有跟进上述历史 SHA 的 inspect/source/diff，仍不能建立公告 `<2.11.1` 的源码版本映射。最终 commit 以 unknown 保留，区别于初稿将两次无关变更标题扩成“unrelated snapshots”的过宽概括；变更路径不证明整个快照没有该机制。

## 4. 最终字段、遮蔽条件与引用边界

EP reason 明确 E0002 的公告输入归因，并引用 E0014 显示的 `connections_add` 205–287 行；该区间确在 E0014 内，相关参数读取也在。无审计 sink 时不选择 EP/CO 或拼接 trace，是合理的不确定性保留；空 trace 不应计为业务调用链完成。

CO reason 的“success message with a masked password”比 v75 的 **derived-URI branch** 限定更宽。当前保存源码 283–287 仍是 `args.conn_uri or urlunsplit(...)`，只有后者分支在 password truthy 时用星号；前者优先使用传入 URI。成功提示只在 Connection 不重复且前置处理成功的分支出现，不能写成所有输入或全日志都已遮蔽，更不能用 print 推断未读的 full_command 构造和审计日志消费。

本轮没有重演 v73“logger 未再次脱敏→全链无遮蔽”的 supported 缺陷断言，但没有 producer/logger/旧版本源码重新验证该命题。最终分类与标识明确归因于公告，CWE-532 为机制分类推断、不是公告原列 CWE；这与独立源码证明保持区分。

`location_checks=[]`、`reason_citation_checks={}`，不存在可宣称的 EP/CO/trace 位置通过率。上文是手工对已保存行号的复核，不把未触发机械检查写成通过。初稿/自审摘要有把 inspect 的 changed-path lists 简称“diffs”的措辞，最终字段改称 changed-path lists；本次没有实际 read_diff，报告不得补记一次比较。

结论：文件范围覆盖有进步；日志依赖导航、最终消费者及旧版本目标尚未达成，局部遮蔽表述仍需收窄。所有原结果保留，本文不启动新批次或修改程序。
