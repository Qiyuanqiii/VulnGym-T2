# Airflow v78：自动导入导航实际读到 wrapper，局部遮蔽不能否定整条公告

## 范围与终态

只读已结束的 `D:\VulnGym-bv2-runtime\t2-representative-20260913\regression-airflow-v78-09` 中 summary/review/actions；actions.jsonl 先取每条 `.action` 对象。源码依据回执 `result.text` 和实际行号读取，不假定必须存在 `lines` 字段；可读导出的 numbered_source 也不等于零源码。不新增目标读取、网络、模型请求或目标执行，不改原结果。

统一会话 79121 退出 0：11 HTTP、17 工具、216.626 秒；0 完整、1 草稿，初稿 accepted，followup、自审均 completed。终态模型/工具/pipeline/格式/字段错误为 0，**读取计划拒收恢复 1 次**，整份 annotation 编码拒收为 0；恢复请求包含在 11 次内，没有自动 HTTP 重试。该批结束时累计 2490 次生成 + 1 次历史查询 = 2491/2600，余 109；不是随后 SQL 运行中的实时余额。

相较 [v77 的零 read_file](t2_representative_airflow_v77_review_20260913.md)，本次四个真实窗口覆盖两个文件，**已观察到自动 imported_context_search/source**，不能继续称新导航从未触发。但 `_build_metrics` 只读到中段，最终日志写入及旧版本仍未读，草稿不等于缺陷已反驳或语义全部通过。

## 1. 四次实际源码读取：三个模型请求，一个自动定义窗口

所有 source 均在 `19c1a16dc8b44ba470198c300b25defc7848576f`（19c）；请求范围与实际显示范围一致，四窗口都 truncated=false，但不等于文件或函数全部读完。

| 回执 | 文件和实际范围 | 谁执行/可见内容 |
| --- | --- | --- |
| E0015 | connection_command.py:180–300，121 行 | call 5 模型读取；205 decorator、207 connections_add、输入条件/Connection 构造/成功提示 |
| E0017 | 同文件 1–60，60 行 | call 8 模型读取头部；39 行 `from airflow.utils import cli as cli_utils, helpers, yaml` |
| E0018 | 同文件 300–382，83 行 | call 9 模型读取；delete/import/test 与其它 action_cli decorators |
| E0020 | airflow/utils/cli.py:54–158，105 行 | 自动 imported_context_source；action_cli/wrapper 与 `_build_metrics` 开头，has_more=true、文件共 479 行 |

命令文件本轮仅覆盖 1–60 与 180–382，61–179 未读，不能借 v76 读过全文件而称本次全覆盖。E0015:283–295 的成功提示仍区分原 args.conn_uri 与派生 URI 分支；Connection/session.add 不等于 audit Log 写入。

### 自动导航的确切动作

call 9 之后，actions 明确记录：

- **E0019** `imported_context_search`，automatic=true、semantic_approval=false；引用 E0015/E0017/E0018，实际在 19c 全局搜 `def action_cli`，唯一完整命中 `airflow-core/src/airflow/utils/cli.py:62`。
- **E0020** `imported_context_source`，automatic=true、semantic_approval=false；引用上述三条及 E0019，实际读取 cli.py:54–158。

所以本次验证了从已读限定 decorator、导入绑定到真实定义的自动两工具导航；**E0017 模块头是模型请求，不是自动 header**。不能把三步都写成自动，也不能宣称所有缺失头补读分支都在本例触发。初稿后的自动 E0016 是另一已 inspect 快照 `df4cb30b116c8628afc465876e08d58f2bcb897b` 上的 Connection 搜索，不是这次导入实现读取或旧受影响版本验证。

## 2. 初读、恢复、补读与为何未继续

call 1 inspect 两个已有 refs；call 2 的 history/search 保存量已有界收窄：E0007/E0008 history 实际 17/16 命中，E0009/E0010 搜索 26/22 命中，均保留截断/不完整标记，不能借旧批 20/30 等命中数填充本轮。

call 3 读取计划在参数类型上整份拒收：`invalid_plan_argument_type`、`schema_path=$[0].arguments.path`、`expected_string`。call 4 的 read_plan_encoding_review 恢复成功，之后四操作实际执行 E0011–E0014。公开诊断不包含原错误值，不猜具体传了什么；这与终态 0 错误并不矛盾。

call 5 首先成功读 E0015，随后计划中的 read_diff 因 result_allowance_chars=0、reserve_annotation_review_context 未执行。与 v77 在 history 前关闭、没有源码不同，本次已到达正文；但没有成功 diff，不把请求过的比较当已执行。本例也未保存“跳过不足空间搜索、继续独立源码”的专门动作，不能仅凭源码出现断言该具体分支已被真实覆盖。

call 6–7 初稿，call 8–9 两次模型 followup，随后自动 E0019/E0020；call 10–11 自审。没有第三次 followup 模型调用。call 9 后每输入 12 次上限仅余 3 次，实际保留并完成两次自审；不臆造第四个源码请求或最终 logger 读取。自动导航前后压缩指标为 63,314 → 63,906 → 69,327 字符，均是各阶段保存消息量，不是新的独立上下文额度。

## 3. 真正读到了什么遮蔽，尚未读到什么

E0020 的 wrapper 显示 `_check_cli_args(args)`、`metrics = _build_metrics(f.__name__, args[0])`、`cli_action_loggers.on_pre_execution(**metrics)`，并在 finally 调 post-execution；这是真实局部调用关系。`cli_action_loggers` 的导入/回调实现和实际 Log 写入仍没有源码窗口，docstring 提到 Log ORM 也不是 sink 读取。

`_build_metrics` 自 128 行开始，实际可见：

- 142–144 行分别列出 users/connections、variables 和敏感旗标集合 `-p/--password/--conn-password`。
- 145 行 `full_command = list(sys.argv)`，不是把 handler 的 Namespace 直接复制为命令文本。
- 153–157 行在 sub_command 属于 users/connections、遍历项恰好匹配旗标时，将后一个 argv 元素替换为八个星号；这是空格分隔参数分支，正常执行还依赖相邻元素存在。
- **158 行止于 `else:`**。后续处理、其它敏感参数路径及最终 metrics 返回/装配未显示；truncated=false 只表示请求的 54–158 窗口未被进一步裁剪，不能称 `_build_metrics` 正文完整。

因此可支持“所示分支遮蔽独立 `--conn-password` 的下一项值”。不能扩展为 `--conn-uri`、`--conn-json`、`--conn-extra` 等全部敏感连接参数都已遮蔽，不能在未读 else 下判断等号形式，也不能反向声称这些未见分支一定不遮蔽。公告 E0002 涉及更广的敏感连接参数，不能缩成单一密码旗标。

最终 commit reason 称此局部遮蔽 **contradicting the reported unmasked-audit-value defect**，范围过宽；trace 理由的“shows masking rather than the reported leak”也应限定到所示分支。正确边界是存在局部反证、全链缺陷仍未建立，而不是公告已经被否定。最终保留 uncertain/null 合理，但草稿身份不豁免理由中的过度概括。

## 4. 旧版本、位置与剩余证据

E0012 对真实历史线索再次精确查询 `mask sensitive values in cli`，得到唯一 SHA `144aab6a9191c17963da262590830d72dafdcab5` 及 parent；本轮仍未 inspect/read/diff 此对象。history 是字面 commit-message 结果，negative_result_conclusive=false；当前只读 19c，df4 只搜同文件，仍未建立 `<2.11.1` 旧版本或修复差异映射。

EP 最终为空，但 suggested_values 保留 E0015:264–275 的局部 Connection 构造。这些行确实已读，却不是整个 handler 边界；commit 未选择时，动作的 revision_consistency 记录 `source_ref_selected_commit_unknown`。最终 reason 前缀另有 `source_ref_invalid_commit`，不能将这些位置绑定诊断偷换成“19c 无法读取”，因为四次该 SHA source 都成功。

E0010:1583 的 registration 是可见搜索命中，不是读取了完整注册/分派模块。EP/CO 理由中的 E0015:205 均在可见范围，机械 reason_citations 为 covered；但 location_checks 为空，没有 EP/CO/trace 正式位置通过率。最终 emitter/Log 仍未读，空 trace 不算审计链完成。

结论：自动导入定义导航与初读正文取得实质进步；旧版本、完整值构造与最终日志消费者仍缺，局部遮蔽的否定范围需要收窄。不再因该单例仍草稿而只重复它；后续同版本代表性验证另行记录，本复核不发起请求或改写结果。
