# Airflow v79 定向复测：终态内容复核

只读主任务确认已终态的 `D:\VulnGym-bv2-runtime\t2-representative-20260913\regression-airflow-v79-10` 中 summary/review/actions；actions.jsonl 先取每条包装记录的 `.action`。依据保存源码正文及实际范围复核，不新增目标读取。生成代码和原结果均未修改。

结论：已真实读取第二个 SHA 的源码，并再次触发 imported_context_search/source；不能写成零跨 SHA 源码。但相关旧版行为、`_build_metrics` 后半及最终日志写入三个缺口仍未闭合。最后补读因保留最终自审的上下文停止，不是 16 次请求上限耗尽。保留草稿是合理的不确定性结果，不代表理由中的所有表述都正确。

## 终态与停止原因

summary：completed，11 HTTP、21 工具、117.910 秒，0 完整、1 草稿；model/tool/pipeline/format/annotation 终态错误为 0。1 次读取计划拒收由 call 4 恢复，整份编码拒收为 0，自动 HTTP 重试为 0；followup 与 self_review 均 completed。profile 为 low，run_request_limit=16。累计授权计数采用主任务统一口径，本页不将 provider 的生成计数误作含历史查询的总计。

- call 3 的 `path` 类型被整份拒收；call 4 为唯一读取计划重编码，不能说全程没有拒收。
- call 5 初读先完成 E0015，随后 `read_diff` 的 `result_allowance_chars=0`，保存 `read_context_closed: reserve_annotation_review_context`。没有 read_diff 回执，不应把未执行比较当成真实阴性结果。
- call 6/7 为初次评估/编码；之后先自动取得 E0016–E0020，再进入模型补读。
- call 8 模型读 E0021 头部，call 9 模型读 E0022 命令文件后段，随后自动取得 E0023/E0024。未出现第三次补读模型调用或主动 finish_reading。
- 最后压缩动作记录 `after_chars=81902`；紧接着 `evidence_followup_skipped: reserve_review_context`，`selected_location_review` 便利预览也因上下文省略。call 10/11 完成最终评估/编码。
- call 9 后本地/run 请求余量为 7，足够原来的 `1 次决策 + 2 次自审 + 1 次编码纠正` 预留；工具也未用尽。用冻结 v79 的预算函数只代入保存的字符总数，得到 `100000 - 81902 - (476 + 1514 + 512) - 14964 - 2048 = -1416`，因此补读 allowance=0，小于最低 4096。这是纯预算算式核对，不重建或重发模型请求。

与 v78 相同的 11 HTTP 并不表示相同停止原因：v78 为 12 次上限下的请求预留；v79 的保存动作明确为上下文预留。两轮 profile/请求上限也不同，不能把本次变化单独归因于指令修复。

## 公开材料参数

- `--input D:\VulnGym-bv2-runtime\t2-representative-20260913\inputs\regression-airflow-only.txt`
- `--cache-dir D:\VulnGym-bv2-runtime\t2-closeout-20260913\new-inputs\cache`
- `--repo-map D:\VulnGym-bv2-runtime\t2-closeout-20260913\new-inputs\repo-map.json`
- 公告 URL：`https://github.com/advisories/GHSA-8r55-rv5w-6pfm`。
- map 中该公告指向公开本地仓库 `D:\VulnGym-bv2-runtime\repositories\apache\airflow.git`。

输入文件、map、公共仓库目录与缓存 `GHSA-8R55-RV5W-6PFM.json` 均存在；缓存 2708 字节。单例 URL 与原 `regression.txt` 第二条逐字一致。核对未输出公告长文本、密钥或私有材料，未执行生成 CLI、模型请求或目标源码。以上是材料参数，不是额外运行授权。

## v78 已保存基线

基线见 [v78 内容复核](t2_representative_airflow_v78_review_20260913.md)。v78 有 11 HTTP、17 工具、四个实际源码窗口；没有旧版本源码或差异比较。E0019/E0020 的 imported_context_search/source 成功读到 `action_cli` 与 `_build_metrics` 开头，后者在第 158 行 `else:` 处结束。最终 emitter/日志写入尚未读取。局部密码参数遮蔽不能扩大成“全部敏感值安全”或公告缺陷已被反驳。

## 实际源码与导航

两个实际 source-read SHA：A=`19c1a16dc8b44ba470198c300b25defc7848576f`；B=`df4cb30b116c8628afc465876e08d58f2bcb897b`。A/B 是引用简称，不是版本或受影响标签。

| 回执 | 实际 SHA / 文件 / 范围 | 来源与作用 |
| --- | --- | --- |
| E0015 | A / `airflow-core/src/airflow/cli/commands/connection_command.py` / 180–300 | call 5 模型读；包含完整添加消息构造及 295 行 print |
| E0017 | B / 同命令文件 / 127–239 | automatic alternative_snapshot_read；包含导出尾部、URI 判断与添加函数开头，239 行止于条件语句，未覆盖完整添加/日志机制 |
| E0019 | A / `airflow-core/tests/unit/cli/commands/test_connection_command.py` / 497–609 | 自动 entry_navigation 命中的测试调用；提供 parser→handler 的测试调用证据，不是运行时日志写入 |
| E0021 | A / 同命令文件 / 1–60 | call 8 模型补头部；39 行给出真实 cli_utils import |
| E0022 | A / 同命令文件 / 300–382 | call 9 模型补读；可识别限定 decorator，触发导入导航 |
| E0024 | A / `airflow-core/src/airflow/utils/cli.py` / 54–158 | 自动 imported_context_source；wrapper 完整，metrics helper 仅前半 |

共六个成功 read_file 窗口、三个不同路径、两个 SHA；不能将其中测试文件误作最终消费者。正文保存在 `result.text`，可读导出的 numbered_source 只是呈现形式，不是新增证据。

自动导航分两段：E0016 搜 B 的 `connections_add`，E0017 读实际窗口；E0018 搜 A 的同名引用，E0019 读测试，再由 E0020 搜测试函数，`entry_navigation.stop_reason=no_usable_reference_hit`。后者停在测试链不是找到审计写入。最后 E0023 搜真实 `def action_cli`，完整唯一命中 A 的 utils/cli.py:62；E0024 读 54–158。imported_context_search/source 的引用为 E0015/E0021/E0022（source 再加 E0023），均成功、semantic_approval=false；本轮无自动 header action，头部是模型 E0021 所读。

## 旧版本与三个机制缺口

- **旧版本：未建立。** B 已读源码是相对 v78 的新增覆盖，但既没有 `<2.11.1` 映射，也没有完整的相关机制比较，不能直接称作受影响旧版。E0012 仍只将历史标题搜成 `144aab6a9191c17963da262590830d72dafdcab5`（附真实 parent），其后没有 inspect/read/diff 该候选。E0007/E0008 的历史列表有截断；本轮没有对 PR 61882 做相应查找或证据充分的不存在证明。
- **metrics 后续：未读。** E0024 96 行由 `_build_metrics` 得到 metrics，97 行调用 on_pre_execution；117–119 行 finally 调用 on_post_execution。128 行起定义 helper，142–157 行仅显示部分子命令/敏感旗标处理和局部 `full_command=list(sys.argv)`；158 行止于 `else:`。尚未见后续参数形式、完整分支、返回字典或其 `full_command` 装配。
- **最终 logger：未读。** 两个实际回调调用可见，不等于实现、配置分发、Log 对象构造或最终持久化已可见；本轮任何 read_file 都不位于该消费者实现。对敏感值到审计写入的必要连接仍有真实缺口。

## 为什么仍为空，以及理由的准确性

最终 commit、EP、CO 均 uncertain/null，optional trace=[]。trace 的公开状态由控制器按“空可选链不作断言”处理，原模型 uncertain 判断保存在 omitted_assessment；不是链路被模型证实。metadata/title/category/IDs 的完成不能替代三个必要字段的事实支持。

未知并非只因版本表缺失：本轮实际消费/日志机制和相关旧快照仍未建立，因此保持草稿具有事实依据。但最终理由需要如下收窄，不能把草稿标签当成内容全对：

1. **局部遮蔽只部分纠正了旧反证范围。** 最终字段理由使用“unmasked audit-log leak is not established”，比 v78 的“与缺陷矛盾”更审慎；但 self_review assessment 仍称两次本地读取“are not this report's affected revision”。没有 release 映射或完整机制证据，最多能说未建立受影响版本，不能反推不受影响。最终 commit.reason 又称所引 PR “absent locally”，本轮回执不能支持整个本地历史不存在该变更。
2. **把未读的 metrics 装配写成了已读事实。** CO.reason 称回调收到 `metrics["full_command"]=list(sys.argv)`；E0024 只证明 helper 内的局部列表创建及回调接收 `**metrics`，helper 返回装配未读。这条数据连接仍需核实，不可按常识补全。
3. **错误地声称已读打印消息尾部 unread。** E0015 283–295 行已包含 URI/fallback、格式化结束与 `print(msg)`；287 行的遮蔽仅在 fallback 分支，283 行的非空原始 URI 分支另行保留。可说其与审计 logger 的关系未读，不能说该消息构造尾部未读。初次 assessment 其实正确识别了 280–294 构造和 295 print，最终自审的“unread tail”是退化，不是新证据。
4. **有保存的引用检查问题。** EP.reason 引 E0010:1583 作为 registration hit；E0010 是 search_code，不是 source read。`reason_citation_checks.entry_point` 明确记录 `reason_citation_read_required`。该搜索行可作导航线索，但不能把它当完整 read_file 位置支持；零 annotation_error 不会消除这一检查。

CO 仅保留 142–158 的 metrics 构造/遮蔽窗口为建议，未批准成最终审计写入位置，这一点比强行填满谨慎。没有证据证明最终 logger 安全或漏洞成立，也没有把声明/配置一刀切排除；本例关键是执行型日志消费者仍未读。

## 最小后续方向（未执行）

优先规划仍未完成的必要依赖：继续实际 helper 的边界后内容，再用真实调用/导入确定最终 logger 消费者与条件；版本问题可从 E0012 的实际历史命中先 inspect，再决定是否需源码比较。均不得把标题、parent 或局部密码遮蔽变成版本/安全结论。

这里暴露的是读取顺序与可用上下文分配问题，不支持仅再提高 HTTP 上限：本轮请求有余而第三补读上下文不够，先前自动另快照/测试导航消耗了可见上下文却未闭合核心机制。后续是否改导航或预算应另行评估；本页未实施改动或开启请求。原源码、历史和最终结果均保留，不将本次诊断注入后续模型输入。

### 自动测试窗口的只读定位

冻结代码中 `pipeline.finish_draft:1603` 在模型 followup 前调用 `navigate_entry_context`。该方法的 imported 分支（1430）本来优先于 alternative/caller 且结束后立即 return；但 E0015 时尚无实际模块头导入，不能建立 import seed。alternative 分支（1456）读完 E0017 后没有 return，1498 又进入 `navigate_entry`，因此一次初始自动扩展叠加了另快照与反向 caller 两种目的。

`entry_navigation._hits:540` 已给非测试路径更高优先级，并非主动偏爱测试。然而 E0018 保存结果经原选择器纯回放所得的十个可用调用命中全在测试文件，首个为 577 行。`navigate_entry:608` 仍读取首个命中的 497–609 窗口，再把可见测试函数当成上一层符号搜索，产生 E0020，才因无可用调用停止。搜索结果或测试调用均不证明部署时的审计日志消费者。

没有证据表明 imported dependency 之后又重复反向搜索：E0024 后动作仅为 compact、followup 停止和自审。单条 followup 的 `pipeline:1653` 仅执行 receipt-only imported 导航；不再调用整个旧 entry 导航。E0014 是路径限定的声明查询，E0018 是全局 caller 查询，也不能把两者简单称作相同参数去重失效。

最小策略候选是：当本次自动反向引用搜索只剩测试调用，且单条仍有模型决策阶段时，保留真实 search 回执但暂停自动测试窗口/反向追测试函数，让模型在必要 consumer、当前边界续读和测试证据之间作有预算的选择；这不是全局禁止测试或认定没有 caller。另一候选是一次自动 pass 只完成一个读取目的：完成 alternative 的实际 source 后返回，不再同 pass 叠加 caller 链。两者都需另行验证；本页未实施。

E0019 前后保存的 compact 字符数由 62226 增至 68008，增量 5782；本轮若其他上下文完全不变，从 allowance 原始余量 -1416 恢复到最低 4096 需释放 5512 字符。这只是说明测试窗口占用与下一次实读余量同量级的字符投影，不证明移除它后模型必然选择正确依赖，更不证明缺陷/安全结论。
