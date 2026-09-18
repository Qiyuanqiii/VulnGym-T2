# 原两例 v74 回归：真实覆盖与中断复核

## 范围、终态与结论

只读已结束的 `D:\VulnGym-bv2-runtime\t2-representative-20260913\regression-v74-05` 中 summary/review/actions，与 `regression-v73-04` 对照。不新增目标源码、网络、模型请求或目标执行；只新增本文，不改代码及原结果。另只读首次快照选择条件解释未触发原因，不把程序诊断当作模型读到的目标证据。

父任务确认会话9171退出0。summary为 `completed`：2输入、0完整、2草稿，19次HTTP、34次工具、84.649秒；0终态格式/字段异常，1模型错误、2工具错误、3pipeline错误。LangChain两个读取错误为整份diff超限及另一commit不可用；Airflow一个followup错误同时计入模型/pipeline，不能重复相加为多个独立事件。`completed`表示批处理结束，不表示每个候选完成自审；全部 `verify=0`。

**本轮没有验证原两例收尾目标已达成。** LangChain仍无源码，虽然末尾终于实际搜索了另一已inspect快照；Airflow读到了新增连接handler，但没有值构造/helper或最终日志消费者，且第二次followup失败使自审未运行。不能把它从v73完整变草稿当成原误判已经被正确复核修好。

| 项目 | v73 | v74 |
| --- | --- | --- |
| LangChain | 11模型/22工具，0source，草稿 | 11模型/18工具，0source，草稿；晚期c2搜索有实际receipt但无声明窗口 |
| Airflow | 11模型/13工具，3source，涉及cli与logger；完整候选有上游未读问题 | 8模型/16工具，3source，全部是connection_command；followup失败，自审未运行 |

## 1. LangChain：无合格空查询，宽泛命中仍挡住early probe

本轮E0005仍成功inspect `c2a3021bb0c5f54649d380b42a0684ca5778c255`（c2），给出父SHA；E0006整份diff失败 `git_output_limit`；E0007另一公告SHA `commit_unavailable`。探索阶段其余list/search/history都在 `b7d1831f9d3560ed4fb45134861eef3f4544eff3`（b7）。

v74 selector已经接受裸符号，不能重复v73“裸词语法不允许”的解释。`revision_navigation.py:149–218`仍要求实际 `search_code` 完整、未截断、结果为空，然后原样复用查询到尚未尝试的已inspect SHA。本次：

- E0009 裸 `GraphCypherQAChain`：`complete=true`，12命中，非空；不能触发当前empty-only规则。
- E0012 限不存在的community graph_qa路径查询 `cypher`，E0015限 `libs/community` 查询 `GraphCypherQAChain`：虽然0命中，均 `complete=false`。
- E0016空的是 `search_history("cypher injection")`，不是source符号查询；空list_files也不构成seed。

因此本轮没有任何满足要求的完整空source查询，足以解释没有 `initial_snapshot_search/source`；并不是新裸词支持完全未接入，也不是c2已被证明没有实现。当前规则仍不能把“完整查询有迁移/shim引用但没有实际声明”识别成另一种源码导航缺口。

### 晚期跨快照搜索确实发生，但没有读到主体

6次探索调用后保存 `read_context_closed=reserve_annotation_review_context`，第7/8次为初稿；第9次followup的E0021 **实际在c2搜索** `GraphCypherQAChain`。其保存结果 `complete=false/truncated=true`，只可见 cookbook/code-analysis-deeplake.ipynb 的897、1068两处字符串，没有类声明。不能称本轮从未尝试c2，也不能把后面未显示的命中补成模型证据。

随后第10/11次自审，没有read_file，没有成功按文件diff，更没有旧父版本运行主体。与v73相同的每输入12次预算下，第9次后只剩自审2次＋编码保留1次，不足进入另一次followup；这里未保存显式budget-stop日志，属于调用序列与既有预留规则的解释。

最终commit/EP/CO为空、trace为空，对本轮没有源码机制的状态合理。commit理由不再明确声称v73的“no graph-qa change”，但提交标题/截断路径列表仍不能否定整个snapshot。EP理由把E0020与搜索引用并列，而E0020实际是截断list_files；community路径为空也只能限定到实际查询的b7，不能扩展成所有已inspect快照不可读。

## 2. Airflow：裸词探针已执行，真实source仍只在handler文件

已inspect的SHA仍是 `19c1a16dc8b44ba470198c300b25defc7848576f`（19c）及 `df4cb30b116c8628afc465876e08d58f2bcb897b`（df4）。

- E0012在19c的CLI路径搜索裸 `add_connection`，完整且0命中；自动E0015把同查询转到已inspect的df4，记录 `initial_snapshot_search` 成功，但仍完整0命中，因此没有探针source read。这个动作是v74裸词支持真实运行的证据；实际函数名后来在E0019显示为 `connections_add`，不能把最初空查询当作新增连接功能不存在。
- E0016读取19c `airflow-core/src/airflow/cli/commands/connection_command.py:1–200`，包含39行真实 `cli as cli_utils` 导入，以及mapper/get/list/export。
- 自动E0017在df4同文件搜 `_connection_mapper`，E0018读取1–78。这是另一snapshot的文件前段，不是相关旧版本或完整handler验证。
- 第7次模型调用、首次followup得到E0019：请求19c同文件200–382，实际保存 **200–373**，`truncated=true/has_more=true`。205–207已含action_cli decorator与connections_add；209起读取URI/JSON/type等输入并检查互斥/必要条件，255–275构造Connection，后续还有delete/import及test开头。

本轮3次source只涉及一个不同文件。**没有 `cli.py` wrapper、`_build_metrics`、`cli_action_loggers.py` 注册/写Log实现的receipt；没有发布版本文件、相关旧行为snapshot或修复diff。** E0019的Connection构造/写Connection表不是audit Log写入；不能用它替代缺失的日志消费者。URI/JSON参数条件也不能偷换成日志内容已脱敏的证明。

## 3. followup失败的证据边界：不要猜被拒工具名

Airflow调用序列：4次探索 → 第5/6次初稿 → 第7次followup成功读取E0019 → 第8次followup标记failed。记录错误只有 `Focused evidence follow-up failed or exceeded its allowed read scope; preserving the draft for review.`，没有为这次失败保存tool名称、arguments或新的tool receipt；`self_review_status=not_requested`，没有任何self-review模型调用。

父任务在本轮结束时的代码核对发现：v74阶段schema已增加search_history，但finish_draft执行筛选仍是旧四工具集合。这是**接口与执行检查不一致的代码层诊断**，可以解释该类followup拒收；然而本次保存的失败记录没有实际请求内容，因此“本次一定请求了search_history”只能推断，不能作为已观察事实，更不能计作一次成功历史读取。复核时当前工作代码已经进入后续接线修复，不能拿新代码替换v74当时执行状态。

### 未自审造成的过时理由

保留的初稿EP/commit理由仍称E0016只有get/list/export、未读add handler。这准确描述初稿当时的E0016，却与后来E0019已读connections_add的最终证据集合不再一致；由于后续失败未自审，不应当作模型在新证据基础上又作出的最终否定。

commit理由还把两个提交主题“不修改日志/连接”扩展成“no inspected SHA fits”。差异主题不是整个snapshot没有该机制的证明。最终日志/旧版本确实未读，但“add handler未读”已不再成立，应分别报告，不把真实缺口与失败前的旧理由混在一起。

v73的“logger局部未再脱敏→整条命令未脱敏”误概括，本轮没有相应producer/consumer源码和完成的自审来重新评判，因此 **未验证修好**。草稿和技术失败边界保留是正确的，但不能把少一个完整候选算作语义准确性提升。

## 4. 本轮留下的最小落点

LangChain的剩余导航缺口是引用/shim命中与真实声明的区分，以及定向跨快照源码窗口，不是重复扩大全仓搜索。Airflow应先完成schema到执行的通用接线，再验证实际值构造、日志消费者及必要旧版本；失败记录未保存的请求内容不能事后补造。v73/v74原结果、草稿及验证标志全部保留；本文不启动新运行或修改任何程序。
