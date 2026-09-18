# T2 保存结果收尾内容复核

日期：2026-09-13。本次由 Codex 对保存的公开材料、源码回执、字段理由及最终判读作有界内容一致性检查；不是人工认可、独立 T1 判断、目标执行复现或新样本测试，不提升 `verify`。

检查对象为 `D:\VulnGym-bv2-runtime\t2-web-20260912\090d187f6f614abf\output` 的 `entries.jsonl`、`review.jsonl`，并核对 `summary.json` 的终态计数。未改写这些文件；未读取私有答案、gold、selection_lock 或 source-map，未联网、调用付费模型、运行目标代码或新增漏洞发现。

## 三条结果的有界判断

下面证据编号均为对应条目 `review.evidence` 内的局部编号，不能跨条目混用。三条均为 `complete`、`verify=0`，commit 判断均使用 `behavior_at_revision`，没有证明 SHA 与公告发布范围的对应关系。

| 条目 | 保存依据支持什么 | 仍未证实、不能扩写什么 |
| --- | --- | --- |
| MLflow / `entry-22990` / `83b9416` | E0011 的同版本函数保存请求取值、`gateway_path` falsiness 判断和出站请求，支持局部 EP/CO/trace。描述已不再将条件缩成“只拒绝空字符串”。 | E0010 的路由注册来自另一 SHA `ba41980d`，最终理由明确仅作上下文；本版外部调度、实际部署及发布范围仍未证。不得把局部路径参数限制缺失扩写成任意目标均可访问。 |
| NLTK / `entry-17579` / `f9036018` | E0014 的请求路径读取、E0011 的 lookup 分支、E0012 的实际调用/赋值及 `if not body` 中插值，支持已显示的局部入口、操作和调用连接。E0005/E0006 只另作修复对照。 | `Reference.decode` 内部未读；攻击者控制来源和服务器注册明确归于公告 E0002，不是源码闭环或部署可达证明。保留具体 `if not body` 分支条件，不扩写为所有请求都反射输入。 |
| ONNX / `entry-36448` / `084c9291` | E0010 保存同一函数内下载文件、打开归档、`extractall(models_dir)` 的连接，且调用未显式传 `members`/`filter`。E0009 是另一 handler 的过滤上下文。 | 归档攻击者控制来源归于公告 E0002；tarfile 运行时默认过滤未检查。只能陈述本函数缺少显式参数和成员检查，不能宣称所有 Python 环境均无过滤、必然覆盖文件或已完成利用。 |

在这些限定下，未发现需要仅因缺少完整路由/部署资料而否定局部 EP/CO/trace 的明确矛盾。此结论不是全部字段语义正确；更强的版本、输入控制及运行时影响判断继续待审。现有 R3/R5/R6/R7 已涵盖这些区别，无需加入案例答案或新固定验收门槛。

## v68 过程计数勘误

原工作台及目标文档的“填表重编码 0”不符合保存 actions，现已改为 **1 次恢复**；终态错误 0、提供商解析拒收 0、读取计划重编码 0 与此不矛盾。位置对象形状校验拒收不等于提供商解析拒收。NLTK 的两个字段诊断来自同一份快照，只计一次恢复。

`review.jsonl` 第 2 行 `entry_id=entry-17579` 的事件如下，`actions` 下标从 0 起；事件未保存时间戳，不臆测精确发生时刻：

| 字段路径 | 保存值 |
| --- | --- |
| `actions[38]` | `model_call`，`call=8`，`stage=self_review`，`prompt_revision=snapshot-guidance-v68` |
| `actions[39]` | `annotation_snapshot_rejected`，`stage=self_review`，`code=invalid_location_shape` |
| `actions[40]` / `actions[41]` | EP/CO 的 `value` 各有多余 `status`；两条 `unexpected_properties` 诊断 |
| `actions[42]` | `model_call`，`call=9`，`stage=encoding_shape_review`，同一 v68 提示版本 |
| `actions[43]` | `annotation_snapshot_reencoding`，`stage=self_review`，`summary=recovered` |

本条最终 `annotation_errors=[]`，本批 `summary.annotation_error_count=0`；终态无未解决错误不能抹去上述恢复。第 9 次调用已经包含在 NLTK 的 9 次及全批 25 次请求中，不增加历史用量、不冒称 HTTP 自动重试，也不与旧 v67 根字段拒收混算。

报告应分开写终态未解决错误、提供商解析拒收、读取计划重编码和填表形状恢复；“当前提示版本”应与本次保存回执一致。本次只勘正文档并保存复核边界，原始成功、失败和不确定记录均保留。
