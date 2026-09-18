# T2 代表性候选内容复核（2026-09-13）

## 结论和范围

本记录是 AI 对两个指定、已保存完整候选的有界静态内容复核，不是人工审定、独立准确率测量、全仓安全扫描或目标执行。`complete`、`supported`、schema 通过和 `verbatim_match` 均不等于漏洞语义已经独立证明。原候选保持 `verify=0`，本次不修改原结果或生产代码。

两份候选的 entry / critical operation（CO）/ trace 在其选定 SHA 上均有逐字位置支持；保存源码也支持它们**已经限定的局部数据流**。本次未发现足以推翻这些局部描述的源码反证，但未确认其 SHA 的发布版本归属，也未证明完整部署中的可利用性。n8n 的框架和 helper 未读限制仍然存在；MLflow 的目标配置前提、外部请求库语义和鉴权边界仍不能从局部 handler 推成无条件结论。

执行边界：只读既有 `review.jsonl`、其中的公共 source receipts、明确引用文件在公共本地 Git 缓存中的限定源码窗口，以及 Airflow 前轮有界本地历史诊断。没有网络、付费调用、目标执行、扫描、检出或缓存变更；没有读取 private / gold / selection-lock / source-map 材料。唯一新增文件为本报告。

## 固定输入和引用约定

| 标签 | 保存结果、身份和修订 | 文件 SHA-256 |
| --- | --- | --- |
| N | `D:\VulnGym-bv2-runtime\t2-closeout-20260913\navigation-run-02\review.jsonl` 第 1 行；`entry-43696`；`GHSA-38C7-23HJ-2WGQ`；n8n；`snapshot-guidance-v69`；保存状态 `complete` | `21B96B4BBAEE09DCAA57A9585C45B2765AD4D7B075263FBB8F37EE7DA5F2F1B2` |
| M | `D:\VulnGym-bv2-runtime\t2-web-20260912\090d187f6f614abf\output\review.jsonl` 第 1 行；`entry-22990`；`GHSA-WXJ7-3FX5-PP9M` / `CVE-2025-52967`；MLflow；`snapshot-guidance-v68`；保存状态 `complete` | `9A5E9637FA7AA78079A562262D5C3FE63C4CA4EAB78D7318C34434AA0792C788` |

M 文件还有 NLTK、ONNX 行，本次未复核；不能把输出目录名称或其它行的结果算给 MLflow。以上 hash 针对整个输入文件，不是单行。

`N:E0012`、`M:E0011` 等表示该行 `evidence` 中的原始保存 receipt；证据 ID 只在各自行内有效。下文 `R-*` 是**本次新增复核证据**，不是原运行中的模型阅读记录，也没有回写或追加到原 `review.jsonl`。

本地源码缓存：

- n8n：`D:\VulnGym-bv2-runtime\repositories\n8n-io\n8n.git`。
- MLflow：`D:\VulnGym-bv2-runtime\repositories\mlflow\mlflow.git`。
- Airflow：`D:\VulnGym-bv2-runtime\repositories\apache\airflow.git`。

## 1. n8n：Webhook Forgery on Zendesk Trigger Node

### 原运行实际读到了什么

选定 SHA 为 `24af748fd3c809920afddfe58bf99c7fce6063d9`。`N:E0004` 只给出本地 refs；公告引用的两个 fix SHA 在 `N:E0005/E0006` 均返回 `commit_unavailable`，没有成功的修复 diff 或版本映射。

| 保存证据 | 实际范围和用途 |
| --- | --- |
| `N:E0002` | 公告输入：知道使用 ZendeskTrigger 的工作流 webhook URL 的攻击者，可以发送未签名 POST 并注入任意数据；公告称缺少 Zendesk HMAC-SHA256 验证。给出两个修复版本范围和两个修复 commit URL。 |
| `N:E0009` | 在 Zendesk 节点目录 24 个文件中，对小写字面串 `hmac` 搜索为空；`complete=true` 只限定该字面搜索，不证明其它拼写、其它模块或框架没有验证。 |
| `N:E0010` | `packages/nodes-base/nodes/Zendesk/ZendeskTrigger.node.ts:1-200`。50-57 是 POST webhook 配置；30-48 是节点 Zendesk API/OAuth 凭据配置。 |
| `N:E0011` | 同文件请求 200-432，实际保存可见范围仅 200-307，`context_truncated=true`。不能把请求窗口末尾误当成已经可见。 |
| `N:E0012` | 同文件 307-432，补齐到完整回调；426-431 是 `webhook()` 全函数体。之前创建/删除 webhook 的生命周期代码与该回调分开。 |

### 逐项判断

| 项目 | 支持 | 限定、反证检查与未知 |
| --- | --- | --- |
| SHA 与位置 | `N:E0012` 绑定所选 SHA；本次 `R-N1` 对 entry 426-431、CO 427-430、trace 427 与 429 在同一 Git blob 上逐字对照，全部相符。 | 这证明源码位置，不证明该 SHA 属于公告的受影响发布版本。保存 `revision_basis=behavior_at_revision` 如实表达了不同于版本映射的依据。 |
| entry | `webhook(this: IWebhookFunctions)` 回调取得请求对象；`N:E0010:50-57` 的 POST、`path: 'webhook'` 配置与节点角色一致。 | 不把配置直接当成已读的 HTTP 框架分发边。真实 URL 生成、工作流启用状态、上游网络控制和 HTTP 中间件未读。知道 URL 是公告报告的攻击前提，不是本次运行测出的能力。 |
| CO | `N:E0012:427-430` 将 `req.body` 作为参数传给 `this.helpers.returnJsonArray`，并将其结果放入返回对象的 `workflowData`。完整的六行回调中没有显式签名比较或拒绝分支。 | 此处是节点向工作流交付数据的局部操作，不是已读的后续工作流执行器。`getRequestObject()`、`returnJsonArray()` 实现没有被原运行或本次读取；不能断言 helper 内部逐字保留 payload，也不能凭名字排除验证。 |
| trace | 427 的 `req` 赋值与 429 的 `req.body` 使用在同一完整回调中相邻，中间没有重赋值、条件或过滤。其两项 trace 没有虚构跨函数桥。 | “没有修改”只能指这两处调用之间的可见代码。不得扩大成网络入口到所有下游节点的端到端透明传递。 |
| guard / 前提 | 可见回调正文没有显式签名 guard；配置和生命周期代码与请求消费是不同阶段。 | `N:E0010:30-48` 的 API/OAuth 凭据要求不是该回调已实现请求 HMAC 校验的证据，也不是反证。创建逻辑中至少一个 condition 的校验（`N:E0012:311-313`）是创建 Zendesk trigger 的条件，不能偷换成入站请求签名 guard。是否存在框架级验证仍未知。 |
| 分类与来源 | 标题、唯一 GHSA 标识来自 `N:E0002`；“Improper Authentication / Missing HMAC Signature Verification”结合公告所述机制与局部回调作来源型分类。 | 原 receipt 未列 CWE；这只是模型可见输入的范围，不能据此断言上游公告原始数据绝无 CWE。“HMAC-SHA256 应被验证”来自公告，不是从这个回调单独推导的标准要求。 |

没有发现回调中被候选隐去的显式签名 guard。原候选的短描述使用了“shown handler / shown lines”等限定，field review 也承认 framework dispatch 未读，因此本次不把尚未补全的框架边界误记为候选的已证实错误。

## 2. MLflow：gateway_proxy_handler

### 原运行实际读到了什么

选定 SHA 为 `83b9416cf1cf13216406c81842a5c98c5b1f06fc`（下称 M-selected）；对照 SHA 为 `ba41980d604d7fd7964b038945989a5077d1a645`（M-other）。`M:E0005/E0006` 的提交消息分别是 OpenAI gateway adapter 和 paddle 最低版本维护，均不能凭消息认定是本公告的修复提交。

| 保存证据 | 实际范围和用途 |
| --- | --- |
| `M:E0002` | 公告输入标题为 SSRF，描述 `gateway_proxy_handler` 缺少 `gateway_path` 验证；列出 `<2.22.2` 和 `>=3.0.0rc0,<3.1.0` 两个范围、PR 15970 等引用。没有提供已解析的 fix SHA。 |
| `M:E0007` | M-selected 搜索结果已显示 `mlflow/server/__init__.py:19` 的导入、111 的 `return gateway_proxy_handler()`，但没有该 SHA 的完整路由声明窗口。 |
| `M:E0009` | M-other 的 `mlflow/server/handlers.py:1540-1660`，完整展示 `_validate_gateway_path` 的 GET/POST 格式限制及 handler 调用它。 |
| `M:E0010/E0012` | M-other 的 `mlflow/server/__init__.py:90-130` 和 1-40；路由 111-113 允许 POST/GET 并调用该 handler，导入也可见。与最终选定 SHA 不同。 |
| `M:E0011` | M-selected 的 `mlflow/server/handlers.py:1350-1440`；1374-1401 覆盖完整相关 handler，包含目标未配置的提前返回、请求参数读取、falsiness guard、出站请求及响应分支。 |
| `M:E0013` | M-other 的 `tests/tracking/test_rest_tracking.py:2180-2260`。可见测试源码把 deployments target 设为 localhost，断言空路径/不合格式的 GET/POST 被拒绝以及 DELETE 得到 405。没有执行。 |
| `M:E0014` | M-selected 同 handlers 文件 1230-1349，为其它指标/数据集函数；并未因此读到 `catch_mlflow_exception` 实现。 |

### 逐项判断

| 项目 | 支持 | 限定、反证检查与未知 |
| --- | --- | --- |
| SHA 与位置 | `M:E0011` 绑定所选 SHA；本次 `R-M1` 对 entry 1374-1388、CO 1389-1392、trace 1381-1383 / 1384-1388 / 1389-1392 逐字比对 Git blob，全部相符。 | `behavior_at_revision` 有局部源码依据；没有保存证据把所选 SHA 映射到公告发布范围。其它 SHA 出现校验不是已证明的修复提交身份。 |
| entry | `M:E0011:1381-1383` 从 Flask `request.args`（GET）或 `request.json` 取出 `gateway_path`。 | 原 field review 正确把 M-other 路由声明限定为 registration context，未将它放入所选 SHA 的 trace。本次 `R-M2` 才补读 M-selected 的路由声明 109-111，不能追溯成当时已读证据。 |
| CO | `M:E0011:1389-1392` 把 `request.method`、`json_data` 传给 `requests.request`，URL 由 `target_uri`、斜杠及请求提供的 `gateway_path` 拼接。是清晰的出站请求调用点。 | 源码只直接证明客户端控制 path 拼接片段；`target_uri` 来自配置访问器，而非这个请求字段。没有读取 Requests URL 解析/重定向实现，不能据此宣称可任意替换 scheme/host、访问任意主机或已完成利用。 |
| trace | 三项连续覆盖参数读取、空值拒绝和出站调用。1389-1391 的方法与 JSON 赋值没有被跳过；没有跨 SHA 拼接运行时链。 | 这是 handler 内局部链，不是已验证的部署鉴权→Flask→HTTP 客户端→远端返回全链。 |
| guard / 前提 | 1376-1379 明确：未配置 truthy `MLFLOW_DEPLOYMENTS_TARGET` 时直接返回空 endpoints，不发请求。1384-1388 明确拒绝 falsy `gateway_path`。 | 所以“无任何 guard”或“不配目标也可请求”都被保存源码反驳；原候选 code 保留了这些分支，文字“only falsiness guard”应理解为对 `gateway_path` 的局部校验，不能泛化为整个 handler 仅有一个前提。非 GET 输入还需提供可供 `.get()` 使用的解析对象；任意无效 JSON 都能到达 sink 未获证明。 |
| 校验对照 / 反证 | M-other 中 GET 限于去掉首尾斜杠后的 `api/2.0/endpoints`；POST 使用 `re.fullmatch` 限制 `gateway/{name}/invocations`（`M:E0009:1544-1562`）。这与 M-selected 缺少同类格式限制形成有意义的行为对照。 | 不能把对照 SHA 的校验“搬回”所选 SHA 作为反证。`M:E0013` 是对照 SHA 测试源码，不是测试执行结果，也不说明所选 SHA 通过相同测试。路由显式声明 GET/POST 的完整窗口在原运行来自其它 SHA；本次同 SHA 补读后才得到更强支持。框架可能隐式处理的其它 HTTP 方法未核对，不能将显式列表宣称为完整运行时方法集合。 |
| decorator / 框架 | 原 receipt 显示 `@catch_mlflow_exception` 的应用，但没有其实现。本次 `R-M3` 读到 wrapper 直接调用函数，仅捕获 `MlflowException` 并格式化响应。 | 本次未发现这个已见 decorator 是前置访问控制或路径校验；但这不排除未读的应用级鉴权、插件、反向代理、HTTP 库等其它层。不能把相邻函数上的 `_disable_if_artifacts_only` 误归给此 handler。 |
| 分类与来源 | 标题、CVE/GHSA 和 SSRF 一级标签由 `M:E0002` 归因；局部源码支持“未经路径格式限制的 gateway_path 被转发到配置的 target”这一二级机制描述。 | SSRF 标签不等于已独立证明任意主机控制。简述“before 3.1.0”来自公告描述，但不能取代公告同时列出的 2.x 修复线，也不能推出所有 `<3.1.0` 版本均受影响。 |

没有发现已读 `M:E0011` 中存在被候选漏掉的路径格式 allowlist。当前完整候选足以表达受限定的局部源码机制，不足以输出无前提的远程利用结论。

## 3. 本次新增复核证据与可复现边界

| 新证据 | 有界操作和结果 | 与原证据的关系 |
| --- | --- | --- |
| `R-N1` | 对 N-selected 的明确引用文件做 `git show SHA:path`，取四个选定字段的行范围，按 LF 拼接并用 ordinal 字符串比较：4 处相符。 | 再核验原候选位置；没有新增 n8n helper/框架阅读。 |
| `R-M1` | 对 M-selected 的明确引用 handlers 文件采用相同方法：5 处相符。 | 再核验原候选位置；不能当成漏洞语义评分。 |
| `R-M2` | M-selected `mlflow/server/__init__.py:109-111`：`@app.route(_add_static_prefix("/ajax-api/2.0/mlflow/gateway-proxy"), methods=["POST", "GET"])`，随后 `serve_gateway_proxy()` 调用 handler。 | 原运行在该 SHA 仅有搜索命中 111；完整 decorator 先前读取的是 M-other。这是新增的同 SHA 注册对照。 |
| `R-M3` | M-selected `mlflow/server/handlers.py:570-581`：`catch_mlflow_exception` 的 wrapper 直接调用 `func`，捕获 `MlflowException` 后返回 JSON 错误响应。 | 原模型未读此实现。本次只消除“这个 decorator 可能先做路径校验”的局部未知，不消除所有框架未知。 |
| `R-M4` | M-selected 同 handlers 文件 2578-2582：`_add_static_prefix` 从环境取前缀，有值时拼到 route 前；否则返回原 route。 | 路由字面值可能带部署静态前缀；不是固定裸 URL 的部署证明。 |

本次位置对照的第一次 PowerShell 调用错误地把 hashtable 属性放进原生命令参数，Git 返回 `not a git repository`；那次 `false` 比较均没有有效源码输入，已作废。修正为明确字符串参数并增加 Git 退出码检查后，才得到上表 4+5 处有效结果；没有把命令失败解释成源码反证。

只读取目标 Git 对象，没有 import / 执行目标模块、测试、服务、HTTP 请求或利用代码。保存测试文件的内容也仅按源码意图理解。

## 4. 对通用阅读策略的启示

这些限定本身并不是必须“补成完整标注”的理由。当前两行没有发现需要通过产品硬编码答案来修正的真实源码矛盾。可泛化、可用合成数据测试的策略是：

1. **身份、版本和机制分开。** 引用存在、SHA 可读、源码相符、行为相关和发布范围匹配是不同证据。`behavior_at_revision` 不得在输出端被隐式升级成 affected release / exact fix attribution。
2. **一条最短同 SHA 桥优先于邻近无关窗口。** 已有搜索结果指向注册/consumer 时，优先补读那一个具体声明/调用窗口；不要仅因同文件邻接就将读取预算花在不相关函数。MLflow 原 `E0007` 已提供同 SHA 的 caller 行，而后续 `E0014` 是其它函数。
3. **显式保留前提和局部 guard。** 未配置目标就返回、空参数被拒绝、HTTP 方法范围等必须随局部机制一起解释；“缺少特定校验”不能缩写成“没有任何校验”。n8n 的配置凭据与生命周期条件不能当成入站认证。
4. **负向搜索与未读 helper 都有边界。** 一个小写字面搜索为空不构成全框架没有 HMAC 的证明；helper 调用处不等于 helper 实现已读。保留未知，必要时只追加一条语义相关的 consumer/helper 阅读。
5. **后续复核不能回填原模型覆盖。** R-M2/R-M3 的补读增强了本报告，不改变原 v68 运行当时缺失同 SHA 路由完整窗口和 decorator 实现的事实。

## 附录 A：Airflow 旧版本与日志消费者可用性定向诊断

此附录概括前轮**人工指定调查方向、由 AI 执行的有界定向诊断**，不是原运行模型自行发现的证据，也不是人工审定。它不为 Airflow 补写 entry、CO、trace 或发布归属结论。

对象是 N 同一结果文件第 3 行：`GHSA-8R55-RV5W-6PFM` / `CVE-2025-27555`，Airflow。公共公告输入指出 `<2.11.1`、CLI 连接敏感值进入 audit log，并引用 PR 61882。原运行 `E0004` 列举 refs，`E0005/E0006` 检查两个 3.x-era SHA，源码只读 `connection_command.py` 和 `utils/cli.py`；没有一次 `search_history`，也未读最终 logger。自动 `E0014` 只是补读 `_build_metrics` 后续掩码窗口。

### 实际可用性

- 本地 bare repo 只有 `refs/vulngym/19c1a16dc8b44ba470198c300b25defc7848576f` 和 `refs/vulngym/df4cb30b116c8628afc465876e08d58f2bcb897b` 两个 refs，无版本 tag；`rev-parse --is-shallow-repository` 为 false。两个 refs 不等于只有两个可读提交。
- 对两个 refs 可达历史进行有界字面消息搜索，PR `61882` / CVE 数字 `27555` 没有命中。本地没有对应 PR named ref；这只说明在此搜索范围未发现，不能证明所有本地对象或其它分支均不存在关联修复。
- `airflow/__init__.py` 历史可找到 `b769870bc802589dc32d43cf0cd8cf93f7dd0872`（更新版本为 `3.0.0.dev0`，PR 41456）。其 parent `1a09e3412d7b963797cdab99b6efb45e18513daa` 可读，且经 `merge-base --is-ancestor` 确认是所选 `19c1a16…` 的祖先；该 parent 的 `airflow/__init__.py:20` 声明 `2.10.0.dev0`。
- 这证明可读取 2.x-era 开发源码，不证明这是某个正式发布 tag 或公告指定受影响版本。版本字符串、源码行为和公告归属仍须分别论证。
- 该旧 parent 的 `airflow/utils/cli.py:142-160` 只对 `-p`、`--password`、`--conn-password` 做掩码，再把 `full_command` 放入 metrics。`airflow/utils/cli_action_loggers.py:106-120` 转交 `full_command`，126-168 将其序列化入 `Log.extra` 并提交，188 注册默认 callback。
- 原选定 `19c1a16…` 的最终消费者也可读：`airflow-core/src/airflow/utils/cli_action_loggers.py:70-84` 分派 callback，107-147 将 `full_command` 写入 `Log.extra`，166-167 注册默认 callback。之前并不是文件不可用，而是没有导航到该文件。

### 路径迁移造成的历史搜索盲点

在所选 `19c1a16…` 上，不加 path 的字面历史查询 `Masking details` 可找到 `25ef2dff8247bc48600c19d219fb23622f1e1fa8`，消息为 “Masking details while creating connections using json & uri (#46595)”。其 parent 是 `a2ee4b2edd9ae63fc2a71c32d343e2e0cb04bb8f`，diff 在旧路径 `airflow/utils/cli.py` 添加 conn-json/conn-uri 处理。

同一个查询若过滤当前路径 `airflow-core/src/airflow/utils/cli.py` 则为空。现有 `RepoReader.search_history` 使用字面 path，不跟踪 rename；一次负向当前路径查询后，可有界地退回不加 path 的同一查询。该掩码提交及其 parent 已处于 `3.0.0.dev0`，不能把它们自动认作公告的 2.x 修复/受影响 revision。

通用修正是把“refs 已枚举”“历史已查询”“版本证据已读”“消费者已读”分开计覆盖：当看到掩码却未匹配公告版本时，允许一次有界历史/版本调查；看到外部 logger 调用时，保留一次跨文件 consumer 阅读。空结果不升级为不存在，读到旧代码不自动批准漏洞或补齐字段。

相关产品 API 已存在于 `vulngym_t2/repository.py:215`（`list_refs`）和 274（`search_history`）：固定字面查询、有界输出/时间、`negative_result_conclusive=False`。此诊断不要求增加针对 Airflow 的名称、SHA、路径或答案规则。

## 附录 B：后续 v70 运行复核

本报告形成时，尚未纳入后续 v70 运行的实际动作和 source receipts。根代理可另续本附录；不得把上文定向诊断或本次补读算作该运行自行完成的阅读。
