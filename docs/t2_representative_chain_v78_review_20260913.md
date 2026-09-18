# 跨组件 v78 low：中断位置与已读关系

日期：2026-09-13。仅复核已结束的 `D:\VulnGym-bv2-runtime\t2-representative-20260913\03-chain-v78-low` 中 summary/actions/review 的公共回执；未读新目标源码、联网、付费或执行目标。原结果和其他复核文档未改。本文不是人工认可或漏洞复现结论。

## 终止在哪里

summary 为 `provider_stopped`：1 份输入，0 完整条目、1 草稿，9 HTTP、21 tools、44.927 秒。format/tool/annotation 错误均为 0，read-plan/encoding 拒收均为 0；自动重试为 0。

动作顺序是：调用 1–4 初读 → 5 初稿评估 → 6 初稿编码成功 → 7/8 两次补读成功 → 9 第三次 `evidence_followup` 发生 `deepseek_transport_error`。保存诊断仅标 `protocol_stage=followup`，未给出更细传输阶段；不能套用其他运行的 read_body/length 诊断。本轮未进入 self-review，状态是 `initial_draft_status=accepted`、`self_review_status=not_requested`。

`model_error_count=2` 与 `pipeline_error_count=2` 对应同样的两个记录：

1. 调用 9 的 `Model request failed during evidence_followup: ProviderError`。
2. 控制器随后记录 `Focused evidence follow-up failed or exceeded its allowed read scope; preserving the draft for review.`。

因此是一次请求传输失败及其后续停止说明，在两个计数字段中重复出现；不是四次独立故障，也没有证据证明本轮真的超出了读取权限。该模板消息不能覆盖实际保存的 transport code。

传输中断不等于模型证明“跨组件关系不成立”。但中断前的初稿本来就未确认 commit、EP、CO，因此也不能声称只差网络、内容早已完成。草稿保留公告身份/分类、`verify=0`，关键字段未证，trace 为空。

## 已经读到的直接关系

主要本地观察 SHA 为 `24af748fd3c809920afddfe58bf99c7fce6063d9`；不是已确认的受影响版本。当前真实回执包括：

| 证据 | 已保存关系及条件 | 不能据此推出 |
| --- | --- | --- |
| E0018，ReadWriteFile.node.ts:1–74 | operation 参数为 write 时调用 `write.execute.call(this, items)`，导入与调度已读 | 任意参数均进入写分支、或写入必然导致后续执行 |
| E0023，write.operation.ts:1–135 | 每个 item 读取 fileName/二进制字段；按 binaryData.id 选择 stream 或 Buffer；经 resolvePath 后传给 writeContentToFile；append 改变打开标志 | helper 内无路径限制、任意文件均可写、写入对象会被 Git 消费 |
| E0024，Git.node.ts:240–340 | repositoryPath 经 resolvePath/isFilePathBlocked，命中拦截会抛错；创建 SimpleGit 时设置 baseDir/config；窗口还包含分支 checkout helper | 输入路径无校验、所有 Git 操作均走同一分支、当前配置必定允许相关行为 |
| 同 E0024:320–337 | cloud 或 disableBareRepos 时加入 bare-repository 限制；`!enableGitNodeHooks` 时加入 hooksPath 禁用配置 | 当前默认值/部署类型已知，或公告中的机制在此 SHA/配置必定成立 |

这些不是只有“公告说如此”：已经有调度、文件值/内容构造、写入 helper 调用，以及 Git 路径/配置的直接源码关系。不过两个组件之间“写入的具体状态被哪个后续操作读取并按什么条件使用”仍未由保存窗口连接起来。

## 注意评估与补读时间不同

初稿调用 5/6 时证据仅到 E0019。E0020/E0021 的另一 SHA 搜索/窄窗和 E0022 导航是在初稿之后加入；调用 7 取得 E0023 的完整写操作，调用 8 取得 E0024 的 Git 窗口。调用 9 失败，没有后续有效自检。

因此原 `field_reviews` 的“write.operation.ts 和 Git operations 未读”描述的是初稿时状态，不能当作终态材料清单。本轮后续确已补读两者，但没有模型返回的重评结果；不可将本复核的新判断倒填为原模型已完成的判断。

## 仍缺什么，下一步先读哪里

尚未读取：resolvePath/writeContentToFile/isFilePathBlocked 的实际实现与配置默认值；E0024:340 之后的实际 Git 操作分派及调用；两个组件使用同一文件/仓库状态的关系和执行顺序；公告修复范围与观察 SHA 的对应。E0021 只是另一 SHA 的节点定义开头，不是相关机制的前后修复比较。已有路径保护和禁用配置必须保留，不能忽略后把局部源码说成“无条件可达”。

最有效的补读方向是沿已保存的两个端点收紧：先续读 Git 窗口后的实际消费者/操作分支，再针对该分支所用的路径与写入 helper 读取窄窗口，核对共享状态和配置条件；需要版本比较时再按已观察机制和公告发布线索定位相关历史。无需再广泛枚举无关提交，也无需新增“必须读满若干文件”之类硬门槛。

这次中断没有抹除已完成的自然文本材料整理、分阶段初稿、工具读取、跨文件导航及如实保留不确定字段等能力；也不改变其他已结束运行的结果。准确状态是“本条跨组件内容仍未收口，补读在传输阶段中断”，不是项目整体重新失败。
