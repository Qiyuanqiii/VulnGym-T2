# 跨组件 v81 代表性回归复核

日期：2026-09-14。输入为既有自然文本材料，运行目录为 `D:\VulnGym-bv2-runtime\t2-representative-20260913\10-chain-v81-low`。只读本批公开保存回执，与已完成的 v80 QA 对照；没有新增目标读取、执行、网络或模型调用。这是 AI 辅助证据检查，不是独立盲测、人工认可或漏洞认证。

## 运行事实

- 退出 0，summary.status=completed；1 输入、0 完整候选、1 草稿。
- 10 HTTP、18 本地工具调用、68.731 秒；本批上限 12，无自动 HTTP 重试。
- 初稿 accepted、补读 completed、自审 completed；终态 model/tool/pipeline/format/annotation 错误均 0，读取计划与编码拒收均 0。
- 阶段为 5 次探索、初稿评估/编码 2 次、补读决策 1 次、自审评估/编码 2 次。探索中实际剩余结果空间为 0 后停止；补读后因 reserve_review_context 未再补读。
- 实际上下文重打包两次：70,323→66,255；79,499→77,949 字符。不能把单轮耗时下降归因成质量或压缩收益。
- 配置为 deepseek-flash / staged_tool / assessed_tool / plan_tool / thinking enabled / reasoning-effort low / max_tokens 32768；版本 snapshot-guidance-v81。
- 本批结束累计 2658 次生成＋1 次历史查询＝**2659/3000，剩余 341**；本次四批合计 53/60 HTTP。生成账本 header 仍为 3000，执行期 effective_request_limit=2999 保留历史一次请求。

## 已读与未读不能混用

所有源码回执均属于同一 SHA `24af748fd3c809920afddfe58bf99c7fce6063d9`。9 次 read_file，6 个不同路径：

| 保存回执 | 文件与范围 | 能证明什么 |
| --- | --- | --- |
| E0012 | Files/ReadWriteFile/actions/write.operation.ts 1–135 | 有 fileName 参数读取及 writeContentToFile(resolvePath(...)) 调用 |
| E0013、E0016、E0019、E0021 | Git/Git.node.ts 1–200、200–315、315–465、465–661 | Git 节点部分操作、配置限制及 git.commit 等调用真实出现 |
| E0014 | Files/ReadWriteFile/ReadWriteFile.node.ts 1–74 | 节点分发文件片段 |
| E0015 | Git/GenericFunctions.ts 1–42 | 本批所读的 Git 辅助片段 |
| E0017 | Git/descriptions/AddConfigDescription.ts 1–84 | 允许配置键等声明 |
| E0018 | Files/ReadWriteFile/helpers/utils.ts 1–55 | 该节点局部辅助文件，不是 core 文件系统 helper |

v80 读到了 core 文件系统 helper 1–189，但没有读 Git 操作实现；v81 读了 Git 文件更多范围，却**没有读到那份 core helper**。不同轮回执不能合并成“本轮链路完整”，不能宣称 v81 全面优于 v80。两轮均未建立相关旧版本与共享文件/配置被消费者使用的完整关系。

## 对草稿理由的核对与勘误

1. entry_point/critical_operation/commit 保留 uncertain，空 trace 不断言完整运行链，这比无依据补齐合适；但存在源码可读而模型未读的缺口，不能统称材料不存在。
2. E0019 确实显示 `core.hooksPath=/dev/null` 受 enableGitNodeHooks 条件控制。`safe.bareRepository=explicit` 则受 isCloud 或 disableBareRepos 条件控制；配置键限制也受 enableGitNodeAllConfigKeys 控制。最终 commit 理由将后两项简写为已具备限制，省略条件，容易给出过强反证。
3. 源码没有给出运行时这些配置的取值，也没有建立该 SHA 与受影响发行版本的映射。局部条件限制不足以反驳整份公告；“apparently mitigated at this SHA”只能当待核假设，不能作为已确认修复结论。
4. 本批已见 Git 操作调用，缺的是写入文件与实际执行消费者之间的证据关系，以及底层调用行为。不能继续沿用旧轮“完全未读 Git 操作”的描述，也不能反过来声称运行链已闭合。
5. 保存理由中的行号引用检查为 covered，只说明引用范围可见，不证明条件、版本或跨组件关系判断正确。建议位置未被提升为正式完整条目；verify 保持 0。

## 交验判断

流程正常完成，草稿及限制可交给复核者；**不能视为跨组件提取能力已经达标**。优先补足核心 helper、相关旧版及消费者共享状态的依据，再判断 entry-to-operation 关系。原始 JSONL、理由和回执全部保留；本文勘误是单独的 QA 说明，不冒充产品已自动纠正或人工已经确认。
