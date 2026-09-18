# 跨组件 v80：初读与补读分开，缺口不止版本映射

日期：2026-09-14。仅复核已结束的 `D:\VulnGym-bv2-runtime\t2-representative-20260913\06-chain-v80-low` 保存的 summary/review/actions；不新增目标源码或运行，不改原结果。本文是 snapshot-guidance-v80 历史批次，后续 v81 已真实复测，见[跨组件 v81 QA](t2_representative_chain_v81_review_20260914.md)。最新实现、验证与预算见[代表性验证](t2_representative_validation_20260913.md)，不将本批当成后续版本成绩。

## 终态与配置

退出 0、completed：**11 HTTP、22 工具、188.451 秒，0 完整、1 草稿**；11 HTTP 全部 success，provider.halted=null。followup 与 self_review 均 completed；终态 model/tool/pipeline/format/annotation 错误及 encoding 拒收为 0，但有 **1 次读取计划拒收恢复**，不能说全程零纠正。

deepseek-flash / staged_tool / assessed_tool / plan_tool / thinking enabled / low / 32768 tokens / 64 tools / retries 0；自然文本使用 `--advisory <共同目录>\03-chain-natural.md`，不加 multi-entry，max-calls-per-report 与 max-requests 均 12。与 v79 的基础 profile 和上限相同，但 **continue_on_format_error=true，而 v79=false**；不是所有运行开关均相同的对照。

## E22 不是 followup 新增

保存调用顺序为初读及一次读取计划重编码（call 1–6）→初稿评估/编码（7/8）→一次模型 followup（9）→自审评估/编码（10/11）。

| 回执 | 阶段 | 保存窗口及意义 |
| --- | --- | --- |
| E0022 | 初读，初稿之前 | `file-system-helper-functions.ts` @ `24af748f`，1–120；相关 helper 正文已在初稿前可见 |
| E0025 | call 9 followup | 同 SHA、同文件，120–189；续读剩余实现，并非从零取得整个 helper |

两窗共享第 120 行，不能把两窗都称为 followup 成果，或把“跨窗口完整覆盖”当成两条独立证据。可以确认本批 followup 实际执行并完成；不能仅凭此把全部改进归因于窗口预留，或宣称探索机会成本为零。

## 仍缺的机制证据

本批已读当前观察 SHA 的 helper，不代表以下三处已经读到：

- 较旧 SHA 对应的 helper 实现。
- 旧节点分发与该写入路径的完整连接。
- 实际 Git 执行代码、共享文件/仓库状态如何被消费以及其条件。

受影响发布范围与 SHA 的映射也未建立，但**不是唯一缺口**。已读两个 SHA 的部分写调用差异，不能据此补齐旧 helper 行为、旧分发或最终 Git 执行。草稿可合理保留不确定；其理由仍须逐项限于已保存字节，不因 draft 标签就视为表述全对。此前“只差版本映射”“helper 全由补读取得”的措辞已纠正。

该批结束累计 2605 次生成 + 1 次历史查询 = **2606/3000、余 394**，与此前 NLTK 合计 26 HTTP。原两批及 v79 结果分别保留，不拼接完整率、独立准确率或新版验收结论。
