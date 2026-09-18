# NLTK v80：保存终态、配置差异与恢复边界

日期：2026-09-14。仅复核已结束的 `D:\VulnGym-bv2-runtime\t2-representative-20260913\05-nltk-v80-low` 的 summary/review/actions；不新增目标读取，不执行目标或模型，不修改原结果。本文是 `snapshot-guidance-v80` 历史批次，后续 v81 已真实复测，见[NLTK v81 QA](t2_representative_nltk_v81_review_20260914.md)；当前实现、验证与预算统一见[代表性验证](t2_representative_validation_20260913.md)，不将本批当成后续版本成绩。

v81 展示层已将这份原结果另行离线导出到 `D:\VulnGym-bv2-runtime\t2-representative-20260913\05-nltk-v80-review-v81-export.md`：3 review、1 complete、2 draft，0 HTTP。旧文件和原 JSONL 未覆盖；重导出不等于重新调用模型或证明 v81 提取效果。

## 终态与配置

退出 0、status=completed：**15 HTTP、11 工具、98.276 秒，1 完整、2 草稿**；15 HTTP 全部 success，provider.halted=null，自动 HTTP 重试 0。encoding 拒收 2 次（missing_root_fields），model/pipeline 各 1；read-plan 拒收及终态 tool/format/annotation 为 0。HTTP 成功不等于整份编码或自审成功。

基础配置为 deepseek-flash、staged_tool、assessed_tool、plan_tool、thinking enabled、reasoning-effort low、32768 tokens、64 tools，多候选材料为 `--input <共同目录>\02-nltk-bundle\record.jsonl --multi-entry`。与 v79 对照存在两项已保存差异：

| 参数 | NLTK v79 | 本批 v80 |
| --- | --- | --- |
| run_request_limit / max-requests | 16 | 80（未显式传参时默认值） |
| continue_on_format_error | false | true |

两次均实际使用 15 HTTP，不代表上限与控制策略没有影响；不能称严格同配置对照，也不能把变化单独归因于某一行代码。

## 三槽各自发生什么

| 条目 | 初稿 | 自审 | 终态 |
| --- | --- | --- | --- |
| entry-20579 | accepted | completed | complete |
| entry-00000 | accepted | failed；自审编码缺根字段，恢复 budget_unavailable | draft |
| entry-00001 | draft 编码拒收后 reencoding=recovered，initial_draft=accepted | not_requested | draft |

因此确实有一次多候选 draft 重编码恢复，但**没有恢复失败自审，也没有三槽完整通过**。两个草稿均有已接受初稿可保留，不是 v79 word_tokenize 式无初稿占位；拒收对象本身不应被当作已接受快照。model/pipeline 是同一失败的不同计数字段，不相加为独立事件。

完整候选仍是同一公告中的 sent_tokenize 范围；其 CO 窗口与 v79 一样覆盖实际 finditer 点。位置一致不消除生成器消费、加载类型、默认包装或版本范围等语义前提，本页没有重新证明这些关系，也不将三入口视为三个独立漏洞。

## 允许和不允许的结论

可以说：本批保存了一次 draft 编码拒收后的 recovered，并保留另槽 self_review=failed 与末槽未自审。不能说“恢复策略已稳定通过”“没有空槽所以整体改善”，也不能由完整数 2→1 单独判定退化；样本重复、输出变化及两项配置差异都存在。此前文档将恢复完全归因于局部预留修正的措辞已收窄。

该批结束时累计 2594 次生成 + 1 次历史查询 = 2595/3000、余 405；它不是两批结束后的当前余额。随后 chain 使用 11 HTTP，两批共 26。历史授权账本扩容记录保持不变；当前执行期上限与总预算见代表性验证，不将账本 header 当作总额边界已经正确的证明。
