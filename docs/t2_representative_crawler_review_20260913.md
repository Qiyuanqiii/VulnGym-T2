# Crawler 新材料 v72：边界逻辑与内容复核

## 范围与终态

已结束目录：`D:\VulnGym-bv2-runtime\t2-representative-20260913\04-crawler-v72`，输入 `GHSA-H9J7-5XVC-QHG5`。父任务确认统一会话 14991 退出 0；保存终态 `completed`，1 输入、1 完整候选、0 草稿，8 次 HTTP、9 次工具、68.704 秒，最终格式/模型/工具/pipeline/当前字段协议异常均为 0，重新编码恢复为 0。

本次只读该运行的公共结果/receipts，没有额外访问源仓、网络、付费服务或执行目标，没有修改原结果或生产代码。`verify=0`，本复核不是人工认可、盲测或独立准确率。

## 1. 旧检查与修复后检查的实际区别

选定 SHA：`817b84de9e2cd9f2e16a11004caea6fa53aefed8`；公告关联修复 SHA：`bf0b3cc0b5ade1fb95a5b1b6fa260e99064c2e22`。

- E0005 inspect 给出前后关系；E0006 完整 diff；E0007 旧 `libs/core/langchain_core/utils/html.py:55–89`；E0008 新同文件 `55–103`。本轮并非只凭父关系选版本。
- 旧代码先从候选链接形成 absolute_paths，再应用 exclude_prefixes；当 `prevent_outside` 为真，仅用 `path.startswith(base_url)` 作范围限制。它比较的是**整个字符串前缀，不是主机名相等**。
- 因而最终 CO 举出的“另一个主机的 URL 字符串与根 base URL 同前缀”这一局部判断有代码支持。不能把它扩大成所有 base URL、所有排除配置均可通过：候选须先进入 all_links，且没有命中 exclude_prefixes。
- 新代码先解析 URL，在 `prevent_outside` 为真时要求 `parsed_base_url.netloc == parsed_path.netloc`，**然后仍检查 `path.startswith(base_url_to_use)`**。准确描述是“增加 netloc 比较并保留更具体 URL 前缀限制”，不是“完全用 hostname 校验替换前缀”。`netloc` 也不等同于只取 `.hostname`；本复核不把它称为所有 URL 风险的全面验证。

最终 commit reason 的“replaces it with a netloc comparison”是过度简写，以上双重条件应在交验说明中保留。没有发现需要推翻“旧代码只有字符串前缀限制”这一局部结论的反证。

## 2. 入口、消费位置与 trace

`entry-37140` 的 EP 是 crawler 对页面 response.text 的读取及传给 extract_sub_links，CO 是 helper 的 prefix-only 筛选。对于本例，关键操作标在错误的边界判断，而不是随意标任一个网络调用，有明确机制对应。

保存证据：

- E0009 完整覆盖 loader `1–120`，19 行明确导入 `langchain_core.utils.html.extract_sub_links`，支持跨文件调用目标。
- E0012 覆盖 loader `121–149`，显示实例字段设置：默认 `max_depth=2`、`use_async=False`、`prevent_outside=True`，排除目录为用户配置或空集合。
- E0011 覆盖 loader `150–303`，包含同步递归体、异步体及 lazy_load/load 分派。最终候选选择的是同步路径，并非所有路径混为同一 trace。
- E0007 显示收到 raw_html 后调用 `find_all_links`，处理 absolute paths、检查 exclude/prevent_outside 并返回结果；`find_all_links` 本体没有 source receipt。

对 EP、CO、4 个 trace 字段的位置与保存 source 原文比较，**6/6 逐字匹配**；其中 EP/CO 在 trace 中重复出现，实际上是 4 个不同窗口，不应宣传成 6 份独立内容证据。

trace 的顺序“response → helper 链接处理 → 边界检查 → 未访问链接的递归调用”有相应源码和导入依据；`visited` 与深度限制在最后一步描述中保留，未假造无条件无限递归。原始字段没有确认的前提仍包括：

1. 页面内容受攻击者影响来自公告归因，未验证实际部署或任意现实目标。
2. 返回页面要成功取得；配置要求时错误 HTTP 状态会中止，异常分支会返回。
3. 候选链接必须能被 `find_all_links` 按当时 pattern 提取。该 helper 实现未读，所以本次强项是“已成为候选的 URL 如何被检查”，不是任意 HTML 都能产生指定 URL 的完整证明。
4. 选定路径是同步 lazy generator。调用 lazy_load 取得迭代器本身不等于已发生所有网络读取；在正文非空时还会先 yield Document，调用方要继续消费才继续到子链接提取和递归。`load()` 在 303 行用 list 消费这一点已读，不能把所有可能的 lazy 消费方式都写成必然展开全部子链接。
5. 候选要未被 exclude_prefixes 过滤、未访问且未超过 max_depth 才进一步递归。CO “所以 append”应理解为这些前置分支允许时，不能孤立取一句作无条件主张。

上述限定无需执行目标或发起额外请求；它们来自已保存代码，交验展示应连同 review reason 使用。

## 3. 版本与结果边界

选定旧快照实际出现前缀检查，前后 diff 与两侧源文件支持该行为，所以使用 `behavior_at_revision` 有具体依据。没有 source/release 映射证明这个 SHA 属于公告 `<0.1.0` 的发布范围，理由已如实保留。这里不是“所有字段都已获人工验证”，也不应把 schema 完整输出当作部署风险定论。

这是四份材料中范围较窄、局部跨文件关系支持较强的完整候选：没有发现迫使它全部退回的源码矛盾；待完善的是准确表述上述条件、netloc 与前缀的组合及有限未读前提，而不是重做整个 pipeline。

## 4. 四份固定新材料的总括（不算整体准确率）

| 固定材料 / 实际版本 | 真实产物 | 内容复核所得 | 尚缺什么 |
| --- | --- | --- | --- |
| SQL / v71 | 1 输入，1 完整、2 草稿 | 有局部 MSSQL DELETE 支持，但两个 UPDATE 槽位重叠 | v72 范围保留改进还没在这份 SQL 上复测；已定位 helper/消费者的补读和范围去重 |
| NLTK / v72 | 1 输入，3 完整入口 | 原提案范围保持，同一个 regex 机制的不同入口，时间边界清楚 | 条件性 load 类型/trace 口径、generator 消费条件；不能算 3 个独立漏洞 |
| 文件写入 + Git / v72 | 1 输入，1 草稿 | 自然文本解析/受控格式恢复成功，未把文件写入冒充已证命令执行 | Git 已搜索但未 source-read，修复/版本关联和共享文件依赖未核实 |
| Crawler / v72 | 1 输入，1 完整 | 旧 prefix-only 检查及局部递归链有实际支持 | 用户说明补齐 netloc+prefix、排除/消费等条件与有限未读前提 |

四份都按原选择跑完，没有因草稿换题。它们不是同一版本的四份全部内容通过，更不是独立随机测试集；表中的候选条数不能变成正确率分子。跨材料能力已经获得比旧三例更多的真实证据，同时也实际暴露 SQL 范围重复和复杂消费者漏读。

最小剩余工作是：修正已有已知消费者/旧主体的读取优先级并在原失败材料复测；把机器结果中的条件前提、共享机制计数及证据时间用统一口径呈现。原两例 LangChain/Airflow 的未完成项另见 `t2_representative_regression_v72_review_20260913.md`。无需为了这一复核重启大修，也不能据此提前声明所有显式目标已完成。

本次复核到此冻结，不修改四份原始运行结果。
