# 四份公开公告输入示例

这个目录提供可携带的 T2 输入材料，不含目标仓库、预测结果、标准答案、私有基准、密钥或请求账本。四份公告都是已经用于开发与调试的公开样本，**不是盲测、未见样本或独立准确率测评**。

| 公告 | 项目 | 公告描述的主题 |
|---|---|---|
| [GHSA-JP4J-Q5FC-58GV](https://github.com/advisories/GHSA-jp4j-q5fc-58gv) | [OpenClaw](https://github.com/openclaw/openclaw) | Discord 组件交互的 guild/channel 策略检查。 |
| [GHSA-8C4J-F57C-35CF](https://github.com/advisories/GHSA-8c4j-f57c-35cf) | [Langflow](https://github.com/langflow-ai/langflow) | Flow 读取、修改与删除的所有权检查。 |
| [GHSA-MQ4R-H2GH-QV7X](https://github.com/advisories/GHSA-mq4r-h2gh-qv7x) | [Flowise](https://github.com/FlowiseAI/Flowise) | Leads 端点批量赋值。 |
| [GHSA-CM35-V4VP-5XVX](https://github.com/advisories/GHSA-cm35-v4vp-5xvx) | [Open WebUI](https://github.com/open-webui/open-webui) | 外部模型服务器 SSE 事件代码注入。 |

`cache/` 中四份 JSON 与指定公开输入缓存逐字节一致，`urls.txt` 与对应 URL 列表一致。它们保留原来的结构与内容，未补写字段答案。公告自身可能包含源码路径、修复提交或 PoC，这是公开原文的一部分，不是程序额外要求的预选源码位置或隐藏标注。

## 准备本地仓库映射

先准备上述项目的独立本地 Git clone 或 bare 仓库，并让需要检查的历史对象在本地可用；程序不会联网下载公告、clone 或 fetch，也不会执行目标代码。

`repo-map.example.json` 只包含项目身份和相对占位路径 `repos/...`。**运行前必须把各项 `repo_path` 改为自己的实际本地仓库路径**，或把仓库放到这些相对位置。相对路径以映射文件所在目录为基准：例如当前映射中的 `repos/langflow` 指本目录下的 `repos/langflow`，不是程序根目录下的同名路径。

建议在交付包外保存自己的映射副本，避免把机器上的实际路径加入公开示例。既可使用绝对路径，也可使用相对于该映射文件的路径。不要把实际仓库、`.git`、本地账本或密钥放进交付包。

## 离线预检查

从项目或解压包根目录执行，下面假设映射占位路径已经修改或准备好：

```powershell
python -E -s -B -m vulngym_t2 --input examples/t2_v2_input/urls.txt --cache-dir examples/t2_v2_input/cache --repo-map examples/t2_v2_input/repo-map.example.json --prepare-only
```

此步骤不需要密钥，也不产生 HTTP 请求。映射未修改或本地仓库不可用时，输入错误是预期结果；不要为绕过错误而填写猜测的源码路径或答案。

若只演示一份公告，可以把 `--advisory` 指向对应 `cache/GHSA-....json`，同时提供自己的 `--repo`，不必使用 URL 列表。真实模型运行还需使用者另行授权，指定新的输出目录和同一授权复用的外部请求账本，并在运行时通过隐藏提示或已配置的环境变量提供凭据；详细参数见产品根目录 `README.md`（开发目录中为 `README_T2_V2.md`）。

这里不提供 `source_paths`、候选编号、指定入口/缺陷位置或预期输出。代码位置与漏洞 revision 应由实际证据建立；公开公告和本地提交的存在不等于本次模型结果已经人工验证。

## V4.1 Flash 回归及减线索输入

`v41/full-urls.txt` 保留本轮完整材料的处理顺序，仍使用上层 `cache/` 与接收者自备的仓库映射。`v41/` 的两份公告 JSON 是明确标记的减线索变体：保留原摘要和编号，移除详细描述、修复候选与源码摘录，不是新的陌生公告。

`v41/reduced-inputs.example.jsonl` 只将实际运行中的机器本地仓库路径改为可携带占位路径。`../repos/langflow` 和 `../repos/flowise` 相对于该 JSONL 所在的 `v41/` 目录，运行前请替换或准备好这些本地仓库；其余公告和项目身份与本轮一致。这些文件不包含模型预测或预选漏洞版本。

完整材料与变体重复同一案例，必须分开解释，不能相加作独立样本。详细真实结果及失败见 `docs/t2_v41_results.md`。正式模型运行需显式传 `--model deepseek-flash` 和使用者自己的授权，不复用交付者已停用的 key。
