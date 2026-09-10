"""Generate a Chinese assessment from public run outputs, without re-analysis."""
from __future__ import annotations

import argparse
from collections import Counter
import html
import json
import math
from pathlib import Path
import re
from typing import Any, Mapping


MAX_INPUT_BYTES = 20_000_000
_FIELDS = ("entry_id", "report_id", "source_link", "origin", "project", "repo_url",
           "commit", "vuln_title", "vuln_ids", "vuln_category_l1", "vuln_category_l2",
           "entry_point", "critical_operation", "trace", "verify")
_STATUS_LABELS = {"supported": "已支持（模型/控制器）", "uncertain": "不确定",
                  "missing": "缺失", "conflicting": "冲突"}
_REVISION_BASIS_LABELS = {
    "behavior_at_revision": "源码机制依据", "affected_range_and_source": "影响范围+源码",
    "inspected_only": "仅检查过", "unknown": "未建立",
}
_SELF_REVIEW_LABELS = {"not_requested": "未请求（不是失败）", "completed": "已完成机器自查",
                       "failed": "机器自查失败"}
_SECRET = re.compile(r"\bsk-[A-Za-z0-9_-]{8,}\b|(?i:Bearer\s+)[^\s\"']+")
_PATH = re.compile(r"(?<![A-Za-z0-9])(?:[A-Za-z]:[\\/][^\s\"'<>]*|\\\\[^\s\"'<>]+|/(?:Users|home|tmp|var/tmp)/[^\s\"'<>]*)")


def _object(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _list(value: Any) -> list:
    return value if isinstance(value, list) else []


def _md(value: Any, limit: int = 320) -> str:
    """Render bounded plain text; output data cannot inject Markdown or HTML."""
    if value is None:
        return "未记录"
    if not isinstance(value, str):
        value = json.dumps(value, ensure_ascii=False, sort_keys=True)
    text = " ".join(value.split())
    text = _PATH.sub("<本地路径已省略>", _SECRET.sub("<密钥已省略>", text))
    if len(text) > limit:
        text = text[:limit] + "…（已截短）"
    text = html.escape(text, quote=False)
    for character in ("\\", "`", "|", "[", "]", "*", "_", "#"):
        text = text.replace(character, "\\" + character)
    return text or "（空）"


def _number(value: Any) -> str:
    if type(value) is int and value >= 0:
        return str(value)
    if isinstance(value, float) and math.isfinite(value) and value >= 0:
        return f"{value:.3f}".rstrip("0").rstrip(".")
    return "未记录"


def _location(value: Any) -> str:
    value = _object(value)
    if not value or value.get("file") is None or value.get("line") is None:
        return "未建立；以字段状态和建议值为准"
    text = _md(value["file"], 220) + "，行 " + _md(value["line"], 40)
    if value.get("desc"):
        text += "；" + _md(value["desc"], 240)
    return text


def _revision_basis_label(assessment: Mapping[str, Any]) -> str:
    if "revision_basis" not in assessment:
        return "旧记录未声明"
    value = assessment["revision_basis"]
    return _REVISION_BASIS_LABELS.get(value, "未识别声明") if isinstance(value, str) else "未识别声明"


def _self_review_status_label(review: Mapping[str, Any]) -> str:
    if "self_review_status" not in review:
        return "旧记录未声明"
    value = review["self_review_status"]
    return _SELF_REVIEW_LABELS.get(value, "未识别声明") if isinstance(value, str) else "未识别声明"


def _validate_terminal_counts(summary: Mapping[str, Any], reviews: list[dict]) -> None:
    """Do not describe unfinished inputs as a finished batch; keep old files readable."""
    if summary.get("status") not in ("completed", "completed_with_errors"):
        return
    requires_counts = summary.get("status") == "completed_with_errors"
    if requires_counts or "requested_input_count" in summary or "unprocessed_input_count" in summary:
        for name in ("requested_input_count", "unprocessed_input_count"):
            if type(summary.get(name)) is not int or summary[name] < 0:
                raise ValueError("summary_count_invalid")
        if summary["unprocessed_input_count"] != 0:
            raise ValueError("completed_run_has_unprocessed_inputs")
        if summary["requested_input_count"] != len(reviews):
            raise ValueError("summary_count_mismatch")
    if requires_counts and (type(summary.get("format_failure_count")) is not int
                            or summary["format_failure_count"] < 1):
        raise ValueError("format_failure_count_invalid")


def _read_inputs(run_dir: Path) -> tuple[dict, list[dict]]:
    if not run_dir.is_dir():
        raise ValueError("run_directory_unavailable")
    remaining = MAX_INPUT_BYTES
    data = {}
    root = run_dir.resolve()
    for name in ("summary.json", "review.jsonl"):
        path = root / name
        if path.is_symlink() or not path.is_file() or path.resolve().parent != root:
            raise ValueError("completed_public_outputs_required")
        if path.stat().st_size > remaining:
            raise ValueError("public_run_exceeds_20mb")
        with path.open("rb") as stream:
            content = stream.read(remaining + 1)
        if len(content) > remaining:
            raise ValueError("public_run_exceeds_20mb")
        remaining -= len(content)
        try:
            data[name] = content.decode("utf-8-sig")
        except UnicodeError as error:
            raise ValueError("public_output_not_utf8") from error
    try:
        summary = json.loads(data["summary.json"])
    except (ValueError, RecursionError) as error:
        raise ValueError("summary_json_invalid") from error
    if not isinstance(summary, dict):
        raise ValueError("summary_object_required")
    reviews = []
    for index, line in enumerate(data["review.jsonl"].splitlines(), 1):
        if not line.strip():
            continue
        try:
            review = json.loads(line)
        except (ValueError, RecursionError) as error:
            raise ValueError(f"review_json_invalid_line_{index}") from error
        if not isinstance(review, dict):
            raise ValueError(f"review_object_required_line_{index}")
        reviews.append(review)
    return summary, reviews


def _assessment(summary: Mapping[str, Any], reviews: list[dict]) -> str:
    _validate_terminal_counts(summary, reviews)
    provider = _object(summary.get("provider"))
    usage = _object(provider.get("usage"))
    counts = Counter(review.get("status") for review in reviews if isinstance(review.get("status"), str))
    lines = [
        "# T2 v2 自动运行自评（待人工复核）", "",
        "本文仅依据已生成的 `summary.json` 与 `review.jsonl` 自动汇总；没有重新访问目标仓库、调用模型或联网。",
        "`supported` 表示带引用的模型判断或控制器事实，**不是独立人工审核或漏洞语义正确的证明**。源码逐字匹配与 schema 通过也不能替代可达性、攻击者可控性和缺陷机制复核。未提供外部独立标签，不计算或宣称 F1、准确率、精确率或召回率。", "",
        "## 本次实际产出与用量", "",
        "| 项目 | 已记录结果 |", "|---|---|",
        f"| 批次执行状态 | {_md(summary.get('status'))}（执行状态，不是正确性结论） |",
        f"| 请求 / 已处理 / 未处理输入 | {_number(summary.get('requested_input_count'))} / {_number(summary.get('input_count'))} / {_number(summary.get('unprocessed_input_count'))} |",
        f"| 完整候选 / 草稿 / 输入失败 | {_number(summary.get('candidate_count'))} / {_number(summary.get('draft_count'))} / {_number(summary.get('input_failure_count'))} |",
        f"| 模型错误 / 工具错误 / 流程错误总项数 | {_number(summary.get('model_error_count'))} / {_number(summary.get('tool_error_count'))} / {_number(summary.get('pipeline_error_count'))} |",
        f"| 格式失败输入数 | {_number(summary.get('format_failure_count'))} |",
        f"| 模型调用 / 仓库工具调用 | {_number(summary.get('model_calls'))} / {_number(summary.get('tool_calls'))} |",
        f"| 已记录耗时（秒） | {_number(summary.get('elapsed_seconds'))} |",
        f"| 模型 | {_md(provider.get('model'))} |",
        f"| 本次 / 同一授权累计 HTTP 尝试 | {_number(provider.get('http_attempts'))} / {_number(provider.get('authorization_http_attempts'))} |",
        f"| 本次 token：输入 / 输出 / 总计 | {_number(usage.get('prompt_tokens'))} / {_number(usage.get('completion_tokens'))} / {_number(usage.get('total_tokens'))} |",
        f"| 授权内用量未知的请求数 | {_number(provider.get('unknown_usage_attempts'))} |", "",
        "完整候选仅指通过终检的正式条目；草稿、输入失败与未处理输入不计为完整候选。错误项数可能一份输入含多项，不等于失败公告数。HTTP 尝试包括失败尝试，且不同于模型调用次数。未知用量保持未知，不能把缺失 token 当作零。货币费用未在本报告中独立核算。", "",
        f"逐条 review 实际读取 **{len(reviews)}** 条：complete={counts['complete']}，draft={counts['draft']}，input_failure={counts['input_failure']}。",
    ]
    if summary.get("status") == "completed_with_errors":
        lines.extend(["", "**批次已处理完但含格式错误：全部输入已处理，至少一项格式失败；不是全成功。失败输入仍是草稿，不因生成报告而补成完整候选。**"])
    failures = [item for item in _list(summary.get("case_failures")) if isinstance(item, dict)]
    if failures:
        lines.extend(["", "已记录逐项格式失败："])
        for failure in failures:
            lines.append("- 公告：" + _md(failure.get("report_id"), 100)
                         + "；错误：" + _md(failure.get("code"), 160)
                         + "；失败后是否继续批次：" + _md(failure.get("continued"), 20) + "。")
    expected = {"input_count": len(reviews), "candidate_count": counts["complete"],
                "draft_count": counts["draft"], "input_failure_count": counts["input_failure"]}
    mismatches = [f"{key}：summary={summary[key]}，review={actual}" for key, actual in expected.items()
                  if type(summary.get(key)) is int and summary[key] != actual]
    if mismatches:
        lines.extend(["", "**需要核对：summary 与逐条 review 的计数不一致。**"] + ["- " + _md(item) for item in mismatches])
    if len(reviews) != sum(counts.get(status, 0) for status in ("complete", "draft", "input_failure")):
        lines.extend(["", "**存在未识别的 review 状态，不能归入已完成候选；需人工核对原始输出。**"])
    lines.extend(["", "## 逐报告结果与待解决字段", ""])
    if not reviews:
        lines.extend(["没有已处理输入的 review 可供逐项评价；请依据停止状态与未处理数量说明进度。不能据此宣称无漏洞或分析成功。", ""])
    for index, review in enumerate(reviews, 1):
        fields = _object(review.get("draft_fields"))
        field_reviews = _object(review.get("field_reviews"))
        suggestions = _object(review.get("suggested_values"))
        actions = Counter(item.get("action") for item in _list(review.get("actions"))
                          if isinstance(item, dict) and isinstance(item.get("action"), str))
        checks = [item for item in _list(review.get("location_checks")) if isinstance(item, dict)]
        lines.extend([
            f"### {index}. {_md(review.get('report_id'), 100)} / {_md(review.get('entry_id'), 80)}", "",
            f"- 状态：{_md(review.get('status'))}；公告：{_md(review.get('source_link'), 240)}。",
            "- 机器自查状态：" + _self_review_status_label(review) + "；机器自查不等于独立人工审核。",
            f"- 已知项目 / 标题：{_md(fields.get('project'), 120)} / {_md(fields.get('vuln_title'), 320)}。",
            f"- 已记录 commit（不代表已确认漏洞版本）：{_md(fields.get('commit'), 80)}。",
            "- 版本判断依据（已记录机器声明）："
            + _revision_basis_label(_object(field_reviews.get("commit")))
            + "；机器声明不等于人工审核。缺少旧字段不会改变原有状态，也不会补造版本依据。",
            f"- 入口 EP：{_location(fields.get('entry_point'))}。",
            f"- 关键操作 CO：{_location(fields.get('critical_operation'))}。",
            f"- 模型 / 工具调用：{_number(review.get('model_calls'))} / {_number(review.get('tool_calls'))}；动作记录中的计划 / 工具 / 草稿 / 自查：{actions['plan']} / {actions['tool']} / {actions['draft']} / {actions['self_review']}。",
            f"- 已记录位置核验：{sum(item.get('valid') is True for item in checks)} / {len(checks)} 通过（仅为位置与代码的确定性检查）。", "",
            "| 字段 | 状态 | 已记录理由与证据引用 |", "|---|---|---|",
        ])
        for field in _FIELDS:
            assessment = _object(field_reviews.get(field))
            status = assessment.get("status")
            label = _STATUS_LABELS.get(status, "未记录/未识别") if isinstance(status, str) else "未记录/未识别"
            refs = [ref for ref in _list(assessment.get("evidence_refs")) if isinstance(ref, str)]
            detail = _md(assessment.get("reason"), 240)
            if refs:
                detail += "；引用：" + _md(", ".join(refs[:5]), 160) + (f"（另 {len(refs) - 5} 项）" if len(refs) > 5 else "")
            if assessment.get("validation_errors"):
                detail += "；终检：" + _md(assessment["validation_errors"], 180)
            lines.append(f"| `{field}` | {label} | {detail} |")
        unresolved = [field for field in _FIELDS if _object(field_reviews.get(field)).get("status") in ("uncertain", "missing", "conflicting")]
        lines.extend(["", "未解决字段：" + ("、".join(f"`{field}`" for field in unresolved) if unresolved else "当前 review 未标注未解决字段；仍不等于独立确认") + "。"])
        for field in _FIELDS:
            if field in suggestions:
                lines.append(f"- `{field}` 的建议值（不是已确认字段）：" + (_location(suggestions[field]) if field in {"entry_point", "critical_operation"} else _md(suggestions[field], 240)) + "。")
        public_errors = _list(review.get("errors")) + _list(review.get("pipeline_errors"))
        if not review.get("pipeline_errors"):
            public_errors += _list(review.get("model_errors")) + _list(review.get("tool_errors"))
        if public_errors:
            lines.extend(["", "本条已记录错误摘录："] + ["- " + _md(error, 320) for error in public_errors[:5]])
            if len(public_errors) > 5:
                lines.append(f"- 另有 {len(public_errors) - 5} 项，完整内容见本条 `review.jsonl`。")
        lines.append("")
    lines.extend([
        "## 自动自评与人工复核建议", "",
        "- **可陈述的结果：** 上述数量、字段状态、引用、用量与错误来自本次公开输出。可追溯性和完整度可以展示；漏洞分析质量仍需按具体证据判断。",
        "- **不能据此陈述的结果：** schema/源码一致不证明 EP 可达、输入可控、CO 确为缺陷，也不证明两者形成利用链。一次同模型自查可能重复原有误判，不是独立审核。",
        "- **人工优先复核：** 项目与标题是否同源；公告影响范围和本地历史是否支持选定漏洞 commit；EP 的触发权限与输入控制；CO 的缺陷机制及其与 EP 的关系；类别是否与实际机制相符。",
        "- **保守处理：** 缺失历史、证据不充分或相互矛盾时保留不确定性和建议值，不用空 SHA、行 0 或推断片段凑完整。合法的 `trace=[]` 不声称已证明数据流。",
        "- **机器与人工分开：** 本报告不改变原始记录，不将自动候选改为人工真值；自动条目仍应为 `verify=0`。人工结论、理由与审核者信息需另行记录。", "",
        "完整字段理由、证据片段与来源坐标见原始 `review.jsonl`；本文为便于阅读截短部分文字，不替代原始运行产物。", "",
    ])
    return "\n".join(lines)


def build_assessment(run_dir: str | Path) -> Path:
    """Read only the two public inputs and exclusively create assessment.md."""
    run_dir = Path(run_dir)
    destination = run_dir / "assessment.md"
    if destination.exists() or destination.is_symlink():
        raise ValueError("assessment_already_exists")
    summary, reviews = _read_inputs(run_dir)
    content = _assessment(summary, reviews)
    with destination.open("x", encoding="utf-8", newline="\n") as stream:
        stream.write(content)
    return destination


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Generate a Chinese self-assessment from completed public outputs; no model or repository access.")
    parser.add_argument("--run-dir", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        build_assessment(args.run_dir)
    except (OSError, ValueError, RecursionError) as error:
        code = str(error)
        if not re.fullmatch(r"[a-z][a-z0-9_]{0,100}", code):
            code = "assessment_failed"
        print(json.dumps({"status": "error", "code": code}, ensure_ascii=False))
        return 2
    print(json.dumps({"status": "written", "file": "assessment.md"}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
