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

from .review_export import _input_reviews, _process_record, _SERIAL_SCOPE, _object_pairs, _constant, _float


MAX_INPUT_BYTES = 20_000_000
_FIELDS = ("entry_id", "report_id", "source_link", "origin", "project", "repo_url",
           "commit", "vuln_title", "vuln_ids", "vuln_category_l1", "vuln_category_l2",
           "entry_point", "critical_operation", "trace", "verify")
_STATUS_LABELS = {"supported": "已支持（模型/控制器）", "uncertain": "不确定",
                  "missing": "缺失", "conflicting": "冲突"}
_REVIEW_DECISIONS = {"supported": "支持", "reasonable_alternative": "合理替代",
                     "contradicted": "反证", "uncertain": "不确定", "not_reviewed": "未评"}
_REVIEW_CHECKS = {
    "project_source": "项目身份与来源是否一致",
    "title_source": "漏洞标题是否得到对应来源支持",
    "affected_version": "受影响版本、公告范围与所选 commit 是否相符",
    "entry_point_role": "入口角色、触发权限与输入控制是否得到支持",
    "critical_operation": "关键操作与缺陷机制是否得到支持",
    "entry_operation_link": "入口与关键操作的关联是否得到支持",
    "classification": "分类是否符合实际缺陷机制",
}
_REVISION_BASIS_LABELS = {
    "behavior_at_revision": "源码机制依据", "affected_range_and_source": "影响范围+源码",
    "inspected_only": "仅检查过", "unknown": "未建立",
}
_SELF_REVIEW_LABELS = {"not_requested": "未请求（不是失败）", "completed": "已完成机器自查",
                       "failed": "机器自查失败"}
_EVIDENCE_FOLLOWUP_LABELS = {"not_requested": "未请求（不是失败）", "completed": "已完成聚焦补证",
                             "failed": "聚焦补证失败"}
_DIAGNOSTIC_LABELS = {
    "complete": "完整候选（complete；非人工确认）",
    "input_failure": "输入失败（input_failure）",
    "draft_with_technical_anomaly": "伴技术异常的草稿",
    "draft_without_recorded_technical_anomaly": "未记录技术异常的草稿（仍需核对证据缺口）",
    "draft_diagnostic_insufficient": "草稿诊断不足（诊断字段缺失或无效）",
    "unrecognized_status": "状态未识别（诊断不足）",
}
_DIAGNOSTIC_NOTE = "按条目计数，同一条有多条错误仍只计一次；仅描述已记录信号，不推断唯一根因。未记录技术异常不等于已证明只是证据不足；旧字段缺失或无效时保留诊断不足。此分层不使用 format_failure_count 代替逐条诊断，也不改变原 status 或 verify。"
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
    if review.get("annotation_mode") == "snapshot" and review.get("self_review_status") == "not_requested":
        return "未完成必需自查（保留草稿，不等于请求失败）"
    if "self_review_status" not in review:
        return "旧记录未声明"
    value = review["self_review_status"]
    return _SELF_REVIEW_LABELS.get(value, "未识别声明") if isinstance(value, str) else "未识别声明"


def _evidence_followup_status_label(review: Mapping[str, Any]) -> str:
    if "evidence_followup_status" not in review:
        return "旧记录未声明"
    value = review["evidence_followup_status"]
    return _EVIDENCE_FOLLOWUP_LABELS.get(value, "未识别声明") if isinstance(value, str) else "未识别声明"


def _entry_diagnostic(review: Mapping[str, Any], process: Mapping[str, Any] | None = None) -> dict[str, str]:
    """Describe recorded draft signals, never an exclusive causal diagnosis."""
    status = review.get("status")
    if status in ("complete", "input_failure"):
        return {"category": status, "label": _DIAGNOSTIC_LABELS[status], "detail": "保留原状态，不归入草稿诊断。"}
    if status != "draft":
        return {"category": "unrecognized_status", "label": _DIAGNOSTIC_LABELS["unrecognized_status"],
                "detail": "原状态保持不变，不能归为完整候选或推断技术异常不存在。"}
    signals, incomplete = [], []
    if any(isinstance(item, Mapping) and item.get("code") == "entry_result_invalid"
           for item in _list(review.get("errors"))):
        signals.append("entry_result_invalid（候选中间记录损坏，非模型请求失败计数）")
    annotation_errors = review.get("annotation_errors", [])
    if not isinstance(annotation_errors, list):
        incomplete.append("annotation_errors")
    elif annotation_errors:
        signals.append("annotation_errors")
    if process is None:
        process = {} if review.get("process_metadata_scope") == "shared_input" else review
    for name in ("model_errors", "tool_errors", "pipeline_errors"):
        value = process.get(name)
        if not isinstance(value, list):
            incomplete.append(name)
        elif value:
            signals.append(name)
    for name in ("self_review_status", "evidence_followup_status"):
        value = review.get(name)
        if value == "failed":
            signals.append(name + "=failed")
        elif value not in ("not_requested", "completed"):
            incomplete.append(name)
    if signals:
        category = "draft_with_technical_anomaly"
        detail = "已记录信号：" + "、".join(signals) + "；不据此推断唯一根因。"
    elif incomplete:
        category = "draft_diagnostic_insufficient"
        detail = "不能把未知诊断当作零或没有异常。"
    else:
        category = "draft_without_recorded_technical_anomaly"
        detail = "上述诊断字段未记录技术异常；仍需核对证据缺口，不断言全部由证据不足造成。"
    if incomplete:
        detail += "诊断不足（字段缺失或无效）：" + "、".join(incomplete) + "。"
    if isinstance(annotation_errors, list) and annotation_errors:
        detail += "其中 annotation_errors 是尚未解决、可恢复的字段协议异常，不等于模型整体请求失败，也不能当作纯证据不足。"
    if review.get("process_metadata_scope") == "shared_input":
        detail += "过程信号关联同 input_id 的 slot 1；共享错误不代表本候选独立失败。"
    elif review.get("process_metadata_scope") == _SERIAL_SCOPE:
        detail += "只按本候选的状态和错误描述；输入背景及后续候选失败不倒推否定本候选。"
    return {"category": category, "label": _DIAGNOSTIC_LABELS[category], "detail": detail}


def _diagnostic_counts(reviews: list[dict]) -> dict[str, int]:
    counts = Counter(_entry_diagnostic(review, _process_record(review, reviews))["category"] for review in reviews)
    return {category: counts[category] for category in _DIAGNOSTIC_LABELS}


def _diagnostic_lines(reviews: list[dict]) -> list[str]:
    counts = _diagnostic_counts(reviews)
    return ["", "## 已记录的条目诊断（不是唯一根因）", "", _DIAGNOSTIC_NOTE, "",
            "| 诊断分层 | 条目数 |", "|---|---|",
            *(f"| {label} | {counts[category]} |" for category, label in _DIAGNOSTIC_LABELS.items()), ""]


def _validate_terminal_counts(summary: Mapping[str, Any], reviews: list[dict]) -> None:
    """Do not describe unfinished inputs as a finished batch; keep old files readable."""
    groups = _input_reviews(summary, reviews)
    processed = len(groups) if groups is not None else len(reviews)
    if summary.get("status") not in ("completed", "completed_with_errors"):
        return
    requires_counts = summary.get("status") == "completed_with_errors"
    if requires_counts or "requested_input_count" in summary or "unprocessed_input_count" in summary:
        for name in ("requested_input_count", "unprocessed_input_count"):
            if type(summary.get(name)) is not int or summary[name] < 0:
                raise ValueError("summary_count_invalid")
        if summary["unprocessed_input_count"] != 0:
            raise ValueError("completed_run_has_unprocessed_inputs")
        if summary["requested_input_count"] != processed:
            raise ValueError("summary_count_mismatch")
    if requires_counts and (type(summary.get("format_failure_count")) is not int
                            or summary["format_failure_count"] < 1):
        raise ValueError("format_failure_count_invalid")


def _input_count_lines(summary: Mapping[str, Any], reviews: list[dict]) -> list[str]:
    if summary.get("counting_version") != "input-review-v2":
        return []
    return ["", "## 输入与候选两套分母", "",
            f"输入分母：{summary['input_count']} 个已处理输入；候选复核分母：{len(reviews)} 条 review（包含草稿与输入失败占位）。未处理输入另外保留，不进入候选意见分母。",
            "一输入可产生多条候选；输入级 complete 表示候选均完整，partial 表示既有完整候选也有草稿，draft 表示没有完整候选。输入失败只保留一条占位。", "",
            "| 输入级状态 | 输入数 |", "|---|---|",
            *(f"| {name} | {summary[key]} |" for name, key in
              (("complete", "complete_input_count"), ("partial", "partial_input_count"),
               ("draft", "draft_input_count"), ("input_failure", "input_failure_count"))), "",
            "调用用量仅由同 input_id 的 slot 1 承载，不重复累加。旧 shared_input 的过程错误/actions 共享；串行 candidate_with_shared_usage 的错误与 actions 属于本候选，input_errors/input_actions 单列输入背景，不倒推否定先前已完成候选。", ""]


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
        summary = json.loads(data["summary.json"], object_pairs_hook=_object_pairs,
                             parse_constant=_constant, parse_float=_float)
    except (ValueError, RecursionError) as error:
        raise ValueError("summary_json_invalid") from error
    if not isinstance(summary, dict):
        raise ValueError("summary_object_required")
    reviews = []
    for index, line in enumerate(data["review.jsonl"].splitlines(), 1):
        if not line.strip():
            continue
        try:
            review = json.loads(line, object_pairs_hook=_object_pairs,
                                parse_constant=_constant, parse_float=_float)
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
        f"| 报告聚合冲突 / 涉及条目 | {_number(summary.get('report_conflict_count'))} / {_number(summary.get('report_conflict_entry_count'))} |",
        f"| entries → reports 关联齐全（非语义合格） | {_md(summary.get('report_linkage_complete'))} |",
        f"| 模型错误 / 工具错误 / 流程错误总项数 | {_number(summary.get('model_error_count'))} / {_number(summary.get('tool_error_count'))} / {_number(summary.get('pipeline_error_count'))} |",
        f"| 未解决字段协议异常项数 / 涉及输入数 | {_number(summary.get('annotation_error_count'))} / {_number(summary.get('jobs_with_annotation_errors'))} |",
        f"| 格式失败输入数 | {_number(summary.get('format_failure_count'))} |",
        f"| 模型调用 / 仓库工具调用 | {_number(summary.get('model_calls'))} / {_number(summary.get('tool_calls'))} |",
        f"| 已记录耗时（秒） | {_number(summary.get('elapsed_seconds'))} |",
        f"| 模型 | {_md(provider.get('model'))} |",
        f"| 本次 / 同一授权累计 HTTP 尝试 | {_number(provider.get('http_attempts'))} / {_number(provider.get('authorization_http_attempts'))} |",
        f"| 本次 token：输入 / 输出 / 总计 | {_number(usage.get('prompt_tokens'))} / {_number(usage.get('completion_tokens'))} / {_number(usage.get('total_tokens'))} |",
        f"| 授权内用量未知的请求数 | {_number(provider.get('unknown_usage_attempts'))} |", "",
        "完整候选仅指通过终检的正式条目；草稿、输入失败与未处理输入不计为完整候选。错误项数可能一份输入含多项，不等于失败公告数。HTTP 尝试包括失败尝试，且不同于模型调用次数。未知用量保持未知，不能把缺失 token 当作零。货币费用未在本报告中独立核算。", "",
        "annotation_error_count 按候选逐条累加当前未解决的字段协议异常；jobs_with_annotation_errors 按涉及输入去重。它们不是模型整体请求失败数，也不是纯证据不足；合法兄弟字段保留，修复后的历史异常只留在 actions，不永久阻止完整候选。旧摘要缺失时显示“未记录”，不回填为零。", "",
        "format_failure_count 沿用原摘要的计数口径；旧记录中该计数为 0 不排除协议失败，应结合 model_failure 结构诊断和逐条阶段状态核对。错误文字项数不等于失败 HTTP 请求数。", "",
        *(["本记录的格式失败计数定义：" + _md(summary["format_failure_definition"], 500), ""]
          if "format_failure_definition" in summary else []),
        "同一报告的元数据相互矛盾时记录聚合冲突警告；当前导出按 schema 保留 canonical report 与完整 entry。冲突不等于 entries → reports 关联缺失，关联齐全也不证明语义合格。历史输出保持原样；冲突计数缺失时显示“未记录”，不当作零。", "",
        f"逐条 review 实际读取 **{len(reviews)}** 条：complete={counts['complete']}，draft={counts['draft']}，input_failure={counts['input_failure']}。",
        *_input_count_lines(summary, reviews),
        *_diagnostic_lines(reviews),
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
    expected = {"input_count": len(summary["input_reviews"]) if summary.get("counting_version") == "input-review-v2" else len(reviews), "candidate_count": counts["complete"],
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
        process = _process_record(review, reviews)
        fields = _object(review.get("draft_fields"))
        diagnostic = _entry_diagnostic(review, process)
        field_reviews = _object(review.get("field_reviews"))
        suggestions = _object(review.get("suggested_values"))
        actions = Counter(item.get("action") for item in _list(process.get("actions"))
                          if isinstance(item, dict) and isinstance(item.get("action"), str))
        checks = [item for item in _list(review.get("location_checks")) if isinstance(item, dict)]
        lines.extend([
            f"### {index}. {_md(review.get('report_id'), 100)} / {_md(review.get('entry_id'), 80)}", "",
            f"- 状态：{_md(review.get('status'))}；公告：{_md(review.get('source_link'), 240)}。",
            *([f"- 输入：{_md(review.get('input_id'))}；候选 slot：{_number(review.get('slot'))}；共享用量记录：{_md(process.get('usage_entry_id', process.get('entry_id')))}。"] if "input_id" in review else []),
            f"- 记录诊断：{diagnostic['label']}；{_md(diagnostic['detail'], 600)}",
            *(["- 初稿接收状态（仅格式处理，不是事实确认）：" + _md(review["initial_draft_status"]) + "。no_valid_updates 不代表收到有效初稿。"]
              if "initial_draft_status" in review else []),
            "- 聚焦补证状态：" + _evidence_followup_status_label(review)
            + "；首次草稿后、最终自查前的预算内只读补证，实际次数见动作记录；非人工验收，不保证语义正确。",
            "- 机器自查状态：" + _self_review_status_label(review) + "；机器自查不等于独立人工审核。",
            f"- 已知项目 / 标题：{_md(fields.get('project'), 120)} / {_md(fields.get('vuln_title'), 320)}。",
            f"- 已记录 commit（不代表已确认漏洞版本）：{_md(fields.get('commit'), 80)}。",
            "- 版本判断依据（已记录机器声明）："
            + _revision_basis_label(_object(field_reviews.get("commit")))
            + "；机器声明不等于人工审核。缺少旧字段不会改变原有状态，也不会补造版本依据。",
            f"- 入口 EP：{_location(fields.get('entry_point'))}。",
            f"- 关键操作 CO：{_location(fields.get('critical_operation'))}。",
            f"- 模型 / 工具调用（新格式为输入共享）：{_number(process.get('model_calls'))} / {_number(process.get('tool_calls'))}；动作记录中的计划 / 工具 / 草稿 / 自查：{actions['plan']} / {actions['tool']} / {actions['draft']} / {actions['self_review']}。",
            f"- 已记录位置核验：{sum(item.get('valid') is True for item in checks)} / {len(checks)} 通过（仅为位置与代码的确定性检查）。", "",
            "| 字段 | 状态 | 已记录理由与证据引用 |", "|---|---|---|",
        ])
        for field in _FIELDS:
            assessment = _object(field_reviews.get(field))
            status = assessment.get("status")
            label = _STATUS_LABELS.get(status, "未记录/未识别") if isinstance(status, str) else "未记录/未识别"
            refs = [ref for ref in _list(assessment.get("evidence_refs")) if isinstance(ref, str)]
            detail = _md(assessment.get("reason"), 240)
            if assessment.get("reason_truncated") is True:
                detail += "；原始理由已截短，未保存的尾部不猜补"
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
        annotation_errors = _list(review.get("annotation_errors"))
        if annotation_errors:
            lines.extend(["", "本候选未解决的字段协议异常（可恢复；非模型整体请求失败、非纯证据不足）：", "",
                          "| field | code | path |", "|---|---|---|"])
            for error in annotation_errors:
                item = _object(error)
                lines.append("| " + " | ".join(_md(item.get(key), 240) for key in ("field", "code", "path")) + " |")
        public_errors = _list(review.get("errors")) + _list(process.get("pipeline_errors"))
        if not process.get("pipeline_errors"):
            public_errors += _list(process.get("model_errors")) + _list(process.get("tool_errors"))
        if public_errors:
            lines.extend(["", "本条已记录错误摘录："] + ["- " + _md(error, 320) for error in public_errors[:5]])
            if len(public_errors) > 5:
                lines.append(f"- 另有 {len(public_errors) - 5} 项，完整内容见本条 `review.jsonl`。")
        if review.get("process_metadata_scope") == _SERIAL_SCOPE and process.get("input_errors"):
            lines.extend(["", "输入背景错误（不作为本候选被否定的依据，不重复计数）："]
                         + ["- " + _md(error, 320) for error in _list(process["input_errors"])[:5]])
        plans = [item for item in _list(process.get("input_actions")) + _list(process.get("actions"))
                 if isinstance(item, dict) and item.get("action") == "candidate_plan"]
        if plans:
            lines.extend(["", "候选规划仅为程序选取/省略计数，不证明入口独立性或语义成功。", "",
                          "| proposed_count | selected_count | omitted_count | duplicate_count | budget_slots |",
                          "|---|---|---|---|---|"])
            for plan in plans:
                lines.append("| " + " | ".join(_number(plan.get(key)) for key in
                             ("proposed_count", "selected_count", "omitted_count", "duplicate_count", "budget_slots")) + " |")
        failures = [item for item in _list(process.get("actions")) + _list(process.get("input_actions"))
                    if isinstance(item, dict) and item.get("action") == "model_failure"]
        if failures:
            lines.extend(["", "已保存的模型失败结构诊断（缺失信息不猜补）：", "",
                          "| stage | code | protocol_reason | protocol_path |", "|---|---|---|---|"])
            for failure in failures:
                lines.append("| " + " | ".join(_md(failure.get(key), 240) for key in
                             ("stage", "code", "protocol_reason", "protocol_path")) + " |")
            from .transport import public_failure_diagnostics
            for failure in failures:
                detail = public_failure_diagnostics(failure.get("diagnostics"))
                if detail:
                    lines.extend(["", "解析层诊断：" + _md(json.dumps(detail, ensure_ascii=False, sort_keys=True), 1600)])
        citation_issues = [(field, row) for field, packet in _object(review.get("reason_citation_checks")).items()
                           for row in _list(_object(packet).get("citations"))
                           if isinstance(row, dict) and row.get("severity") in ("error", "warning")]
        if citation_issues:
            lines.extend(["", "理由引用覆盖问题（warning 不作自动语义裁决）：", "",
                          "| 字段 | 引用 | 首行 | 末行 | 问题 | 级别 |", "|---|---|---|---|---|---|"])
            for field, issue in citation_issues:
                lines.append("| " + " | ".join(_md(value) for value in
                    (field, issue.get("evidence_ref"), issue.get("start_line"), issue.get("end_line"), issue.get("code"), issue.get("severity"))) + " |")
        from .support_consistency import public_checks
        support_checks = public_checks(review.get("support_consistency_checks"))
        if support_checks:
            lines.extend(["", "必要前提与 supported 判断冲突：对应字段留待复核，原建议和理由保留。", "",
                          "只识别有限的明确自我否定；未命中不代表语义正确。不是 API/格式故障。", "",
                          "| 字段 | 待核对前提 | 规则 |", "|---|---|---|"])
            for field, packet in support_checks.items():
                for issue in packet["issues"]:
                    lines.append("| " + " | ".join(_md(value) for value in
                        (field, issue["prerequisite"], issue["rule"])) + " |")
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


def _review_bindings(reviews: list[dict]) -> dict[tuple[str, str | None], dict]:
    bindings = {}
    entry_ids = set()
    for review in reviews:
        entry_id, report_id = review.get("entry_id"), review.get("report_id")
        missing_report = (report_id is None and review.get("status") == "input_failure"
                          and review.get("process_metadata_scope") in ("shared_input", _SERIAL_SCOPE)
                          and review.get("input_id") == entry_id and review.get("slot") == 1)
        if (not isinstance(entry_id, str) or not entry_id.strip()
                or not (missing_report or isinstance(report_id, str) and report_id.strip())):
            raise ValueError("review_binding_ids_required")
        if entry_id in entry_ids:
            raise ValueError("public_review_entry_id_duplicate")
        entry_ids.add(entry_id)
        bindings[(entry_id, report_id)] = review
    return bindings


def _blank_judgment() -> dict:
    return {"reviewer": "", "decision": "not_reviewed", "reason": "", "evidence_refs": []}


def _new_output(destination: Path) -> None:
    if destination.exists() or destination.is_symlink():
        raise ValueError("review_output_already_exists")


def build_review_template(run_dir: str | Path, destination: str | Path) -> Path:
    """Create a separate, unfilled review form bound to actual public entries."""
    destination = Path(destination)
    _new_output(destination)
    summary, reviews = _read_inputs(Path(run_dir))
    _validate_terminal_counts(summary, reviews)
    bindings = _review_bindings(reviews)
    entries = []
    for (entry_id, report_id), review in bindings.items():
        fields = _object(review.get("draft_fields"))
        # Context is bounded, redacted display text, never a replacement record.
        context = {name: _md(fields.get(name), 800) for name in
                   ("project", "repo_url", "vuln_title", "commit", "entry_point",
                    "critical_operation", "trace", "vuln_category_l1", "vuln_category_l2", "verify")}
        context.update(status=_md(review.get("status")), source_link=_md(review.get("source_link"), 800),
                       diagnostic=_entry_diagnostic(review, _process_record(review, reviews)))
        if "input_id" in review:
            context.update(input_id=_md(review["input_id"]), slot=_number(review.get("slot")))
        entries.append({"entry_id": entry_id, "report_id": report_id,
                        "source_snapshot": review,
                        "source_context_display": context,
                        "overall": _blank_judgment(),
                        "checks": {key: _blank_judgment() for key in _REVIEW_CHECKS}})
    template = {
        "schema_version": 1, "kind": "t2_external_human_review",
        "instructions": "仅填写 overall/checks；source_snapshot 是原始公开 review 的完整内容快照，不可修改。原候选、理由、引用或建议值变更时必须重新生成表格，不可沿用旧意见。总体判定不由分项自动推导。非 not_reviewed 必须填写 reviewer 和 reason；evidence_refs 可引用公开 review 中的证据 ID 或外部证据位置，工具不会读取或核实其内容。合理替代答案可用 reasonable_alternative，并在理由中说明替代项。原 status/verify 不变。",
        "decision_values": _REVIEW_DECISIONS,
        "check_labels": _REVIEW_CHECKS,
        "diagnostic_summary_display": {"note": _DIAGNOSTIC_NOTE, "category_labels": _DIAGNOSTIC_LABELS,
                                       "counts_by_category": _diagnostic_counts(reviews)},
        "run_context_display": {"status": _md(summary.get("status")),
                                "counting_version": _md(summary.get("counting_version")),
                                "processed_input_count": _number(summary.get("input_count")),
                                "candidate_review_count": len(reviews),
                                "input_counts": {key: summary[key] for key in
                                                 ("complete_input_count", "partial_input_count", "draft_input_count", "input_failure_count") if key in summary},
                                "requested_input_count": _number(summary.get("requested_input_count")),
                                "unprocessed_input_count": _number(summary.get("unprocessed_input_count"))},
        "entries": entries,
    }
    with destination.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(template, stream, ensure_ascii=False, indent=2)
        stream.write("\n")
    return destination


def _read_human_review(path: Path) -> dict:
    if path.is_symlink() or not path.is_file():
        raise ValueError("human_review_file_required")
    if path.stat().st_size > MAX_INPUT_BYTES:
        raise ValueError("human_review_exceeds_20mb")
    with path.open("rb") as stream:
        content = stream.read(MAX_INPUT_BYTES + 1)
    if len(content) > MAX_INPUT_BYTES:
        raise ValueError("human_review_exceeds_20mb")
    try:
        document = json.loads(content.decode("utf-8-sig"), object_pairs_hook=_object_pairs,
                              parse_constant=_constant, parse_float=_float)
    except (ValueError, UnicodeError, RecursionError) as error:
        raise ValueError("human_review_json_invalid") from error
    if not isinstance(document, dict):
        raise ValueError("human_review_object_required")
    return document


def _validate_judgment(value: Any) -> None:
    if not isinstance(value, dict):
        raise ValueError("human_review_judgment_required")
    decision = value.get("decision")
    if not isinstance(decision, str) or decision not in _REVIEW_DECISIONS:
        raise ValueError("human_review_decision_invalid")
    if not all(isinstance(value.get(key), str) for key in ("reviewer", "reason")):
        raise ValueError("human_review_reviewer_reason_required")
    if decision != "not_reviewed" and not all(value[key].strip() for key in ("reviewer", "reason")):
        raise ValueError("human_review_reviewer_reason_required")
    refs = value.get("evidence_refs")
    if not isinstance(refs, list) or any(not isinstance(ref, str) or not ref.strip() for ref in refs):
        raise ValueError("human_review_evidence_refs_invalid")


def _validate_human_review(document: dict, reviews: list[dict]) -> dict[tuple[str, str | None], dict]:
    if type(document.get("schema_version")) is not int or document["schema_version"] != 1 or document.get("kind") != "t2_external_human_review":
        raise ValueError("human_review_schema_invalid")
    entries = document.get("entries")
    if not isinstance(entries, list):
        raise ValueError("human_review_entries_required")
    bindings = _review_bindings(reviews)
    reviewed = {}
    for entry in entries:
        if not isinstance(entry, dict):
            raise ValueError("human_review_entry_invalid")
        ids = entry.get("entry_id"), entry.get("report_id")
        if (not isinstance(ids[0], str) or not ids[0].strip()
                or not (ids[1] is None or isinstance(ids[1], str) and ids[1].strip())):
            raise ValueError("human_review_binding_invalid")
        if ids not in bindings or ids in reviewed:
            raise ValueError("human_review_binding_mismatch")
        # Compare full public content directly, not a hash or display excerpt.
        # JSON comparison preserves type differences such as true versus 1.
        snapshot = json.dumps(entry.get("source_snapshot"), ensure_ascii=False, sort_keys=True, allow_nan=False)
        actual = json.dumps(bindings[ids], ensure_ascii=False, sort_keys=True, allow_nan=False)
        if snapshot != actual:
            raise ValueError("human_review_source_snapshot_mismatch")
        checks = entry.get("checks")
        if not isinstance(checks, dict) or set(checks) != set(_REVIEW_CHECKS):
            raise ValueError("human_review_check_coverage_mismatch")
        _validate_judgment(entry.get("overall"))
        for judgment in checks.values():
            _validate_judgment(judgment)
        reviewed[ids] = entry
    if set(reviewed) != set(bindings):
        raise ValueError("human_review_entry_coverage_mismatch")
    return reviewed


def _human_assessment(summary: dict, reviews: list[dict], reviewed: dict) -> str:
    total = len(reviews)
    counts = Counter(entry["overall"]["decision"] for entry in reviewed.values())
    lines = [
        "# T2 v2 外部填写的人工复核汇总", "",
        "本文先逐条校验标识、原始公开 review 内容快照、覆盖范围和填写结构，再汇总外部填写的判断。审核者身份、理由与证据引用未被独立核实；没有访问仓库、联网、调用模型或读取引用指向的内容。",
        "这是复核意见分布，不计算或宣称 accuracy、准确率、F1、精确率或召回率。支持或合理替代不是自动确立的真值；合理替代意见与原答案支持分开保留。", "",
        f"原运行状态：{_md(summary.get('status'))}；请求输入：{_number(summary.get('requested_input_count'))}；未处理输入：{_number(summary.get('unprocessed_input_count'))}。",
        f"条目分母为公开 review 中的全部 {total} 条，**包含未评**，不以已审核数量作为分母；无逐条 review 的未处理输入不冒充已复核条目。总体判定与分项判定分别填写、分别统计，不相互自动推导。", "",
        *_input_count_lines(summary, reviews),
        *_diagnostic_lines(reviews),
        "## 外部填写的逐条总判定", "",
        "| 决策 | 数量 / 全部条目 |", "|---|---|",
    ]
    lines.extend(f"| {label} | {counts[decision]} / {total} |" for decision, label in _REVIEW_DECISIONS.items())
    lines.extend(["", "## 分项判定（每项分母均包含未评）", "",
                  "| 判定项 | 支持 | 合理替代 | 反证 | 不确定 | 未评 | 分母 |", "|---|---|---|---|---|---|---|"])
    for key, label in _REVIEW_CHECKS.items():
        field_counts = Counter(entry["checks"][key]["decision"] for entry in reviewed.values())
        lines.append("| " + label + " | " + " | ".join(str(field_counts[decision]) for decision in _REVIEW_DECISIONS) + f" | {total} |")
    lines.extend(["", "## 逐条意见与原始状态", ""])
    for index, review in enumerate(reviews, 1):
        entry = reviewed[(review["entry_id"], review["report_id"])]
        fields = _object(review.get("draft_fields"))
        diagnostic = _entry_diagnostic(review, _process_record(review, reviews))
        lines.extend([
            f"### {index}. {_md(review['entry_id'], 100)} / {_md(review['report_id'], 120)}", "",
            f"原状态：{_md(review.get('status'))}；原 verify：{_md(fields.get('verify'))}。",
            *([f"输入：{_md(review.get('input_id'))}；候选 slot：{_number(review.get('slot'))}。"] if "input_id" in review else []),
            f"记录诊断：{diagnostic['label']}；{_md(diagnostic['detail'], 600)}",
            f"项目 / 标题：{_md(fields.get('project'), 120)} / {_md(fields.get('vuln_title'), 320)}；来源：{_md(review.get('source_link'), 320)}。", "",
            "| 判定项 | 外部决策 | 审核者 | 理由 / 证据引用 |", "|---|---|---|---|",
        ])
        judgments = [("总体判定", entry["overall"])] + [(label, entry["checks"][key]) for key, label in _REVIEW_CHECKS.items()]
        for label, judgment in judgments:
            refs = ", ".join(judgment["evidence_refs"])
            detail = _md(judgment["reason"], 800) + "；引用：" + (_md(refs, 600) if refs else "未填写")
            lines.append(f"| {label} | {_REVIEW_DECISIONS[judgment['decision']]} | {_md(judgment['reviewer'], 120)} | {detail} |")
        lines.append("")
    lines.extend([
        "原运行文件未被修改。草稿、unknown 或其它原状态不会因复核意见变为 complete；verify=0 不会升级为人工验证标记。未评与不确定均保留，缺失计数也不当作零。",
        "此 Markdown 为有界展示；完整的外部理由与引用保留在填写后的 JSON 中，引用内容与审核者身份仍须自行核实。", "",
    ])
    return "\n".join(lines)


def build_human_assessment(run_dir: str | Path, human_review: str | Path, destination: str | Path) -> Path:
    """Validate an external form and exclusively create a separate report."""
    destination = Path(destination)
    _new_output(destination)
    summary, reviews = _read_inputs(Path(run_dir))
    _validate_terminal_counts(summary, reviews)
    reviewed = _validate_human_review(_read_human_review(Path(human_review)), reviews)
    content = _human_assessment(summary, reviews, reviewed)
    with destination.open("x", encoding="utf-8", newline="\n") as stream:
        stream.write(content)
    return destination


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Generate a Chinese self-assessment from completed public outputs; no model or repository access.")
    parser.add_argument("--run-dir", type=Path, required=True)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--review-template", type=Path, help="Exclusively create an unfilled, entry-bound human review JSON.")
    mode.add_argument("--human-review", type=Path, help="Validate and summarize an externally filled review JSON.")
    parser.add_argument("--output", type=Path, help="New Markdown path; required only with --human-review.")
    args = parser.parse_args(argv)
    if bool(args.human_review) != bool(args.output):
        parser.error("--output is required with --human-review and is not valid in other modes")
    try:
        if args.review_template:
            destination = build_review_template(args.run_dir, args.review_template)
        elif args.human_review:
            destination = build_human_assessment(args.run_dir, args.human_review, args.output)
        else:
            destination = build_assessment(args.run_dir)
    except (OSError, ValueError, RecursionError) as error:
        code = str(error)
        if not re.fullmatch(r"[a-z][a-z0-9_]{0,100}", code):
            code = "assessment_failed"
        print(json.dumps({"status": "error", "code": code}, ensure_ascii=False))
        return 2
    print(json.dumps({"status": "written", "file": destination.name}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
