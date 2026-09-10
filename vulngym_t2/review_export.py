"""Render saved public T2 records for humans, without invoking a provider.

This standard-library-only reader checks record associations, not vulnerability
semantics or the truth of saved machine assessments. It never changes a run.
"""
from __future__ import annotations

import argparse
from collections import Counter
import json
import math
from pathlib import Path
import re
import sys


MAX_FILE_BYTES = 20_000_000
MAX_RECORDS = 500
MAX_CELL_CHARS = 8_000
_ERROR_FIELDS = ("errors", "model_errors", "tool_errors", "pipeline_errors")
_REVISION_BASIS_LABELS = {
    "behavior_at_revision": "源码机制依据", "affected_range_and_source": "影响范围+源码",
    "inspected_only": "仅检查过", "unknown": "未建立",
}
_SELF_REVIEW_LABELS = {"not_requested": "未请求（不是失败）", "completed": "已完成机器自查",
                       "failed": "机器自查失败"}
_ARGUMENTS = ("commit", "path", "file", "start_line", "end_line", "before", "after",
              "ref", "revision", "query", "pattern", "limit", "max_results", "glob", "prefix", "offset", "paths")
_RESULT_METADATA = ("commit", "path", "file", "start_line", "end_line", "before", "after",
                    "truncated", "error", "errors", "reason", "head", "shallow")
# Match the public assessment renderer's secret/local-path redaction, while
# keeping this exporter independent of every target/provider module.
_SECRET = re.compile(r"\bsk-[A-Za-z0-9_-]{8,}\b|(?i:Bearer\s+)[^\s\"']+")
_PATH = re.compile(r"(?<![A-Za-z0-9])(?:[A-Za-z]:[\\/][^\s\"'<>]*|\\\\[^\s\"'<>]+|/(?:Users|home|tmp|var/tmp)/[^\s\"'<>]*)")


class ExportError(ValueError):
    """A stable, public error code; never contains source text or paths."""


def _require(condition: bool, code: str) -> None:
    if not condition:
        raise ExportError(code)


def _local(path: str | Path) -> Path:
    value = str(path)
    _require("://" not in value and not value.startswith(("\\\\", "//")), "local_path_required")
    return Path(path)


def _object_pairs(pairs):
    result = {}
    for key, value in pairs:
        _require(key not in result, "duplicate_json_key")
        result[key] = value
    return result


def _constant(value):
    raise ExportError("nonstandard_json_constant")


def _float(value):
    number = float(value)
    _require(math.isfinite(number), "nonfinite_json_number")
    return number


def _json_object(text: str) -> dict:
    try:
        value = json.loads(text, object_pairs_hook=_object_pairs, parse_constant=_constant, parse_float=_float)
    except (ValueError, RecursionError) as error:
        raise ExportError("invalid_json") from error
    _require(isinstance(value, dict), "json_object_required")
    return value


def _read(run: Path, name: str) -> str:
    path = run / name
    _require(not path.is_symlink() and path.is_file() and path.resolve().parent == run,
             "source_file_unavailable")
    with path.open("rb") as stream:
        raw = stream.read(MAX_FILE_BYTES + 1)
    _require(len(raw) <= MAX_FILE_BYTES, "source_file_too_large")
    try:
        return raw.decode("utf-8-sig", errors="strict")
    except UnicodeError as error:
        raise ExportError("source_file_not_utf8") from error


def _rows(text: str) -> list[dict]:
    rows = []
    lines = text.split("\n") if text else []
    if lines and lines[-1] == "":
        lines.pop()
    for line in lines:
        _require(bool(line.strip()), "blank_jsonl_record")
        rows.append(_json_object(line))
        _require(len(rows) <= MAX_RECORDS, "record_limit_exceeded")
    return rows


def _index(rows: list[dict]) -> dict[str, dict]:
    result = {}
    for row in rows:
        identity = row.get("entry_id")
        _require(isinstance(identity, str) and bool(identity.strip()), "entry_id_required")
        _require(identity not in result, "duplicate_entry_id")
        result[identity] = row
    return result


def _count(summary: dict, name: str, expected: int | None = None, *, required=True) -> None:
    if not required and name not in summary:
        return
    value = summary.get(name)
    _require(type(value) is int and value >= 0, "summary_count_invalid")
    _require(expected is None or value == expected, "summary_count_mismatch")


def _validate(summary: dict, entries: list[dict], reviews: list[dict]) -> dict[str, dict]:
    entry_map, review_map = _index(entries), _index(reviews)
    _require(isinstance(summary.get("status"), str) and bool(summary["status"]), "run_status_required")
    _require(summary["status"] in {"completed", "completed_with_errors", "provider_stopped"},
             "finished_run_required")
    provider = summary.get("provider", {})
    _require(isinstance(provider, dict), "provider_summary_invalid")
    for review in reviews:
        status, identity = review.get("status"), review["entry_id"]
        _require(isinstance(status, str) and status in {"complete", "draft", "input_failure"}, "review_status_invalid")
        _require((identity in entry_map) == (status == "complete"), "entry_review_status_mismatch")
        for name in ("report_id", "source_link"):
            value = review.get(name)
            _require(value is None or isinstance(value, str), "record_identity_invalid")
            if status == "complete":
                _require(isinstance(entry_map[identity].get(name), str)
                         and bool(entry_map[identity][name].strip()), "record_identity_invalid")
        for name in ("draft_fields", "suggested_values", "field_reviews"):
            _require(isinstance(review.get(name), dict), "review_fields_invalid")
        for fields in (review["draft_fields"], review["suggested_values"], entry_map.get(identity, {})):
            for name in ("entry_id", "report_id", "source_link"):
                if fields.get(name) is not None:
                    _require(fields[name] == review.get(name), "record_identity_mismatch")
        evidence = review.get("evidence")
        _require(isinstance(evidence, list), "evidence_invalid")
        evidence_ids = set()
        for item in evidence:
            _require(isinstance(item, dict), "evidence_invalid")
            evidence_id = item.get("id")
            _require(isinstance(evidence_id, str) and bool(evidence_id.strip()), "evidence_id_required")
            _require(evidence_id not in evidence_ids, "duplicate_evidence_id")
            evidence_ids.add(evidence_id)
            if "arguments" in item:
                _require(isinstance(item["arguments"], dict), "evidence_arguments_invalid")
        for assessment in review["field_reviews"].values():
            _require(isinstance(assessment, dict), "field_review_invalid")
            _require(isinstance(assessment.get("status"), str)
                     and isinstance(assessment.get("reason"), str), "field_review_invalid")
            refs = assessment.get("evidence_refs")
            _require(isinstance(refs, list) and all(isinstance(ref, str) for ref in refs),
                     "evidence_refs_invalid")
        for name in _ERROR_FIELDS:
            _require(isinstance(review.get(name), list), "review_errors_invalid")
        for name in ("model_calls", "tool_calls"):
            _require(type(review.get(name)) is int and review[name] >= 0, "review_count_invalid")
    _require(set(entry_map) <= set(review_map), "entry_without_review")
    counts = Counter(review["status"] for review in reviews)
    for name, expected in (("input_count", len(reviews)), ("entry_count", len(entries)),
                           ("schema_entry_count", len(entries)), ("candidate_count", len(entries)),
                           ("draft_count", counts["draft"]), ("input_failure_count", counts["input_failure"])):
        _count(summary, name, expected)
    _count(summary, "human_verified_count", required=False)
    _count(summary, "report_count", len({entry.get("report_id") for entry in entries}), required=False)
    for name, field in (("model_error_count", "model_errors"), ("tool_error_count", "tool_errors"),
                        ("pipeline_error_count", "pipeline_errors")):
        _count(summary, name, sum(len(review[field]) for review in reviews), required=False)
    _count(summary, "jobs_with_model_errors", sum(bool(row["model_errors"]) for row in reviews), required=False)
    _count(summary, "format_failure_count", required=summary["status"] == "completed_with_errors")
    if summary["status"] == "completed_with_errors":
        _require(summary["format_failure_count"] > 0, "format_failure_count_invalid")
        _count(summary, "unprocessed_input_count", 0)
    if "case_failures" in summary:
        failures = summary["case_failures"]
        _require(isinstance(failures, list), "case_failures_invalid")
        for failure in failures:
            _require(isinstance(failure, dict)
                     and isinstance(failure.get("report_id"), str)
                     and isinstance(failure.get("code"), str)
                     and type(failure.get("continued")) is bool, "case_failures_invalid")
    for name in ("model_calls", "tool_calls"):
        _count(summary, name, sum(review[name] for review in reviews), required=False)
    requested = "requested_input_count" in summary
    unprocessed = "unprocessed_input_count" in summary
    _require(requested == unprocessed, "incomplete_input_counts")
    if requested:
        _count(summary, "requested_input_count")
        _count(summary, "unprocessed_input_count")
        _require(summary["requested_input_count"] == len(reviews) + summary["unprocessed_input_count"],
                 "summary_count_mismatch")
        _require(summary["status"] not in {"completed", "completed_with_errors"}
                 or summary["unprocessed_input_count"] == 0,
                 "completed_run_has_unprocessed_inputs")
    return entry_map


def _cell(value) -> str:
    """Entity-escape Markdown/HTML syntax; source newlines stay inside one cell."""
    text = value if isinstance(value, str) else json.dumps(value, ensure_ascii=False, sort_keys=True, allow_nan=False)
    text = _PATH.sub("[local path redacted]", _SECRET.sub("[secret redacted]", text))
    if len(text) > MAX_CELL_CHARS:
        text = text[:MAX_CELL_CHARS] + f" [truncated: {len(text) - MAX_CELL_CHARS} characters omitted]"
    text = text.replace("\r", "\\r").replace("\n", "\\n").replace("\t", "\\t")
    syntax = "&<>\"'|`*_{}[]()\\#+-.!~=:/$"
    return "".join(f"&#{ord(char)};" if char in syntax or ord(char) < 32 or 127 <= ord(char) < 160
                   or char in "\u2028\u2029\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069" else char
                   for char in text)


def _table(headers, rows) -> list[str]:
    return ["| " + " | ".join(headers) + " |", "| " + " | ".join("---" for _ in headers) + " |",
            *("| " + " | ".join(_cell(value) for value in row) + " |" for row in rows), ""]


def _fields(title: str, fields: dict) -> list[str]:
    return ["### " + title, "", *(_table(("字段", "已记录值"), sorted(fields.items()))
                                   if fields else ["无记录。", ""])]


def _revision_basis_label(assessment: dict) -> str:
    if "revision_basis" not in assessment:
        return "旧记录未声明"
    value = assessment["revision_basis"]
    return _REVISION_BASIS_LABELS.get(value, "未识别声明") if isinstance(value, str) else "未识别声明"


def _self_review_status_label(review: dict) -> str:
    if "self_review_status" not in review:
        return "旧记录未声明"
    value = review["self_review_status"]
    return _SELF_REVIEW_LABELS.get(value, "未识别声明") if isinstance(value, str) else "未识别声明"


def render_packet(summary: dict, entries: list[dict], reviews: list[dict]) -> str:
    """Validate saved record structure and render an inert Markdown packet."""
    entry_map = _validate(summary, entries, reviews)
    lines = ["# T2 人工复核材料包", "",
             "仅离线导出：本次导出发出 0 次 HTTP 请求，未调用模型、读取目标仓库或修改原始运行文件。", "",
             "下列机器判断仅为已记录的主张，不是独立证据或人工批准。complete 仅表示已保存完整 schema 条目，不等于漏洞已确认。", "",
             "人工复核状态：未知。已记录的 verify 字段及 human_verified_count 不能证明人工复核；本工具不填写批准或验证结果。", "",
             "疑似密钥和本地绝对路径已脱敏。过长单元格以 truncated 标记截断；原始记录保持不变。", "",
             "## 已保存运行摘要", ""]
    summary_keys = ("status", "input_count", "requested_input_count", "unprocessed_input_count", "candidate_count",
                    "entry_count", "schema_entry_count", "draft_count", "input_failure_count", "report_count",
                    "human_verified_count", "model_calls", "tool_calls", "model_error_count", "tool_error_count",
                    "pipeline_error_count", "jobs_with_model_errors", "format_failure_count", "elapsed_seconds")
    lines += _table(("已记录指标", "值"), ((key, summary[key]) for key in summary_keys if key in summary))
    if summary["status"] == "completed_with_errors":
        lines += ["批次已处理完但含格式错误（completed_with_errors）：全部输入已处理，至少一项格式失败；不是全成功。失败输入仍是草稿，不因导出而补成完整候选。", ""]
    if summary.get("case_failures"):
        lines += ["### 已记录逐项格式失败", ""]
        lines += _table(("公告", "错误代码", "失败后是否继续批次"),
                        ((item["report_id"], item["code"], item["continued"]) for item in summary["case_failures"]))
    provider = summary.get("provider", {})
    if summary["status"] == "provider_stopped" or provider.get("halted"):
        lines += ["提供方已停止（provider_stopped）：已保存处理被中止。未处理输入没有逐条复核章节；本材料包不会恢复运行。", ""]
    lines += ["输入失败（input_failure）、草稿（draft）与完整候选（complete）分别统计。无论运行状态如何，未提供人工判断时，人工复核状态始终为未知。", ""]
    lines += _fields("已记录提供方信息（历史运行，不是本次导出活动）",
                     {key: provider[key] for key in ("model", "reasoning_effort", "halted", "http_attempts", "usage",
                                                    "unknown_usage_attempts", "automatic_retries") if key in provider})
    for number, review in enumerate(reviews, 1):
        lines += [f"## 逐条复核 {number}：{_cell(review['entry_id'])}", ""]
        lines += _table(("已记录身份 / 状态", "值"),
                        ((key, review.get(key)) for key in ("entry_id", "report_id", "source_link", "status", "verification")))
        lines += ["机器自查状态：" + _self_review_status_label(review) + "。机器自查不等于独立人工审核。", ""]
        if review["status"] == "complete":
            lines += _fields("完整字段（按 entry_id 匹配 entries.jsonl）", entry_map[review["entry_id"]])
        else:
            if review["status"] == "input_failure":
                lines += ["输入失败：该输入未导出完整条目。", ""]
            lines += _fields("草稿字段（review.jsonl；不是完整条目）", review["draft_fields"])
            lines += _fields("建议值（未验证；不是已采纳字段）", review["suggested_values"])
        lines += ["### 字段判断（已记录机器复核）", ""]
        lines += ["版本判断依据（已记录机器声明）："
                  + _revision_basis_label(review["field_reviews"].get("commit", {}))
                  + "。机器声明不等于人工审核；缺少旧字段不会改变原有状态，也不会补造版本依据。", ""]
        known = {item["id"] for item in review["evidence"]}
        rows = []
        for field, assessment in sorted(review["field_reviews"].items()):
            refs = assessment["evidence_refs"]
            unresolved = [ref for ref in refs if ref not in known and not ref.startswith("controller:")]
            notes = {key: value for key, value in assessment.items() if key not in {"status", "reason", "evidence_refs"}}
            if unresolved:
                notes["unresolved_evidence_refs"] = unresolved
            rows.append((field, assessment["status"], assessment["reason"], refs, notes))
        lines += _table(("字段", "状态", "理由", "证据引用", "其他已记录细节"), rows)
        lines += ["controller 引用表示已记录控制器规则，不是源码证据。无法解析的引用仅标记为 unresolved_evidence_refs，不会自动修复。", "",
                  "### 证据清单", "",
                  "仅列清单：不展开原始结果、源码、差异或公告正文，只显示选定工具参数和结果元数据。", ""]
        evidence_rows = []
        for item in review["evidence"]:
            args = item.get("arguments", {})
            metadata = {key: item[key] for key in ("name", "document_kind", "truncated") if key in item}
            result = item.get("result")
            if isinstance(result, dict):
                metadata["result_metadata"] = {key: result[key] for key in _RESULT_METADATA if key in result}
            omitted = sorted(set(args) - set(_ARGUMENTS))
            if omitted:
                metadata["omitted_argument_keys"] = omitted
            evidence_rows.append((item["id"], item.get("kind", "not recorded"), item.get("tool", "not applicable / not recorded"),
                                  item.get("success", "not recorded"), {key: args[key] for key in _ARGUMENTS if key in args}, metadata))
        lines += _table(("引用", "类型", "工具", "成功状态", "选定参数", "元数据"), evidence_rows)
        lines += ["### 已记录错误", ""]
        for name in _ERROR_FIELDS:
            values = review[name]
            lines += _table((name, "已记录细节"), enumerate(values, 1)) if values else [name + "：无记录。", ""]
        lines += ["### 人工复核清单（有意留空）", "",
                  "- [ ] 复核人及日期：__________",
                  "- [ ] 独立检查公告及准确的源码版本。",
                  "- [ ] 核对条目字段、源码坐标、证据引用和未解决问题。",
                  "- [ ] 填写人工决定及理由：__________", "",
                  "本材料包没有填写任何批准结论或 verify 值。", ""]
    if not reviews:
        lines += ["没有已处理的复核记录；不暗示任何逐输入判断。", ""]
    return "\n".join(lines)


def export_review(run_dir: str | Path, output: str | Path) -> dict:
    run, destination = _local(run_dir), _local(output)
    _require(not run.is_symlink() and run.is_dir(), "run_directory_unavailable")
    run = run.resolve(strict=True)
    _require(not destination.is_symlink(), "output_exists")
    destination = destination.resolve(strict=False)
    _require(not destination.is_relative_to(run), "output_must_be_outside_run")
    _require(not destination.exists(), "output_exists")
    _require(destination.parent.is_dir(), "output_parent_unavailable")
    summary = _json_object(_read(run, "summary.json"))
    entries, reviews = _rows(_read(run, "entries.jsonl")), _rows(_read(run, "review.jsonl"))
    packet = render_packet(summary, entries, reviews)
    with destination.open("x", encoding="utf-8", newline="\n") as stream:
        stream.write(packet)
    return {"status": "exported", "output": str(destination), "review_count": len(reviews),
            "entry_count": len(entries), "http_attempts": 0}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-dir", required=True, help="Finished run containing public summary, entries and review records")
    parser.add_argument("--output", required=True, help="New Markdown file outside the run; parent directory must exist")
    args = parser.parse_args(argv)
    try:
        result = export_review(args.run_dir, args.output)
    except (ExportError, OSError, ValueError, RecursionError) as error:
        result = {"status": "error", "code": str(error) if isinstance(error, ExportError) else "export_failed", "http_attempts": 0}
        print(json.dumps(result, ensure_ascii=True, separators=(",", ":")))
        return 2
    print(json.dumps(result, ensure_ascii=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    sys.exit(main())
