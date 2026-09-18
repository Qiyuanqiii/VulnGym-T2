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

from .output import DRAFT_EXPORT_VERSION, _SERIAL_SCOPE, _split_errors, draft_export_row


MAX_FILE_BYTES = 20_000_000
MAX_RECORDS = 500
MAX_MULTI_RECORDS = 2_000  # 500 inputs, at most four candidates each.
MAX_CELL_CHARS = 8_000
_ERROR_FIELDS = ("errors", "model_errors", "tool_errors", "pipeline_errors")
_REVISION_BASIS_LABELS = {
    "behavior_at_revision": "源码机制依据", "affected_range_and_source": "影响范围+源码",
    "inspected_only": "仅检查过", "unknown": "未建立",
}
_SELF_REVIEW_LABELS = {"not_requested": "未请求（不是失败）", "completed": "已完成机器自查",
                       "failed": "机器自查失败"}
_EVIDENCE_FOLLOWUP_LABELS = {"not_requested": "未请求（不是失败）", "completed": "已完成聚焦补证",
                             "failed": "聚焦补证失败"}
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


def _rows(text: str, *, max_records: int = MAX_RECORDS) -> list[dict]:
    rows = []
    lines = text.split("\n") if text else []
    if lines and lines[-1] == "":
        lines.pop()
    for line in lines:
        _require(bool(line.strip()), "blank_jsonl_record")
        rows.append(_json_object(line))
        _require(len(rows) <= max_records, "record_limit_exceeded")
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


def _input_reviews(summary: dict, reviews: list[dict]) -> list[dict] | None:
    """Check the versioned input-to-candidate association; no semantic verdict."""
    if "counting_version" not in summary:
        return None
    _require(summary["counting_version"] == "input-review-v2", "counting_version_unsupported")
    groups = summary.get("input_reviews")
    _require(isinstance(groups, list), "input_reviews_required")
    _require(len(groups) <= MAX_RECORDS, "input_limit_exceeded")
    review_map = _index(reviews)
    seen_inputs, ordered_ids, input_counts = set(), [], Counter()
    for group in groups:
        _require(isinstance(group, dict), "input_review_invalid")
        input_id = group.get("input_id")
        _require(isinstance(input_id, str) and bool(input_id.strip()), "input_id_required")
        _require(input_id not in seen_inputs, "duplicate_input_id")
        seen_inputs.add(input_id)
        ids = group.get("review_entry_ids")
        _require(isinstance(ids, list) and 1 <= len(ids) <= 4
                 and all(isinstance(identity, str) and identity in review_map for identity in ids),
                 "input_review_coverage_mismatch")
        _require(ids[0] == input_id, "input_review_first_slot_mismatch")
        rows = [review_map[identity] for identity in ids]
        statuses = []
        for slot, row in enumerate(rows, 1):
            _require(row.get("input_id") == input_id and type(row.get("slot")) is int
                     and row["slot"] == slot, "input_review_slot_mismatch")
            scope = row.get("process_metadata_scope")
            _require(scope in ("shared_input", _SERIAL_SCOPE)
                     and scope == rows[0].get("process_metadata_scope"), "process_metadata_scope_invalid")
            if scope == _SERIAL_SCOPE:
                _require(row.get("annotation_mode") == "snapshot"
                         and isinstance(row.get("input_errors"), list)
                         and isinstance(row.get("input_actions"), list), "candidate_process_invalid")
            for name in ("report_id", "source_link"):
                _require(group.get(name) == row.get(name), "input_review_identity_mismatch")
            _require(isinstance(row.get("status"), str)
                     and row["status"] in {"complete", "draft", "input_failure"}, "review_status_invalid")
            statuses.append(row["status"])
            for name in ("model_calls", "tool_calls"):
                _require(type(row.get(name)) is int and row[name] >= 0, "review_count_invalid")
                if slot > 1:
                    _require(row[name] == 0, "shared_process_metadata_repeated")
            if slot > 1:
                for name in (("input_errors", "input_actions") if scope == _SERIAL_SCOPE else
                             ("model_errors", "tool_errors", "pipeline_errors", "actions")):
                    _require(row.get(name) == [], "shared_process_metadata_repeated")
        if "input_failure" in statuses:
            _require(statuses == ["input_failure"], "input_failure_candidates_invalid")
            status = "input_failure"
        else:
            status = ("complete" if all(value == "complete" for value in statuses)
                      else "partial" if "complete" in statuses else "draft")
        _require(group.get("status") == status, "input_review_status_mismatch")
        _require(group.get("entry_ids") == [row["entry_id"] for row in rows if row["status"] == "complete"],
                 "input_entry_coverage_mismatch")
        for name in ("model_calls", "tool_calls"):
            _require(type(group.get(name)) is int and group[name] == rows[0][name], "input_process_count_mismatch")
        input_counts[status] += 1
        ordered_ids.extend(ids)
    _require(ordered_ids == [row["entry_id"] for row in reviews]
             and len(ordered_ids) == len(set(ordered_ids)), "input_review_coverage_mismatch")
    for name, expected in (("input_count", len(groups)), ("review_count", len(reviews)),
                           ("complete_input_count", input_counts["complete"]),
                           ("partial_input_count", input_counts["partial"]),
                           ("draft_input_count", input_counts["draft"]),
                           ("input_failure_count", input_counts["input_failure"]),
                           ("candidate_count", sum(row["status"] == "complete" for row in reviews)),
                           ("entry_count", sum(row["status"] == "complete" for row in reviews)),
                           ("schema_entry_count", sum(row["status"] == "complete" for row in reviews)),
                           ("draft_count", sum(row["status"] == "draft" for row in reviews))):
        _count(summary, name, expected)
    for name in ("requested_input_count", "unprocessed_input_count"):
        _count(summary, name)
    _require(summary["requested_input_count"] == len(groups) + summary["unprocessed_input_count"],
             "summary_count_mismatch")
    _require(summary.get("status") not in ("completed", "completed_with_errors")
             or summary["unprocessed_input_count"] == 0, "completed_run_has_unprocessed_inputs")
    return groups


def _process_record(review: dict, reviews: list[dict]) -> dict:
    """Resolve shared process metadata without mutating either saved row."""
    if review.get("process_metadata_scope") == _SERIAL_SCOPE:
        shared = next((row for row in reviews if row.get("input_id") == review.get("input_id") and row.get("slot") == 1), {})
        return dict(review, **{key: shared.get(key) for key in ("model_calls", "tool_calls", "input_errors", "input_actions")},
                    usage_entry_id=shared.get("entry_id"))
    if review.get("process_metadata_scope") != "shared_input":
        return review
    return next((row for row in reviews if row.get("input_id") == review.get("input_id")
                 and row.get("slot") == 1), {})


def _validate(summary: dict, entries: list[dict], reviews: list[dict]) -> dict[str, dict]:
    entry_map, review_map = _index(entries), _index(reviews)
    _require(isinstance(summary.get("status"), str) and bool(summary["status"]), "run_status_required")
    _require(summary["status"] in {"completed", "completed_with_errors", "provider_stopped", "interrupted"},
             "finished_run_required")
    provider = summary.get("provider", {})
    _require(isinstance(provider, dict), "provider_summary_invalid")
    for review in reviews:
        status, identity = review.get("status"), review["entry_id"]
        _require(isinstance(status, str) and status in {"complete", "draft", "input_failure"}, "review_status_invalid")
        _require((identity in entry_map) == (status == "complete"), "entry_review_status_mismatch")
        if review.get("annotation_mode") == "snapshot" and status == "complete":
            _require(review.get("self_review_status") == "completed", "snapshot_self_review_required")
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
        for name in ("actions", "input_actions"):
            if name in review:
                _require(isinstance(review[name], list), "review_actions_invalid")
        if "input_errors" in review:
            _require(isinstance(review["input_errors"], list), "review_errors_invalid")
        if status == "complete" and review.get("annotation_mode") == "snapshot":
            _require(entry_map[identity] == review["draft_fields"], "entry_review_content_mismatch")
        if "annotation_errors" in review:
            field_errors = review["annotation_errors"]
            _require(isinstance(field_errors, list) and all(
                isinstance(item, dict) and all(isinstance(item.get(key), str) for key in ("field", "code", "path"))
                for item in field_errors), "annotation_errors_invalid")
            _require(not field_errors or status != "complete", "annotation_errors_complete_mismatch")
        for name in ("model_calls", "tool_calls"):
            _require(type(review.get(name)) is int and review[name] >= 0, "review_count_invalid")
    _require(set(entry_map) <= set(review_map), "entry_without_review")
    groups = _input_reviews(summary, reviews)
    processed = len(groups) if groups is not None else len(reviews)
    counts = Counter(review["status"] for review in reviews)
    for name, expected in (("input_count", processed), ("entry_count", len(entries)),
                           ("schema_entry_count", len(entries)), ("candidate_count", len(entries)),
                           ("draft_count", counts["draft"]), ("input_failure_count", counts["input_failure"])):
        _count(summary, name, expected)
    _count(summary, "draft_export_count", counts["draft"] + counts["input_failure"], required=False)
    if "draft_export_version" in summary:
        _require(summary["draft_export_version"] == DRAFT_EXPORT_VERSION, "draft_export_version_unsupported")
        _count(summary, "draft_export_count", counts["draft"] + counts["input_failure"])
    _count(summary, "human_verified_count", required=False)
    reports = len({entry.get("report_id") for entry in entries})
    _count(summary, "report_conflict_count", required=False)
    conflicts = summary.get("report_conflict_count", 0)
    _require(conflicts <= reports, "report_conflict_count_invalid")
    _count(summary, "report_count", reports, required=False)
    if "report_linkage_complete" in summary:
        _require(type(summary["report_linkage_complete"]) is bool, "report_linkage_invalid")
    shared_errors = [_split_errors(row.get("input_errors", []), input_failure=row.get("status") == "input_failure") for row in reviews]
    for name, field, index in (("model_error_count", "model_errors", 1), ("tool_error_count", "tool_errors", 2),
                               ("pipeline_error_count", "pipeline_errors", 0)):
        _count(summary, name, sum(len(review[field]) + len(extra[index]) for review, extra in zip(reviews, shared_errors)), required=False)
    model_error_inputs = {row["input_id"] if groups is not None else row["entry_id"]
                          for row, extra in zip(reviews, shared_errors) if row["model_errors"] or extra[1]}
    _count(summary, "jobs_with_model_errors", len(model_error_inputs), required=False)
    _count(summary, "annotation_error_count", sum(len(row.get("annotation_errors", [])) for row in reviews), required=False)
    affected_inputs = {row["input_id"] if groups is not None else row["entry_id"]
                       for row in reviews if row.get("annotation_errors")}
    _count(summary, "jobs_with_annotation_errors", len(affected_inputs), required=False)
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
    if summary["status"] == "interrupted":
        _require(requested and unprocessed, "incomplete_input_counts")
    _require(requested == unprocessed, "incomplete_input_counts")
    if requested:
        _count(summary, "requested_input_count")
        _count(summary, "unprocessed_input_count")
        _require(summary["requested_input_count"] == processed + summary["unprocessed_input_count"],
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
    if review.get("annotation_mode") == "snapshot" and review.get("self_review_status") == "not_requested":
        return "未完成必需自查（保留草稿，不等于请求失败）"
    if "self_review_status" not in review:
        return "旧记录未声明"
    value = review["self_review_status"]
    return _SELF_REVIEW_LABELS.get(value, "未识别声明") if isinstance(value, str) else "未识别声明"


def _evidence_followup_status_label(review: dict) -> str:
    if "evidence_followup_status" not in review:
        return "旧记录未声明"
    value = review["evidence_followup_status"]
    return _EVIDENCE_FOLLOWUP_LABELS.get(value, "未识别声明") if isinstance(value, str) else "未识别声明"


# Re-encoding records whose saved summaries are known non-recovery outcomes;
# "recovered" / "partial" mean a draft was received and are never flagged.
_SNAPSHOT_REENCODE_UNRECOVERED = ("budget_unavailable", "provider_stopped", "context_unavailable", "failed")


def _initial_draft_gap_signals(review: dict) -> list[tuple[str, str]]:
    """Recorded signals that no valid structured initial draft was received.

    Pure display over saved records; nothing is inferred or repaired. Only the
    two statuses meaning no draft content arrived are flagged. An accepted or
    partial initial draft takes precedence over failed later-stage encodings:
    that row already holds received fields and is not an empty placeholder.
    Rows without the field (old records) fall back only to their own explicit
    draft-stage actions, never self-review, unstaged or shared process actions.
    """
    if review.get("status") == "complete":
        return []
    status = review.get("initial_draft_status")
    if isinstance(status, str) and status in ("accepted", "partial"):
        return []
    signals = []
    if isinstance(status, str) and status in ("not_received", "no_valid_updates"):
        signals.append(("initial_draft_status", status))
    actions = review.get("actions")
    if isinstance(actions, list):
        signals.extend(("annotation_snapshot_reencoding", item["summary"]) for item in actions
                       if isinstance(item, dict) and item.get("action") == "annotation_snapshot_reencoding"
                       and item.get("stage") == "draft"
                       and item.get("summary") in _SNAPSHOT_REENCODE_UNRECOVERED)
    return signals


def _candidate_provenance_lines(review: dict) -> list[str]:
    """Display a closed, bounded subset of saved provenance; infer no history."""
    lines = ["### 原始候选提案与证据时间边界", "",
             "原提案是未验证的候选范围，不是事实或人工批准；不得仅据范围或源码重叠合并候选。", ""]
    provenance = review.get("candidate_provenance")
    unknown = "后来共享证据：未记录或边界未知（unknown_boundary），无法区分当时可用与后来补读；不能推断没有补读。"
    if not isinstance(provenance, dict):
        return lines + ["原提案及逐调用证据截止：未记录（旧记录或无有效候选来源元数据）。", "", unknown, ""]

    def refs(value):
        if (not isinstance(value, list) or len(value) > 256
                or any(not isinstance(item, str) or re.fullmatch(r"E[0-9]{4,8}", item) is None for item in value)):
            return None
        return value

    proposal = provenance.get("original_proposal")
    proposal = proposal if isinstance(proposal, dict) else {}
    scope = proposal.get("scope")
    proposal_refs = refs(proposal.get("evidence_refs"))
    lines += _table(("原提案（未验证）", "提出时引用的已保存 EIDs"),
                    [(scope if isinstance(scope, str) else "未记录",
                      proposal_refs if proposal_refs is not None else "未记录或超出展示边界")])
    lines += ["下表仅记录每次模型调用开始时可用的已保存证据；可用不等于调用成功、评估完成、证据已被采纳或每个字节都已见。失败调用也可有截止记录。", ""]
    calls = provenance.get("model_call_evidence")
    if isinstance(calls, list):
        rows = []
        for call in calls[:256]:
            if not isinstance(call, dict):
                rows.append(("未记录", "未记录", "未记录", "未记录"))
                continue
            stage, number = call.get("stage"), call.get("call")
            count, last = call.get("evidence_count"), call.get("last_evidence_ref")
            rows.append((stage[:80] + (" [truncated]" if len(stage) > 80 else "") if isinstance(stage, str) else "未记录",
                         number if type(number) is int and number > 0 else "未记录",
                         count if type(count) is int and count >= 0 else "未记录",
                         last if isinstance(last, str) and re.fullmatch(r"E[0-9]{4,8}", last) else
                         "空证据边界" if type(count) is int and count == 0 and last is None else "未记录"))
        lines += (_table(("阶段", "调用号", "调用前证据数", "调用前截止 EID"), rows) if rows else
                  ["已保存的逐 model_call 列表为空；不据此补造成功评估。", ""])
        if len(calls) > 256:
            lines += [f"逐调用展示已截断：另有 {len(calls) - 256} 项未展开。", ""]
    else:
        lines += ["逐 model_call 证据截止未记录；不能按当前共享证据清单倒推。", ""]
    later = refs(provenance.get("later_shared_evidence_refs"))
    if provenance.get("later_shared_evidence_status") == "recorded" and later is not None:
        lines += _table(("候选处理结束后加入共享表的 EIDs",), [(later,)])
        lines += ["按已记录边界，这些后来共享回执未用于该候选当时评估；它们仍保留在下方共享证据清单。空列表仅指候选结束后无已记录新增，不表示候选内部没有补读。", ""]
    else:
        lines += [unknown, ""]
    return lines


def _candidate_selection_lines(reviews: list[dict]) -> list[str]:
    """Show recorded proposal coverage once per input, without inferring omissions."""
    rows = []
    seen = set()
    for review in reviews:
        identity = review.get("input_id", review.get("entry_id"))
        if identity in seen:
            continue
        seen.add(identity)
        # Serial runs store input actions only on slot 1. Older runs keep actions
        # on the shared process record. Never sum a copied plan across children.
        process = _process_record(review, reviews)
        actions = process.get("input_actions")
        if actions is None:
            actions = process.get("actions", [])
        plans = [item for item in actions if isinstance(item, dict)
                 and item.get("action") == "candidate_plan"] if isinstance(actions, list) else []
        if not plans:
            continue
        plan = plans[0]
        counts = [plan.get(key) for key in ("proposed_count", "selected_count", "omitted_count")]
        valid = (len(plans) == 1 and all(type(value) is int and 0 <= value <= 500 for value in counts)
                 and counts[0] == counts[1] + counts[2])
        reserve = plan.get("encoding_reserve")
        rows.append((identity, *(counts if valid else ["记录不一致"] * 3),
                     reserve if type(reserve) is int and reserve in (0, 1) else "未记录"))
    if not rows:
        return []
    return ["### 候选选择覆盖（不是准确率）", ""] + _table(
        ("输入", "提出", "实际选择", "未选择（含去重）", "编码纠正预留调用"), rows) + [
        "未选择的提案没有完成逐条处理，也未在此判定是否成立；不能把所选候选处理完解释为全部提案已处理。预留调用未必实际消费，实际消费见 annotation_encoding_reserve 动作。旧记录未提供预留值时不补算。", ""]


def render_packet(summary: dict, entries: list[dict], reviews: list[dict],
                  drafts: list[dict] | None = None) -> str:
    """Validate saved record structure and render an inert Markdown packet."""
    entry_map = _validate(summary, entries, reviews)
    draft_map = None
    if drafts is not None:
        draft_map = _index(drafts)
        expected = {review["entry_id"]: draft_export_row(review) for review in reviews
                    if review["status"] != "complete"}
        # JSON booleans/floats must not compare equal to integer verify/lines.
        _require(json.dumps(draft_map, sort_keys=True, allow_nan=False)
                 == json.dumps(expected, sort_keys=True, allow_nan=False), "draft_review_content_mismatch")
    lines = ["# T2 人工复核材料包", "",
             "仅离线导出：本次导出发出 0 次 HTTP 请求，未调用模型、读取目标仓库或修改原始运行文件。", "",
             "下列机器判断仅为已记录的主张，不是独立证据或人工批准。complete 仅表示已保存完整 schema 条目，不等于漏洞已确认。", "",
             "人工复核状态：未知。已记录的 verify 字段及 human_verified_count 不能证明人工复核；本工具不填写批准或验证结果。", "",
             "疑似密钥和本地绝对路径已脱敏。过长单元格以 truncated 标记截断；原始记录保持不变。", "",
             "## 已保存运行摘要", ""]
    summary_keys = ("status", "counting_version", "input_count", "requested_input_count", "unprocessed_input_count",
                    "complete_input_count", "partial_input_count", "draft_input_count", "review_count", "candidate_count",
                    "entry_count", "schema_entry_count", "draft_count", "draft_export_count", "input_failure_count", "report_count",
                    "report_conflict_count", "report_conflict_entry_count", "report_linkage_complete",
                    "human_verified_count", "model_calls", "tool_calls", "model_error_count", "tool_error_count",
                    "pipeline_error_count", "jobs_with_model_errors", "annotation_error_count",
                    "jobs_with_annotation_errors", "format_failure_count", "format_failure_definition", "elapsed_seconds")
    lines += _table(("已记录指标", "值"), ((key, summary[key]) for key in summary_keys if key in summary))
    lines += _candidate_selection_lines(reviews)
    if "draft_export_version" in summary or drafts is not None:
        lines += ["drafts.jsonl 是待复核草稿，不是符合正式 schema 的完整数据集；每个 draft / input_failure 记录各保留一行，完整候选只在 entries.jsonl 中。", "",
                  '草稿固定保留 15 个正式字段名；缺失标量及缺失 entry_point / critical_operation 用空字符串 ""，已有位置仍为对象，不补造文件、行号或代码。缺失 trace / vuln_ids 用空数组 []，verify 固定为 0。仅投影 draft_fields，不采纳 suggested_values；原始 null、证据、理由和建议仍在 review.jsonl。', "",
                  "draft_export_count 包含输入失败占位，draft_count 不包含；字段齐全但自查等过程未完成的草稿仍不能升级为完整候选。", ""]
    lines += ["annotation_error_count 是各候选当前未解决的字段协议异常项数，jobs_with_annotation_errors 是涉及输入的去重数；可恢复的字段协议异常不等于模型整体请求失败，也不能算作纯证据不足。合法兄弟字段保留；已修复历史只在 actions 中保留，不永久禁止完整候选。旧记录缺失这两个指标时保持未记录。", ""]
    lines += ["format_failure_count 沿用原摘要计数口径；旧记录中该计数为 0 不排除协议失败，应结合 model_failure 结构诊断和逐条阶段状态核对。错误文字项数不等于失败 HTTP 请求数。", ""]
    if summary.get("counting_version") == "input-review-v2":
        lines += [f"输入分母：{summary['input_count']} 个已处理输入；候选复核分母：{len(reviews)} 条 review（包含草稿与输入失败占位）。一输入可以产生多条候选，不能将 review 数当作已处理输入数。", "",
                  "输入级 complete / partial / draft / input_failure 与候选级 complete / draft 分开；partial 表示同输入既有完整候选也有草稿。输入失败仅保留一条占位记录。", "",
                  "调用用量仅在同 input_id 的 slot 1 记录，不再次累加。旧 shared_input 的过程错误/actions 共享；串行 candidate_with_shared_usage 的状态、错误和 actions 属于本候选，input_errors/input_actions 单列输入背景，不倒推否定先前已完成候选。", ""]
    if "report_linkage_complete" in summary:
        lines += ["report_linkage_complete 只说明完整 entries 到 reports 的聚合关联是否齐全，不证明语义合格；报告元数据冲突另记警告，当前导出仍保留 canonical report 与完整 entry，冲突不等于关联缺失。", ""]
    if summary["status"] == "completed_with_errors":
        lines += ["批次已处理完但含格式错误（completed_with_errors）：全部输入已处理，至少一项格式失败；不是全成功。失败输入仍是草稿，不因导出而补成完整候选。", ""]
    if summary.get("case_failures"):
        lines += ["### 已记录逐项格式失败", ""]
        lines += _table(("公告", "错误代码", "失败后是否继续批次"),
                        ((item["report_id"], item["code"], item["continued"]) for item in summary["case_failures"]))
    provider = summary.get("provider", {})
    if summary["status"] == "provider_stopped" or provider.get("halted"):
        lines += ["提供方已停止（provider_stopped）：已保存处理被中止。未处理输入没有逐条复核章节；本材料包不会恢复运行。", ""]
    if summary["status"] == "interrupted":
        lines += ["本地中断（interrupted）：仅展示已保存记录，不恢复运行；不能仅凭可导出就认定剩余输入可以安全重跑。", ""]
    lines += ["输入失败（input_failure）、草稿（draft）与完整候选（complete）分别统计。无论运行状态如何，未提供人工判断时，人工复核状态始终为未知。", ""]
    lines += _fields("已记录提供方信息（历史运行，不是本次导出活动）",
                     {key: provider[key] for key in ("model", "reasoning_effort", "halted", "http_attempts", "usage",
                                                    "unknown_usage_attempts", "automatic_retries") if key in provider})
    for number, review in enumerate(reviews, 1):
        process = _process_record(review, reviews)
        lines += [f"## 逐条复核 {number}：{_cell(review['entry_id'])}", ""]
        lines += _table(("已记录身份 / 状态", "值"),
                        ((key, review.get(key)) for key in ("entry_id", "report_id", "source_link", "status", "verification")))
        if "input_id" in review:
            lines += _table(("输入关联 / 共享过程", "值"),
                            (("input_id", review["input_id"]), ("slot", review.get("slot")),
                             ("共享用量记录 entry_id", process.get("usage_entry_id", process.get("entry_id"))),
                             ("共享 model_calls", process.get("model_calls")),
                             ("共享 tool_calls", process.get("tool_calls"))))
        lines += ["聚焦补证状态：" + _evidence_followup_status_label(review)
                  + "。首次草稿后、最终自查前的预算内只读补证，实际次数见动作记录；非人工验收，不保证语义正确。", "",
                  "机器自查状态：" + _self_review_status_label(review) + "。机器自查不等于独立人工审核。", ""]
        if "initial_draft_status" in review:
            lines += ["初稿接收状态（仅格式处理，不是事实确认）：" + _cell(review["initial_draft_status"])
                      + "。no_valid_updates 不代表收到有效初稿。", ""]
        if review["status"] == "complete":
            lines += _fields("完整字段（按 entry_id 匹配 entries.jsonl）", entry_map[review["entry_id"]])
        else:
            if review["status"] == "input_failure":
                lines += ["输入失败：该输入未导出完整条目。", ""]
            if draft_map is not None:
                lines += _fields("空值草稿（drafts.jsonl；不是完整数据集）", draft_map[review["entry_id"]])
            lines += _fields("草稿字段（review.jsonl；不是完整条目）", review["draft_fields"])
            lines += _fields("建议值（未验证；不是已采纳字段）", review["suggested_values"])
        if _initial_draft_gap_signals(review):
            lines += ["### 初稿未接收说明（仅展示已记录事实）", "",
                      "已记录信号表明本候选的结构化初稿未接收或未恢复：review.jsonl 中该草稿行仅有输入元数据与已收集证据，"
                      "drafts.jsonl 对应行的缺失字段只是空占位，不代表任何字段判断。", ""]
            lines += _table(("已记录信号", "已记录值"), _initial_draft_gap_signals(review))
            evidence_ids = ", ".join(item["id"] for item in review["evidence"])
            lines += _table(("已保留证据条数", "证据引用 ID（仅列 ID，不展开原始内容；内容仅在下方证据清单按既有脱敏与截断规则显示）"),
                            [(len(review["evidence"]), evidence_ids if evidence_ids else "无已保存证据")])
            lines += ["以下证据仅供人工复核时完成草稿字段：本工具不自动填充任何字段，被拒收对象的字段值从未被应用。", ""]
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
            reason = assessment["reason"]
            if assessment.get("reason_truncated") is True:
                reason += "（原始理由已截短，未保存的尾部不猜补）"
            rows.append((field, assessment["status"], reason, refs, notes))
        lines += _table(("字段", "状态", "理由", "证据引用", "其他已记录细节"), rows)
        lines += ["controller 引用表示已记录控制器规则，不是源码证据。无法解析的引用仅标记为 unresolved_evidence_refs，不会自动修复。", ""]
        lines += _candidate_provenance_lines(review)
        lines += ["### 证据清单", "",
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
        if review.get("process_metadata_scope") == _SERIAL_SCOPE:
            lines += ["本候选错误与输入背景分开：后续候选失败不会自动否定本候选；完整候选仍不是独立入口已获语义确认。", ""]
            if process.get("input_errors"):
                lines += _table(("输入背景错误（不重复计数）", "已记录细节"), enumerate(process["input_errors"], 1))
        plans = [item for item in process.get("input_actions", []) + process.get("actions", [])
                 if isinstance(item, dict) and item.get("action") == "candidate_plan"]
        if plans:
            lines += ["### 候选规划（程序计数，不证明入口独立性）", ""]
            lines += _table(("proposed_count", "selected_count", "omitted_count", "duplicate_count", "budget_slots"),
                            (tuple(item.get(key) for key in ("proposed_count", "selected_count", "omitted_count", "duplicate_count", "budget_slots")) for item in plans))
        failures = [item for item in process.get("actions", []) + process.get("input_actions", [])
                    if isinstance(item, dict) and item.get("action") == "model_failure"]
        if failures:
            lines += ["### 已保存模型失败结构诊断（缺失信息不猜补）", ""]
            lines += _table(("stage", "code", "protocol_reason", "protocol_path"),
                            (tuple(item.get(key) for key in ("stage", "code", "protocol_reason", "protocol_path")) for item in failures))
            from .transport import public_failure_diagnostics
            for failure in failures:
                detail = public_failure_diagnostics(failure.get("diagnostics"))
                if detail:
                    lines += _table(("解析诊断字段", "值"), detail.items())
        citation_checks = review.get("reason_citation_checks")
        citation_issues = [(field, issue) for field, packet in (citation_checks.items() if isinstance(citation_checks, dict) else [])
                           if isinstance(packet, dict) and isinstance(packet.get("citations"), list)
                           for issue in packet["citations"]
                           if isinstance(issue, dict) and issue.get("severity") in ("error", "warning")]
        if citation_issues:
            lines += ["理由引用覆盖问题（含位置说明；warning 不作自动语义裁决）：", ""]
            lines += _table(("字段", "引用", "首行", "末行", "问题", "级别"),
                            ((row.get("text_path", field), row.get("evidence_ref"), row.get("start_line"), row.get("end_line"), row.get("code"), row.get("severity"))
                             for field, row in citation_issues))
        from .support_consistency import public_checks
        support_checks = public_checks(review.get("support_consistency_checks"))
        if support_checks:
            lines += ["必要前提与 supported 判断冲突：对应字段留待复核，原建议和理由保留。", "",
                      "只识别有限的明确自我否定；未命中不代表语义正确。不是 API/格式故障。", ""]
            lines += _table(("字段", "待核对前提", "规则"),
                            ((field, issue["prerequisite"], issue["rule"])
                             for field, packet in support_checks.items() for issue in packet["issues"]))
        if "annotation_errors" in review:
            field_errors = review["annotation_errors"]
            lines += ["本候选未解决的字段协议异常（可恢复；非模型整体请求失败、非纯证据不足）：", ""]
            lines += (_table(("field", "code", "path"),
                             ((item["field"], item["code"], item["path"]) for item in field_errors))
                      if field_errors else ["annotation_errors：无当前未解决项。", ""])
        else:
            lines += ["annotation_errors：旧记录未声明。", ""]
        for name in _ERROR_FIELDS:
            values = review[name] if name == "errors" else process[name]
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
    limit = MAX_MULTI_RECORDS if summary.get("counting_version") == "input-review-v2" else MAX_RECORDS
    entries, reviews = (_rows(_read(run, name), max_records=limit) for name in ("entries.jsonl", "review.jsonl"))
    drafts_path = run / "drafts.jsonl"
    has_drafts = "draft_export_version" in summary or drafts_path.exists() or drafts_path.is_symlink()
    drafts = _rows(_read(run, "drafts.jsonl"), max_records=limit) if has_drafts else None
    packet = render_packet(summary, entries, reviews, drafts)
    with destination.open("x", encoding="utf-8", newline="\n") as stream:
        stream.write(packet)
    return {"status": "exported", "output": str(destination), "review_count": len(reviews),
            "entry_count": len(entries), "http_attempts": 0,
            **({"draft_export_count": len(drafts)} if drafts is not None else {})}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-dir", required=True, help="Finished run containing public summary, entries, review records and drafts when declared")
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
