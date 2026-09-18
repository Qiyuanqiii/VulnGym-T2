"""Evidence-aware T2 finalization and separate completed/draft batch exports.

``supported`` is the model's cited assessment, never a human-audit claim.
Source-reading receipts and exact repository checks are additional requirements;
neither a citation nor a syntactically valid location substitutes for reading it.
"""
from __future__ import annotations

from collections import defaultdict
from copy import deepcopy
import json
import os
from pathlib import Path, PurePosixPath, PureWindowsPath
import re
import tempfile
import time
from typing import Any, Mapping

from ._vendor.schema_adapter import ENTRY_FIELDS, ORIGIN, SchemaAdapter
from . import staged_protocol


_ADAPTER = SchemaAdapter()
_STATUSES = frozenset({"supported", "uncertain", "missing", "conflicting"})
_REVISION_BASES = frozenset({"behavior_at_revision", "affected_range_and_source", "inspected_only", "unknown"})
_ANNOTATION_FIELDS = frozenset({"commit", "vuln_title", "vuln_category_l1", "vuln_category_l2",
                                "entry_point", "critical_operation", "trace", "vuln_ids"})
_SERIAL_SCOPE = "candidate_with_shared_usage"
DRAFT_EXPORT_VERSION = "t2-drafts-v1"
DRAFT_EXPORT_DEFINITION = (
    "drafts.jsonl is an incomplete review artifact, not a schema-valid completed dataset. "
    "It contains one 15-field row per draft or input_failure review, never complete entries. "
    "Missing scalar fields and missing entry_point/critical_operation locations are empty strings; "
    "present locations remain objects, with no fabricated coordinates. Missing trace/vuln_ids are empty arrays. "
    "verify is always 0. Values come only from draft_fields, never suggested_values. "
    "Structurally full drafts may still have unresolved process requirements; review.jsonl retains reasons, "
    "evidence, suggestions and original nulls. draft_export_count includes input_failure placeholders; "
    "draft_count continues to exclude input failures."
)
_TOOL_ERROR_PREFIXES = ("repository ", "read_file failed:", "read_diff failed:", "inspect_commit failed:", "list_files failed:", "search_code failed:", "list_refs failed:", "search_history failed:")
_FAILURE_CODES = frozenset("deepseek_staged_protocol_invalid deepseek_strict_protocol_invalid deepseek_strict_tool_call_invalid deepseek_strict_tool_arguments_invalid deepseek_response_invalid_json deepseek_response_invalid deepseek_response_not_object deepseek_response_model_mismatch deepseek_response_incomplete deepseek_response_too_large deepseek_response_encoding_unsupported deepseek_completion_incomplete deepseek_output_truncated deepseek_assessment_limit deepseek_empty_content deepseek_refusal deepseek_content_filtered deepseek_resource_unavailable deepseek_transport_error deepseek_timeout deepseek_authentication_failed deepseek_access_denied deepseek_balance_insufficient deepseek_rate_limited deepseek_server_error deepseek_http_error deepseek_redirect_rejected".split())
_SECRET_KEYS = re.compile(r"(?i)^(?:api[_-]?key|authorization|password|access[_-]?token|secret|credential)s?$")
_PRIVATE_KEYS = frozenset({"reasoning", "reasoning_content", "chain_of_thought", "raw_response", "messages", "repo_path"})
_KEY_VALUE = re.compile(r'''(?i)\b(api[_-]?key|access[_-]?token|authorization|password)\s*[:=]\s*(?:"[^"\r\n]{8,}"|'[^'\r\n]{8,}'|[A-Za-z0-9_-]{24,})''')
_TOKEN = re.compile(r"\bsk-[A-Za-z0-9_-]{8,}\b|(?i:Bearer\s+)[^\s\"']+")
_LOCAL_PATH = re.compile(r"(?<![A-Za-z0-9])(?:[A-Za-z]:[\\/][^\s\"'<>]*|\\\\[^\s\"'<>]+|/(?:Users|home|tmp|var/tmp)/[^\s\"'<>]*)")


def _redact(text: str, repo_path: str = "") -> str:
    if repo_path:
        for root in {repo_path, repo_path.replace("\\", "/"), repo_path.replace("/", "\\")}:
            text = text.replace(root, "<local-repository>")
    text = _TOKEN.sub("<redacted-secret>", text)
    text = _KEY_VALUE.sub(lambda match: match.group(1) + "=<redacted-secret>", text)
    return _LOCAL_PATH.sub("<local-path>", text)


def _public(value: Any, repo_path: str = "", *, depth: int = 0) -> Any:
    """Whitelist JSON types, bound sidecars, and omit private transport material."""
    if depth > 12:
        return "<depth-limit>"
    if isinstance(value, str):
        text = _redact(value, repo_path)
        return text if len(text) <= 16000 else text[:16000] + "<truncated>"
    if isinstance(value, Mapping):
        return {
            _redact(str(key), repo_path): ("<redacted>" if _SECRET_KEYS.fullmatch(str(key)) else
                       _public(item, repo_path, depth=depth + 1))
            for key, item in value.items()
            if str(key).lower() not in _PRIVATE_KEYS
        }
    if isinstance(value, (list, tuple)):
        return [_public(item, repo_path, depth=depth + 1) for item in value[:256]]
    if value is None or isinstance(value, (bool, int)):
        return value
    if isinstance(value, float):
        return value if value == value and abs(value) != float("inf") else None
    return "<unsupported-value>"


def _contains_private_text(value: Any, repo_path: str) -> bool:
    if isinstance(value, str):
        return _redact(value, repo_path) != value
    if isinstance(value, Mapping):
        return any(_contains_private_text(item, repo_path) for item in value.values())
    if isinstance(value, list):
        return any(_contains_private_text(item, repo_path) for item in value)
    return False


def draft_export_row(review: Mapping[str, Any]) -> dict[str, Any]:
    """Project accepted draft fields without repairing or promoting assessments.

    This is deliberately not SchemaAdapter input: absent locations use ``""``
    (location-object | empty-string), never a made-up file, line or snippet.
    The original public review, including its nulls and suggestions, is untouched.
    """
    if review.get("status") not in ("draft", "input_failure"):
        raise ValueError("draft_review_required")
    fields = review.get("draft_fields")
    if not isinstance(fields, Mapping):
        raise ValueError("draft_fields_required")
    public_fields = _public(fields)
    return {field: (0 if field == "verify" else
                    deepcopy(public_fields[field]) if public_fields.get(field) is not None else
                    [] if field in ("trace", "vuln_ids") else "")
            for field in ENTRY_FIELDS}


def _split_errors(value: Any, *, input_failure: bool = False) -> tuple[list, list, list]:
    errors = value if isinstance(value, list) else [value]
    tools = [error for error in errors if str(error).lower().startswith(_TOOL_ERROR_PREFIXES)]
    models = [error for error in errors if error not in tools and not str(error).lower().startswith("input error:")] if not input_failure else []
    return errors, models, tools


def _reason(review: Mapping[str, Any]) -> dict:
    text = review.get("reason")
    text = text.strip() if isinstance(text, str) else ""
    return {"reason": text[:2000], **({"reason_truncated": True}
            if len(text) > 2000 or review.get("reason_truncated") is True else {})}


def _diagnostics(value: Any) -> list[dict]:
    """Persist schema diagnostics, not attacker-chosen property names or prose."""
    from .staged_protocol import is_safe_diagnostic_item
    rows = []
    for item in value[:8] if isinstance(value, list) else []:
        if not isinstance(item, Mapping) or item.get("field") not in tuple(_ANNOTATION_FIELDS):
            continue
        rows.append({"field": item["field"],
                     "code": item.get("code") if is_safe_diagnostic_item("protocol_reason", item.get("code")) else "schema_mismatch",
                     "path": item.get("path") if is_safe_diagnostic_item("protocol_path", item.get("path")) else "$"})
    return rows


def _revision_feedback(value: Any) -> dict:
    """A bounded structural receipt inventory; descriptive prose stays in review."""
    if not isinstance(value, Mapping):
        return {}
    allowed_fields = re.compile(r"(?:commit|entry_point|critical_operation|trace(?:\[[0-9]{1,2}\])?)")
    packet = {key: val if isinstance(val, str) and re.fullmatch(r"[0-9a-f]{40}", val) else None
              for key in ("selected_commit", "suggested_commit") for val in (value.get(key),)}
    packet.update(commit_status=value.get("commit_status") if value.get("commit_status") in tuple(_STATUSES) else "unknown",
                  revision_basis=_revision_basis(value.get("revision_basis")))
    for key in ("required_review_fields", "unresolved_fields"):
        packet[key] = [item for item in value.get(key, [])[:36] if isinstance(item, str) and allowed_fields.fullmatch(item)] if isinstance(value.get(key), list) else []
    rows = []
    source = value.get("location_references")
    resolution_codes = {"source_ref_" + name for name in ("ambiguous_evidence", "unknown_evidence", "read_required", "failed_read", "receipt_metadata_unknown", "invalid_source_range", "invalid_range", "invalid_evidence_ref", "invalid_path", "ambiguous_revision", "receipt_unknown", "selected_commit_unknown", "commit_mismatch", "out_of_bounds")}
    for item in source[:16] if isinstance(source, list) else []:
        if not isinstance(item, Mapping) or not isinstance(item.get("field"), str) or not allowed_fields.fullmatch(item["field"]):
            continue
        row = {"field": item["field"]}
        for key in ("from_suggestion", "matches_selected_commit"):
            row[key] = item.get(key) if type(item.get(key)) is bool else None
        row["status"] = item.get("status") if item.get("status") in tuple(_STATUSES) else "unknown"
        for key, pattern in (("evidence_ref", r"E[0-9]{4,8}"), ("receipt_commit", r"[0-9a-f]{40}")):
            val = item.get(key)
            row[key] = val if isinstance(val, str) and re.fullmatch(pattern, val) else None
        path = item.get("path")
        row["path"] = path if isinstance(path, str) and len(path) <= 500 and _relative_source_path(path) else None
        for key in ("start_line", "end_line"):
            row[key] = item.get(key) if type(item.get(key)) is int and 1 <= item[key] <= 100_000_000 else None
        row["resolution_error"] = item.get("resolution_error") if item.get("resolution_error") in tuple(resolution_codes) else None
        rows.append(row)
    packet["location_references"] = rows
    omitted = value.get("omitted")
    packet["omitted"] = {key: omitted[key] for key in ("item_limit", "budget", "commit_reason_chars")
                         if isinstance(omitted, Mapping) and type(omitted.get(key)) is int and omitted[key] >= 0}
    packet["truncated"] = value.get("truncated") is True or (isinstance(source, list) and len(source) > len(rows))
    packet["prose_omitted"] = True
    return packet


def _saved_actions(value: Any) -> list[dict]:
    from .staged_protocol import is_safe_diagnostic_item
    allowed = {"action", "kind", "tool", "arguments", "evidence_id", "evidence_ref", "evidence_refs", "stage", "protocol_stage", "annotation_contract", "plan", "summary", "reason", "error", "errors", "location_corrections", "note", "model_call", "tool_call", "call_index", "call", "success", "automatic", "requested_calls", "slot", "slots", "entries", "field", "code", "path"}
    output = []
    for item in value[:96] if isinstance(value, list) else []:
        if not isinstance(item, Mapping):
            continue
        name = item.get("action")
        saved = {key: val for key, val in item.items() if key in allowed}
        if name == "candidate_plan":
            saved = {"action": name, **{key: item[key] for key in ("proposed_count", "selected_count", "omitted_count", "duplicate_count", "budget_slots")
                                        if type(item.get(key)) is int and 0 <= item[key] <= 500}}
            for key, maximum in (("encoding_reserve", 1), ("budget_slots_without_reserve", 4)):
                if type(item.get(key)) is int and 0 <= item[key] <= maximum:
                    saved[key] = item[key]
            if item.get("encoding_reserve_reason") in ("reserved", "insufficient_budget", "no_candidates"):
                saved["encoding_reserve_reason"] = item["encoding_reserve_reason"]
        elif name == "annotation_encoding_reserve":
            saved = {"action": name}
            if item.get("stage") in ("draft", "self_review", "field_recovery"):
                saved["stage"] = item["stage"]
            if item.get("summary") == "consumed":
                saved["summary"] = "consumed"
            if type(item.get("call")) is int and 1 <= item["call"] <= 1_000_000:
                saved["call"] = item["call"]
        elif name == "entry_navigation":
            from .entry_navigation import public_navigation_report
            saved = {"action": name, **public_navigation_report(item)}
        elif name in {"imported_call_search", "imported_call_source", "imported_context_header",
                      "imported_context_search", "imported_context_source", "imported_context_skipped"}:
            saved["semantic_approval"] = False
        elif name in {"read_context_closed", "planning_read_skipped"}:
            allowance = item.get("result_allowance_chars")
            if type(allowance) is int and 0 <= allowance <= 16_000:
                saved["result_allowance_chars"] = allowance
        elif name == "evidence_context_compacted":
            saved = {"action": name, **{key: item[key] for key in
                     ("before_chars", "after_chars", "evidence_count")
                     if type(item.get(key)) is int and 0 <= item[key] <= 1_000_000}}
            if type(item.get("scope_retained")) is bool:
                saved["scope_retained"] = item["scope_retained"]
        elif name == "evidence_assessment":
            from .annotation_rules import ASSESSMENT_MAX_CHARS
            saved = {"action": name, "semantic_approval": False}
            if item.get("stage") in ("draft", "self_review", "field_recovery"):
                saved["stage"] = item["stage"]
            text = item.get("text")
            if isinstance(text, str) and 0 < len(text) <= ASSESSMENT_MAX_CHARS:
                saved["summary"] = text
        elif name == "model_failure":
            saved = {"action": name, "code": item.get("code") if item.get("code") in tuple(_FAILURE_CODES) else "unrecorded_error"}
            from .transport import public_failure_diagnostics
            diagnostics = public_failure_diagnostics(item.get("diagnostics"))
            if diagnostics:
                saved["diagnostics"] = diagnostics
            if item.get("stage") in ("plan_and_read", "candidate_selection", "draft", "evidence_followup", "self_review", "field_recovery", "draft_assessment", "self_review_assessment", "field_recovery_assessment", "encoding_shape_review", "read_plan_encoding_review"):
                saved["stage"] = item["stage"]
            for key in ("protocol_reason", "protocol_path"):
                if is_safe_diagnostic_item(key, item.get(key)):
                    saved[key] = item[key]
        elif name in ("annotation_field_rejected", "annotation_field_recovered"):
            saved = {"action": name}
            if item.get("field") in tuple(_ANNOTATION_FIELDS):
                saved["field"] = item["field"]
            if "code" in item or "path" in item:
                saved.update(next(iter(_diagnostics([item])), {}))
        elif name == "annotation_properties_normalized":
            from .staged_protocol import public_normalizations
            clean = public_normalizations(item.get("normalizations") if "normalizations" in item else
                [{key: item[key] for key in ("field", "code", "path", "removed_keys") if key in item}])
            if not clean:
                continue
            saved = {"action": name, "normalizations": clean}
        elif name == "completion_json_normalized":
            from .completion_json import public_normalizations as public_json_normalizations
            clean = public_json_normalizations(item.get("normalizations"))
            if not clean:
                continue
            saved = {"action": name, "normalizations": clean,
                     "stage": item.get("stage") if item.get("stage") in
                     ("candidate_selection", "draft", "self_review", "field_recovery") else "unrecorded"}
        elif name == "annotation_error_shape":
            from .staged_protocol import public_error_shapes
            clean = public_error_shapes([{key: item[key] for key in
                ("field", "code", "path", "known_extra_keys", "unknown_extra_count", "location_reference_key") if key in item}])
            if not clean:
                continue
            saved = {"action": name, **clean[0]}
        elif name == "annotation_field_recovery":
            fields = item.get("fields")
            saved = {"action": name, "fields": [field for field in (fields if isinstance(fields, list) else [])
                     if isinstance(field, str) and field in _ANNOTATION_FIELDS][:8],
                     "summary": item.get("summary") if item.get("summary") in
                     ("recovered", "unresolved", "failed") else "unrecorded"}
        elif name == "read_plan_rejected":
            from .read_plan_protocol import public_rejection
            saved = public_rejection(dict(item))
            if not saved:
                continue
            if item.get("stage") in ("plan_and_read", "evidence_followup", "read_plan_encoding_review"):
                saved["stage"] = item["stage"]
        elif name == "read_plan_reencoding":
            saved = {"action": name, "summary": item.get("summary") if item.get("summary") in
                     ("recovered", "schema_rejected", "failed", "provider_stopped", "correction_limit",
                      "budget_unavailable", "context_unavailable") else "unrecorded"}
            if item.get("stage") in ("plan_and_read", "evidence_followup"):
                saved["stage"] = item["stage"]
        elif name == "annotation_snapshot_rejected":
            from .staged_protocol import public_snapshot_rejection
            saved = public_snapshot_rejection(dict(item))
            if not saved:
                continue
            if item.get("stage") in ("draft", "self_review", "field_recovery", "encoding_shape_review"):
                saved["stage"] = item["stage"]
        elif name == "annotation_snapshot_reencoding":
            saved = {"action": name, "summary": item.get("summary") if item.get("summary") in
                     ("recovered", "partial", "failed", "provider_stopped", "budget_unavailable", "context_unavailable") else "unrecorded"}
            if item.get("stage") in ("draft", "self_review", "field_recovery"):
                saved["stage"] = item["stage"]
        elif name == "draft_validation":
            from .support_consistency import public_checks
            support_checks = public_checks(item.get("support_consistency_checks"))
            if support_checks:
                saved["support_consistency_checks"] = support_checks
            if isinstance(item.get("reason_citation_checks"), Mapping):
                saved["reason_citation_checks"] = _public(item["reason_citation_checks"])
            if "annotation_errors" in item:
                saved["annotation_errors"] = _diagnostics(item["annotation_errors"])
            if "revision_consistency" in item:
                saved["revision_consistency"] = _revision_feedback(item["revision_consistency"])
            if isinstance(item.get("entries"), list):
                saved["entries"] = [_saved_actions([{**{key: val for key, val in entry.items() if key in
                                                        {"slot", "errors", "annotation_errors", "location_corrections", "revision_consistency"}}, "action": "draft_validation"}])[0]
                                    for entry in item["entries"][:4] if isinstance(entry, Mapping)]
                for entry in saved["entries"]:
                    entry.pop("action", None)
        if type(item.get("slot")) is int and 1 <= item["slot"] <= 4 and name != "candidate_plan":
            saved["slot"] = item["slot"]
        if item.get("prompt_revision") == staged_protocol.PROMPT_REVISION:
            saved["prompt_revision"] = staged_protocol.PROMPT_REVISION
        output.append(saved)
    return output


def _normalize(field: str, value: Any) -> Any:
    value = deepcopy(value)
    if field == "vuln_ids" and isinstance(value, list) and all(isinstance(item, str) for item in value):
        value = sorted(set(item.upper() for item in value), key=lambda item: (0 if item.startswith("CVE-") else 1 if item.startswith("GHSA-") else 2, item))
    locations = value if field == "trace" and isinstance(value, list) else [value] if field in {"entry_point", "critical_operation"} else []
    for location in locations:
        if isinstance(location, dict) and isinstance(location.get("line"), str):
            line = location["line"]
            if line.isascii() and line.isdigit() and len(line) < 12:
                location["line"] = int(line)
    return value


def _successful(evidence: Mapping[str, Any]) -> bool:
    result = evidence.get("result")
    return (evidence.get("success") is not False and not evidence.get("error")
            and not (isinstance(result, Mapping) and (result.get("error") or result.get("ok") is False or result.get("success") is False)))


def _revision_basis(value: Any) -> str:
    return value if isinstance(value, str) and value in _REVISION_BASES else "unknown"


def _commit_support_problem(commit, basis, reason, refs, evidence):
    """Check a declared basis and source receipts, never the prose's semantics."""
    if basis not in {"behavior_at_revision", "affected_range_and_source"}:
        return ("revision_basis_not_established",
                "Commit requires a declared behavior_at_revision or affected_range_and_source basis; inspecting a revision alone is insufficient.")
    if not isinstance(reason, str) or not reason.strip():
        return ("revision_reason_required", "Briefly explain why the cited mechanism applies at this revision; this remains a model assessment.")
    if isinstance(commit, str) and re.fullmatch(r"[0-9a-f]{40}", commit):
        for ref in refs:
            record = evidence.get(ref, {})
            result = record.get("result")
            if (record.get("tool") != "read_file" or record.get("success") is not True or not _successful(record)
                    or not isinstance(result, Mapping) or result.get("commit") != commit
                    or not isinstance(result.get("path"), str) or not _relative_source_path(result["path"])):
                continue
            text, lines = result.get("text"), result.get("lines")
            if ((isinstance(text, str) and bool(text.strip())) or
                    (isinstance(lines, list) and any(isinstance(row, Mapping) and
                     isinstance(row.get("code"), str) and row["code"].strip() for row in lines))):
                return None
    return ("revision_source_not_read", "Commit requires cited successful read_file source content at the selected full SHA, not only history, metadata, or a diff.")


def _span(location: Mapping[str, Any]) -> tuple[int, int]:
    line = location["line"]
    if type(line) is int:
        return line, line + len(location["code"].split("\n")) - 1
    first, last = line.split("-")
    return int(first), int(last)


def _relative_source_path(path: str) -> bool:
    return bool(path and not PurePosixPath(path).is_absolute()
                and not PureWindowsPath(path).is_absolute()
                and not PureWindowsPath(path).drive
                and "\\" not in path and "\x00" not in path
                and ".." not in PurePosixPath(path).parts)


def _read_covers(evidence: Mapping[str, Any], commit: str, location: Mapping[str, Any]) -> bool:
    if evidence.get("tool") != "read_file" or not _successful(evidence):
        return False
    result = evidence.get("result")
    if not isinstance(result, Mapping) or result.get("commit") != commit or result.get("path") != location["file"]:
        return False
    first, last = _span(location)
    read_first, read_last = result.get("start_line"), result.get("end_line")
    if type(read_first) is not int or type(read_last) is not int or not read_first <= first <= last <= read_last:
        return False
    # Check the actual returned bytes, not only the requested window or metadata.
    rows = result.get("lines")
    if isinstance(rows, list):
        by_line = {row.get("line"): row.get("code") for row in rows if isinstance(row, Mapping)}
        selected = [by_line.get(line) for line in range(first, last + 1)]
        return all(isinstance(line, str) for line in selected) and "\n".join(selected) == location["code"]
    text = result.get("text")
    return (isinstance(text, str)
            and "\n".join(text.split("\n")[first - read_first:last - read_first + 1]) == location["code"])


def _evidence_receipt(item: Mapping[str, Any]) -> dict[str, Any]:
    """Keep reviewable source excerpts, not arbitrary envelopes or model output."""
    allowed = ("id", "kind", "tool", "name", "document_kind", "document_role", "advisory_metadata", "arguments", "result", "text", "success", "error", "truncated")
    receipt = {key: item[key] for key in allowed if key in item}
    if isinstance(receipt.get("result"), Mapping):
        receipt["result"] = {key: val for key, val in receipt["result"].items() if key != "lines"}
    return receipt


def _resolve_line_from_reads(commit, location, refs, evidence):
    """Resolve the model's exact code to its unique position in cited read text.

    This never changes code, path, commit, or semantic confidence. Ambiguous or
    absent matches remain uncorrected. Re-reading the repository below remains
    mandatory; a line-number slip must not discard correctly quoted source.
    """
    if not isinstance(location, Mapping) or not isinstance(location.get("code"), str) or not location["code"]:
        return location, None
    wanted = location["code"].split("\n")
    matches = {}
    for ref in refs:
        receipt = evidence.get(ref, {})
        result = receipt.get("result", {})
        if (receipt.get("tool") != "read_file" or not _successful(receipt)
                or result.get("commit") != commit or result.get("path") != location.get("file")):
            continue
        claimed_first, claimed_last = _span(location)
        if not (type(result.get("start_line")) is int and type(result.get("end_line")) is int
                and result["start_line"] <= claimed_first <= claimed_last <= result["end_line"]):
            # Never rehabilitate a claim outside the source window actually read.
            continue
        rows = result.get("lines")
        if isinstance(rows, list):
            by_line = {row.get("line"): row.get("code") for row in rows if isinstance(row, Mapping) and type(row.get("line")) is int}
        elif isinstance(result.get("text"), str) and type(result.get("start_line")) is int:
            by_line = {result["start_line"] + i: line for i, line in enumerate(result["text"].split("\n"))}
        else:
            continue
        for first in sorted(by_line):
            if [by_line.get(first + i) for i in range(len(wanted))] == wanted:
                matches.setdefault((first, first + len(wanted) - 1), []).append(ref)
    if len(matches) != 1:
        return location, None
    (first, last), matched_refs = next(iter(matches.items()))
    if _span(location) == (first, last):
        return location, None
    corrected = dict(location, line=first if first == last else f"{first}-{last}")
    return corrected, {"from_line": location["line"], "to_line": corrected["line"],
                       "evidence_refs": list(dict.fromkeys(matched_refs)),
                       "reason": "Exact unchanged code uniquely matched the cited source read; corrected only the line coordinate."}


def finalize_result(job: Mapping[str, Any], result: Mapping[str, Any] | None, repo: Any) -> dict[str, Any]:
    """Return one complete official entry, or an honest and useful partial draft."""
    result = result if isinstance(result, Mapping) else {}
    annotation_errors = result.get("annotation_errors", [])
    if (not isinstance(annotation_errors, list) or len(annotation_errors) > 8
            or any(not isinstance(item, Mapping) or not isinstance(item.get("field"), str)
                   or item["field"] not in _ANNOTATION_FIELDS
                   or not isinstance(item.get("code"), str) or not isinstance(item.get("path"), str)
                   for item in annotation_errors)):
        raise ValueError("annotation_errors_invalid")
    # The protocol supplies safe schema codes/paths, not rejected model values.
    annotation_errors = _diagnostics(annotation_errors)
    fields = result.get("fields") if isinstance(result.get("fields"), Mapping) else {}
    model_reviews = result.get("field_reviews") if isinstance(result.get("field_reviews"), Mapping) else {}
    supplied_evidence = result.get("evidence") if isinstance(result.get("evidence"), list) else []
    evidence = {item["id"]: item for item in supplied_evidence if isinstance(item, Mapping) and isinstance(item.get("id"), str)}
    repo_path = str(job.get("repo_path") or "")
    draft = {field: None for field in ENTRY_FIELDS}
    reviews: dict[str, dict[str, Any]] = {}
    suggestions: dict[str, Any] = {}
    errors: list[dict[str, Any]] = []

    def reject(field: str, code: str, message: str, *, status: str = "uncertain") -> None:
        if draft[field] is not None:
            suggestions[field] = draft[field]
        draft[field] = None
        reviews[field]["status"] = status
        reviews[field].setdefault("validation_errors", []).append(code)
        errors.append({"field": field, "code": code, "message": message})

    trusted = {field: job.get(field) for field in ("entry_id", "report_id", "source_link")}
    if isinstance(trusted["report_id"], str):
        trusted["report_id"] = trusted["report_id"].upper()
    trusted.update(origin=ORIGIN, verify=0)
    if job.get("repo_url"):
        trusted["repo_url"] = job["repo_url"]

    for field in ENTRY_FIELDS:
        if field in trusted:
            draft[field] = trusted[field]
            reviews[field] = {"status": "supported" if trusted[field] is not None else "missing", "reason": "Controller-owned input or schema constant; not a model or human verification claim.", "evidence_refs": ["controller:" + field]}
            if trusted[field] is None:
                errors.append({"field": field, "code": "missing_controller_value", "message": "Trusted input lacks this value; a model cannot supply it."})
            continue
        if field == "trace" and fields.get(field, []) == []:
            draft[field] = []
            reviews[field] = {"status": "supported", "reason": "Empty optional trace makes no asserted source-flow claim; allowed by SCHEMA.md.", "evidence_refs": ["controller:optional_trace"]}
            omitted = model_reviews.get(field)
            if isinstance(omitted, Mapping) and omitted.get("suggested_value") is not None:
                suggestions[field] = omitted["suggested_value"]
                reviews[field]["omitted_assessment"] = {
                    **{key: omitted[key] for key in ("status", "evidence_refs") if key in omitted}, **_reason(omitted)}
            continue
        model_review = model_reviews.get(field)
        model_review = model_review if isinstance(model_review, Mapping) else {}
        value = fields.get(field)
        status = model_review.get("status", "missing" if value is None else "uncertain")
        if not isinstance(status, str) or status not in _STATUSES:
            status = "uncertain"
        refs = model_review.get("evidence_refs")
        refs = list(dict.fromkeys(item for item in refs if isinstance(item, str))) if isinstance(refs, list) else []
        explanation = _reason(model_review)
        reason = explanation["reason"]
        reviews[field] = {"status": status, **explanation, "evidence_refs": refs}
        reviews[field]["reason"] = reason or "No supported, cited field assessment was supplied."
        if field == "commit":
            reviews[field]["revision_basis"] = _revision_basis(model_review.get("revision_basis"))
        suggestion = model_review.get("suggested_value", value)
        if suggestion is not None:
            suggestions[field] = suggestion
        if value is None:
            if status == "supported":
                reject(field, "missing_value", "A supported assessment has no field value.", status="missing")
            else:
                errors.append({"field": field, "code": "missing_value" if status == "missing" else "model_" + status, "message": "No supported field value was established."})
            continue
        if status != "supported":
            errors.append({"field": field, "code": "model_" + status, "message": "Model assessment does not establish this field."})
            continue
        if field == "commit":
            problem = _commit_support_problem(value, reviews[field]["revision_basis"], reason, refs, evidence)
            if problem is not None:
                reject(field, *problem)
                continue
        if not reason or not refs or any(ref not in evidence or not _successful(evidence[ref]) for ref in refs):
            reject(field, "unsupported_evidence", "Supported fields require a concise reason and existing successful evidence references.")
            continue
        draft[field] = _normalize(field, value)
        suggestions.pop(field, None)

    for error in annotation_errors:
        field = error["field"]
        reject(field, "annotation_field_invalid",
               "An unresolved field protocol error remains; valid sibling fields are retained. This is not a whole-request failure or a semantic evidence judgment.")
        reviews[field]["reason"] = "Latest field submission was rejected by the annotation protocol; a valid correction is still required."

    # Reuse the official adapter for field types, IDs, ranges, and provenance.
    # Validate the partial object, but never replace all known fields on one error.
    schema_issues = _ADAPTER.validate(draft, formal_t2=True).issues
    for issue in schema_issues:
        field = issue.path.removeprefix("$.").split(".")[0].split("[")[0]
        if field in draft and draft[field] is not None:
            reject(field, issue.code, issue.message)
    for field, value in list(draft.items()):
        if isinstance(value, str) and not value.strip():
            reject(field, "empty_value", "A required content field cannot be an empty string.", status="missing")
        elif value is not None and _contains_private_text(value, repo_path):
            reject(field, "private_output_redacted", "Potential credential or local absolute path withheld from public output.")

    # Coverage of prose citations is separate from location-byte validation.
    # Only precise positive citation forms can demote a supported assertion;
    # ambiguous prose and already-uncertain suggestions remain review warnings.
    from .source_refs import reason_citations
    reason_citation_checks = {}
    reason_citation_blocked = False
    for field in sorted(_ANNOTATION_FIELDS):
        assessment = model_reviews.get(field)
        if not isinstance(assessment, Mapping):
            continue
        checked = reason_citations(assessment.get("reason"), supplied_evidence, draft["commit"])
        checked["truncated"] |= assessment.get("reason_truncated") is True
        # Location descriptions can contain their own explicit source claims.
        # Validate them exactly like reasons: matching location bytes cannot
        # legitimize a prose citation to an unread line in another receipt.
        candidate_value = draft.get(field) if draft.get(field) is not None else suggestions.get(field)
        locations = (candidate_value if field == "trace" and isinstance(candidate_value, list)
                     else [candidate_value] if field in {"entry_point", "critical_operation"} else [])
        for index, location in enumerate(locations[:32]):
            if not isinstance(location, Mapping):
                continue
            description = reason_citations(location.get("desc"), supplied_evidence, draft["commit"])
            path = f"trace[{index}].desc" if field == "trace" else field + ".desc"
            checked["citations"].extend(dict(row, text_path=path) for row in description["citations"])
            checked["omitted_reason_chars"] += description["omitted_reason_chars"]
            checked["omitted_citations"] += description["omitted_citations"]
            checked["truncated"] |= description["truncated"]
        if len(checked["citations"]) > 32:
            # Keep actual problems ahead of convenience coverage information.
            checked["citations"].sort(key=lambda row: {"error": 0, "warning": 1, "info": 2}[row["severity"]])
            checked["omitted_citations"] += len(checked["citations"]) - 32
            checked["citations"] = checked["citations"][:32]
            checked["truncated"] = True
        if not checked["citations"] and not checked["truncated"]:
            continue
        reason_citation_checks[field] = checked
        reviews[field]["reason_citations"] = checked
        bad = [row for row in checked["citations"] if row["severity"] == "error"]
        if bad and assessment.get("status") == "supported":
            reason_citation_blocked = True
            omitted_trace = suggestions.get("trace") if field == "trace" and draft[field] == [] else None
            for row in bad:
                reject(field, row["code"],
                       f"Explicit citation {row['evidence_ref']}:{row['start_line']}-{row['end_line']} "
                       "is not covered by a successful visible source receipt. Original explanation and suggestion retained; this is not a semantic verdict.")
            if omitted_trace is not None:
                suggestions["trace"] = omitted_trace
            if field == "trace" and "omitted_assessment" not in reviews[field]:
                reviews[field]["omitted_assessment"] = {"status": assessment.get("status"),
                    "evidence_refs": reviews[field]["evidence_refs"], **_reason(assessment)}

    # A few explicit admissions negate the field's own claimed support. This
    # conservative hold is neither an independent source verdict nor a blanket
    # unknown-word filter. Never propagate optional trace caveats to EP/CO.
    from .support_consistency import check_support, public_checks
    support_consistency_checks = {}
    for field in ("commit", "entry_point", "critical_operation", "trace"):
        checked = check_support(field, model_reviews.get(field), value=draft.get(field))
        assessment = model_reviews.get(field)
        pending = public_checks({field: assessment.get("pending_support_conflict")}) if isinstance(assessment, Mapping) else {}
        if field in pending and (field != "trace" or isinstance(draft.get(field), list) and draft[field]):
            checked = pending[field]
        if not checked["issues"]:
            continue
        support_consistency_checks[field] = checked
        reviews[field]["support_consistency"] = checked
        if reviews[field]["status"] == "supported":
            reviews[field]["pre_check_status"] = reviews[field]["status"]
            reject(field, "supported_reason_conflict",
                   "Current or earlier field reasoning disclaims required support without an evidenced correction. Retain the suggestion for review; correct using direct saved evidence or keep uncertain, not just remove the caveat. This is a limited consistency check, not source-truth validation.")

    commit = draft["commit"]
    # Conflicting input roles require review, not a claim that every fix works.
    # An incomplete fix or an incorrect input label needs reconciliation; model
    # prose alone cannot relabel the supplied repair as an affected revision.
    fix_inputs = job.get("fix_commits")
    fix_inputs = {item for item in fix_inputs if isinstance(item, str)} if isinstance(fix_inputs, list) else set()
    reported_fixes = {item.lower() for item in fix_inputs if re.fullmatch(r"[0-9a-fA-F]{40}", item)}
    for receipt in evidence.values():
        args, data = receipt.get("arguments"), receipt.get("result")
        if (receipt.get("tool") == "inspect_commit" and _successful(receipt)
                and isinstance(args, Mapping) and isinstance(args.get("commit"), str) and args["commit"] in fix_inputs
                and isinstance(data, Mapping) and isinstance(data.get("commit"), str)
                and re.fullmatch(r"[0-9a-f]{40}", data["commit"])):
            reported_fixes.add(data["commit"])
    if commit and commit in reported_fixes:
        reject("commit", "selected_revision_is_reported_fix",
               "Selected affected revision is explicitly supplied as a fix for this input. Keep it for review and reconcile the conflicting roles; a fix is not automatically effective, and its parent is not automatically affected.",
               status="conflicting")
        commit = None
    if isinstance(job.get("vulnerable_commit"), str) and re.fullmatch(r"[0-9a-f]{40}", job["vulnerable_commit"]) and commit and commit != job["vulnerable_commit"]:
        reject("commit", "selected_commit_conflict", "Selected commit differs from the explicitly supplied vulnerable commit.", status="conflicting")
        commit = None
    location_checks: list[dict[str, Any]] = []
    location_corrections: list[dict[str, Any]] = []
    for field in ("entry_point", "critical_operation", "trace"):
        value = draft[field]
        if value is None:
            continue
        locations = value if field == "trace" else [value]
        for index, location in enumerate(locations):
            label = f"{field}[{index}]" if field == "trace" else field
            if not commit:
                reject(field, "commit_not_established", "Code locations require an established vulnerable commit.")
                break
            if not location["code"] or not _relative_source_path(location["file"]):
                reject(field, "invalid_source_location", "Code must be nonempty and the file must be a safe repository-relative path.")
                break
            refs = reviews[field]["evidence_refs"]
            location, correction = _resolve_line_from_reads(commit, location, refs, evidence)
            if correction is not None:
                if field == "trace":
                    draft[field][index] = location
                else:
                    draft[field] = location
                location_corrections.append({"field": label, **correction})
            if not any(ref in evidence and _read_covers(evidence[ref], commit, location) for ref in refs):
                reject(field, "source_not_read", "No cited read_file result contains these exact lines and bytes at the selected commit.")
                break
            try:
                checked = repo.validate_location(commit, location)
            except Exception as error:  # A failed read cannot abort other batch jobs.
                checked = {"valid": False, "reason": "repository_validation_" + type(error).__name__}
            valid = isinstance(checked, Mapping) and checked.get("valid") is True and checked.get("commit") == commit
            location_checks.append({"field": label, "valid": valid, "result": checked})
            if not valid:
                reject(field, "location_validation_failed", "Repository rejected the exact location at the selected commit.")
                break

    if draft["trace"] is None:
        # Optional flow is not a prerequisite for the required record. Keep
        # disputed steps and their reasons in review, but assert no flow steps.
        draft["trace"] = []
        reviews["trace"]["export_policy"] = "Unestablished optional trace omitted; suggested steps remain unverified."
    input_error = job.get("input_error")
    if input_error:
        errors.append({"field": None, "code": "input_failure", "message": input_error})
    self_review_status = result.get("self_review_status", "not_requested")
    if self_review_status not in ("not_requested", "completed", "failed"):
        self_review_status = "failed"
    if self_review_status == "failed":
        errors.append({"field": None, "code": "self_review_incomplete",
                       "message": "The requested self-review did not return a valid draft; initial fields and evidence are retained for review, not exported as a complete entry."})
    snapshot_mode = result.get("annotation_mode") == "snapshot"
    if snapshot_mode and self_review_status == "not_requested":
        errors.append({"field": None, "code": "self_review_required",
                       "message": "Snapshot candidates require a completed self-review. An unreviewed or budget-deferred candidate remains a draft, even when its fields look complete."})
    evidence_followup_status = result.get("evidence_followup_status", "not_requested")
    if evidence_followup_status not in ("not_requested", "completed", "failed"):
        evidence_followup_status = "failed"
    if evidence_followup_status == "failed":
        errors.append({"field": None, "code": "evidence_followup_incomplete",
                       "message": "The focused evidence follow-up failed; preserve the draft and evidence for review without claiming a complete entry."})
    entry = None
    if (not input_error and not annotation_errors and not reason_citation_blocked and self_review_status != "failed"
            and (not snapshot_mode or self_review_status == "completed")
            and evidence_followup_status != "failed" and all(draft[field] is not None for field in ENTRY_FIELDS)):
        entry = _ADAPTER.adapt(draft, formal_t2=True)
    pipeline_errors, model_errors, tool_errors = _split_errors(result.get("errors", []), input_failure=bool(input_error))
    actions = result.get("actions") if isinstance(result.get("actions"), list) else []
    review = {
        "entry_id": trusted.get("entry_id"), "report_id": trusted.get("report_id"),
        "source_link": trusted.get("source_link"),
        "status": "input_failure" if input_error else "complete" if entry is not None else "draft",
        "input_warnings": job.get("input_warnings", []),
        "input_conflicts": job.get("input_conflicts", []),
        "self_review_status": self_review_status,
        "evidence_followup_status": evidence_followup_status,
        **({"annotation_mode": "snapshot"} if snapshot_mode else {}),
        **({"initial_draft_status": result["initial_draft_status"]}
           if result.get("initial_draft_status") in ("not_received", "accepted", "partial", "no_valid_updates") else {}),
        **({"annotation_contract": result["annotation_contract"]} if result.get("annotation_contract") in ("t2-evidence-v1", "t2-evidence-v2") else {}),
        **({"prompt_revision": result["prompt_revision"]} if result.get("prompt_revision") == staged_protocol.PROMPT_REVISION else {}),
        "draft_fields": draft, "field_reviews": reviews, "suggested_values": suggestions,
        "reason_citation_checks": reason_citation_checks,
        "support_consistency_checks": support_consistency_checks,
        "annotation_errors": annotation_errors,
        "errors": errors, "pipeline_errors": pipeline_errors, "model_errors": model_errors, "tool_errors": tool_errors,
        "model_calls": result.get("model_calls", 0), "tool_calls": result.get("tool_calls", 0),
        "evidence": [_evidence_receipt(item) for item in evidence.values()],
        "location_checks": location_checks,
        "location_corrections": location_corrections,
        "actions": _saved_actions(actions),
        **({"review_cycle_history": _saved_actions([
            row for row in actions if isinstance(row, Mapping)
            and str(row.get("action", "")).startswith("review_cycle_")])}
           if any(isinstance(row, Mapping) and row.get("action") == "review_cycle_policy"
                  for row in actions) else {}),
        "verification": "Machine annotation only (verify=0). Supported means cited model assessment plus applicable deterministic checks, not independent human proof.",
    }
    return {"entry": entry, "review": _public(review, repo_path)}


def finalize_job(job: Mapping[str, Any], result: Mapping[str, Any] | None, repo: Any,
                 *, entry_ids: Mapping[int, str]) -> dict[str, Any]:
    """Finalize independent candidates while retaining one shared input process.

    Slot 1 carries shared actions, usage and process errors. Other reviews link
    to it through input_id; zero local usage never claims a separate clean run.
    """
    from .multi_entry import MAX_ENTRIES, validate_entry_ids

    assigned = validate_entry_ids(job.get("entry_id"), entry_ids)
    parent = result if isinstance(result, Mapping) else {}
    supplied = parent.get("entry_results")
    valid = (isinstance(supplied, list) and 1 <= len(supplied) <= MAX_ENTRIES
             and all(isinstance(item, Mapping) and type(item.get("slot")) is int for item in supplied))
    if valid:
        valid = sorted(item["slot"] for item in supplied) == list(range(1, len(supplied) + 1))
    has_candidates = valid and not job.get("input_error")
    serial = has_candidates and parent.get("annotation_mode") == "snapshot"
    rows = sorted(supplied, key=lambda item: item["slot"]) if has_candidates else [{"slot": 1}]
    if any(row["slot"] not in assigned for row in rows):
        raise ValueError("entry_ids_incomplete")
    items = []
    for row in rows:
        slot = row["slot"]
        child_job = dict(job, entry_id=assigned[slot])
        child_result = {key: value for key, value in parent.items() if key != "entry_results"}
        damaged = has_candidates and any(not isinstance(row.get(key), Mapping) for key in ("fields", "field_reviews"))
        if has_candidates:
            child_result.update(fields=deepcopy(row["fields"]) if isinstance(row.get("fields"), Mapping) else {},
                                field_reviews=deepcopy(row["field_reviews"]) if isinstance(row.get("field_reviews"), Mapping) else {},
                                annotation_errors=deepcopy(row.get("annotation_errors", [])))
            for key, default in (("self_review_status", "not_requested"), ("evidence_followup_status", "not_requested"),
                                 ("initial_draft_status", "not_received"), ("errors", []), ("actions", [])):
                if serial or key in row:
                    child_result[key] = deepcopy(row.get(key, default))
        finalized = finalize_result(child_job, child_result, repo)
        review = finalized["review"]
        if damaged:
            finalized["entry"] = None
            review["status"] = "draft"
            review["errors"].append({"field": None, "code": "entry_result_invalid",
                                     "message": "Candidate fields or assessments have an invalid container; this slot remains a draft without discarding valid siblings."})
        if not has_candidates and not job.get("input_error"):
            finalized["entry"] = None
            review["status"] = "draft"
            review["errors"].append({"field": None, "code": "entry_results_unavailable",
                                     "message": "No valid multi-entry annotation was accepted; input fields and evidence remain a draft."})
        review.update(input_id=job["entry_id"], slot=slot,
                      process_metadata_scope=_SERIAL_SCOPE if serial else "shared_input")
        if serial:
            review.update(input_errors=[], input_actions=[])
            provenance = row.get("candidate_provenance")
            if isinstance(provenance, Mapping):
                saved = {key: deepcopy(provenance[key]) for key in (
                    "original_proposal", "previous_candidates_context", "slot_start", "slot_end", "model_call_evidence", "note")
                    if key in provenance}
                # The shared evidence table includes later siblings' reads.
                # Only a verified list-prefix boundary can label those as later;
                # old/malformed metadata must not imply an assessment occurred.
                evidence = parent.get("evidence", [])
                refs = [item.get("id") for item in evidence if isinstance(item, Mapping)] if isinstance(evidence, list) else []
                end = provenance.get("slot_end")
                count = end.get("evidence_count") if isinstance(end, Mapping) else None
                valid_end = (type(count) is int and 0 <= count <= len(refs)
                             and end.get("evidence_refs") == refs[:count]
                             and end.get("last_evidence_ref") == (refs[count - 1] if count else None))
                saved["later_shared_evidence_refs"] = refs[count:] if valid_end else None
                saved["later_shared_evidence_status"] = "recorded" if valid_end else "unknown_boundary"
                review["candidate_provenance"] = _public(saved, str(job.get("repo_path") or ""))
        if slot != 1:
            review.update(model_calls=0, tool_calls=0)
            if not serial:
                review.update(actions=[], model_errors=[], tool_errors=[], pipeline_errors=[])
        items.append({"slot": slot, **finalized})
    if serial:
        shared = items[0]["review"]
        shared["input_errors"] = _public(_split_errors(parent.get("errors", []))[0], str(job.get("repo_path") or ""))
        shared["input_actions"] = _public(_saved_actions(parent.get("actions", [])), str(job.get("repo_path") or ""))
    complete = sum(item["entry"] is not None for item in items)
    status = ("input_failure" if job.get("input_error") else "complete" if complete == len(items)
              else "partial" if complete else "draft")
    return {"input_id": job["entry_id"], "status": status, "items": items}


def _reports(entries: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for entry in entries:
        groups[entry["report_id"]].append(entry)
    reports = []
    conflicts = []
    for report_id, group in sorted(groups.items()):
        report = {}
        disputed = {}
        for field in ("source_link", "origin", "project", "repo_url", "commit", "vuln_title"):
            by_value = defaultdict(list)
            for entry in sorted(group, key=lambda item: item["entry_id"]):
                value = entry[field]
                if field == "vuln_title":
                    # SCHEMA normalizes the per-entry filename suffix before
                    # choosing the canonical report-level title.
                    value = re.sub(r" - [^\s]+\.[A-Za-z0-9]+$", "", value)
                by_value[value].append(entry["entry_id"])
            # Canonical aggregation is a representation rule, not evidence
            # that any conflicting entry-level assertion is correct.
            report[field] = min(by_value, key=lambda value: (-len(by_value[value]), by_value[value][0]))
            if len(by_value) > 1:
                disputed[field] = [{"value": value, "entry_ids": ids}
                                   for value, ids in sorted(by_value.items())]
        if disputed:
            conflicts.append({"report_id": report_id, "status": "conflicting",
                              "entry_ids": sorted(entry["entry_id"] for entry in group),
                              "num_entries": len(group), "conflicts": disputed,
                              "reason": "Report-level metadata differs across complete entries. The canonical report follows SCHEMA majority values and smallest-entry-ID tie breaks; aggregation does not verify the conflicting claims."})
        report.update(report_id=report_id, entry_ids=sorted(entry["entry_id"] for entry in group), num_entries=len(group), vuln_ids=_normalize("vuln_ids", [identifier for entry in group for identifier in entry["vuln_ids"]]))
        reports.append(report)
    return reports, conflicts


def _json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, allow_nan=False)


class OutputPublicationError(OSError):
    """A terminal local publish failure, with no path or exception-text leak."""

    def __init__(self, phase, target, error):
        self.phase = phase if phase in {"stage", "replace"} else "unknown"
        super().__init__("output_finalize_" + self.phase + "_failed")
        self.diagnostics = {"phase": "output_finalize_" + self.phase,
                            "target": target if target in {"entries.jsonl", "drafts.jsonl", "reports.jsonl", "report_conflicts.jsonl", "summary.json"} else "unknown"}
        for key in ("errno", "winerror"):
            number = getattr(error, key, None)
            if type(number) is int and 0 <= number <= 65535:
                self.diagnostics[key] = number


def _replace_final_output(temporary, destination):
    """Wait at most 350 ms for Windows reader contention, never access denial.

    Windows sharing/lock violations (32/33) are transient occupancy, not an
    authorization grant. Access denied (5), read-only/disk errors, unknown
    failures and interruption stop immediately. This never retries HTTP,
    regenerates data, resumes a failed run or removes its retained staging.
    """
    waits = (0.05, 0.1, 0.2)
    for attempt in range(len(waits) + 1):
        try:
            os.replace(temporary, destination)
            return
        except OSError as error:
            if (os.name != "nt" or getattr(error, "winerror", None) not in {32, 33}
                    or attempt >= len(waits)):
                raise
            time.sleep(waits[attempt])


class BatchWriter:
    """Own one new output directory; append progress, then sort final exports."""

    def __init__(self, directory: str | Path, *, multi_entry: bool = False):
        if type(multi_entry) is not bool:
            raise ValueError("multi_entry_invalid")
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=False)
        self._entries: list[dict[str, Any]] = []
        self._drafts: list[dict[str, Any]] = []
        self._seen: set[str] = set()
        self._counts = {key: 0 for key in ("input_count", "candidate_count", "draft_count", "input_failure_count", "model_error_count", "tool_error_count", "pipeline_error_count", "jobs_with_model_errors", "annotation_error_count", "jobs_with_annotation_errors", "model_calls", "tool_calls")}
        self._multi_mode = multi_entry
        self._input_reviews: list[dict[str, Any]] = []
        self._review_seen: set[str] = set()
        self._finished = False
        self._write_failed = False
        for name in ("entries.jsonl", "drafts.jsonl", "reports.jsonl", "report_conflicts.jsonl", "review.jsonl", "actions.jsonl"):
            (self.directory / name).touch(exist_ok=False)

    def _append(self, name: str, value: Any) -> None:
        with (self.directory / name).open("a", encoding="utf-8", newline="\n") as stream:
            stream.write(_json(value) + "\n")

    def _check_open(self) -> None:
        if self._finished:
            raise RuntimeError("batch_already_finished")
        if self._write_failed:
            raise RuntimeError("batch_write_failed")

    def _persist(self, rows: list[tuple[str, Any]]) -> None:
        # Refuse unserializable rows before appending any part of this input.
        for _, value in rows:
            _json(value)
        try:
            for name, value in rows:
                self._append(name, value)
        except BaseException:
            # Preserve the durable prefix and failure scene. It is not a
            # finalized run and must not receive a misleading summary later.
            self._write_failed = True
            raise

    @staticmethod
    def _check_review(entry: Any, review: Mapping[str, Any]) -> None:
        for key in ("annotation_errors", "errors", "model_errors", "tool_errors", "pipeline_errors", "actions"):
            if not isinstance(review.get(key), list):
                raise ValueError("finalized_review_invalid")
        for key in ("model_calls", "tool_calls"):
            if type(review.get(key)) is not int or review[key] < 0:
                raise ValueError("review_count_invalid")
        if entry is None:
            if review.get("status") not in ("draft", "input_failure"):
                raise ValueError("entry_review_mismatch")
        elif (review.get("status") != "complete" or entry != review.get("draft_fields")
              or review["annotation_errors"] or entry.get("verify") != 0
              or review.get("self_review_status") == "failed"
              or review.get("evidence_followup_status") == "failed"
              or (review.get("annotation_mode") == "snapshot" and review.get("self_review_status") != "completed")):
            raise ValueError("entry_review_mismatch")

    def record(self, job: Mapping[str, Any], finalized: Mapping[str, Any]) -> None:
        self._check_open()
        if self._multi_mode:
            raise ValueError("mixed_counting_modes")
        entry, review = finalized.get("entry"), finalized.get("review")
        if not isinstance(review, Mapping):
            raise ValueError("finalized_review_required")
        review = _public(review, str(job.get("repo_path") or ""))
        review.setdefault("annotation_errors", [])
        identity = review.get("entry_id")
        if not isinstance(identity, str) or not re.fullmatch(r"entry-[0-9]{5}", identity):
            raise ValueError("entry_id_invalid")
        if identity in self._review_seen:
            raise ValueError("duplicate_entry_id")
        expected_report = job.get("report_id")
        if isinstance(expected_report, str):
            expected_report = expected_report.upper()
        if (identity != job.get("entry_id") or review.get("source_link") != job.get("source_link")
                or review.get("report_id") != expected_report):
            raise ValueError("entry_job_provenance_mismatch")
        if entry is not None:
            entry = _ADAPTER.adapt(entry, formal_t2=True)
            if any(entry[field] != job.get(field) for field in ("entry_id", "source_link")) or entry["report_id"] != str(job.get("report_id", "")).upper():
                raise ValueError("entry_job_provenance_mismatch")
            if entry["entry_id"] in self._seen:
                raise ValueError("duplicate_entry_id")
            if _contains_private_text(entry, str(job.get("repo_path") or "")):
                raise ValueError("private_entry_output_refused")
        self._check_review(entry, review)
        if (review["status"] == "input_failure") != bool(job.get("input_error")):
            raise ValueError("entry_review_mismatch")
        draft = draft_export_row(review) if entry is None else None
        rows = [("entries.jsonl", entry)] if entry is not None else [("drafts.jsonl", draft)]
        rows.append(("review.jsonl", review))
        rows.extend(("actions.jsonl", {"entry_id": identity, "report_id": review.get("report_id"), "action": action})
                    for action in review["actions"])
        self._persist(rows)
        self._review_seen.add(identity)
        if draft is not None:
            self._drafts.append(deepcopy(draft))
        if entry is not None:
            self._seen.add(identity)
            self._entries.append(deepcopy(entry))
            self._counts["candidate_count"] += 1
        elif job.get("input_error") or review.get("status") == "input_failure":
            self._counts["input_failure_count"] += 1
        else:
            self._counts["draft_count"] += 1
        self._counts["input_count"] += 1
        model_errors = review.get("model_errors") or []
        self._counts["model_error_count"] += len(model_errors)
        self._counts["tool_error_count"] += len(review.get("tool_errors") or [])
        self._counts["pipeline_error_count"] += len(review.get("pipeline_errors") or [])
        self._counts["jobs_with_model_errors"] += int(bool(model_errors))
        annotation_errors = review.get("annotation_errors") or []
        self._counts["annotation_error_count"] += len(annotation_errors)
        self._counts["jobs_with_annotation_errors"] += int(bool(annotation_errors))
        for field in ("model_calls", "tool_calls"):
            if type(review.get(field)) is int and review[field] >= 0:
                self._counts[field] += review[field]

    def record_job(self, job: Mapping[str, Any], finalized: Mapping[str, Any]) -> None:
        """Persist a complete input once, with independently checked child rows."""
        self._check_open()
        if self._counts["input_count"] and not self._multi_mode:
            raise ValueError("mixed_counting_modes")
        input_id = job.get("entry_id")
        items = finalized.get("items")
        if (finalized.get("input_id") != input_id or not isinstance(items, list)
                or not 1 <= len(items) <= 4):
            raise ValueError("finalized_job_invalid")
        if any(row["input_id"] == input_id for row in self._input_reviews):
            raise ValueError("duplicate_input_id")
        prepared = []
        identities = {}
        expected_report = job.get("report_id")
        if isinstance(expected_report, str):
            expected_report = expected_report.upper()
        for index, item in enumerate(items, 1):
            if not isinstance(item, Mapping) or item.get("slot") != index or type(item.get("slot")) is not int:
                raise ValueError("entry_slots_invalid")
            review, entry = item.get("review"), item.get("entry")
            if not isinstance(review, Mapping):
                raise ValueError("finalized_review_required")
            review = _public(review, str(job.get("repo_path") or ""))
            review.setdefault("annotation_errors", [])
            entry_id = review.get("entry_id")
            if (review.get("input_id") != input_id or type(review.get("slot")) is not int or review.get("slot") != index
                    or review.get("source_link") != job.get("source_link")
                    or review.get("report_id") != expected_report):
                raise ValueError("entry_job_provenance_mismatch")
            identities[index] = entry_id
            if not isinstance(entry_id, str):
                raise ValueError("entry_id_invalid")
            if entry_id in self._review_seen or entry_id in self._seen:
                raise ValueError("duplicate_entry_id")
            if entry is not None:
                entry = _ADAPTER.adapt(entry, formal_t2=True)
                if (entry != review.get("draft_fields") or review.get("status") != "complete"
                        or entry["entry_id"] != entry_id or entry["verify"] != 0):
                    raise ValueError("entry_review_mismatch")
                if any(entry[field] != review.get(field) for field in ("report_id", "source_link")):
                    raise ValueError("entry_job_provenance_mismatch")
                if _contains_private_text(entry, str(job.get("repo_path") or "")):
                    raise ValueError("private_entry_output_refused")
            elif review.get("status") not in {"draft", "input_failure"}:
                raise ValueError("entry_review_mismatch")
            self._check_review(entry, review)
            serial = review.get("process_metadata_scope") == _SERIAL_SCOPE
            if serial and (review.get("annotation_mode") != "snapshot"
                           or not isinstance(review.get("input_errors"), list) or not isinstance(review.get("input_actions"), list)):
                raise ValueError("candidate_process_invalid")
            if index != 1 and any(review.get(key) for key in
                                  (("model_calls", "tool_calls", "input_errors", "input_actions") if serial else
                                   ("model_calls", "tool_calls", "actions", "model_errors", "tool_errors", "pipeline_errors"))):
                raise ValueError("shared_process_duplicated")
            prepared.append((entry, review))
        from .multi_entry import validate_entry_ids
        validate_entry_ids(input_id, identities)
        complete = sum(entry is not None for entry, _ in prepared)
        failed = any(review["status"] == "input_failure" for _, review in prepared)
        if failed and (len(prepared) != 1 or not job.get("input_error")):
            raise ValueError("input_failure_children_invalid")
        status = "input_failure" if failed else "complete" if complete == len(prepared) else "partial" if complete else "draft"
        if finalized.get("status") != status:
            raise ValueError("input_status_mismatch")
        shared = prepared[0][1]
        if any(review.get("process_metadata_scope") != shared.get("process_metadata_scope") for _, review in prepared):
            raise ValueError("mixed_process_scopes")
        input_errors, input_model_errors, input_tool_errors = _split_errors(shared.get("input_errors", []), input_failure=failed)
        mapping = {"input_id": input_id, "report_id": shared["report_id"],
                   "source_link": shared["source_link"], "status": status,
                   "review_entry_ids": [review["entry_id"] for _, review in prepared],
                   "entry_ids": [entry["entry_id"] for entry, _ in prepared if entry is not None],
                   "model_calls": shared.get("model_calls", 0), "tool_calls": shared.get("tool_calls", 0)}
        rows = []
        drafts = []
        for entry, review in prepared:
            if entry is not None:
                rows.append(("entries.jsonl", entry))
            else:
                draft = draft_export_row(review)
                drafts.append(draft)
                rows.append(("drafts.jsonl", draft))
            rows.append(("review.jsonl", review))
        rows.extend(("actions.jsonl", {"input_id": input_id, "entry_id": shared["entry_id"],
                                      "report_id": shared["report_id"], "scope": "input", "action": action})
                    for action in shared.get("input_actions", []))
        for _, review in prepared:
            rows.extend(("actions.jsonl", {"input_id": input_id, "entry_id": review["entry_id"],
                                          "report_id": review["report_id"], "action": action})
                        for action in review["actions"])
        self._persist(rows)
        self._drafts.extend(deepcopy(drafts))
        self._multi_mode = True
        self._input_reviews.append(mapping)
        self._counts["input_count"] += 1
        self._counts["candidate_count"] += complete
        self._counts["draft_count"] += sum(review["status"] == "draft" for _, review in prepared)
        self._counts["input_failure_count"] += int(failed)
        self._counts["jobs_with_model_errors"] += int(bool(input_model_errors) or any(review.get("model_errors") for _, review in prepared))
        annotation_count = sum(len(review.get("annotation_errors") or []) for _, review in prepared)
        self._counts["annotation_error_count"] += annotation_count
        self._counts["jobs_with_annotation_errors"] += int(bool(annotation_count))
        for output_key, review_key, shared_errors in (("model_error_count", "model_errors", input_model_errors),
                                                      ("tool_error_count", "tool_errors", input_tool_errors),
                                                      ("pipeline_error_count", "pipeline_errors", input_errors)):
            self._counts[output_key] += len(shared_errors) + sum(len(review.get(review_key) or []) for _, review in prepared)
        for key in ("model_calls", "tool_calls"):
            if type(shared.get(key)) is int and shared[key] >= 0:
                self._counts[key] += shared[key]
        for entry, review in prepared:
            self._review_seen.add(review["entry_id"])
            if entry is not None:
                self._seen.add(entry["entry_id"])
                self._entries.append(deepcopy(entry))

    def finish(self, extra_summary: Mapping[str, Any] | None = None) -> dict[str, Any]:
        self._check_open()
        if (self.directory / "summary.json").exists():
            raise FileExistsError("summary_already_exists")
        entries = sorted(self._entries, key=lambda item: item["entry_id"])
        drafts = sorted(self._drafts, key=lambda item: item["entry_id"])
        reports, report_conflicts = _reports(entries)
        expected_links = defaultdict(list)
        for entry in entries:
            expected_links[entry["report_id"]].append(entry["entry_id"])
        report_links = {report["report_id"]: report["entry_ids"] for report in reports}
        linkage_complete = (len(reports) == len(expected_links)
                            and report_links == dict(expected_links))
        summary = dict(_public(extra_summary or {}))
        summary.update(self._counts)
        summary.update(entry_count=len(entries), report_count=len(reports), schema_entry_count=len(entries), human_verified_count=0,
                       report_conflict_count=len(report_conflicts),
                       report_linkage_complete=linkage_complete,
                       report_conflict_entry_count=sum(item["num_entries"] for item in report_conflicts),
                       draft_export_count=len(drafts), draft_export_version=DRAFT_EXPORT_VERSION,
                       draft_export_definition=DRAFT_EXPORT_DEFINITION,
                       files=["entries.jsonl", "drafts.jsonl", "reports.jsonl", "report_conflicts.jsonl", "review.jsonl", "actions.jsonl", "summary.json"],
                       candidate_definition="Complete schema entries only; drafts and input failures are excluded.")
        if self._multi_mode:
            from .multi_entry import COUNTING_VERSION
            summary.update(counting_version=COUNTING_VERSION, review_count=len(self._review_seen),
                           input_reviews=deepcopy(self._input_reviews))
            for status in ("complete", "partial", "draft"):
                summary[status + "_input_count"] = sum(row["status"] == status for row in self._input_reviews)
        contents = [(name, "".join(_json(row) + "\n" for row in rows)) for name, rows in
                    (("entries.jsonl", entries), ("drafts.jsonl", drafts), ("reports.jsonl", reports), ("report_conflicts.jsonl", report_conflicts))]
        contents.append(("summary.json", json.dumps(summary, ensure_ascii=False, sort_keys=True, allow_nan=False, indent=2) + "\n"))
        staged = []
        phase, target = "stage", "unknown"
        try:
            # Same-directory atomic replacements never truncate an append log.
            # Summary is the last commit marker. Failed staging files are kept
            # for diagnosis; no automatic resume or successful finish is claimed.
            for name, content in contents:
                target = name
                with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", newline="\n",
                                                 prefix=".t2-output-", suffix=".tmp", dir=self.directory,
                                                 delete=False) as stream:
                    staged.append((Path(stream.name), self.directory / name))
                    stream.write(content)
                    stream.flush()
                    os.fsync(stream.fileno())
            for temporary, destination in staged:
                phase, target = "replace", destination.name
                _replace_final_output(temporary, destination)
        except OSError as error:
            self._write_failed = True
            raise OutputPublicationError(phase, target, error) from None
        except BaseException:
            self._write_failed = True
            raise
        self._finished = True
        return summary
