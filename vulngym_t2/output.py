"""Evidence-aware T2 finalization and recoverable, schema-only batch exports.

``supported`` is the model's cited assessment, never a human-audit claim.
Source-reading receipts and exact repository checks are additional requirements;
neither a citation nor a syntactically valid location substitutes for reading it.
"""
from __future__ import annotations

from collections import Counter, defaultdict
from copy import deepcopy
import json
from pathlib import Path, PurePosixPath, PureWindowsPath
import re
from typing import Any, Mapping

from ._vendor.schema_adapter import ENTRY_FIELDS, ORIGIN, SchemaAdapter


_ADAPTER = SchemaAdapter()
_STATUSES = frozenset({"supported", "uncertain", "missing", "conflicting"})
_REVISION_BASES = frozenset({"behavior_at_revision", "affected_range_and_source", "inspected_only", "unknown"})
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
    allowed = ("id", "kind", "tool", "name", "document_kind", "advisory_metadata", "arguments", "result", "text", "success", "error", "truncated")
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
                reviews[field]["omitted_assessment"] = {key: omitted[key] for key in ("status", "reason", "evidence_refs") if key in omitted}
            continue
        model_review = model_reviews.get(field)
        model_review = model_review if isinstance(model_review, Mapping) else {}
        value = fields.get(field)
        status = model_review.get("status", "missing" if value is None else "uncertain")
        if status not in _STATUSES:
            status = "uncertain"
        refs = model_review.get("evidence_refs")
        refs = list(dict.fromkeys(item for item in refs if isinstance(item, str))) if isinstance(refs, list) else []
        reason = model_review.get("reason")
        reason = reason.strip()[:1600] if isinstance(reason, str) else ""
        reviews[field] = {"status": status, "reason": reason or "No supported, cited field assessment was supplied.", "evidence_refs": refs}
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

    commit = draft["commit"]
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
    evidence_followup_status = result.get("evidence_followup_status", "not_requested")
    if evidence_followup_status not in ("not_requested", "completed", "failed"):
        evidence_followup_status = "failed"
    if evidence_followup_status == "failed":
        errors.append({"field": None, "code": "evidence_followup_incomplete",
                       "message": "The focused evidence follow-up failed; preserve the draft and evidence for review without claiming a complete entry."})
    entry = None
    if not input_error and self_review_status != "failed" and evidence_followup_status != "failed" and all(draft[field] is not None for field in ENTRY_FIELDS):
        entry = _ADAPTER.adapt(draft, formal_t2=True)
    pipeline_errors = result.get("errors", [])
    pipeline_errors = pipeline_errors if isinstance(pipeline_errors, list) else [pipeline_errors]
    tool_error_prefixes = ("repository ", "read_file failed:", "read_diff failed:", "inspect_commit failed:", "list_files failed:", "search_code failed:", "list_refs failed:", "search_history failed:")
    tool_errors = [error for error in pipeline_errors if str(error).lower().startswith(tool_error_prefixes)]
    model_errors = [error for error in pipeline_errors if error not in tool_errors and not str(error).lower().startswith("input error:")] if not input_error else []
    actions = result.get("actions") if isinstance(result.get("actions"), list) else []
    review = {
        "entry_id": trusted.get("entry_id"), "report_id": trusted.get("report_id"),
        "source_link": trusted.get("source_link"),
        "status": "input_failure" if input_error else "complete" if entry is not None else "draft",
        "self_review_status": self_review_status,
        "evidence_followup_status": evidence_followup_status,
        "draft_fields": draft, "field_reviews": reviews, "suggested_values": suggestions,
        "errors": errors, "pipeline_errors": pipeline_errors, "model_errors": model_errors, "tool_errors": tool_errors,
        "model_calls": result.get("model_calls", 0), "tool_calls": result.get("tool_calls", 0),
        "evidence": [_evidence_receipt(item) for item in evidence.values()],
        "location_checks": location_checks,
        "location_corrections": location_corrections,
        "actions": [{key: val for key, val in item.items() if key in {"action", "kind", "tool", "arguments", "evidence_id", "evidence_ref", "evidence_refs", "stage", "plan", "summary", "reason", "error", "errors", "location_corrections", "note", "model_call", "tool_call", "call_index", "call", "success", "automatic", "requested_calls"}} for item in actions[:96] if isinstance(item, Mapping)],
        "verification": "Machine annotation only (verify=0). Supported means cited model assessment plus applicable deterministic checks, not independent human proof.",
    }
    return {"entry": entry, "review": _public(review, repo_path)}


def _majority(entries: list[dict[str, Any]], field: str) -> str:
    values = [entry[field] for entry in sorted(entries, key=lambda item: item["entry_id"])]
    if field == "vuln_title":
        values = [re.sub(r" - [^\s]+\.[A-Za-z0-9]+$", "", value) for value in values]
    counts = Counter(values)
    return max(values, key=counts.get)


def _reports(entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for entry in entries:
        groups[entry["report_id"]].append(entry)
    reports = []
    for report_id, group in sorted(groups.items()):
        report = {field: _majority(group, field) for field in ("source_link", "origin", "project", "repo_url", "commit", "vuln_title")}
        report.update(report_id=report_id, entry_ids=sorted(entry["entry_id"] for entry in group), num_entries=len(group), vuln_ids=_normalize("vuln_ids", [identifier for entry in group for identifier in entry["vuln_ids"]]))
        reports.append(report)
    return reports


def _json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, allow_nan=False)


class BatchWriter:
    """Own one new output directory; append progress, then sort final exports."""

    def __init__(self, directory: str | Path):
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=False)
        self._entries: list[dict[str, Any]] = []
        self._seen: set[str] = set()
        self._counts = {key: 0 for key in ("input_count", "candidate_count", "draft_count", "input_failure_count", "model_error_count", "tool_error_count", "pipeline_error_count", "jobs_with_model_errors", "model_calls", "tool_calls")}
        self._finished = False
        for name in ("entries.jsonl", "reports.jsonl", "review.jsonl", "actions.jsonl"):
            (self.directory / name).touch(exist_ok=False)

    def _append(self, name: str, value: Any) -> None:
        with (self.directory / name).open("a", encoding="utf-8", newline="\n") as stream:
            stream.write(_json(value) + "\n")

    def record(self, job: Mapping[str, Any], finalized: Mapping[str, Any]) -> None:
        if self._finished:
            raise RuntimeError("batch_already_finished")
        entry, review = finalized.get("entry"), finalized.get("review")
        if not isinstance(review, Mapping):
            raise ValueError("finalized_review_required")
        review = _public(review, str(job.get("repo_path") or ""))
        if entry is not None:
            entry = _ADAPTER.adapt(entry, formal_t2=True)
            if any(entry[field] != job.get(field) for field in ("entry_id", "source_link")) or entry["report_id"] != str(job.get("report_id", "")).upper():
                raise ValueError("entry_job_provenance_mismatch")
            if entry["entry_id"] in self._seen:
                raise ValueError("duplicate_entry_id")
            if _contains_private_text(entry, str(job.get("repo_path") or "")):
                raise ValueError("private_entry_output_refused")
            self._seen.add(entry["entry_id"])
            self._entries.append(entry)
            self._append("entries.jsonl", entry)
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
        for field in ("model_calls", "tool_calls"):
            if type(review.get(field)) is int and review[field] >= 0:
                self._counts[field] += review[field]
        self._append("review.jsonl", review)
        for action in review.get("actions", []):
            self._append("actions.jsonl", {"entry_id": review.get("entry_id"), "report_id": review.get("report_id"), "action": action})

    def finish(self, extra_summary: Mapping[str, Any] | None = None) -> dict[str, Any]:
        if self._finished:
            raise RuntimeError("batch_already_finished")
        entries = sorted(self._entries, key=lambda item: item["entry_id"])
        reports = _reports(entries)
        for name, rows in (("entries.jsonl", entries), ("reports.jsonl", reports)):
            with (self.directory / name).open("w", encoding="utf-8", newline="\n") as stream:
                for row in rows:
                    stream.write(_json(row) + "\n")
        summary = dict(_public(extra_summary or {}))
        summary.update(self._counts)
        summary.update(entry_count=len(entries), report_count=len(reports), schema_entry_count=len(entries), human_verified_count=0,
                       files=["entries.jsonl", "reports.jsonl", "review.jsonl", "actions.jsonl", "summary.json"],
                       candidate_definition="Complete schema entries only; drafts and input failures are excluded.")
        with (self.directory / "summary.json").open("x", encoding="utf-8", newline="\n") as stream:
            stream.write(json.dumps(summary, ensure_ascii=False, sort_keys=True, allow_nan=False, indent=2) + "\n")
        self._finished = True
        return summary
