"""Resolve source locations and check citations using already shown receipts.

No repository access, source execution, or semantic assessment is performed.
Location resolution requires line rows; citation checks can also use the text
retained in public receipts. The caller owns final location validation.
"""
from __future__ import annotations

from collections.abc import Mapping
import json
from pathlib import PurePosixPath, PureWindowsPath
import re


MAX_SPAN_LINES = 200
_REFERENCE_KEYS = frozenset({"evidence_ref", "start_line", "end_line", "desc"})


def _require(condition: bool, code: str) -> None:
    if not condition:
        raise ValueError("source_ref_" + code)


def _positive_line(value) -> bool:
    return type(value) is int and value > 0


def _relative_path(value) -> bool:
    if not isinstance(value, str) or not value.strip() or "\\" in value or "\x00" in value:
        return False
    posix, windows = PurePosixPath(value), PureWindowsPath(value)
    return bool(posix.parts and not posix.is_absolute() and not windows.is_absolute()
                and not windows.drive and ".." not in posix.parts)


def resolve_location(reference, evidence, commit) -> dict:
    """Build ``file/line/code/desc?`` from one successful same-SHA receipt.

    ``reference`` contains evidence_ref, start_line, end_line, and optional desc.
    Only the receipt's continuous ``result.lines`` are authoritative: requested
    arguments and ``result.text`` cannot supply omitted source. Blank lines and
    whitespace are preserved verbatim. Failures use stable source_ref_* codes.
    """
    _require(isinstance(reference, Mapping) and not (set(reference) - _REFERENCE_KEYS), "invalid_reference")
    identity = reference.get("evidence_ref")
    _require(isinstance(identity, str) and bool(identity.strip()), "invalid_evidence_ref")
    first, last = reference.get("start_line"), reference.get("end_line")
    _require(_positive_line(first) and _positive_line(last) and first <= last, "invalid_range")
    _require(last - first + 1 <= MAX_SPAN_LINES, "span_limit")
    if "desc" in reference:
        _require(isinstance(reference["desc"], str), "invalid_description")
    _require(isinstance(commit, str) and re.fullmatch(r"[0-9a-f]{40}", commit) is not None, "invalid_commit")
    _require(isinstance(evidence, list) and all(isinstance(row, Mapping) for row in evidence), "invalid_evidence")
    matches = [row for row in evidence if row.get("id") == identity]
    _require(bool(matches), "unknown_evidence")
    _require(len(matches) == 1, "ambiguous_evidence")
    receipt = matches[0]
    _require(receipt.get("tool") == "read_file", "read_required")
    result = receipt.get("result")
    _require(receipt.get("success") is True and not receipt.get("error") and isinstance(result, Mapping)
             and not result.get("error") and result.get("ok") is not False
             and result.get("success") is not False, "failed_read")
    _require(result.get("commit") == commit, "commit_mismatch")
    _require(_relative_path(result.get("path")), "invalid_path")
    start, end = result.get("start_line"), result.get("end_line")
    _require(_positive_line(start) and _positive_line(end) and start <= end, "invalid_source_range")
    _require(start <= first <= last <= end, "out_of_bounds")
    rows = result.get("lines")
    _require(isinstance(rows, list) and bool(rows), "source_missing")
    selected, expected = [], start
    for row in rows:
        _require(isinstance(row, Mapping) and _positive_line(row.get("line"))
                 and isinstance(row.get("code"), str) and "\n" not in row["code"] and "\r" not in row["code"],
                 "invalid_source_rows")
        _require(row["line"] == expected and row["line"] <= end, "noncontiguous_source")
        if first <= row["line"] <= last:
            selected.append(row["code"])
        expected += 1
    _require(expected == end + 1 and len(selected) == last - first + 1, "noncontiguous_source")
    location = {"file": result["path"], "line": first if first == last else f"{first}-{last}",
                "code": "\n".join(selected)}
    if "desc" in reference:
        location["desc"] = reference["desc"]
    return location


_CITATION_ID = r"(?<![A-Za-z0-9_])E[0-9]{4,8}(?![A-Za-z0-9_])"
# Match whole numbers in the already bounded reason. A malformed/oversized
# range must not backtrack into a seemingly valid single-line citation.
_CITATION_SPAN = r"(?P<first>[0-9]+)(?:\s*(?:[-–—~～至]|to)\s*(?P<last>[0-9]+))?(?![0-9]|\s*(?:[-–—~～至]|to\b))"
_EXPLICIT_CITATION = re.compile(
    r"(?P<eid>" + _CITATION_ID + r")"
    r"(?:\s*[:：]\s*(?:lines?\s*)?|\s*[（(]\s*lines?\s+|\s+lines?\s+|\s*的\s*第)"
    + _CITATION_SPAN, re.IGNORECASE)
_LABELED_COMPACT_CITATION = re.compile(
    r"\b(?:declared|defined|called|invoked|call|declaration|definition|statement|return)\s+(?:at\s+)?"
    r"(?P<eid>" + _CITATION_ID + r")[ \t]+" + _CITATION_SPAN
    + r"(?=[ \t]*(?:[,，)）\]}]|$))", re.IGNORECASE)
_COMPACT_CITATION = re.compile(
    r"(?P<eid>" + _CITATION_ID + r")[ \t]+" + _CITATION_SPAN
    + r"(?=[ \t]*(?:[,，)）\]}]|$))", re.IGNORECASE)
_PROSE_LINES = re.compile(r"\blines?\s+" + _CITATION_SPAN, re.IGNORECASE)
_CHINESE_LINES = re.compile(r"第?" + _CITATION_SPAN + r"\s*行")
# These cues only *disable* automatic rejection. They never establish the
# meaning of a claim. Ambiguous free prose remains a warning for human review.
_NONASSERTION = re.compile(r"\b(?:not|no|never|without|unread|unverified|uncertain|unknown|missing)\b|n['’]t\b|未|不|没有", re.IGNORECASE)


def _citation_window(result):
    """Return a continuous visible prefix, never a requested/total line range."""
    first, last = result.get("start_line"), result.get("end_line")
    if not (_positive_line(first) and _positive_line(last) and first <= last <= 100_000_000):
        return None, None, "invalid_source_range"
    if "lines" in result:
        lines = result["lines"]
        if not isinstance(lines, list) or not lines:
            return None, None, "source_missing"
        if len(lines) > 10_000:
            return None, None, "invalid_source_rows"
        for offset, row in enumerate(lines):
            if (not isinstance(row, Mapping) or not _positive_line(row.get("line"))
                    or row["line"] != first + offset or row["line"] > last
                    or not isinstance(row.get("code"), str) or "\n" in row["code"] or "\r" in row["code"]):
                return None, None, "invalid_source_rows"
        return first, first + len(lines) - 1, None
    # Public review receipts omit result.lines but retain the displayed text.
    # A clipped last line is not complete source evidence. read_file otherwise
    # returns whole lines, even when truncated=True means more lines exist.
    text = result.get("text")
    if not isinstance(text, str) or not text:
        return None, None, "source_missing"
    clipped = len(text) > 16000 or "<truncated>" in text
    text = text[:16000].split("<truncated>", 1)[0]
    lines = text.split("\n")
    if clipped:
        lines.pop()
    if not lines:
        return None, None, "source_missing"
    return first, min(last, first + len(lines) - 1), None


def reason_citations(reason, evidence, commit) -> dict:
    """Check explicit EID/line coverage using saved receipts; never source meaning.

    Adjacent E0001:1-2, E0001 lines 1-2, E0001 (lines 1-2), and E0001 的第1至2行
    and explicitly labeled compact forms such as 'declared E0001 42' are
    bounded citation forms. Bare 'E0001 42' is warning-only when not covered:
    an adjacent number alone need not be a line. A single EID and a nonadjacent line phrase in
    one sentence are warning-only: no multi-ID or cross-sentence guessing.
    Negative/uncertain prose cues also disable automatic rejection. Different
    full SHAs are context (e.g. fix/parent comparisons), not citation failures.
    Coverage is not a semantic approval. No input, file, or repository changes.
    """
    text = reason if isinstance(reason, str) else ""
    packet = {"citations": [], "omitted_reason_chars": max(0, len(text) - 2000),
              "omitted_citations": 0, "truncated": False}
    receipts = {}
    for item in evidence if isinstance(evidence, list) else []:
        if isinstance(item, Mapping) and isinstance(item.get("id"), str):
            receipts.setdefault(item["id"], []).append(item)
    selected = commit if isinstance(commit, str) and re.fullmatch(r"[0-9a-f]{40}", commit) else None
    for sentence in re.split(r"[.!?;。\r\n]+", text[:2000]):
        matches = [(match, "explicit", match.group("eid").upper())
                   for pattern in (_EXPLICIT_CITATION, _LABELED_COMPACT_CITATION)
                   for match in pattern.finditer(sentence)]
        for match in _COMPACT_CITATION.finditer(sentence):
            if not any(start.start() <= match.start() < start.end() for start, _, _ in matches):
                matches.append((match, "compact", match.group("eid").upper()))
        identities = list(re.finditer(_CITATION_ID, sentence))
        if len(identities) == 1:
            identity = identities[0]
            for pattern in (_PROSE_LINES, _CHINESE_LINES):
                for match in pattern.finditer(sentence, identity.end()):
                    if not any(start.start() <= match.start() < start.end() for start, _, _ in matches):
                        matches.append((match, "same_sentence", identity.group()))
        for match, binding, identity in sorted(matches, key=lambda item: item[0].start()):
            if len(packet["citations"]) >= 16:
                packet["omitted_citations"] += 1
                continue
            first_text = match.group("first")
            last_text = match.group("last") or first_text
            first = int(first_text) if len(first_text) <= 9 else None
            last = int(last_text) if len(last_text) <= 9 else None
            row = {"evidence_ref": identity, "start_line": first, "end_line": last,
                   "binding": binding, "code": "covered", "severity": "info",
                   "receipt_commit": None, "matches_selected_commit": None,
                   "visible_start_line": None, "visible_end_line": None}
            found = receipts.get(identity, [])
            issue = None
            if first is None or last is None or not 1 <= first <= last <= 100_000_000:
                issue = "invalid_range"
            elif len(found) != 1:
                issue = "ambiguous_evidence" if found else "unknown_evidence"
            else:
                item = found[0]
                result = item.get("result")
                if item.get("tool") != "read_file":
                    issue = "read_required"
                elif (item.get("success") is not True or item.get("error") or not isinstance(result, Mapping)
                      or result.get("error") or result.get("ok") is False or result.get("success") is False):
                    issue = "failed_read"
                elif (not isinstance(result.get("commit"), str) or not re.fullmatch(r"[0-9a-f]{40}", result["commit"])
                      or not _relative_path(result.get("path"))):
                    issue = "receipt_metadata_unknown"
                else:
                    row["receipt_commit"] = result["commit"]
                    row["matches_selected_commit"] = result["commit"] == selected if selected else None
                    visible_first, visible_last, issue = _citation_window(result)
                    row.update(visible_start_line=visible_first, visible_end_line=visible_last)
                    if issue is None and not visible_first <= first <= last <= visible_last:
                        issue = "out_of_bounds"
            if issue:
                row["code"] = "reason_citation_" + issue
                row["severity"] = "error" if binding == "explicit" and not _NONASSERTION.search(sentence) else "warning"
            packet["citations"].append(row)
    packet["truncated"] = bool(packet["omitted_reason_chars"] or packet["omitted_citations"])
    return packet


def visible_location_feedback(review, *, max_chars: int = 8_000) -> dict:
    """Describe saved visible windows and unresolved references, never repair them.

    A review containing only ``evidence`` produces a pre-draft receipt directory.
    With draft_fields/suggested_values/field_reviews it also describes the current
    EP/CO/trace references. Other covering receipts are navigation choices, not
    replacements: they must have the same path and SHA as the referenced read.
    Public text can describe visibility but cannot replace resolve_location's
    authoritative line rows. No source body, reason or description is returned.
    The complete default-json-encoded packet fits the caller's character budget.
    """
    if type(max_chars) is not int or not 1_024 <= max_chars <= 16_000:
        raise ValueError("visible_location_feedback_budget_invalid")
    review = review if isinstance(review, Mapping) else {}
    packet = {
        "version": "visible-location-v1", "selected_commit": None, "suggested_commit": None,
        "max_location_span_lines": MAX_SPAN_LINES, "ranges": [], "references": [],
        "omitted": {"invalid_receipts": 0, "ambiguous_receipts": 0, "range_limit": 0,
                    "reference_limit": 0, "available_limit": 0, "budget_ranges": 0,
                    "budget_references": 0}, "truncated": False,
        "note": "Visible windows only, not semantic approval. Select an existing evidence ID and a fully shown range, or keep uncertainty; never clamp lines or switch IDs automatically. public_text is navigation metadata, not a substitute for live line rows. Unlisted windows may be omitted.",
    }
    evidence = review.get("evidence")
    evidence = evidence if isinstance(evidence, list) else []
    # An oversized inventory cannot safely be prefix-scanned: a later duplicate
    # ID could make an earlier apparently unique receipt ambiguous.
    if len(evidence) > 1_024:
        packet["omitted"]["range_limit"] = len(evidence)
        packet["truncated"] = True
        return packet
    identities = {}
    for item in evidence:
        if not isinstance(item, Mapping):
            packet["omitted"]["invalid_receipts"] += 1
            continue
        identity = item.get("id")
        if not isinstance(identity, str) or re.fullmatch(r"E[0-9]{4,8}", identity) is None:
            packet["omitted"]["invalid_receipts"] += 1
            continue
        identities.setdefault(identity, []).append(item)
    windows = {}
    for identity, matches in identities.items():
        if len(matches) != 1:
            packet["omitted"]["ambiguous_receipts"] += len(matches)
            continue
        receipt = matches[0]
        if receipt.get("tool") != "read_file":
            continue
        result = receipt.get("result")
        if (receipt.get("success") is not True or receipt.get("error") or not isinstance(result, Mapping)
                or result.get("error") or result.get("ok") is False or result.get("success") is False):
            packet["omitted"]["invalid_receipts"] += 1
            continue
        commit, path = result.get("commit"), result.get("path")
        if (not isinstance(commit, str) or re.fullmatch(r"[0-9a-f]{40}", commit) is None
                or not _relative_path(path) or len(path) > 500
                or any(ord(char) < 32 for char in path)):
            packet["omitted"]["invalid_receipts"] += 1
            continue
        first, last, issue = _citation_window(result)
        if issue:
            packet["omitted"]["invalid_receipts"] += 1
            continue
        windows[identity] = {
            "evidence_ref": identity, "receipt_commit": commit, "path": path,
            "visible_start_line": first, "visible_end_line": last,
            "visibility_basis": "line_rows" if "lines" in result else "public_text",
            "reference_usable": last == result["end_line"] if "lines" in result else None,
            "receipt_truncated": result.get("truncated") is True or result.get("context_truncated") is True,
        }

    # Reuse the existing bounded, field-specific association logic. It never
    # chooses an alternative SHA or silently prefers one of ambiguous reads.
    associations = revision_consistency(dict(review))
    for key in ("selected_commit", "suggested_commit"):
        packet[key] = associations[key]
    packet["omitted"]["reference_limit"] = (associations["omitted"]["item_limit"]
                                              + associations["omitted"]["budget"])
    preferred = []
    for associated in associations["location_references"]:
        row = {key: associated[key] for key in
               ("field", "from_suggestion", "evidence_ref", "receipt_commit", "path", "start_line", "end_line")}
        row.update(visible_start_line=None, visible_end_line=None,
                   resolution_error=associated["resolution_error"], coverage_error=None, available_receipts=[])
        window = windows.get(row["evidence_ref"])
        if window is not None:
            preferred.append(window["evidence_ref"])
            row.update(visible_start_line=window["visible_start_line"], visible_end_line=window["visible_end_line"])
            first, last = row["start_line"], row["end_line"]
            if first is not None and last is not None:
                if last - first + 1 > MAX_SPAN_LINES:
                    row["coverage_error"] = "source_ref_span_limit"
                elif not window["visible_start_line"] <= first <= last <= window["visible_end_line"]:
                    row["coverage_error"] = "source_ref_out_of_bounds"
                elif window["reference_usable"] is False:
                    row["coverage_error"] = "source_ref_noncontiguous_source"
                if row["coverage_error"] in {"source_ref_out_of_bounds", "source_ref_noncontiguous_source"}:
                    # Do not offer a different revision as a coordinate repair.
                    selected = packet["selected_commit"] or packet["suggested_commit"]
                    if selected is None or selected == window["receipt_commit"]:
                        available = [other for other in windows.values()
                                     if other["evidence_ref"] != window["evidence_ref"]
                                     and other["reference_usable"] is not False
                                     and other["path"] == window["path"]
                                     and other["receipt_commit"] == window["receipt_commit"]
                                     and other["visible_start_line"] <= first <= last <= other["visible_end_line"]]
                        packet["omitted"]["available_limit"] += max(0, len(available) - 4)
                        row["available_receipts"] = [{key: other[key] for key in
                            ("evidence_ref", "visible_start_line", "visible_end_line", "visibility_basis", "reference_usable")}
                            for other in available[:4]]
                        preferred.extend(other["evidence_ref"] for other in available[:4])
        packet["references"].append(row)
    ordered = list(dict.fromkeys(preferred + list(windows)))
    packet["ranges"] = [windows[identity] for identity in ordered[:32]]
    packet["omitted"]["range_limit"] += max(0, len(ordered) - 32)
    packet["truncated"] = any(packet["omitted"].values())
    # References (including possible covering windows) are more actionable than
    # a repeated full directory during review. Omit complete rows, never IDs,
    # paths, SHAs or coordinate digits; the omission itself stays explicit.
    for key, counter in (("ranges", "budget_ranges"), ("references", "budget_references")):
        while len(json.dumps(packet)) > max_chars and packet[key]:
            packet[key].pop()
            packet["omitted"][counter] += 1
            packet["truncated"] = True
    return packet


def entry_context_request(review, *, include_supported=False) -> dict | None:
    """Propose one unread preceding window for an entry-point role.

    Return only read_file arguments; the caller owns execution and budgets.
    This is navigation, not a claim that a declaration exists in that window.
    The EP must be uncertain/missing/conflicting, or have a recorded support
    conflict by default. The controller may include a supported initial draft
    for pre-review context; that status is a model claim, not evidence that the
    enclosing input source was already read. No status or location is changed.
    Its location must associate with successful, unambiguous saved
    reads at one SHA/path. No reason-keyword or source-body interpretation occurs.

    A candidate start from 120 lines before through 79 lines after a receipt's
    visible start is "near" that boundary. Request the closest continuous unread
    gap in the preceding at-most-120 lines (therefore also below the 200-line
    ceiling). Coverage can span multiple already-read windows, but no source
    locations or annotations are combined. A covering failed attempt is not
    retried. An incomplete directory, ambiguous identity/SHA, or unknown path
    yields None instead of inventing a request.
    """
    if not isinstance(review, Mapping):
        return None
    fields = review.get("draft_fields")
    fields = fields if isinstance(fields, Mapping) else {}
    suggestions = review.get("suggested_values")
    suggestions = suggestions if isinstance(suggestions, Mapping) else {}
    assessments = review.get("field_reviews")
    assessments = assessments if isinstance(assessments, Mapping) else {}
    assessment = assessments.get("entry_point")
    if not isinstance(assessment, Mapping):
        return None
    checks = review.get("support_consistency_checks")
    checks = checks if isinstance(checks, Mapping) else {}
    validation_errors = assessment.get("validation_errors")
    conflict = (isinstance(validation_errors, list)
                and "supported_reason_conflict" in validation_errors[:32])
    for packet in (assessment.get("support_consistency"), checks.get("entry_point")):
        if isinstance(packet, Mapping) and isinstance(packet.get("issues"), list):
            conflict |= any(isinstance(issue, Mapping) and issue.get("code") == "supported_reason_conflict"
                            and issue.get("prerequisite") == "external_entry_role" for issue in packet["issues"][:8])
    if (assessment.get("status") not in ("uncertain", "missing", "conflicting") and not conflict
            and not (include_supported is True and assessment.get("status") == "supported")):
        return None
    value = fields.get("entry_point")
    suggestion = suggestions.get("entry_point")
    if value is not None and suggestion is not None and value != suggestion:
        return None  # Two different current candidates do not identify one navigation target.
    value = value if value is not None else suggestion
    if not isinstance(value, Mapping):
        return None
    evidence = review.get("evidence")
    if not isinstance(evidence, list):
        return None
    directory = visible_location_feedback({"evidence": evidence}, max_chars=16_000)
    if (directory["omitted"]["range_limit"] or directory["omitted"]["budget_ranges"]
            or directory["omitted"]["ambiguous_receipts"]):
        return None  # Omitted windows must not be mistaken for unread source.
    windows = directory["ranges"]
    first, last = value.get("start_line"), value.get("end_line")
    if "evidence_ref" in value:
        if set(value) - _REFERENCE_KEYS:
            return None
        linked = [window for window in windows if window["evidence_ref"] == value["evidence_ref"]]
    else:
        first = last = value.get("line")
        if isinstance(first, str) and re.fullmatch(r"[1-9][0-9]{0,8}-[1-9][0-9]{0,8}", first):
            first, last = map(int, first.split("-"))
        refs = assessment.get("evidence_refs")
        refs = refs if isinstance(refs, list) else []
        if len(refs) > 24:
            return None
        linked = [window for window in windows if window["evidence_ref"] in refs and window["path"] == value.get("file")]
        if len({window["receipt_commit"] for window in linked}) > 1:
            # Reasons may cite a contrasting revision. It is not an ambiguous
            # location when an explicit single SHA and exact cited source bytes
            # identify the selected value. Never choose a SHA from the prose.
            selected = [item for item in (fields.get("commit"), suggestions.get("commit")) if item is not None]
            if (not selected or any(not isinstance(item, str) or not re.fullmatch(r"[0-9a-f]{40}", item)
                                    for item in selected) or len(set(selected)) != 1):
                return None
            from .entry_navigation import _selected_location_source
            by_id = {row["id"]: row for row in evidence if isinstance(row, Mapping) and isinstance(row.get("id"), str)}
            if _selected_location_source(value, assessment, selected[0], by_id) is None:
                return None
            linked = [window for window in linked if window["receipt_commit"] == selected[0]]
    if (not _positive_line(first) or not _positive_line(last) or not first <= last <= 100_000_000
            or last - first + 1 > MAX_SPAN_LINES or not linked):
        return None
    if len({(window["receipt_commit"], window["path"]) for window in linked}) != 1:
        return None
    commit, path = linked[0]["receipt_commit"], linked[0]["path"]
    for selected in (fields.get("commit"), suggestions.get("commit")):
        if selected is not None and selected != commit:
            return None
    nearby = [window for window in linked if window["reference_usable"] is not False
              and max(1, window["visible_start_line"] - 120) <= first <= window["visible_start_line"] + 79]
    if not nearby:
        return None
    # Prefer a window that actually shows the candidate, then its earliest
    # boundary. This selects a navigation boundary, never another source value.
    covered = [window for window in nearby if window["visible_start_line"] <= first <= last <= window["visible_end_line"]]
    anchor = min(covered or nearby, key=lambda window: window["visible_start_line"])["visible_start_line"]
    if anchor <= 1:
        return None
    lower, upper = max(1, anchor - 120), anchor - 1
    intervals = sorted((max(lower, window["visible_start_line"]), min(upper, window["visible_end_line"]))
                       for window in windows if window["receipt_commit"] == commit and window["path"] == path
                       and window["visible_start_line"] <= upper and window["visible_end_line"] >= lower)
    missing, cursor = [], lower
    for start, end in intervals:
        if start > cursor:
            missing.append((cursor, start - 1))
        cursor = max(cursor, end + 1)
    if cursor <= upper:
        missing.append((cursor, upper))
    if not missing:
        return None
    start, end = missing[-1]
    for item in evidence:
        if not isinstance(item, Mapping) or item.get("tool") != "read_file":
            continue
        result, arguments = item.get("result"), item.get("arguments")
        failed = (item.get("success") is False or bool(item.get("error"))
                  or (isinstance(result, Mapping) and (bool(result.get("error"))
                      or result.get("ok") is False or result.get("success") is False)))
        if not failed or not isinstance(arguments, Mapping) or arguments.get("commit") != commit or arguments.get("path") != path:
            continue
        prior_start, prior_end = arguments.get("start_line"), arguments.get("end_line")
        if (_positive_line(prior_start) and _positive_line(prior_end) and prior_start <= start <= end <= prior_end
                or prior_start == start and prior_end is None):
            return None
    return {"commit": commit, "path": path, "start_line": start, "end_line": end}


def review_locations(review: dict) -> dict:
    """Copy selected claim excerpts for review, without inspecting their meaning.

    EP/CO values and suggestions precede trace values (in their original order).
    Unexpanded suggested references keep their identity, never invented source.
    Only ordinary JSON-shaped dictionaries/lists/scalars are accepted. Invalid
    items are counted and skipped. The returned JSON is at most 12000 characters
    even with json.dumps' default ASCII escaping and separators.
    """
    packet = {
        "title": "待复核的所选片段（不是新增独立证据）",
        "notes": "仅复制已保存的片段、描述与字段状态，不判断语义或调用连接。预览截断、遗漏或缺失不表示源码不存在。",
        "locations": [], "omitted": {"invalid_shape": 0, "item_limit": 0, "budget": 0},
        "truncated": False,
    }
    omitted = packet["omitted"]

    def mapping(value):
        if type(value) is dict:
            return value
        omitted["invalid_shape"] += 1
        return {}

    def line_number(value):
        return type(value) is int and 1 <= value <= 100_000_000

    def line_span(value):
        if line_number(value):
            return True
        if type(value) is not str or len(value) > 19 or re.fullmatch(r"[1-9][0-9]*-[1-9][0-9]*", value) is None:
            return False
        first, last = map(int, value.split("-"))
        return line_number(first) and line_number(last) and first <= last

    def item(field, index, value, assessment, suggestion):
        if (type(value) is not dict or type(assessment) is not dict
                or type(assessment.get("status")) is not str
                or assessment["status"] not in {"supported", "uncertain", "missing", "conflicting"}
                or type(assessment.get("reason", "")) is not str
                or type(value.get("desc", "")) is not str):
            return None
        selected = {"field": field if index is None else f"{field}[{index}]",
                    "from_suggestion": suggestion, "status": assessment["status"], "truncated": []}
        if "evidence_ref" in value:
            identity, first, last = value["evidence_ref"], value.get("start_line"), value.get("end_line")
            if (type(identity) is not str or re.fullmatch(r"E[0-9]{4,8}", identity) is None
                    or not line_number(first) or not line_number(last) or first > last):
                return None
            selected["reference"] = {"evidence_ref": identity, "start_line": first, "end_line": last}
        else:
            path = value.get("file")
            if (type(path) is not str or len(path) > 500 or not _relative_path(path)
                    or not line_span(value.get("line")) or type(value.get("code")) is not str):
                return None
            selected.update(file=path, line=value["line"])
            selected["code"] = value["code"][:1600]
            if len(value["code"]) > 1600:
                selected["truncated"].append("code")
        for name, text, limit in (("desc", value.get("desc", ""), 500),
                                  ("reason", assessment.get("reason", ""), 600)):
            selected[name] = text[:limit]
            if len(text) > limit:
                selected["truncated"].append(name)
        if assessment.get("reason_truncated") is True and "reason" not in selected["truncated"]:
            selected["truncated"].append("reason")
        return selected

    review = mapping(review)
    fields = mapping(review.get("draft_fields", {}))
    suggestions = mapping(review.get("suggested_values", {}))
    assessments = mapping(review.get("field_reviews", {}))
    sources = ((fields, False), (suggestions, True))
    for field in ("entry_point", "critical_operation", "trace"):
        for source, suggestion in sources:
            value = source.get(field)
            if value is None:
                continue
            if field == "trace" and type(value) is not list:
                omitted["invalid_shape"] += 1
                continue
            values = value if field == "trace" else [value]
            available = 10 - len(packet["locations"])
            omitted["item_limit"] += max(0, len(values) - available)
            assessment = assessments.get(field)
            if (suggestion and field == "trace" and type(assessment) is dict
                    and type(assessment.get("omitted_assessment")) is dict):
                assessment = assessment["omitted_assessment"]
            for index, value in enumerate(values[:available]):
                selected = item(field, index if field == "trace" else None, value,
                                assessment, suggestion)
                if selected is None:
                    omitted["invalid_shape"] += 1
                    continue
                packet["locations"].append(selected)
                if len(json.dumps(packet)) > 12000:
                    packet["locations"].pop()
                    omitted["budget"] += 1
    packet["truncated"] = any(omitted.values()) or any(row["truncated"] for row in packet["locations"])
    # Count/boolean changes after the last append also count toward the bound.
    while len(json.dumps(packet)) > 12000 and packet["locations"]:
        packet["locations"].pop()
        omitted["budget"] += 1
        packet["truncated"] = True
    return packet


def revision_consistency(review: dict, *, max_chars: int = 16_000) -> dict:
    """Return bounded SHA-association feedback using saved receipts only.

    This is not source validation or a vulnerable-version decision. No input is
    changed, no source body is copied, and ambiguous expanded references remain
    unknown even when one possible receipt matches the selected SHA. The entire
    result fits ``max_chars`` using default ASCII-escaped json.dumps output;
    display reason text is trimmed before location rows. SHA identities, status
    fields, required/unresolved fields, and omission counters are never trimmed.
    """
    if type(max_chars) is not int or not 1_024 <= max_chars <= 16_000:
        raise ValueError("revision_feedback_budget_invalid")
    def obj(value):
        return value if type(value) is dict else {}

    def sha(value):
        return value if type(value) is str and re.fullmatch(r"[0-9a-f]{40}", value) else None

    def eid(value):
        return value if type(value) is str and re.fullmatch(r"E[0-9]{4,8}", value) else None

    def path(value):
        return value if type(value) is str and len(value) <= 500 and _relative_path(value) else None

    def number(value):
        return type(value) is int and 1 <= value <= 100_000_000

    def span(first, last):
        return number(first) and number(last) and first <= last

    def status(value):
        return value if type(value) is str and value in {"supported", "uncertain", "missing", "conflicting"} else "unknown"

    review = obj(review)
    fields, suggestions = obj(review.get("draft_fields")), obj(review.get("suggested_values"))
    assessments = obj(review.get("field_reviews"))
    commit_review = obj(assessments.get("commit"))
    reason = commit_review.get("reason")
    reason = reason if type(reason) is str else ""
    # Reason is display-only; redact local absolute paths rather than copying a
    # repository root accidentally included in a saved explanation.
    reason = re.sub(r"(?<![A-Za-z0-9:/])(?:[A-Za-z]:[\\/][^\s\"'<>]*|\\\\[^\s\"'<>]+|/[^\s\"'<>]+)",
                    "[local path omitted]", reason)
    omitted_reason_chars = max(0, len(reason) - 800)
    reason = reason[:800]
    basis = commit_review.get("revision_basis")
    packet = {
        "selected_commit": sha(fields.get("commit")), "suggested_commit": sha(suggestions.get("commit")),
        "commit_status": status(commit_review.get("status")),
        "revision_basis": basis if type(basis) is str and basis in
        {"behavior_at_revision", "affected_range_and_source", "inspected_only", "unknown"} else "unknown",
        "commit_reason": reason, "location_references": [], "required_review_fields": [],
        "unresolved_fields": [], "omitted": {"item_limit": 0, "budget": 0, "commit_reason_chars": omitted_reason_chars}, "truncated": False,
        "note": "Saved SHA associations only, not proof of affected behavior. Explicitly revise the commit and relevant locations consistently from existing evidence, or retain uncertainty. No automatic parent-SHA selection.",
    }
    receipts = {}
    evidence = review.get("evidence")
    for item in evidence if type(evidence) is list else []:
        item = obj(item)
        identity = eid(item.get("id"))
        if identity:
            receipts.setdefault(identity, []).append(item)

    def receipt(identity):
        matches = receipts.get(identity, [])
        if len(matches) != 1:
            return None, "source_ref_ambiguous_evidence" if matches else "source_ref_unknown_evidence"
        item = matches[0]
        result = obj(item.get("result"))
        if item.get("tool") != "read_file":
            return None, "source_ref_read_required"
        if (item.get("success") is not True or item.get("error") or not result
                or result.get("error") or result.get("success") is False or result.get("ok") is False):
            return None, "source_ref_failed_read"
        if not sha(result.get("commit")) or not path(result.get("path")):
            return None, "source_ref_receipt_metadata_unknown"
        if not span(result.get("start_line"), result.get("end_line")):
            return None, "source_ref_invalid_source_range"
        return result, None

    def location(field, index, value, assessment, suggestion):
        value = obj(value)
        row = {"field": field if index is None else f"{field}[{index}]", "from_suggestion": suggestion,
               "status": status(assessment.get("status")), "evidence_ref": None,
               "receipt_commit": None, "path": None, "start_line": None, "end_line": None,
               "matches_selected_commit": None, "resolution_error": None}
        first, last = value.get("start_line"), value.get("end_line")
        if "evidence_ref" not in value:
            first = last = value.get("line")
            if type(first) is str and re.fullmatch(r"[1-9][0-9]{0,8}-[1-9][0-9]{0,8}", first):
                first, last = map(int, first.split("-"))
        if span(first, last):
            row.update(start_line=first, end_line=last)
        else:
            row["resolution_error"] = "source_ref_invalid_range"
            return row
        resolved = None
        if "evidence_ref" in value:
            identity = eid(value.get("evidence_ref"))
            row["evidence_ref"] = identity
            if identity:
                resolved, row["resolution_error"] = receipt(identity)
            else:
                row["resolution_error"] = "source_ref_invalid_evidence_ref"
        else:
            row["path"] = path(value.get("file"))
            if not row["path"]:
                row["resolution_error"] = "source_ref_invalid_path"
                return row
            refs = assessment.get("evidence_refs")
            matches, ambiguous_id = [], False
            for identity in dict.fromkeys(ref for ref in refs if eid(ref)) if type(refs) is list else []:
                result, error = receipt(identity)
                ambiguous_id |= error == "source_ref_ambiguous_evidence"
                if (result is not None and result["path"] == row["path"]
                        and result["start_line"] <= first <= last <= result["end_line"]):
                    matches.append((identity, result))
            # Do not select the first receipt, nor prefer the selected SHA, when
            # cited same-file reads span multiple revisions.
            if ambiguous_id or len({result["commit"] for _, result in matches}) > 1:
                row["resolution_error"] = "source_ref_ambiguous_revision"
            elif not matches:
                row["resolution_error"] = "source_ref_receipt_unknown"
            else:
                resolved = matches[0][1]
                row["evidence_ref"] = matches[0][0] if len(matches) == 1 else None
        if resolved is not None:
            row.update(receipt_commit=resolved["commit"], path=resolved["path"])
            if packet["selected_commit"] is None:
                row["resolution_error"] = "source_ref_selected_commit_unknown"
            else:
                row["matches_selected_commit"] = resolved["commit"] == packet["selected_commit"]
                if not row["matches_selected_commit"]:
                    row["resolution_error"] = "source_ref_commit_mismatch"
            if not resolved["start_line"] <= first <= last <= resolved["end_line"]:
                row["resolution_error"] = "source_ref_out_of_bounds"
        return row

    required, unresolved = set(), []
    if packet["selected_commit"] is None or packet["commit_status"] != "supported":
        required.add("commit")
        unresolved.append("commit")
    for field in ("entry_point", "critical_operation", "trace"):
        for source, suggestion in ((fields, False), (suggestions, True)):
            value = source.get(field)
            if value is None:
                if not suggestion and field != "trace":
                    required.add(field)
                continue
            assessment = obj(assessments.get(field))
            if suggestion and field == "trace" and type(assessment.get("omitted_assessment")) is dict:
                assessment = assessment["omitted_assessment"]
            values = value if field == "trace" and type(value) is list else [value]
            remaining = 16 - len(packet["location_references"])
            packet["omitted"]["item_limit"] += max(0, len(values) - remaining)
            if len(values) > remaining:
                required.add(field)
            for index, item in enumerate(values[:remaining]):
                row = location(field, index if field == "trace" else None, item, assessment, suggestion)
                packet["location_references"].append(row)
                if row["resolution_error"] or row["status"] != "supported":
                    required.add(field)
                    unresolved.append(row["field"])
                    if row["resolution_error"] == "source_ref_commit_mismatch":
                        required.add("commit")
    packet["required_review_fields"] = [field for field in ("commit", "entry_point", "critical_operation", "trace") if field in required]
    packet["unresolved_fields"] = list(dict.fromkeys(unresolved))
    packet["truncated"] = any(packet["omitted"].values()) or commit_review.get("reason_truncated") is True
    # Spend the caller's smaller review-context budget on facts, not display
    # prose. Keep the longest reason prefix that fits without removing rows;
    # if even an empty reason cannot fit, only then omit complete location rows.
    if len(json.dumps(packet)) > max_chars and packet["commit_reason"]:
        reason = packet["commit_reason"]
        packet["commit_reason"] = ""
        packet["omitted"]["commit_reason_chars"] = omitted_reason_chars + len(reason)
        packet["truncated"] = True
        if len(json.dumps(packet)) <= max_chars:
            low, high = 0, len(reason) - 1
            while low < high:
                middle = (low + high + 1) // 2
                packet["commit_reason"] = reason[:middle]
                packet["omitted"]["commit_reason_chars"] = omitted_reason_chars + len(reason) - middle
                if len(json.dumps(packet)) <= max_chars:
                    low = middle
                else:
                    high = middle - 1
            packet["commit_reason"] = reason[:low]
            packet["omitted"]["commit_reason_chars"] = omitted_reason_chars + len(reason) - low
    # Full SHA/EID identities are never truncated; excess locations are
    # explicitly counted as omitted. The fixed diagnostic header fits 1024.
    while len(json.dumps(packet)) > max_chars and packet["location_references"]:
        packet["location_references"].pop()
        packet["omitted"]["budget"] += 1
        packet["truncated"] = True
    return packet
