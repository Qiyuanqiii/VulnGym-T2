"""Resolve one location from source lines already shown to the model.

No repository access, text fallback, source execution, or semantic assessment is
performed. The caller still owns field review and final location validation.
"""
from __future__ import annotations

from collections.abc import Mapping
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
