"""Lossless prompt-only tables for repeated navigation receipt structure.

This layer accepts an already displayed receipt. It does not clip source,
matches, strings, limits or provenance. A ``columns``/``rows`` table represents
the original ordered list of objects. ``consecutive_file_groups`` factor out
only adjacent identical ``file`` values; each group's rows inherit that file.
They remain search hits, not read-file evidence or approved relationships.

Stored receipts and their validators continue to use the original objects.
Unknown item schemas, errors and representations that would grow stay intact.
The inverse is provided for deterministic QA, not for fetching hidden evidence.
"""
from __future__ import annotations

import copy
import json


_SCHEMAS = {
    "search_code": ("matches", ("file", "line", "code")),
    "search_history": ("matches", ("commit", "parents", "subject", "subject_truncated")),
    "list_refs": ("refs", ("name", "kind", "object_type", "object_id", "commit")),
}


def _size(value):
    return len(json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")))


def _known_rows(rows, columns):
    return (isinstance(rows, list) and bool(rows)
            and all(isinstance(row, dict) and set(row) == set(columns) for row in rows))


def _table(rows, columns):
    return {"columns": list(columns), "rows": [[row[key] for key in columns] for row in rows]}


def _grouped_matches(rows):
    groups = []
    for row in rows:
        # Do not sort: an A/B/A sequence must remain three consecutive groups.
        if not groups or groups[-1]["file"] != row["file"]:
            groups.append({"file": row["file"], "matches": []})
        groups[-1]["matches"].append({key: row[key] for key in ("line", "code")})
    for group in groups:
        table = _table(group["matches"], ("line", "code"))
        if _size(table) < _size(group["matches"]):
            group["matches"] = table
    return {"consecutive_file_groups": groups}


def _eligible(record):
    if (not isinstance(record, dict) or not isinstance(record.get("tool"), str)
            or record["tool"] not in _SCHEMAS):
        return None
    data = record.get("result")
    if (record.get("success") is not True or record.get("error")
            or not isinstance(data, dict) or data.get("error") or data.get("error_code")
            or data.get("ok") is False or data.get("success") is False):
        return None
    return _SCHEMAS[record["tool"]]


def compact_record(record):
    """Return a strictly smaller equivalent receipt, or an unchanged deep copy.

    Only the named navigation list is transformed. All outer/result fields,
    including future metadata, remain byte-equivalent JSON values. Unknown
    list-item keys cause the entire list to retain its original representation.
    Source/diff/advisory/commit-inspection receipts never enter this transform.
    """
    shown = copy.deepcopy(record)
    schema = _eligible(shown)
    if schema is None:
        return shown
    key, columns = schema
    rows = shown["result"].get(key)
    if not _known_rows(rows, columns):
        return shown
    candidates = [rows, _table(rows, columns)]
    if shown["tool"] == "search_code" and all(isinstance(row["file"], str) for row in rows):
        candidates.append(_grouped_matches(rows))
    # Ties deliberately preserve the older, simpler list representation.
    shown["result"][key] = min(candidates, key=_size)
    return shown


def _expand_table(value, columns):
    if (not isinstance(value, dict) or set(value) != {"columns", "rows"}
            or value["columns"] != list(columns) or not isinstance(value["rows"], list)
            or not value["rows"]
            or not all(isinstance(row, list) and len(row) == len(columns) for row in value["rows"])):
        return None
    return [dict(zip(columns, row)) for row in value["rows"]]


def _expand_groups(value):
    if (not isinstance(value, dict) or set(value) != {"consecutive_file_groups"}
            or not isinstance(value["consecutive_file_groups"], list)
            or not value["consecutive_file_groups"]):
        return None
    result = []
    for group in value["consecutive_file_groups"]:
        if (not isinstance(group, dict) or set(group) != {"file", "matches"}
                or not isinstance(group["file"], str)):
            return None
        rows = group["matches"]
        if not _known_rows(rows, ("line", "code")):
            rows = _expand_table(rows, ("line", "code"))
        if rows is None:
            return None
        result.extend({"file": group["file"], **row} for row in rows)
    return result


def expand_record(record):
    """Invert this module's tables exactly; unknown shapes are not repaired."""
    shown = copy.deepcopy(record)
    schema = _eligible(shown)
    if schema is None:
        return shown
    key, columns = schema
    value = shown["result"].get(key)
    rows = _expand_table(value, columns)
    if rows is None and shown["tool"] == "search_code":
        rows = _expand_groups(value)
    if rows is not None:
        shown["result"][key] = rows
    return shown
