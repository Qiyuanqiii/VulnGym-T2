"""Lossless compact display of source receipts, with explicit read limits.

Stored receipts keep normal line objects for location validation. Compact
prompts show long reads as numbered source text, not summaries.
Bounded navigation retains a visible interval, never hidden citable lines.
"""
import copy
import json


def _size(value):
    return len(json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")))


def _source_rows(data):
    rows = data.get("lines")
    first, last = data.get("start_line"), data.get("end_line")
    return (isinstance(rows, list) and bool(rows) and type(first) is int and first > 0
            and type(last) is int and last == first + len(rows) - 1
            and all(isinstance(row, dict) and type(row.get("line")) is int and row["line"] == first + index
                    and isinstance(row.get("code"), str) and "\n" not in row["code"] and "\r" not in row["code"]
                    for index, row in enumerate(rows)))


def display_record(record, *, compact=False):
    shown = copy.deepcopy(record)
    data = shown.get("result")
    if isinstance(data, dict) and isinstance(data.get("lines"), list):
        data.pop("text", None)
        if compact and len(data["lines"]) >= 16 and _source_rows(data):
            data["numbered_source"] = "\n".join(f"{row['line']}: {row['code']}" for row in data.pop("lines"))
            data["source_encoding"] = "numbered_source: <line_number>: <exact_source_line>"
    if compact and shown.get("success") is True and isinstance(data, dict) and isinstance(shown.get("arguments"), dict):
        # Successful results already carry these exact request coordinates.
        # Keep differing/request-only arguments (e.g. a truncated end_line),
        # and keep failed requests in full. The stored receipt is unchanged.
        arguments = {key: value for key, value in shown["arguments"].items() if key not in data or data[key] != value}
        if arguments:
            shown["arguments"] = arguments
        else:
            shown.pop("arguments")
    return shown


def _declaration_first_matches(result):
    """Prioritize actual same-name declaration hits, never assert uniqueness."""
    from .entry_navigation import _declaration
    from .revision_navigation import _PROBE_QUERY
    from .source_refs import _relative_path

    query, matches = result.get("query"), result["matches"]
    parsed = _PROBE_QUERY.fullmatch(query) if isinstance(query, str) else None
    if parsed is None or len(matches) > 100:
        return matches
    def declaration(hit):
        if not isinstance(hit, dict):
            return False
        code, line = hit.get("code"), hit.get("line")
        return (isinstance(code, str) and not any(char in code for char in "\x00\r\n")
                and _relative_path(hit.get("file")) and type(line) is int and 1 <= line <= 100_000_000
                and query in code and _declaration(code) == parsed["name"])
    # Stable within each group, with byte-for-byte original hit objects. This
    # only changes which real hits survive display clipping, not search scope.
    return sorted(matches, key=lambda hit: not declaration(hit))


def bounded_navigation_result(value, max_chars, *, anchor_line=None):
    """Bound the displayed result; retain exactly the same source in storage.

    The ordinary reader already bounds transport. This additional display cap
    is per navigation read. Truncated searches are explicitly incomplete, and
    a truncated source read's coordinates refer only to its retained interval.
    A supplied search-hit anchor stays visible; trim distant context first.
    """
    result = copy.deepcopy(value)
    anchored = anchor_line is not None
    if anchored and (not _source_rows(result) or type(anchor_line) is not int
                     or not result["start_line"] <= anchor_line <= result["end_line"]):
        return {"error": "Navigation anchor is not in the returned source.",
                "error_code": "navigation_anchor_unavailable"}
    def size():
        return _size(display_record({"result": result}, compact=True)["result"])
    if size() <= max_chars:
        return result
    if _source_rows(result):
        result.update(truncated=True, context_truncated=True)
        while result["lines"] and size() > max_chars:
            if anchored and len(result["lines"]) == 1:
                break  # Never return success without the requested hit.
            if anchored and anchor_line - result["start_line"] > result["end_line"] - anchor_line:
                result["lines"].pop(0)
                result["start_line"] = result["lines"][0]["line"]
            else:
                result["lines"].pop()
                result["end_line"] = result["lines"][-1]["line"] if result["lines"] else None
                result["has_more"] = True
        result["text"] = "\n".join(row["code"] for row in result["lines"])
        if result["lines"] and size() <= max_chars:
            return result
    elif isinstance(result.get("matches"), list):
        result.update(truncated=True, context_truncated=True, complete=False)
        if "has_more" in result:
            result["has_more"] = True
        if "negative_result_conclusive" in result:
            result["negative_result_conclusive"] = False
        result["matches"] = _declaration_first_matches(result)
        while result["matches"] and size() > max_chars:
            result["matches"].pop()
        if size() <= max_chars:
            return result
    return {"error": "Navigation result cannot fit its display allowance.", "error_code": "navigation_display_limit"}
