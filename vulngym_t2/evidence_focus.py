"""Small, verbatim bookmarks into saved source, never an inferred call graph.

The full evidence remains in the prompt. These excerpts put actual read rows
next to the final decision, including the visible prefix of truncated reads.
Search strings only select bookmarks; they do not prove a relationship.
"""
from __future__ import annotations

import json
import re
from collections.abc import Mapping

from .entry_navigation import _declaration, _source


_SHA = re.compile(r"[0-9a-f]{40}\Z")
_METHOD = re.compile(r"^\s*(?:async\s+)?[A-Za-z_$][\w$]*\s*\([^;]*\)\s*(?::[^=]+)?\s*\{")
_NOTE = (
    "Verbatim bookmarks from existing read_file receipts, not new evidence or approved conclusions. "
    "All other saved rows remain available. A truncated read still contains its displayed prefix; "
    "only rows beyond visible_end are unread. Compare these rows with any claim that a handler or "
    "registration was not read. Matching names are navigation clues, not proven call edges. "
    "Candidate scope and earlier judgments are proposals; correct them when the source disagrees."
)


def _size(value):
    return len(json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")))


def source_bookmarks(evidence, *, max_chars=6000):
    """Return a bounded view; do not mutate receipts or assign field status.

    Latest reads are preferred because they commonly resolve earlier gaps.
    Each excerpt includes real surrounding rows, not only a search-hit line.
    Unsupported syntax simply receives a prefix bookmark, not a guessed symbol.
    """
    packet = {"note": _NOTE, "bookmarks": [], "omitted_excerpts": 0}
    if max_chars < _size(packet):
        return {}
    queries = {}
    for record in evidence:
        if not isinstance(record, Mapping) or not isinstance(record.get("result"), Mapping):
            continue
        data = record.get("result", {})
        if record.get("tool") != "search_code" or record.get("success") is not True or record.get("error") or data.get("error"):
            continue
        sha, query = data.get("commit"), data.get("query")
        if isinstance(sha, str) and _SHA.fullmatch(sha) and isinstance(query, str) and 2 <= len(query) <= 128:
            queries.setdefault(sha, set()).add(query)

    seen = set()
    for record in reversed(evidence):
        if (not isinstance(record, Mapping) or not isinstance(record.get("result"), Mapping)
                or not isinstance(record.get("id"), str) or not re.fullmatch(r"E[0-9]{4,8}", record["id"])):
            continue
        sha = record.get("result", {}).get("commit")
        if not isinstance(sha, str) or not _SHA.fullmatch(sha):
            continue
        source = _source(record, sha)
        if source is None:
            continue
        rows = source["lines"]
        # Literal, already supplied queries only; never derive executable code.
        hits = [index for index, line in enumerate(rows) if any(query in line for query in queries.get(sha, ()))]
        declarations = [index for index, line in enumerate(rows)
                        if _declaration(line) or _METHOD.match(line) or line.lstrip().startswith("@")]
        anchors = hits or declarations or [0]
        windows = []
        for index in anchors:
            start, end = max(0, index - 8), min(len(rows) - 1, index + 10)
            if windows and start <= windows[-1][1] + 1 and end - windows[-1][0] < 40:
                windows[-1] = (windows[-1][0], end)
            else:
                windows.append((start, end))
        # Two windows per receipt prevent one large file from hiding other reads.
        packet["omitted_excerpts"] += max(0, len(windows) - 2)
        for start, end in windows[:2]:
            first, last = source["first"] + start, source["first"] + end
            key = (sha, source["path"], first, last)
            if key in seen:
                continue
            seen.add(key)
            excerpt = {"evidence_ref": record["id"], "commit": sha, "path": source["path"],
                       "visible_start": source["first"], "visible_end": source["last"],
                       "start_line": first, "end_line": last,
                       "numbered_source": "\n".join(f"{source['first'] + index}: {rows[index]}" for index in range(start, end + 1))}
            packet["bookmarks"].append(excerpt)
            if _size(packet) > max_chars - 16:
                packet["bookmarks"].pop()
                packet["omitted_excerpts"] += 1
    return packet
