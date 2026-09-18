"""Suggest a small continuation for a visibly called, boundary-cut Python body.

This is lexical reading guidance, not a call-edge or field approval. Only saved,
cited source participates; the session still owns all tool and context budgets.
"""
from __future__ import annotations

import ast
from collections.abc import Mapping
from io import StringIO
from pathlib import PurePosixPath
import re
import tokenize

from .entry_navigation import _source


_SHA = re.compile(r"[0-9a-f]{40}\Z")
_REF = re.compile(r"E[0-9]{4,8}\Z")
_DEF = re.compile(r"^(?P<indent>[ \t]*)(?:async\s+)?def\s+(?P<name>[A-Za-z_]\w*)\s*\(.*:\s*(?:#.*)?$")
_IGNORED = {tokenize.ENCODING, tokenize.INDENT, tokenize.DEDENT, tokenize.NEWLINE,
            tokenize.NL, tokenize.COMMENT, tokenize.ENDMARKER, tokenize.STRING}
_VIEW_LINES = 256
_CONTINUATION_LINES = 40


def _open_called_body(lines):
    """Find one unclosed declaration with an earlier actual call-like token.

    Tokenization excludes comments and strings. An incomplete statement at the
    visible boundary is expected, but uncertain strings/indentation are not.
    This deliberately recognizes only single-line Python function headers.
    """
    # tokenize columns are raw character offsets, not expanded tab stops.
    # Leave tab-indented fragments to normal reading rather than compare two
    # incompatible column systems or guess whether a sibling scope has ended.
    if any("\t" in line[:len(line) - len(line.lstrip(" \t"))] for line in lines):
        return None
    tokens = []
    try:
        tokens.extend(tokenize.generate_tokens(StringIO("\n".join(lines)).readline))
    except tokenize.TokenError as error:
        if error.args[0] not in ("EOF in multi-line statement", "unexpected EOF in multi-line statement"):
            return None
    except (IndentationError, SyntaxError):
        return None
    if any(token.type == tokenize.ERRORTOKEN and token.string.strip() for token in tokens):
        return None
    declarations, calls, significant = [], [], {}
    for index, token in enumerate(tokens):
        if token.type not in _IGNORED:
            significant[token.start[0]] = min(significant.get(token.start[0], token.start[1]), token.start[1])
        if token.type != tokenize.NAME:
            continue
        if token.string == "def" and index + 1 < len(tokens):
            match = _DEF.match(lines[token.start[0] - 1])
            following = tokens[index + 1]
            if match and following.type == tokenize.NAME and following.string == match["name"]:
                try:
                    # Parse only the observed header with an inert placeholder;
                    # annotations and default values are never evaluated.
                    ast.parse(lines[token.start[0] - 1].lstrip(" \t") + "\n    pass")
                except SyntaxError:
                    continue
                declarations.append((match["name"], token.start[0], len(match["indent"].expandtabs(4))))
        elif index + 1 < len(tokens):
            following = tokens[index + 1]
            previous = tokens[index - 1].string if index else None
            if (following.string == "(" and following.start[0] == token.start[0]
                    and previous not in ("def", "class", ".")):
                calls.append((token.string, token.start[0]))
    candidates = []
    for name, line, indent in declarations:
        if (sum(other == name for other, _, _ in declarations) != 1
                or not any(symbol == name and before < line for symbol, before in calls)):
            continue
        following = [column for number, column in significant.items() if number > line]
        if following and all(column > indent for column in following):
            candidates.append((name, line))
    return candidates[0] if len(candidates) == 1 else None


def called_body_continuations(review, *, limit=2):
    """Return at most two adjacent, <=40-line reads; never jump an unseen gap.

    Required-field citations alone provide the call and function declaration.
    Same-path/SHA windows may form a temporary continuous view, with conflicting
    overlaps rejected. Other saved receipts only prevent duplicate reads; they
    do not silently supply an uncited call or select a different revision.
    """
    if not isinstance(review, Mapping) or type(limit) is not int or limit < 1:
        return []
    evidence, judgments = review.get("evidence"), review.get("field_reviews")
    if not isinstance(evidence, list) or len(evidence) > 256 or not isinstance(judgments, Mapping):
        return []
    choices = []
    for name in ("draft_fields", "suggested_values"):
        fields = review.get(name) or {}
        if not isinstance(fields, Mapping):
            return []
        if fields.get("commit") is not None:
            choices.append(fields["commit"])
    if any(not isinstance(sha, str) or not _SHA.fullmatch(sha) for sha in choices) or len(set(choices)) > 1:
        return []
    selected = choices[0] if choices else None
    receipts = {}
    for receipt in evidence:
        if not isinstance(receipt, Mapping) or not isinstance(receipt.get("id"), str):
            continue
        identity = receipt["id"]
        if identity in receipts:
            return []
        receipts[identity] = receipt
    groups = {}
    for field in ("critical_operation", "commit", "entry_point"):
        judgment = judgments.get(field)
        refs = judgment.get("evidence_refs") if isinstance(judgment, Mapping) else None
        for identity in refs[:24] if isinstance(refs, list) else []:
            if not isinstance(identity, str) or not _REF.fullmatch(identity):
                continue
            receipt = receipts.get(identity)
            data = receipt.get("result") if isinstance(receipt, Mapping) else None
            sha = data.get("commit") if isinstance(data, Mapping) else None
            if not isinstance(sha, str) or not _SHA.fullmatch(sha) or (selected is not None and selected != sha):
                continue
            source = _source(receipt, sha)
            if source is None or len(source["path"]) > 500 or PurePosixPath(source["path"]).suffix != ".py":
                continue
            group = groups.setdefault((sha, source["path"]), {})
            group.setdefault(identity, (field, source, data))
    requests = []
    for (sha, path), group in groups.items():
        for identity, (field, tail, data) in group.items():
            total, last = data.get("total_lines"), tail["last"]
            if (data.get("has_more") is not True or data.get("end_line") != last
                    or type(total) is not int or not last < total <= 100_000_000):
                continue
            if any(other and other["path"] == path and other["first"] <= last + 1 <= other["last"]
                   for other in (_source(row, sha) for row in evidence)):
                continue
            rows, conflict = {}, False
            for ref, (_, source, _) in group.items():
                for line in range(max(1, last - _VIEW_LINES + 1, source["first"]), min(last, source["last"]) + 1):
                    code = source["lines"][line - source["first"]]
                    if line in rows and rows[line][0] != code:
                        conflict = True
                    rows.setdefault(line, (code, ref))
            if conflict or last not in rows:
                continue
            first = last
            while first - 1 in rows:
                first -= 1
            body = _open_called_body([rows[line][0] for line in range(first, last + 1)])
            if body is None:
                continue
            symbol, declaration = body
            refs = list(dict.fromkeys(rows[line][1] for line in range(first, last + 1)))
            requests.append({"field": field, "evidence_ref": identity, "evidence_refs": refs,
                             "symbol": symbol, "boundary_line": first + declaration - 1,
                             "arguments": {"commit": sha, "path": path, "start_line": last + 1,
                                           "end_line": min(total, last + _CONTINUATION_LINES)}})
            if len(requests) >= min(limit, 2):
                return requests
    return requests
