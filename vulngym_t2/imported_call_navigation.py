"""Two pure Python-only import-candidate navigation helpers.

Observed imports and qualified uses are lexical hints, not proof of runtime
binding, a call edge, or vulnerability. Gaps may hide rebinding. No guessed
model-prose path, repository access, execution, field update, or budget change
occurs here; the caller owns the single search/source pair and its receipts.
"""
from __future__ import annotations

import ast
from collections.abc import Mapping
import io
from pathlib import PurePosixPath
import re
import textwrap
import tokenize

from .entry_navigation import _selected_location_source, _source
from .source_refs import _positive_line, _relative_path


VERSION = "imported-call-navigation-v1"
_SHA = re.compile(r"[0-9a-f]{40}\Z")
_ID = re.compile(r"E[0-9]{4,8}\Z")
_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,127}\Z")
_MODULE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*\Z")
_ASSIGN = frozenset({"=", ":=", "+=", "-=", "*=", "/=", "//=", "%=", "&=", "|=", "^=", ">>=", "<<=", "**="})


def _tokens(text):
    tokens = []
    try:
        for token in tokenize.generate_tokens(io.StringIO(text).readline):
            tokens.append(token)
    except (tokenize.TokenError, IndentationError, SyntaxError, UnicodeError):
        # Complete earlier logical lines remain observed; incomplete imports
        # never receive a NEWLINE token and cannot supply a binding.
        pass
    return tokens


def _imports(lines):
    """Complete absolute top-level import statements from a visible prefix."""
    found, current, depth = [], [], 0
    for token in _tokens("\n".join(lines) + "\n"):
        if token.type == tokenize.INDENT:
            depth += 1
        elif token.type == tokenize.DEDENT:
            depth -= 1
        elif token.type == tokenize.NEWLINE:
            if depth == 0 and current and current[0].string in {"from", "import"}:
                try:
                    tree = ast.parse(tokenize.untokenize([(item.type, item.string) for item in current]))
                except (SyntaxError, ValueError, UnicodeError):
                    tree = None
                if tree is not None and len(tree.body) == 1:
                    node = tree.body[0]
                    if isinstance(node, ast.Import) or isinstance(node, ast.ImportFrom) and node.level == 0:
                        for item in node.names:
                            module = item.name if isinstance(node, ast.Import) else f"{node.module}.{item.name}"
                            alias = item.asname or (item.name.split(".")[0] if isinstance(node, ast.Import) else item.name)
                            if not _NAME.fullmatch(alias) or not _MODULE.fullmatch(module):
                                continue
                            qualifier = module if isinstance(node, ast.Import) and item.asname is None else alias
                            found.append({"alias": alias, "module": module, "qualifier": qualifier,
                                          "first": current[0].start[0], "last": token.end[0]})
            current = []
        elif token.type not in {tokenize.COMMENT, tokenize.NL, tokenize.ENCODING, tokenize.ENDMARKER}:
            current.append(token)
    return found


def _qualified_uses(lines, first):
    tokens = [item for item in _tokens(textwrap.dedent("\n".join(lines)) + "\n")
              if item.type not in {tokenize.COMMENT, tokenize.NL, tokenize.INDENT, tokenize.DEDENT,
                                   tokenize.ENCODING, tokenize.ENDMARKER}]
    uses = []
    for index, token in enumerate(tokens):
        if token.type != tokenize.NAME or not _NAME.fullmatch(token.string):
            continue
        if index and tokens[index - 1].string == ".":
            continue
        names, end = [token.string], index + 1
        while (end + 1 < len(tokens) and tokens[end].string == "."
               and tokens[end + 1].type == tokenize.NAME
               and tokens[end + 1].start[0] == token.start[0]):
            names.append(tokens[end + 1].string)
            end += 2
        if len(names) < 2 or end >= len(tokens):
            continue
        preceding = [item for item in tokens[:index] if item.start[0] == token.start[0]]
        decorator = len(preceding) == 1 and preceding[0].string == "@"
        if tokens[end].string != "(" and not (decorator and tokens[end].type == tokenize.NEWLINE):
            continue
        uses.append({"qualified_name": ".".join(names), "symbol": names[-1],
                     "qualifier": ".".join(names[:-1]), "alias": names[0],
                     "line": first + token.start[0] - 1,
                     "use_kind": "decorator" if decorator else "direct_call"})
    return uses


def _visible_rebinding(sources, binding):
    """Conservatively reject visible assignments/shadowing; never prove absence."""
    alias = binding["alias"]
    for source in sources:
        text = textwrap.dedent("\n".join(source["lines"])) + "\n"
        try:
            tree = ast.parse(text)
        except (SyntaxError, ValueError, UnicodeError):
            tree = None
        for node in ast.walk(tree) if tree is not None else ():
            if (isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)) and node.id == alias
                    or isinstance(node, ast.arg) and node.arg == alias
                    or isinstance(node, (ast.MatchAs, ast.MatchStar, ast.ExceptHandler)) and node.name == alias
                    or isinstance(node, ast.MatchMapping) and node.rest == alias):
                return True
        rows = {}
        logical_first = None
        for token in _tokens(text):
            if token.type == tokenize.NEWLINE:
                logical_first = None
                continue
            if token.type not in {tokenize.COMMENT, tokenize.STRING, tokenize.INDENT, tokenize.DEDENT,
                                  tokenize.NL, tokenize.NEWLINE, tokenize.ENDMARKER}:
                if logical_first is None:
                    logical_first = source["first"] + token.start[0] - 1
                rows.setdefault(logical_first, []).append(token.string)
        for number, words in rows.items():
            if binding["first"] <= number <= binding["last"]:
                continue
            if "import" in words and "*" in words:
                return True
            if alias not in words:
                continue
            if any(word in words for word in ("import", "def", "class", "del", "lambda", "case")):
                return True
            for index, word in enumerate(words):
                if word != alias:
                    continue
                if index and words[index - 1] == "as":
                    return True
                if "for" in words[:index] and "in" in words[index + 1:]:
                    return True
                tail = index + 1
                while tail + 1 < len(words) and words[tail] == "." and _NAME.fullmatch(words[tail + 1]):
                    tail += 2
                if tail < len(words) and words[tail] in _ASSIGN:
                    return True
                assigned = next((n for n, item in enumerate(words) if item in _ASSIGN), None)
                if assigned is not None and index < assigned and "(" not in words[:assigned]:
                    return True
    return False


def _module_path(path, module):
    if not isinstance(path, str) or len(path) > 500 or not _relative_path(path):
        return False
    relative = module.replace(".", "/")
    return any(path == suffix or path.endswith("/" + suffix)
               for suffix in (relative + ".py", relative + "/__init__.py"))


def _import_context(source, commit, receipts):
    """Join only agreeing actual same-file source; gaps never establish scope."""
    sources, visible = [], {}
    for identity, receipt in receipts.items():
        other = _source(receipt, commit)
        if other is None or other["path"] != source["path"]:
            continue
        sources.append(other)
        for offset, code in enumerate(other["lines"]):
            number = other["first"] + offset
            if number in visible and visible[number][0] != code:
                return None
            visible.setdefault(number, (code, identity))
    if len(visible) > 8000 or sum(len(item[0]) for item in visible.values()) > 262_144:
        return None
    prefix = []
    while len(prefix) + 1 in visible and len(prefix) < 2048:
        prefix.append(visible[len(prefix) + 1][0])
    return sources, visible, prefix, _imports(prefix)


def _import_candidates(uses, sources, bindings):
    """Shared observed-binding/rebinding checks for either navigation entry."""
    candidates = []
    for use in uses:
        matching = [item for item in bindings if item["alias"] == use["alias"]]
        if len(matching) > 1:
            return None
        if not matching:
            continue
        binding = matching[0]
        if binding["last"] >= use["line"] or binding["qualifier"] != use["qualifier"]:
            continue
        if _visible_rebinding(sources, binding):
            return None
        candidates.append((use, binding))
    return candidates


def _import_seed(source, commit, use, binding, visible, first, last):
    provenance = sorted({visible[number][1] for number in range(binding["first"], binding["last"] + 1)}
                        | {visible[number][1] for number in range(first, last + 1)})
    return {"version": VERSION, "semantic_approval": False, "binding_basis": "observed_import_only",
            "shadowing_proof": False, "source_path": source["path"],
            "source_line": use["line"], "qualified_name": use["qualified_name"],
            "module_candidate": binding["module"], "symbol": use["symbol"],
            "evidence_refs": provenance, "arguments": {"commit": commit, "query": "def " + use["symbol"]}}


def _receipt_qualified_uses(source, prefix):
    """Recover complete logical lines only with known module lexical context."""
    if len(prefix) >= source["last"]:
        # An overlapping continuation can start/end inside an expression or
        # string. Tokenize from actual line one, never from that fragment's
        # apparent indentation. _tokens stops at the first tokenizer exception;
        # ERRORTOKEN also ends usable context, even if later tokens were yielded.
        lines, complete = prefix[:source["last"]], 0
        for token in _tokens("\n".join(lines) + "\n"):
            if token.type == tokenize.ERRORTOKEN:
                break
            if token.type == tokenize.NEWLINE:
                complete = token.end[0]
        return [use for use in _qualified_uses(lines[:complete], 1)
                if source["first"] <= use["line"] <= min(source["last"], complete)]
    # Without continuous line-one coverage, retain the earlier strict window
    # rule. A failed token stream cannot establish its missing string context.
    try:
        tokens = list(tokenize.generate_tokens(io.StringIO(textwrap.dedent("\n".join(source["lines"])) + "\n").readline))
    except (tokenize.TokenError, IndentationError, SyntaxError, UnicodeError):
        return []
    if any(token.type == tokenize.ERRORTOKEN for token in tokens):
        return []
    return _qualified_uses(source["lines"], source["first"])


def imported_receipt_context(receipt, evidence):
    """One real receipt supplies a lexical use, never a proposed EP/CO field.

    A unique qualified decorator precedes direct calls. Only if no qualified
    decorator is visible may a unique qualified direct call supply the anchor.
    Missing imports permit one bounded prefix request, not a guessed module.
    The caller owns the shared once-per-input flag and original budgets.
    """
    if (not isinstance(receipt, Mapping) or not isinstance(evidence, list) or len(evidence) > 256
            or any(not isinstance(row, Mapping) or not isinstance(row.get("id"), str)
                   or not _ID.fullmatch(row["id"]) for row in evidence)):
        return None
    receipts = {row["id"]: row for row in evidence}
    if len(receipts) != len(evidence) or receipts.get(receipt.get("id")) != receipt:
        return None
    data = receipt.get("result")
    commit = data.get("commit") if isinstance(data, Mapping) else None
    source = _source(receipt, commit) if isinstance(commit, str) and _SHA.fullmatch(commit) else None
    if source is None or PurePosixPath(source["path"]).suffix != ".py" or len(source["path"]) > 500:
        return None
    context = _import_context(source, commit, receipts)
    if context is None:
        return None
    sources, visible, prefix, bindings = context
    uses = _receipt_qualified_uses(source, prefix)
    decorators = [use for use in uses if use["use_kind"] == "decorator"]
    uses = decorators or uses
    unique = {use["qualified_name"]: use for use in uses}
    if len(unique) != 1:
        return None
    use = next(iter(unique.values()))
    candidates = _import_candidates([use], sources, bindings)
    if candidates is None:
        return None
    packet = {"source_ref": receipt["id"], "source_path": source["path"], "commit": commit,
              "source_line": use["line"], "qualified_name": use["qualified_name"],
              "evidence_refs": [receipt["id"]], "semantic_approval": False, "header": None, "seed": None}
    if candidates:
        packet["seed"] = _import_seed(source, commit, use, candidates[0][1], visible,
                                      source["first"], source["last"])
        return packet
    # An existing binding that failed qualifier/order checks must not be
    # bypassed by reading more prefix and selecting another import.
    if any(binding["alias"] == use["alias"] for binding in bindings):
        return None
    if (use["alias"] in {"self", "cls"}
            or _visible_rebinding(sources, {"alias": use["alias"], "first": 0, "last": 0})):
        return None  # Visible local/parameter objects are not missing module imports.
    start, end = len(prefix) + 1, min(120, source["first"] - 1)
    if start > end:
        return None
    # Fill only the first missing prefix segment. Never overlap known source
    # or retry any failed/partial read that already attempted this interval.
    end = min((number - 1 for number in visible if start < number <= end), default=end)
    for row in evidence:
        arguments = row.get("arguments")
        if (row.get("tool") != "read_file" or not isinstance(arguments, Mapping)
                or arguments.get("commit") != commit or arguments.get("path") != source["path"]):
            continue
        previous_start, previous_end = arguments.get("start_line", 1), arguments.get("end_line", 300)
        if (type(previous_start) is int and type(previous_end) is int
                and previous_start <= end and previous_end >= start):
            return None
    packet["header"] = {"commit": commit, "path": source["path"], "start_line": start, "end_line": end}
    return packet


def imported_call_seed(review):
    """Return one observed-import search candidate from an exact EP/CO span.

    Qualified decorators precede direct calls within a field. CO precedes EP;
    ambiguity at a selected field is not resolved by trying another candidate.
    A prefix beginning at line one establishes top-level import syntax only;
    unread intervals are explicitly NOT treated as shadowing-proof coverage.
    """
    if not isinstance(review, Mapping):
        return None
    fields, suggested, judgments = (review.get(key) or {} for key in
                                   ("draft_fields", "suggested_values", "field_reviews"))
    evidence = review.get("evidence")
    if (not all(isinstance(item, Mapping) for item in (fields, suggested, judgments))
            or not isinstance(evidence, list) or len(evidence) > 256):
        return None
    choices = [item for item in (fields.get("commit"), suggested.get("commit")) if item is not None]
    if any(not isinstance(item, str) or not _SHA.fullmatch(item) for item in choices) or len(set(choices)) != 1:
        return None
    commit = choices[0]
    receipts = {}
    for row in evidence:
        if not isinstance(row, Mapping) or not isinstance(row.get("id"), str):
            continue
        if row["id"] in receipts:
            return None
        if _ID.fullmatch(row["id"]):
            receipts[row["id"]] = row
    for field in ("critical_operation", "entry_point"):
        current, proposal = fields.get(field), suggested.get(field)
        if current is not None and proposal is not None and current != proposal:
            return None
        value = current if current is not None else proposal
        selected = _selected_location_source(value, judgments.get(field), commit, receipts)
        if selected is None:
            continue
        source, first, last = selected
        if PurePosixPath(source["path"]).suffix != ".py":
            continue
        context = _import_context(source, commit, receipts)
        if context is None:
            return None
        sources, visible, _, bindings = context
        # Keep the complete already-visible STRING/comment context, then bind
        # the qualified use to the exact cited range. Tokenizing only the range
        # could mistake a quoted decorator inside a visible docstring for code.
        uses = [use for use in _qualified_uses(source["lines"], source["first"])
                if first <= use["line"] <= last]
        # An explicit, import-backed decorator is the first investigation tier.
        # Unrelated direct calls inside its handler must not suppress that tier.
        decorators = [use for use in uses if use["use_kind"] == "decorator"
                      and any(binding["alias"] == use["alias"] for binding in bindings)]
        uses = decorators or uses
        candidates = _import_candidates(uses, sources, bindings)
        if candidates is None:
            return None
        decorators = [item for item in candidates if item[0]["use_kind"] == "decorator"]
        candidates = decorators or candidates
        unique = {(item[0]["qualified_name"], item[1]["module"]): item for item in candidates}
        if not unique:
            continue
        if len(unique) != 1:
            return None
        use, binding = next(iter(unique.values()))
        return {**_import_seed(source, commit, use, binding, visible, first, last), "field": field}
    return None


def imported_definition_read(search_receipt, seed, receipts):
    """One real, complete, same-SHA definition hit may supply a source window."""
    if (not isinstance(seed, Mapping) or seed.get("version") != VERSION
            or seed.get("binding_basis") != "observed_import_only" or seed.get("semantic_approval") is not False
            or not isinstance(seed.get("symbol"), str) or not _NAME.fullmatch(seed["symbol"])
            or not isinstance(seed.get("module_candidate"), str) or not _MODULE.fullmatch(seed["module_candidate"])
            or not isinstance(seed.get("arguments"), Mapping) or not isinstance(receipts, list) or len(receipts) > 256):
        return None
    arguments = seed["arguments"]
    commit = arguments.get("commit")
    if (not isinstance(commit, str) or not _SHA.fullmatch(commit)
            or set(arguments) != {"commit", "query"}
            or arguments.get("query") != "def " + seed["symbol"]):
        return None
    data = search_receipt.get("result") if isinstance(search_receipt, Mapping) else None
    if (not isinstance(data, Mapping) or search_receipt.get("tool") != "search_code"
            or search_receipt.get("success") is not True or search_receipt.get("error")
            or data.get("error") or data.get("success") is False or data.get("ok") is False
            or data.get("commit") != commit or data.get("query") != arguments["query"]
            or data.get("complete") is not True or data.get("truncated") is not False
            or data.get("paths") not in (None, [])
            or type(data.get("skipped_count", 0)) is not int or data.get("skipped_count", 0) != 0
            or not isinstance(data.get("matches"), list) or len(data["matches"]) > 100):
        return None
    definition = re.compile(r"^(?:async\s+)?def\s+" + re.escape(seed["symbol"]) + r"\s*\(")
    matches = set()
    for hit in data["matches"]:
        if (not isinstance(hit, Mapping) or not _relative_path(hit.get("file"))
                or not _positive_line(hit.get("line")) or not isinstance(hit.get("code"), str)):
            return None
        if (_module_path(hit["file"], seed["module_candidate"])
                and hit["line"] <= 99_999_904 and definition.match(hit["code"])):
            matches.add((hit["file"], hit["line"]))
    if len(matches) != 1:
        return None
    path, line = next(iter(matches))
    for receipt in receipts:
        source = _source(receipt, commit)
        if source and source["path"] == path and source["first"] <= line <= source["last"]:
            return None
    return {"arguments": {"commit": commit, "path": path, "start_line": max(1, line - 8),
                           "end_line": line + 96}, "anchor_line": line}
