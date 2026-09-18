"""Bounded caller/registration navigation from already-read source.

This is a lexical navigation aid, NOT a call-graph or entry-point classifier.
Search hits select windows to read; only the annotation stage may judge their
meaning. It never changes a field, picks a revision, executes source, or calls
an LLM. The session owns the existing tool/context budgets.
"""
from __future__ import annotations

from collections.abc import Mapping
from pathlib import PurePosixPath
import re

from .source_refs import _citation_window, _positive_line, _relative_path


VERSION = "entry-navigation-v20"
MAX_HOPS = 4
_SHA = re.compile(r"[0-9a-f]{40}\Z")
_NAME = r"[A-Za-z_$][A-Za-z0-9_$]{1,127}"
# Deliberately small syntax recognizer. Unrecognized syntax remains a manual
# model read, rather than a fabricated symbol or a claim that no caller exists.
_DECLARATION = re.compile(
    r"^\s*(?:(?:export|default|declare|async|public|private|static|abstract)\s+)*"
    r"(?:function\s*\*?\s+|def\s+|class\s+|func\s+)(?P<name>" + _NAME + r")\b")
_ARROW = re.compile(
    r"^\s*(?:export\s+)?(?:const|let|var)\s+(?P<name>" + _NAME + r")\s*="
    r"\s*(?:async\s+)?(?:\([^\n]*\)|" + _NAME + r")\s*=>")
_GENERIC = frozenset({"run", "main", "get", "set", "init", "constructor", "__init__"})
_PY_DECORATOR = re.compile(r"\s*@[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*(?:\([^\n]*\))?\s*(?:#.*)?\Z")
_COMPONENT_EXTENSIONS = frozenset({".svelte", ".vue"})
_EXTENSIONS = frozenset({".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".go"}) | _COMPONENT_EXTENSIONS
_COMPONENT_BOUNDARY = re.compile(r"</?(?:script|style)\b", re.IGNORECASE)
_STOPS = frozenset({"no_source_seed", "budget_reserved", "read_failed", "no_usable_reference_hit",
                    "enclosing_symbol_not_visible", "symbol_cycle", "hop_limit"})


def public_navigation_report(value):
    """Export finite navigation diagnostics, never raw source or arbitrary prose."""
    if not isinstance(value, Mapping) or value.get("version") not in ("entry-navigation-v1", "entry-navigation-v2", "entry-navigation-v3", "entry-navigation-v4", "entry-navigation-v5", "entry-navigation-v6", "entry-navigation-v7", "entry-navigation-v8", "entry-navigation-v9", "entry-navigation-v10", "entry-navigation-v11", "entry-navigation-v12", "entry-navigation-v13", "entry-navigation-v14", "entry-navigation-v15", "entry-navigation-v16", "entry-navigation-v17", "entry-navigation-v18", "entry-navigation-v19", VERSION):
        return {}
    packet = {"version": value["version"], "semantic_approval": False, "steps": []}
    if isinstance(value.get("stop_reason"), str) and value["stop_reason"] in _STOPS:
        packet["stop_reason"] = value["stop_reason"]

    def source_fields(row):
        if not isinstance(row, Mapping):
            return {}
        clean = {}
        for key in ("commit", "evidence_ref", "selected_evidence_ref", "symbol", "query"):
            item = row.get(key)
            pattern = r"[0-9a-f]{40}" if key == "commit" else r"E[0-9]{4,8}" if key.endswith("evidence_ref") else _NAME
            if isinstance(item, str) and re.fullmatch(pattern, item):
                clean[key] = item
        if isinstance(row.get("path"), str) and len(row["path"]) <= 500 and _relative_path(row["path"]):
            clean["path"] = row["path"]
        for key in ("line", "start_line", "end_line"):
            if type(row.get(key)) is int and 1 <= row[key] <= 100_000_000:
                clean[key] = row[key]
        return clean

    seed = source_fields(value.get("seed"))
    if seed:
        raw = value["seed"]
        if raw.get("field") in ("entry_point", "critical_operation"):
            seed["field"] = raw["field"]
        packet["seed"] = seed
    steps = value.get("steps")
    for row in steps[:8] if isinstance(steps, list) else []:
        if not isinstance(row, Mapping) or row.get("tool") not in ("read_file", "search_code"):
            continue
        clean = {"tool": row["tool"], "arguments": source_fields(row.get("arguments"))}
        clean.update({key: item for key, item in source_fields(row).items() if key == "evidence_ref"})
        if type(row.get("success")) is bool:
            clean["success"] = row["success"]
        packet["steps"].append(clean)
    budget = value.get("budget")
    if isinstance(budget, Mapping):
        packet["budget"] = {key: budget[key] for key in ("context_chars", "context_limit", "remaining_tool_calls")
                            if type(budget.get(key)) is int and 0 <= budget[key] <= 1_000_000}
        if budget.get("reason") in ("provider_stopped", "tool_budget", "context_budget", "available"):
            packet["budget"]["reason"] = budget["reason"]
    return packet


def _declaration(code):
    match = _DECLARATION.match(code) or _ARROW.match(code)
    return match["name"] if match else None


def _source(receipt, commit):
    """Visible, continuous same-SHA text only; no requested/unseen lines."""
    if not isinstance(receipt, Mapping) or receipt.get("tool") != "read_file" or receipt.get("success") is not True:
        return None
    data = receipt.get("result")
    if (receipt.get("error") or not isinstance(data, Mapping) or data.get("commit") != commit
            or data.get("error") or data.get("ok") is False or data.get("success") is False
            or not _relative_path(data.get("path"))):
        return None
    first, last, problem = _citation_window(data)
    if problem:
        return None
    lines = ([row["code"] for row in data["lines"]] if "lines" in data
             else data["text"].split("\n")[:last - first + 1])
    return {"path": data["path"], "first": first, "last": last, "lines": lines}


def source_window_continuations(review, *, limit=2):
    """At most two adjacent windows for cited, visibly boundary-cut helpers.

    Only required-field evidence participates. A declaration near a read's end
    must also have a literal call-like reference earlier in that same window;
    unrelated sibling declarations and uncited test reads are not seeds. This
    is lexical navigation, not proof of a call edge or a missing mechanism.
    The session owns all tool/context budgets and never applies field changes.
    """
    if not isinstance(review, Mapping) or type(limit) is not int or limit < 1:
        return []
    evidence, judgments = review.get("evidence"), review.get("field_reviews")
    if (not isinstance(evidence, list) or len(evidence) > 256
            or not isinstance(judgments, Mapping)):
        return []
    choices = []
    for name in ("draft_fields", "suggested_values"):
        fields = review.get(name) or {}
        if not isinstance(fields, Mapping):
            return []
        if fields.get("commit") is not None:
            choices.append(fields["commit"])
    if (any(not isinstance(sha, str) or not _SHA.fullmatch(sha) for sha in choices)
            or len(set(choices)) > 1):
        return []
    selected = choices[0] if choices else None
    receipts = {}
    for receipt in evidence:
        if not isinstance(receipt, Mapping) or not isinstance(receipt.get("id"), str):
            continue
        identity = receipt["id"]
        if identity in receipts:
            return []
        if re.fullmatch(r"E[0-9]{4,8}", identity):
            receipts[identity] = receipt
    requests, seen = [], set()
    for field in ("critical_operation", "commit", "entry_point"):
        judgment = judgments.get(field)
        refs = judgment.get("evidence_refs") if isinstance(judgment, Mapping) else None
        if not isinstance(refs, list):
            continue
        for identity in refs[:24]:
            if not isinstance(identity, str) or identity in seen:
                continue
            seen.add(identity)
            receipt = receipts.get(identity)
            data = receipt.get("result") if isinstance(receipt, Mapping) else None
            if not isinstance(data, Mapping):
                continue
            sha = data.get("commit")
            if (not isinstance(sha, str) or not _SHA.fullmatch(sha)
                    or (selected is not None and selected != sha)
                    or data.get("has_more") is not True):
                continue
            source = _source(receipt, sha)
            total = data.get("total_lines")
            if (source is None or len(source["path"]) > 500
                    or PurePosixPath(source["path"]).suffix not in _EXTENSIONS
                    or source["last"] != data.get("end_line")
                    or type(total) is not int or not source["last"] < total <= 100_000_000):
                continue
            first = source["last"] + 1
            # Existing same-SHA receipts, not requested ranges, establish coverage.
            if any(other and other["path"] == source["path"]
                   and other["first"] <= first <= other["last"]
                   for other in (_source(item, sha) for item in evidence)):
                continue
            boundary = None
            for index in range(len(source["lines"]) - 1, max(-1, len(source["lines"]) - 14), -1):
                code = source["lines"][index]
                symbol = _declaration(code)
                if symbol is None:
                    continue
                call = re.compile(r"(?<![A-Za-z0-9_$])" + re.escape(symbol) + r"\s*\(")
                if not any(call.search(line) and _declaration(line) != symbol
                           for line in source["lines"][:index]):
                    continue
                indent = len(code[:len(code) - len(code.lstrip())].expandtabs(4))
                following = source["lines"][index + 1:]
                if PurePosixPath(source["path"]).suffix == ".py":
                    closed = any(line.strip() and not line.lstrip().startswith("#")
                                 and len(line[:len(line) - len(line.lstrip())].expandtabs(4)) <= indent
                                 for line in following)
                else:
                    closed = any(re.fullmatch(r"\s*}[;,)\]]*\s*(?://.*)?", line)
                                 and len(line[:len(line) - len(line.lstrip())].expandtabs(4)) <= indent
                                 for line in following)
                if not closed:
                    boundary = source["first"] + index
                    break
            if boundary is None:
                continue
            requests.append({"field": field, "evidence_ref": identity,
                "boundary_line": boundary, "arguments": {"commit": sha, "path": source["path"],
                    "start_line": first, "end_line": min(total, first + 79)}})
            if len(requests) >= min(limit, 2):
                return requests
    return requests


def _symbol_at(source, line, *, leading_blanks=False, selected_end=None):
    if (PurePosixPath(source["path"]).suffix not in _EXTENSIONS
            or not source["first"] <= line <= source["last"]):
        return None
    if leading_blanks:
        # A selected span can begin with whitespace just before its declaration.
        # Look only inside that selected, visible span and skip at most 8 blank
        # lines. Do not cross executable statements, comments or unseen source.
        upper = min(source["last"], selected_end if selected_end is not None else line, line + 8)
        while line < upper and not source["lines"][line - source["first"]].strip():
            line += 1
    def indentation(code):
        return len(code[:len(code) - len(code.lstrip())].expandtabs(4))

    # Route locations often start at a Python decorator, just before the named
    # handler. Only consume complete single-line decorators inside the selected
    # visible span; never scan forward across statements or an unseen boundary.
    if (leading_blanks and PurePosixPath(source["path"]).suffix == ".py"
            and source["lines"][line - source["first"]].lstrip().startswith("@")):
        level = indentation(source["lines"][line - source["first"]])
        upper = min(source["last"], selected_end if selected_end is not None else line, line + 8)
        while line < upper and _PY_DECORATOR.fullmatch(source["lines"][line - source["first"]]):
            if indentation(source["lines"][line - source["first"]]) != level:
                return None
            line += 1
        declaration = source["lines"][line - source["first"]]
        if indentation(declaration) != level or _declaration(declaration) is None:
            return None

    selected_indent = indentation(source["lines"][line - source["first"]])
    # Methods use the enclosing named class as a navigation key: querying a
    # ubiquitous method name such as run() globally is not useful or bounded.
    for number in range(line, max(source["first"], line - 80) - 1, -1):
        code = source["lines"][number - source["first"]]
        # Component script fragments contain the same JS/TS declarations. The
        # opening tag may be outside a bounded receipt, so do not require it.
        # A visible script/style boundary, however, must never be crossed to
        # attach markup or a separate block to a preceding callback. This is
        # still only a lexical search seed, not proof of execution or mounting.
        if (PurePosixPath(source["path"]).suffix in _COMPONENT_EXTENSIONS
                and _COMPONENT_BOUNDARY.search(code)):
            return None
        name = _declaration(code)
        if not name or name in _GENERIC:
            continue
        level = indentation(code)
        if number != line and level >= selected_indent:
            continue
        between = source["lines"][number - source["first"] + 1:line - source["first"]]
        if PurePosixPath(source["path"]).suffix == ".py":
            closed = any(text.strip() and not text.lstrip().startswith("#") and indentation(text) <= level
                         for text in between)
        else:
            closed = any(re.fullmatch(r"\s*}[;,)\]]*\s*(?://.*)?", text) and indentation(text) <= level
                         for text in between)
        if not closed:
            return {"symbol": name, "path": source["path"], "line": number}
    return None


def entry_navigation_seed(review, *, include_supported=False, prefer_operation=False):
    """Find a source-backed symbol for an unresolved EP, falling back to CO.

    A wrong-SHA EP is never transplanted. The fallback is independently read
    source at the explicitly selected SHA; neither its location nor role is
    copied to EP. Contradictory commit choices or duplicate receipts stop here.
    Revision comparison can inspect a source-backed operation independently of
    the EP's status; normal caller navigation retains its unresolved-EP gate.
    """
    if not isinstance(review, Mapping):
        return None
    fields = review.get("draft_fields") or {}
    suggestions = review.get("suggested_values") or {}
    reviews = review.get("field_reviews") or {}
    if not all(isinstance(item, Mapping) for item in (fields, suggestions, reviews)):
        return None
    errors = review.get("annotation_errors", [])
    if isinstance(errors, list) and any(isinstance(row, Mapping) and row.get("field") == "entry_point" for row in errors):
        return None  # Repair the rejected wire field in review; do not spend reads on malformed data.
    if any(value is not None and not isinstance(value, Mapping)
           for value in (fields.get("entry_point"), suggestions.get("entry_point"))):
        return None
    ep = reviews.get("entry_point", {})
    checks = review.get("support_consistency_checks") or {}
    if not isinstance(ep, Mapping) or not isinstance(checks, Mapping):
        return None
    errors = ep.get("validation_errors")
    conflict = isinstance(errors, list) and "supported_reason_conflict" in errors[:32]
    for packet in (checks.get("entry_point"), ep.get("support_consistency")):
        if isinstance(packet, Mapping) and isinstance(packet.get("issues"), list):
            conflict |= any(isinstance(issue, Mapping) and issue.get("code") == "supported_reason_conflict"
                            and issue.get("prerequisite") == "external_entry_role" for issue in packet["issues"][:8])
    if not include_supported and ep.get("status") not in ("uncertain", "missing", "conflicting") and not conflict:
        return None
    choices = (fields.get("commit"), suggestions.get("commit"))
    if any(value is not None and (not isinstance(value, str) or not _SHA.fullmatch(value)) for value in choices):
        return None
    commits = {value for value in choices if value is not None}
    if len(commits) != 1:
        return None
    commit = next(iter(commits))
    if not _SHA.fullmatch(commit):
        return None
    evidence = review.get("evidence")
    if not isinstance(evidence, list) or len(evidence) > 256:
        return None
    receipts = {}
    for row in evidence:
        if not isinstance(row, Mapping) or not isinstance(row.get("id"), str):
            continue
        if row["id"] in receipts:
            return None
        receipts[row["id"]] = row
    for field in (("critical_operation", "entry_point") if prefer_operation else ("entry_point", "critical_operation")):
        current, suggested = fields.get(field), suggestions.get(field)
        if current is not None and suggested is not None and current != suggested:
            continue
        value = current if current is not None else suggested
        assessment = reviews.get(field, {})
        if not isinstance(value, Mapping) or not isinstance(assessment, Mapping):
            continue
        line = value.get("start_line", value.get("line"))
        last = value.get("end_line", line)
        if isinstance(line, str) and re.fullmatch(r"[1-9][0-9]{0,8}(?:-[1-9][0-9]{0,8})?", line):
            parts = list(map(int, line.split("-")))
            line, last = parts[0], parts[-1]
        if not _positive_line(line) or not _positive_line(last) or last < line:
            continue
        identities = ([value["evidence_ref"]] if isinstance(value.get("evidence_ref"), str)
                      else assessment.get("evidence_refs", []))
        if not isinstance(identities, list):
            continue
        for identity in identities[:24]:
            source = _source(receipts.get(identity) if isinstance(identity, str) else None, commit)
            if source is None or ("evidence_ref" not in value and value.get("file") != source["path"]):
                continue
            symbol = _symbol_at(source, line, leading_blanks=True, selected_end=last)
            if symbol:
                return {"commit": commit, **symbol, "field": field, "evidence_ref": identity}
            # The preceding-context read deliberately ends before the original
            # receipt. Its declaration can still enclose the selected fragment.
            # Join only continuous, agreeing same-SHA bytes for lexical lookup;
            # never create a new receipt or use this view as annotation evidence.
            prefixed = _symbol_across_receipts(source, line, last, commit, receipts)
            if prefixed:
                symbol, declaration_ref = prefixed
                return {"commit": commit, **symbol, "field": field,
                        "evidence_ref": declaration_ref, "selected_evidence_ref": identity}
    return None


def _selected_location_source(value, assessment, commit, receipts):
    """Bind wire references OR the controller's expanded locations to real rows.

    merge_draft expands each reference before navigation. An expanded value
    therefore requires cited same-SHA source, matching path/range AND exact code;
    a field label or an uncited lookalike cannot supply a navigation location.
    """
    if not isinstance(value, Mapping) or not isinstance(assessment, Mapping):
        return None
    first, last = value.get("start_line"), value.get("end_line")
    identity = value.get("evidence_ref")
    expanded = identity is None
    if expanded:
        line = value.get("line")
        if type(line) is int:
            first = last = line
        elif isinstance(line, str) and re.fullmatch(r"[1-9][0-9]{0,8}(?:-[1-9][0-9]{0,8})?", line):
            parts = list(map(int, line.split("-")))
            first, last = parts[0], parts[-1]
        if not _relative_path(value.get("file")) or not isinstance(value.get("code"), str):
            return None
        identities = assessment.get("evidence_refs")
    else:
        identities = [identity] if isinstance(identity, str) else None
    if (not _positive_line(first) or not _positive_line(last) or not first <= last < first + 200
            or not isinstance(identities, list)):
        return None
    for identity in identities[:24]:
        source = _source(receipts.get(identity) if isinstance(identity, str) else None, commit)
        if source is None or not source["first"] <= first <= last <= source["last"]:
            continue
        if expanded and (value["file"] != source["path"] or value["code"] !=
                         "\n".join(source["lines"][first - source["first"]:last - source["first"] + 1])):
            continue
        return source, first, last
    return None


def intermediate_assignment_seed(review):
    """Find one visible assigned-call name between a Python EP and operation.

    Only lexical navigation: all intervening rows must have been read at one
    SHA, and an assigned local name must occur in the selected operation. This
    neither proves data flow nor changes any judgment. Unknown syntax is left
    to the model's ordinary reads; no paths, revisions or call edges are guessed.
    """
    if not isinstance(review, Mapping):
        return None
    fields, suggestions, judgments = (review.get(key) or {} for key in
                                      ("draft_fields", "suggested_values", "field_reviews"))
    if not all(isinstance(value, Mapping) for value in (fields, suggestions, judgments)):
        return None
    # Initial supported labels must not suppress inspection of an actually
    # observed intermediate assignment. This check changes no label itself.
    choices = [source.get("commit") for source in (fields, suggestions) if source.get("commit") is not None]
    if not choices or any(not isinstance(value, str) or not _SHA.fullmatch(value) for value in choices) or len(set(choices)) != 1:
        return None
    commit = choices[0]
    evidence = review.get("evidence")
    if not isinstance(evidence, list) or len(evidence) > 256:
        return None
    receipts = {}
    for row in evidence:
        if not isinstance(row, Mapping) or not isinstance(row.get("id"), str):
            continue
        if row["id"] in receipts:
            return None
        receipts[row["id"]] = row
    locations, owners = [], []
    for field in ("entry_point", "critical_operation"):
        current, suggestion = fields.get(field), suggestions.get(field)
        if current is not None and suggestion is not None and current != suggestion:
            return None
        value = current if current is not None else suggestion
        selected = _selected_location_source(value, judgments.get(field, {}), commit, receipts)
        if selected is None:
            return None
        source, first, last = selected
        owner = _symbol_at(source, first, leading_blanks=True, selected_end=last)
        if owner is None:
            joined = _symbol_across_receipts(source, first, last, commit, receipts)
            owner = joined[0] if joined else None
        if owner is None:
            return None
        owners.append(owner)
        locations.append((source["path"], first, last))
    entry, operation = locations
    if (owners[0] != owners[1] or entry[0] != operation[0] or PurePosixPath(entry[0]).suffix != ".py"
            or not entry[2] < operation[1] or operation[2] - entry[1] >= 200):
        return None
    rows = {}
    for identity, receipt in receipts.items():
        source = _source(receipt, commit)
        if source is None or source["path"] != entry[0]:
            continue
        for line in range(max(source["first"], entry[1]), min(source["last"], operation[2]) + 1):
            code = source["lines"][line - source["first"]]
            if line in rows and rows[line][0] != code:
                return None
            rows[line] = (code, identity)
    if any(line not in rows for line in range(entry[1], operation[2] + 1)):
        return None
    operation_text = "\n".join(rows[line][0] for line in range(operation[1], operation[2] + 1))
    assigned_call = re.compile(r"^\s*(?P<targets>[A-Za-z_]\w*(?:\s*,\s*[A-Za-z_]\w*)*)\s*=\s*"
                               r"(?:await\s+)?(?P<symbol>[A-Za-z_]\w{1,127})\s*\(")
    for line in range(operation[1] - 1, entry[2], -1):
        match = assigned_call.match(rows[line][0])
        if not match or not any(re.search(r"\b" + re.escape(target.strip()) + r"\b", operation_text)
                                for target in match["targets"].split(",")):
            continue
        symbol = match["symbol"]
        if symbol in {"dict", "list", "tuple", "str", "bytes", "int", "float", "bool", "set"}:
            continue
        if any(source and any(_declaration(code) == symbol for code in source["lines"])
               for source in (_source(receipt, commit) for receipt in receipts.values())):
            continue
        return {"commit": commit, "path": entry[0], "symbol": symbol, "line": line,
                "evidence_ref": rows[line][1]}
    return None


def assignment_definition_read(receipt, seed):
    """Read one unambiguous declaration found for the observed assigned call."""
    if not isinstance(seed, Mapping) or not isinstance(receipt, Mapping):
        return None
    if (not isinstance(seed.get("commit"), str) or not _SHA.fullmatch(seed["commit"])
            or not isinstance(seed.get("symbol"), str) or not re.fullmatch(_NAME, seed["symbol"])):
        return None
    data = receipt.get("result")
    if (receipt.get("tool") != "search_code" or receipt.get("success") is not True or receipt.get("error")
            or not isinstance(data, Mapping) or data.get("error") or data.get("ok") is False
            or data.get("success") is False or data.get("commit") != seed.get("commit")
            or data.get("query") != seed.get("symbol") or not isinstance(data.get("matches"), list)):
        return None
    declarations = set()
    for hit in data["matches"][:100]:
        if (not isinstance(hit, Mapping) or not _relative_path(hit.get("file"))
                or not _positive_line(hit.get("line")) or hit["line"] > 99_999_904
                or not isinstance(hit.get("code"), str)
                or not re.match(r"^\s*(?:async\s+)?def\s+", hit["code"])
                or _declaration(hit["code"]) != seed.get("symbol")):
            continue
        declarations.add((hit["file"], hit["line"]))
    if len(declarations) != 1 or data.get("truncated") is True or data.get("complete") is False:
        return None
    path, line = next(iter(declarations))
    return {"commit": seed["commit"], "path": path, "start_line": max(1, line - 4), "end_line": line + 96}


def _symbol_across_receipts(source, line, last, commit, receipts):
    """Resolve an enclosing name across saved adjacent windows, not a call edge.

    The selected start must already be visible in its own receipt. Missing rows,
    conflicting overlaps or another revision cannot bridge a declaration to it.
    At most 80 preceding rows and 8 following rows enter this navigation view.
    The returned evidence ID belongs to the actual declaration, not the view.
    """
    if not source["first"] <= line <= source["last"]:
        return None
    lower, upper = max(1, line - 80), min(source["last"], line + 8)
    visible = {}
    for identity, receipt in receipts.items():
        candidate = _source(receipt, commit)
        if candidate is None or candidate["path"] != source["path"]:
            continue
        for number in range(max(lower, candidate["first"]), min(upper, candidate["last"]) + 1):
            code = candidate["lines"][number - candidate["first"]]
            if number in visible and visible[number][0] != code:
                return None
            visible[number] = (code, identity)
    first = line
    while first > lower and first - 1 in visible:
        first -= 1
    if first >= source["first"]:
        return None  # No newly available preceding context.
    joined = {"path": source["path"], "first": first, "last": upper,
              "lines": [visible[number][0] for number in range(first, upper + 1)]}
    symbol = _symbol_at(joined, line, leading_blanks=True, selected_end=last)
    return (symbol, visible[symbol["line"]][1]) if symbol else None


def _hits(receipt, seed):
    """Rank actual literal hits for reading, not as confirmed call edges."""
    data = receipt.get("result", {}) if isinstance(receipt, Mapping) else {}
    if (not isinstance(receipt, Mapping) or receipt.get("success") is not True or not isinstance(data, Mapping)
            or receipt.get("error") or data.get("error") or data.get("ok") is False
            or data.get("success") is False or data.get("commit") != seed["commit"]
            or data.get("query") != seed["symbol"] or not isinstance(data.get("matches"), list)):
        return []
    pattern = re.compile(r"(?<![A-Za-z0-9_$])" + re.escape(seed["symbol"]) + r"(?![A-Za-z0-9_$])")
    matches = []
    for hit in data["matches"][:100]:
        if (not isinstance(hit, Mapping) or not _relative_path(hit.get("file"))
                or not _positive_line(hit.get("line")) or not isinstance(hit.get("code"), str)):
            continue
        code = hit["code"].strip()
        if (code.startswith(("//", "#", "*", "import ", "from ", "export {"))
                or _declaration(code) == seed["symbol"]):
            continue
        match = pattern.search(code)
        if match is None:
            continue
        after = code[match.end():].lstrip()
        before = code[:match.start()].rstrip()
        # Exclude bare names in multiline imports; include direct calls and
        # callback arguments/assignments. False hits remain merely navigation.
        if not (after.startswith("(") or before.endswith(("(", ",", "=", ":"))):
            continue
        matches.append({"path": hit["file"], "line": hit["line"]})
    def priority(hit):
        path = hit["path"]
        test = bool(re.search(r"(?:^|/)(?:tests?|__tests__)/|(?:^|/|[.])(?:test|spec)[._]", path))
        # Try a cross-file caller before another local helper. This is a
        # navigation preference only; alternatives remain in the search receipt.
        return test, path == seed["path"], path, hit["line"]
    return sorted(matches, key=priority)


def focused_reference_request(focused_reads, receipts):
    """Turn one final literal-reference search into one actual source window.

    A hit is only a direction, never an established entry or call edge. Keep
    alternatives in the original receipt; do not repeat an already visible hit.
    The caller enforces the same tool/context budget and does not chain this
    read into another navigation pass.
    """
    if not isinstance(focused_reads, list) or len(focused_reads) != 1:
        return None
    receipt = focused_reads[0]
    data = receipt.get("result") if isinstance(receipt, Mapping) else None
    if (not isinstance(data, Mapping) or receipt.get("tool") != "search_code"
            or data.get("complete") is not True or data.get("truncated") is True
            or not isinstance(data.get("commit"), str) or not _SHA.fullmatch(data["commit"])
            or not isinstance(data.get("query"), str) or not re.fullmatch(_NAME, data["query"])
            or data["query"] in _GENERIC):
        return None
    seed = {"commit": data["commit"], "symbol": data["query"], "path": ""}
    for hit in _hits(receipt, seed):
        if PurePosixPath(hit["path"]).suffix not in _EXTENSIONS or hit["line"] > 99_999_904:
            continue
        if any(source and source["path"] == hit["path"]
               and source["first"] <= hit["line"] <= source["last"]
               for source in (_source(row, seed["commit"]) for row in receipts)):
            continue
        return {"commit": seed["commit"], "path": hit["path"],
                "start_line": max(1, hit["line"] - 80), "end_line": hit["line"] + 32}
    return None


def navigate_entry(review, execute, can_read, *, execute_anchored_source=None):
    """At most four search/read pairs, with a budget check before EVERY call.

    execute uses the session's existing repository reader and receipt store.
    Stop on missing declarations, failures, cycles or exhausted budgets. The
    model receives real windows plus all search alternatives, not a chosen EP.
    """
    seed = entry_navigation_seed(review)
    report = {"version": VERSION, "steps": [], "stop_reason": "no_source_seed", "semantic_approval": False}
    if seed is None:
        return report
    report["seed"] = dict(seed)
    seen = set()

    def call(tool, arguments, *, anchor_line=None):
        if not can_read():
            report["stop_reason"] = "budget_reserved"
            return None
        response = (execute_anchored_source(arguments, anchor_line)
                    if tool == "read_file" and anchor_line is not None and execute_anchored_source is not None
                    else execute(tool, arguments))
        if isinstance(response, Mapping) and "reused_evidence_ref" in response:
            identity = response["reused_evidence_ref"]
            response = next((row for row in review["evidence"] if row.get("id") == identity), {})
        success = isinstance(response, Mapping) and response.get("success") is True
        report["steps"].append({"tool": tool, "arguments": arguments,
                                "evidence_ref": response.get("id") if isinstance(response, Mapping) else None,
                                "success": success})
        if not success:
            report["stop_reason"] = "read_failed"
            return None
        return response

    for _ in range(MAX_HOPS):
        key = seed["commit"], seed["symbol"]
        if key in seen:
            report["stop_reason"] = "symbol_cycle"
            return report
        seen.add(key)
        search = call("search_code", {"commit": seed["commit"], "query": seed["symbol"]})
        if search is None:
            return report
        hits = _hits(search, seed)
        if not hits:
            report["stop_reason"] = "no_usable_reference_hit"
            return report
        hit = hits[0]
        # A search can already show the nearby factory declaration as well as
        # its return/call. Use that observed coordinate for a smaller source
        # read, instead of always spending 80 preceding lines. Search remains
        # navigation only; the actual read must still establish the owner.
        declarations = [row["line"] for row in search.get("result", {}).get("matches", [])[:100]
                        if isinstance(row, Mapping) and row.get("file") == hit["path"]
                        and _positive_line(row.get("line"))
                        and hit["line"] - 16 <= row["line"] <= hit["line"]
                        and isinstance(row.get("code"), str)
                        and _declaration(row["code"]) not in (None, seed["symbol"])]
        first = max(1, min(declarations) - 8) if declarations else max(1, hit["line"] - 80)
        result = call("read_file", {"commit": seed["commit"], "path": hit["path"],
                                   "start_line": first, "end_line": hit["line"] + 32},
                      anchor_line=hit["line"])
        if result is None:
            return report
        source = _source(result, seed["commit"])
        parent = _symbol_at(source, hit["line"]) if source else None
        if not parent:
            report["stop_reason"] = "enclosing_symbol_not_visible"
            return report
        seed = {"commit": seed["commit"], **parent}
    report["stop_reason"] = "hop_limit"
    return report
