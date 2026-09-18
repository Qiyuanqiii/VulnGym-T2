"""Bounded source comparisons among observed revisions, never field selection."""
import ast
import io
import json
import re
import textwrap
import tokenize
from collections.abc import Mapping

from .source_refs import _relative_path


_SHA = re.compile(r"[0-9a-f]{40}\Z")
_HUNK = re.compile(r"^@@ -(\d{1,9})(?:,(\d{1,9}))? \+(\d{1,9})(?:,(\d{1,9}))? @@")
_PROBE_QUERY = re.compile(r"(?:(?P<kind>(?:async[ \t]+)?def|function|func|class)[ \t]+)?"
                          r"(?P<name>[A-Za-z_$][A-Za-z0-9_$]{1,127})\Z")


def _comparison_path(path):
    """Canonical literal tree paths only; never manufacture a Git pathspec."""
    return (_relative_path(path) and len(path) <= 500
            and not path.startswith(("-", ":")) and not any(ord(char) < 32 for char in path)
            and not any(part in ("", ".", "..") for part in path.split("/")))


def focused_diff_seed(review):
    """Narrow one failed/incomplete whole diff using an actually cited file.

    Both immutable SHAs must be in the saved request (never derive ``^`` or
    choose a parent). A successful truncated result must agree with that pair.
    Failed attempts need no successful diff, but are only navigation, not proof
    either revision exists or is affected. Exact source at one side supplies
    the path. Multiple possible files in the highest-priority citation group
    remain ambiguous unless a selected, byte-matched location disambiguates.
    """
    from .entry_navigation import _source, _selected_location_source

    if not isinstance(review, Mapping):
        return None
    receipts, judgments = review.get("evidence"), review.get("field_reviews")
    fields, suggestions = review.get("draft_fields", {}), review.get("suggested_values", {})
    if (not isinstance(receipts, list) or len(receipts) > 256
            or not all(isinstance(value, Mapping) for value in (judgments, fields, suggestions))):
        return None
    by_id = {}
    for row in receipts:
        identity = row.get("id") if isinstance(row, Mapping) else None
        if not isinstance(identity, str) or not re.fullmatch(r"E\d{4,8}", identity) or identity in by_id:
            return None
        by_id[identity] = row
    for row in receipts:
        arguments, data = row.get("arguments"), row.get("result")
        if (row.get("tool") != "read_diff" or not isinstance(arguments, Mapping)
                or arguments.get("path") is not None or not isinstance(data, Mapping)):
            continue
        before, after = arguments.get("before"), arguments.get("after")
        if (not all(isinstance(sha, str) and _SHA.fullmatch(sha) for sha in (before, after))
                or before == after or any(key in data and data[key] != arguments[key] for key in ("before", "after"))):
            continue
        failed = (row.get("success") is False or row.get("error") or data.get("error")
                  or data.get("ok") is False or data.get("success") is False)
        incomplete = (row.get("truncated") is True or data.get("truncated") is True
                      or data.get("context_truncated") is True or data.get("complete") is False)
        if not failed and not (row.get("success") is True and incomplete
                               and data.get("before") == before and data.get("after") == after):
            continue
        for field in ("critical_operation", "entry_point", "commit"):
            decision = judgments.get(field)
            refs = decision.get("evidence_refs") if isinstance(decision, Mapping) else None
            if not isinstance(refs, list):
                continue
            candidates, selected = [], []
            for identity in refs[:24]:
                source_row = by_id.get(identity) if isinstance(identity, str) else None
                source_data = source_row.get("result") if isinstance(source_row, Mapping) else None
                sha = source_data.get("commit") if isinstance(source_data, Mapping) else None
                source = _source(source_row, sha) if sha in (before, after) else None
                if source is None or not _comparison_path(source["path"]):
                    continue
                candidate = {"arguments": {"before": before, "after": after, "path": source["path"]},
                             "evidence_refs": [row["id"], identity], "source_revision": sha,
                             "source_line": None}
                candidates.append(candidate)
                value = fields.get(field) if fields.get(field) is not None else suggestions.get(field)
                location = _selected_location_source(value, decision, sha, {identity: source_row})
                if location:
                    selected.append({**candidate, "source_line": location[1]})
            candidates = selected or candidates
            if not candidates:
                continue
            if len({item["arguments"]["path"] for item in candidates}) != 1:
                return None
            seed = candidates[0]
            # Failed and reverse-direction scoped attempts also count. Do not
            # reissue a whole diff or invite a retry loop after a narrow error.
            if any(saved.get("tool") == "read_diff" and isinstance(saved.get("arguments"), Mapping)
                   and saved["arguments"].get("path") == seed["arguments"]["path"]
                   and ((saved["arguments"].get("before"), saved["arguments"].get("after"))
                        in ((before, after), (after, before))) for saved in receipts):
                return None
            # A broad read's first line is a transport boundary, not the
            # mechanism. Retain ALL actual same-path essential-field source
            # ranges so hunk selection can compare changed code against them.
            windows, locations = [], []
            for name in ("critical_operation", "entry_point", "commit"):
                assessment = judgments.get(name)
                cited = assessment.get("evidence_refs") if isinstance(assessment, Mapping) else None
                for identity in cited[:24] if isinstance(cited, list) else []:
                    saved = by_id.get(identity) if isinstance(identity, str) else None
                    saved_data = saved.get("result") if isinstance(saved, Mapping) else None
                    sha = saved_data.get("commit") if isinstance(saved_data, Mapping) else None
                    source = _source(saved, sha) if sha in (before, after) else None
                    if source is None or source["path"] != seed["arguments"]["path"]:
                        continue
                    window = {"commit": sha, "start_line": source["first"], "end_line": source["last"]}
                    if window not in windows:
                        windows.append(window)
                    if identity not in seed["evidence_refs"]:
                        seed["evidence_refs"].append(identity)
                    value = fields.get(name) if fields.get(name) is not None else suggestions.get(name)
                    location = _selected_location_source(value, assessment, sha, {identity: saved})
                    if location:
                        selected = {"commit": sha, "start_line": location[1], "end_line": location[2]}
                        if selected not in locations:
                            locations.append(selected)
            seed.update(source_windows=windows, selected_windows=locations)
            return seed
    return None


def _inspection_refs(receipts):
    """Full SHAs with successful inspection receipts, in observed order."""
    inspected = {}
    for receipt in receipts:
        if not isinstance(receipt, Mapping):
            continue
        data = receipt.get("result")
        if (receipt.get("tool") != "inspect_commit" or receipt.get("success") is not True
                or receipt.get("error") or not isinstance(data, Mapping)
                or data.get("error") or data.get("ok") is False or data.get("success") is False):
            continue
        sha, ref = data.get("commit"), receipt.get("id")
        if (isinstance(sha, str) and _SHA.fullmatch(sha) and isinstance(ref, str)
                and re.fullmatch(r"E\d{4,8}", ref)):
            inspected.setdefault(sha, ref)
    return inspected


def _probe_arguments(arguments):
    """Validate an already-issued declaration or bare-name query unchanged."""
    if (not isinstance(arguments, Mapping) or set(arguments) - {"commit", "query", "paths"}
            or not isinstance(arguments.get("commit"), str) or not _SHA.fullmatch(arguments["commit"])
            or not isinstance(arguments.get("query"), str) or not _PROBE_QUERY.fullmatch(arguments["query"])):
        return False
    paths = arguments.get("paths")
    return (paths is None or (isinstance(paths, list) and 1 <= len(paths) <= 8
                             and all(_comparison_path(path) for path in paths)))


def _complete_probe_search(receipt, arguments):
    if (not isinstance(receipt, Mapping) or receipt.get("tool") != "search_code"
            or receipt.get("success") is not True or receipt.get("error")
            or receipt.get("truncated") is True or receipt.get("context_truncated") is True):
        return False
    data = receipt.get("result")
    return (isinstance(data, Mapping) and not data.get("error") and data.get("ok") is not False
            and data.get("success") is not False and data.get("complete") is True
            and data.get("truncated") is not True and data.get("context_truncated") is not True
            and data.get("commit") == arguments["commit"] and data.get("query") == arguments["query"]
            and ("paths" not in data or data["paths"] == arguments.get("paths"))
            and isinstance(data.get("matches"), list) and len(data["matches"]) <= 100)


def _probe_lacks_declaration(receipt, arguments):
    """Recognize a complete empty or bare-name reference-only search.

    This is a navigation gap, not proof that the symbol has no definition.
    Unknown syntax can still be read by the planner at the original snapshot.
    """
    from .entry_navigation import _declaration

    hits = receipt["result"]["matches"]
    if not hits:
        return True
    parsed = _PROBE_QUERY.fullmatch(arguments["query"])
    if parsed["kind"] is not None:
        return False
    for hit in hits:
        if not isinstance(hit, Mapping):
            return False
        code, path, line = hit.get("code"), hit.get("file"), hit.get("line")
        if (not isinstance(code, str) or any(char in code for char in "\x00\r\n")
                or not _comparison_path(path) or type(line) is not int or line < 1
                or hit.get("code_omitted") or hit.get("truncated")
                or (arguments.get("paths") is not None and not any(
                    path == prefix or path.startswith(prefix + "/") for prefix in arguments["paths"]))):
            return False
        if _declaration(code) == parsed["name"]:
            return False
    return True


def initial_snapshot_probe_seed(receipts):
    """Before the first source read, reuse an observed unresolved symbol query.

    A sole ref does not exhaust inspected snapshots. The alternative must have
    a successful full-SHA inspection and no read_file/search_code attempt, even
    a failed one. A complete empty or reference-only bare-name search supplies
    the literal query and scope, without proving that a definition is absent;
    neither an empty directory nor prose creates a symbol, path or revision.
    This pure selector performs no read or field judgment. The caller owns the
    once-per-input flag, the original read/draft/review budget, and both calls.
    """
    from .entry_navigation import _source

    if not isinstance(receipts, list) or len(receipts) > 256:
        return None
    identities, attempted = set(), set()
    for row in receipts:
        identity = row.get("id") if isinstance(row, Mapping) else None
        if (not isinstance(identity, str) or not re.fullmatch(r"E[0-9]{4,8}", identity)
                or identity in identities):
            return None
        identities.add(identity)
        data, arguments = row.get("result"), row.get("arguments")
        sha = data.get("commit") if isinstance(data, Mapping) else None
        if isinstance(sha, str) and _SHA.fullmatch(sha) and _source(row, sha):
            return None  # Any actual source keeps this strictly a first-read aid.
        if row.get("tool") in ("read_file", "search_code"):
            for values in (data, arguments):
                sha = values.get("commit") if isinstance(values, Mapping) else None
                if isinstance(sha, str) and _SHA.fullmatch(sha):
                    attempted.add(sha)
    inspected = _inspection_refs(receipts)
    for row in receipts:
        arguments = row.get("arguments")
        if (not _probe_arguments(arguments) or not _complete_probe_search(row, arguments)
                or not _probe_lacks_declaration(row, arguments)):
            continue
        for sha, inspection_ref in inspected.items():
            if sha in attempted or sha == arguments["commit"]:
                continue
            request = {"commit": sha, "query": arguments["query"]}
            if "paths" in arguments:
                request["paths"] = list(arguments["paths"]) if arguments["paths"] is not None else None
            return {"arguments": request, "evidence_refs": [row["id"], inspection_ref]}
    return None


def initial_snapshot_probe_read(receipt, seed):
    """Read one unique actual declaration at the probed SHA, never a verdict."""
    from .entry_navigation import _declaration

    arguments = seed.get("arguments") if isinstance(seed, Mapping) else None
    refs = seed.get("evidence_refs") if isinstance(seed, Mapping) else None
    if (not _probe_arguments(arguments) or not isinstance(refs, list) or len(refs) != 2
            or any(not isinstance(ref, str) or not re.fullmatch(r"E[0-9]{4,8}", ref) for ref in refs)
            or refs[0] == refs[1] or not _complete_probe_search(receipt, arguments)):
        return None
    query, matches = arguments["query"], receipt["result"]["matches"]
    parsed = _PROBE_QUERY.fullmatch(query)
    name = parsed["name"]
    declaration = (re.compile(r"^\s*(?:(?:export|default|declare|async|public|private|static|abstract)\s+)*"
                              + re.escape(query) + r"(?=[^A-Za-z0-9_$]|$)")
                   if parsed["kind"] is not None else None)
    found = set()
    for hit in matches:
        if not isinstance(hit, Mapping) or not isinstance(hit.get("code"), str):
            return None
        code = hit["code"]
        if any(char in code for char in "\x00\r\n"):
            return None
        if _declaration(code) != name or (declaration is not None and not declaration.match(code)):
            continue  # Imports, comments and string mentions are not declarations.
        path, line = hit.get("file"), hit.get("line")
        if (not _comparison_path(path) or type(line) is not int or not 1 <= line <= 99_999_929
                or (arguments.get("paths") is not None and not any(
                    path == prefix or path.startswith(prefix + "/") for prefix in arguments["paths"]))):
            return None
        found.add((path, line, code))
    if len(found) != 1:
        return None
    path, line, _ = found.pop()
    return {"arguments": {"commit": arguments["commit"], "path": path,
                          "start_line": max(1, line - 8), "end_line": line + 71},
            "anchor_line": line}


def revision_read_coverage(receipts, max_chars=2400):
    """Inventory saved reads across inspected snapshots, not semantic verdicts.

    An unrelated commit message does not describe every file in that snapshot.
    Expose this small, ephemeral inventory while read tools remain available;
    no new revision, path, evidence, tool call or field decision is generated.
    """
    from .entry_navigation import _source

    inspected = _inspection_refs(receipts)
    if not inspected:
        return {}
    rows = []
    for sha, ref in list(inspected.items())[:4]:
        paths, failed_diffs = set(), []
        for receipt in receipts:
            if source := _source(receipt, sha):
                paths.add(source["path"])
            if not isinstance(receipt, Mapping) or receipt.get("tool") != "read_diff":
                continue
            arguments, data = receipt.get("arguments"), receipt.get("result")
            data = data if isinstance(data, Mapping) else {}
            identity = receipt.get("id")
            if (not isinstance(arguments, Mapping)
                    or sha not in (arguments.get("before"), arguments.get("after"))
                    or not isinstance(identity, str) or not re.fullmatch(r"E\d{4,8}", identity)
                    or not (receipt.get("success") is False or receipt.get("error")
                            or data.get("error") or data.get("ok") is False
                            or data.get("success") is False)):
                continue
            failure = {"evidence_ref": identity}
            for key, value in (("error", data.get("error") or receipt.get("error")),
                               ("error_code", data.get("error_code"))):
                if isinstance(value, str) and value:
                    failure[key] = value[:160]
                    if len(value) > 160:
                        failure["metadata_truncated"] = True
            failed_diffs.append(failure)
        row = {"commit": sha, "inspection_ref": ref,
               "paths_with_visible_source": sorted(paths)[:6],
               "omitted_path_count": max(0, len(paths) - 6)}
        if failed_diffs:
            row.update(failed_diff_reads=failed_diffs[:2],
                       omitted_failed_diff_count=max(0, len(failed_diffs) - 2))
        rows.append(row)
    result = {"inspected_snapshots": rows, "omitted_snapshot_count": max(0, len(inspected) - 4),
              "note": "Read coverage only, not affected/fixed labels. Paths may be only partially read. An empty list means no saved visible source at this SHA, not that the repository has no relevant code. Commit messages describe a change, not the whole snapshot; check known relevant source at supplied inspected SHAs even when a diff failed, and compare supplied snapshots before dismissing one by its message, within the original budget."}
    return result if len(json.dumps(result, ensure_ascii=False)) <= max_chars else {}


def _hunk_changes(lines, windows):
    """Lexical changed-code positions, not a classifier of safe/unsafe code.

    Tokenization excludes quoted prose/comments, including multi-line Python
    strings. Import-only edits remain valid fallback hunks, but do not outrank
    cited executable changes merely because the file was read from line one.
    Incomplete or unfamiliar syntax simply supplies fewer priority hints.
    """
    before, after = windows[0][0], windows[1][0]
    bodies, changed = {before: [], after: []}, {before: set(), after: set()}
    for line in lines:
        if line.startswith(("@@ ", "diff --git ")):
            break
        if line.startswith(" "):
            for sha in (before, after):
                bodies[sha].append(line[1:])
        elif line.startswith(("+", "-")):
            sha = after if line[0] == "+" else before
            changed[sha].add(len(bodies[sha]) + 1)
            bodies[sha].append(line[1:])
        elif not line.startswith("\\ No newline"):
            break
    meaningful, all_changes = set(), set()
    for sha, first, count in windows:
        body = bodies[sha][:count]
        tokens = {}
        try:
            for token in tokenize.generate_tokens(io.StringIO(textwrap.dedent("\n".join(body))).readline):
                if token.type in (tokenize.NAME, tokenize.OP):
                    tokens.setdefault(token.start[0], set()).add(token.string)
        except (tokenize.TokenError, IndentationError, SyntaxError):
            pass  # Earlier complete tokens remain lexical hints only.
        for offset in changed[sha]:
            if not 1 <= offset <= len(body):
                continue
            position = (sha, first + offset - 1)
            all_changes.add(position)
            code, words = body[offset - 1].lstrip(), tokens.get(offset, set())
            if (re.match(r"(?:from\s+\S+\s+import\b|import\b|using\b|package\b|#\s*include\b)", code)
                    or code.startswith(("#", "//", "/*", "*"))):
                continue
            if words & {"=", "+=", "-=", "*=", "/=", "(", "return", "yield", "raise", "throw",
                        "if", "for", "while", "try", "except", "await", "with", "assert", "del",
                        "def", "function", "func", "class"}:
                meaningful.add(position)
    return meaningful, all_changes


def _valid_comparison_windows(value, before, after):
    return (isinstance(value, list) and len(value) <= 72 and all(
        isinstance(row, Mapping) and row.get("commit") in (before, after)
        and type(row.get("start_line")) is int and type(row.get("end_line")) is int
        and 1 <= row["start_line"] <= row["end_line"] <= 100_000_000 for row in value))


def comparison_reads(receipt, *, focus=None):
    """Return at most two bounded read requests for one visible changed hunk.

    Inspecting both sides avoids presenting only repaired source to annotation.
    Neither side is labelled affected; the source still must be interpreted.
    Quoted/renamed/unknown paths and zero-length sides are not guessed.
    A focused pair/path prioritizes actual changed code at selected locations
    or in essential-field source ranges. A broad window's first line is never
    a relevance anchor; these lexical priorities approve no mechanism.
    """
    if (not isinstance(receipt, Mapping) or receipt.get("tool") != "read_diff"
            or receipt.get("success") is not True or receipt.get("error")):
        return []
    data = receipt.get("result")
    if (not isinstance(data, Mapping) or data.get("error") or data.get("success") is False
            or data.get("ok") is False or not isinstance(data.get("diff"), str)):
        return []
    before, after = data.get("before"), data.get("after")
    if not all(isinstance(value, str) and _SHA.fullmatch(value) for value in (before, after)) or before == after:
        return []
    if focus is not None and (not isinstance(focus, Mapping) or not isinstance(focus.get("arguments"), Mapping)
            or focus["arguments"] != {"before": before, "after": after,
                                      "path": focus["arguments"].get("path")}
            or not _comparison_path(focus["arguments"].get("path"))
            or focus.get("source_revision") not in (before, after)
            or (focus.get("source_line") is not None and (type(focus["source_line"]) is not int
                or not 1 <= focus["source_line"] <= 100_000_000))
            or not _valid_comparison_windows(focus.get("source_windows", []), before, after)
            or not _valid_comparison_windows(focus.get("selected_windows", []), before, after)):
        return []
    old_path = new_path = None
    candidates = []
    texts = data["diff"].splitlines()
    for index, text in enumerate(texts):
        if text.startswith("diff --git "):
            old_path = new_path = None
        elif text.startswith("--- "):
            old_path = text[6:] if text.startswith("--- a/") else None
        elif text.startswith("+++ "):
            new_path = text[6:] if text.startswith("+++ b/") else None
        elif (match := _HUNK.match(text)):
            if not old_path or old_path != new_path or not _comparison_path(old_path):
                return []
            if focus is not None and old_path != focus["arguments"]["path"]:
                return []
            first_before, count_before, first_after, count_after = match.groups()
            windows = [(before, int(first_before), int(count_before or 1)),
                       (after, int(first_after), int(count_after or 1))]
            if any(not 1 <= first <= 99_999_928 or not 1 <= count <= 100_000_000
                   for _, first, count in windows):
                return []
            requests = [{"commit": sha, "path": old_path, "start_line": max(1, first - 12),
                         "end_line": first + min(count, 60) + 11} for sha, first, count in windows]
            if focus is None:
                return requests
            _, first, count = next(window for window in windows if window[0] == focus["source_revision"])
            meaningful, changed = _hunk_changes(texts[index + 1:], windows)
            def overlaps(positions, ranges):
                return any(sha == row["commit"] and row["start_line"] <= line <= row["end_line"]
                           for sha, line in positions for row in ranges)
            source_windows, selected_windows = focus.get("source_windows", []), focus.get("selected_windows", [])
            visible = [(sha, first, first + count - 1) for sha, first, count in windows]
            in_source = any(sha == row["commit"] and first <= row["end_line"] and row["start_line"] <= last
                            for sha, first, last in visible for row in source_windows)
            anchor = focus.get("source_line")
            distance = max(first - anchor, anchor - (first + count - 1), 0) if anchor is not None else 0
            range_distance = min((max(first - row["end_line"], row["start_line"] - last, 0)
                                  for sha, first, last in visible for row in source_windows
                                  if sha == row["commit"]), default=0)
            priority = (overlaps(meaningful, selected_windows), overlaps(changed, selected_windows),
                        overlaps(meaningful, source_windows), bool(meaningful) and in_source,
                        in_source, -distance, -range_distance)
            candidates.append((priority, requests))
    return max(candidates, key=lambda item: item[0])[1] if candidates else []


def uncovered_comparison_reads(requests, receipts):
    """Skip source already visible across agreeing adjacent same-SHA receipts.

    This is union coverage only, not a synthetic receipt. The original IDs and
    bytes stay authoritative; conflicting intervals never establish coverage.
    """
    from .entry_navigation import _source

    remaining = []
    for request in requests[:2]:
        first, last, rows, conflict = request["start_line"], request["end_line"], {}, False
        for receipt in receipts:
            source = _source(receipt, request["commit"])
            if source is None or source["path"] != request["path"]:
                continue
            for line in range(max(first, source["first"]), min(last, source["last"]) + 1):
                code = source["lines"][line - source["first"]]
                if line in rows and rows[line] != code:
                    conflict = True
                rows[line] = code
        if conflict or any(line not in rows for line in range(first, last + 1)):
            remaining.append(request)
    return remaining


def _searched_declaration_seed(review):
    """A read declaration can guide comparison even without a chosen location.

    Only repeat an explicit declaration search that actually hit the cited
    same-SHA source. This is one investigation direction, not a field value.
    An empty/invalid annotation location cannot itself provide any coordinates.
    """
    from .entry_navigation import _source, _declaration

    fields, suggestions = review.get("draft_fields", {}), review.get("suggested_values", {})
    judgments, receipts = review.get("field_reviews"), review.get("evidence")
    if (not all(isinstance(item, Mapping) for item in (fields, suggestions, judgments))
            or not isinstance(receipts, list) or len(receipts) > 256):
        return None
    choices = [item for item in (fields.get("commit"), suggestions.get("commit")) if item is not None]
    if not choices or any(not isinstance(item, str) or not _SHA.fullmatch(item) for item in choices) or len(set(choices)) != 1:
        return None
    commit = choices[0]
    by_id = {}
    for row in receipts:
        if not isinstance(row, Mapping) or not isinstance(row.get("id"), str) or row["id"] in by_id:
            return None
        by_id[row["id"]] = row
    cited = set()
    for field in ("commit", "entry_point", "critical_operation"):
        decision = judgments.get(field)
        refs = decision.get("evidence_refs") if isinstance(decision, Mapping) else None
        if isinstance(refs, list):
            cited.update(ref for ref in refs[:24] if isinstance(ref, str))
    sources = {identity: source for identity, row in by_id.items()
               if identity in cited and (source := _source(row, commit))}
    query_pattern = re.compile(r"(?:async\s+)?(?:def|function|func|class)\s+([A-Za-z_$][A-Za-z0-9_$]{1,127})\Z")
    for row in receipts:
        data = row.get("result")
        if (row.get("tool") != "search_code" or row.get("success") is not True or row.get("error")
                or not isinstance(data, Mapping) or data.get("commit") != commit or data.get("error")
                or data.get("ok") is False or data.get("success") is False
                or data.get("truncated") is True or data.get("complete") is False
                or not isinstance(data.get("matches"), list) or not isinstance(data.get("query"), str)):
            continue
        match = query_pattern.fullmatch(data["query"].strip())
        if match is None:
            continue
        name, candidates = match[1], {}
        for hit in data["matches"][:100]:
            if not isinstance(hit, Mapping) or type(hit.get("line")) is not int or not isinstance(hit.get("code"), str):
                continue
            for identity, source in sources.items():
                if (hit.get("file") == source["path"] and source["first"] <= hit["line"] <= source["last"]
                        and source["lines"][hit["line"] - source["first"]] == hit["code"]
                        and _declaration(hit["code"]) == name):
                    candidates.setdefault((source["path"], hit["line"]), identity)
        if len(candidates) == 1:
            (path, _), identity = next(iter(candidates.items()))
            return {"commit": commit, "path": path, "symbol": name, "evidence_ref": identity}
    return None


def _unselected_source_seed(review):
    """Choose a read direction when the draft did not suggest any revision.

    A missing model selection must not prevent looking at an already inspected
    alternative. Require one unambiguous cited source file/SHA. Prefer the
    actual operation/entry location, then those fields' source citations, before
    broad commit citations. This does not choose an affected revision or role.
    """
    from .entry_navigation import _source, _declaration

    fields, suggestions = review.get("draft_fields", {}), review.get("suggested_values", {})
    judgments, receipts = review.get("field_reviews"), review.get("evidence")
    if (not all(isinstance(item, Mapping) for item in (fields, suggestions, judgments))
            or not isinstance(receipts, list) or len(receipts) > 256
            or fields.get("commit") is not None or suggestions.get("commit") is not None):
        return None
    by_id = {}
    for row in receipts:
        if not isinstance(row, Mapping) or not isinstance(row.get("id"), str) or row["id"] in by_id:
            return None
        by_id[row["id"]] = row
    cited = set()
    for field in ("critical_operation", "entry_point", "commit"):
        decision = judgments.get(field)
        refs = decision.get("evidence_refs") if isinstance(decision, Mapping) else None
        if isinstance(refs, list):
            cited.update(ref for ref in refs[:24] if isinstance(ref, str))
    sources = []
    for identity, row in by_id.items():
        data = row.get("result")
        sha = data.get("commit") if isinstance(data, Mapping) else None
        if identity in cited and isinstance(sha, str) and _SHA.fullmatch(sha):
            source = _source(row, sha)
            if source:
                sources.append((identity, sha, source))
    if len({(sha, source["path"]) for _, sha, source in sources}) != 1:
        return None
    sha = sources[0][1]
    # The source SHA is a read direction, NOT a synthesized commit decision.
    # Preserve all original fields, suggestions, judgments and receipt bytes.
    if direction := _selected_comparison_direction(review, sha, by_id):
        return direction
    priorities = {}
    for rank, field in enumerate(("critical_operation", "entry_point", "commit")):
        decision = judgments.get(field)
        refs = decision.get("evidence_refs") if isinstance(decision, Mapping) else None
        if isinstance(refs, list):
            for identity in refs[:24]:
                if isinstance(identity, str):
                    priorities.setdefault(identity, rank)
    declarations = []
    for identity, sha, source in sources:
        for offset, line in enumerate(source["lines"]):
            name = _declaration(line)
            if name:
                declarations.append((priorities.get(identity, 3), source["first"] + offset,
                                     identity, name, sha, source["path"]))
    if not declarations:
        return None
    _, _, identity, name, sha, path = min(declarations)
    return {"commit": sha, "path": path, "symbol": name, "evidence_ref": identity}


def _selected_comparison_direction(review, sha, receipts):
    """An actual selected local call/owner outranks a file's first declaration.

    A selected declaration identifies the function to compare, even if its
    body assigns a library call. For a call-only selection, a direct assigned
    callee can guide the search; the other snapshot must contain its declaration.
    This lexical clue establishes neither a call graph nor a field's support.
    """
    from .entry_navigation import _selected_location_source, _symbol_at, _symbol_across_receipts, _source

    fields, suggestions, judgments = (review.get(key, {}) for key in
                                      ("draft_fields", "suggested_values", "field_reviews"))
    assigned_call = re.compile(r"^\s*[A-Za-z_]\w*\s*=\s*(?:await\s+)?([A-Za-z_]\w{1,127})\s*\(")
    for field in ("critical_operation", "entry_point"):
        current, suggested = fields.get(field), suggestions.get(field)
        if current is not None and suggested is not None and current != suggested:
            continue
        value = current if current is not None else suggested
        selected = _selected_location_source(value, judgments.get(field, {}), sha, receipts)
        if selected is None:
            continue
        source, first, last = selected
        identities = ([value["evidence_ref"]] if isinstance(value.get("evidence_ref"), str)
                      else judgments.get(field, {}).get("evidence_refs", []))
        identity = next((ref for ref in identities[:24] if isinstance(ref, str)
                         and ref in receipts and _source(receipts[ref], sha) == source), None)
        if identity is None:
            continue
        owner = _symbol_at(source, first, leading_blanks=True, selected_end=last)
        if owner and first <= owner["line"] <= last:
            # A whole-function selection is not a request to compare a nested
            # query builder or constructor. Keep the actual selected owner;
            # no name list, framework guess or field promotion is needed.
            return {"commit": sha, "path": source["path"], "symbol": owner["symbol"], "evidence_ref": identity}
        calls = {match[1] for line in source["lines"][first - source["first"]:last - source["first"] + 1]
                 if (match := assigned_call.match(line)) and match[1] not in
                 {"dict", "list", "tuple", "str", "bytes", "int", "float", "bool", "set"}}
        if len(calls) == 1:
            return {"commit": sha, "path": source["path"], "symbol": next(iter(calls)), "evidence_ref": identity}
        if owner is None:
            joined = _symbol_across_receipts(source, first, last, sha, receipts)
            if joined:
                owner, identity = joined
        if owner:
            return {"commit": sha, "path": source["path"], "symbol": owner["symbol"], "evidence_ref": identity}
    return None


def alternative_snapshot_seed(review):
    """One unexamined inspected snapshot for an unresolved source judgment.

    The path/name come from an actual current source window. The alternative
    SHA must already have a successful inspect_commit receipt; never derive a
    parent, use HEAD, or label either side affected. Only a read containing the
    relevant declaration prevents comparison; a file header is not its body.
    """
    from .entry_navigation import entry_navigation_seed, _source, _declaration

    if not isinstance(review, Mapping):
        return None
    judgments = review.get("field_reviews")
    decision = judgments.get("commit") if isinstance(judgments, Mapping) else None
    if (not isinstance(decision, Mapping) or decision.get("status") not in ("uncertain", "missing")
            or decision.get("revision_basis") not in ("inspected_only", "unknown", "behavior_at_revision", "affected_range_and_source")):
        return None
    # An uncertain revision still needs comparison when its route is an
    # established entry. Prefer the observed operation's enclosing symbol;
    # neither an EP label nor a proposed basis proves the revision correct.
    if "navigation_evidence_refs" in review:
        # A late pass is scoped to the newly completed reads. Do not repeat
        # earlier navigation when the focused request failed or read no body.
        seed = _focused_source_seed(review)
    else:
        seed = entry_navigation_seed(review, include_supported=True, prefer_operation=True)
        if seed is None:
            seed = _searched_declaration_seed(review)
        if seed is None:
            seed = _unselected_source_seed(review)
    if seed is None:
        return None
    receipts = review["evidence"]  # Validated by either source-seed path.
    # The seed already proves a successful full-SHA source read. Its SHA need
    # not also have an inspect_commit receipt. Only the alternative needs that
    # receipt; coverage display is not a read prerequisite.
    for candidate, inspection_ref in list(_inspection_refs(receipts).items())[:4]:
        if candidate == seed["commit"]:
            continue
        if seed.get("target_revision") is not None and candidate != seed["target_revision"]:
            continue
        if any(source and source["path"] == seed["path"]
               and any(_declaration(line) == seed["symbol"] for line in source["lines"])
               for source in (_source(receipt, candidate) for receipt in receipts)):
            continue
        return {"commit": candidate, "path": seed["path"], "symbol": seed["symbol"],
                "inspection_ref": inspection_ref, "source_evidence_ref": seed["evidence_ref"],
                "source_revision": seed["commit"]}
    return None


def _focused_assigned_helper(direction, receipts):
    """Prefer one direct assigned callee inside the newly read Python function.

    Comparing another wrapper can leave its decisive helper unread. Parse only
    the observed function, not its siblings, strings or nested definitions.
    Ambiguous/partial/unsupported syntax keeps the original read direction.
    This selects a search string, never an edge, field or affected revision.
    """
    from .entry_navigation import _source, _declaration

    if not direction["path"].endswith(".py"):
        return direction
    receipt = next((row for row in receipts if row.get("id") == direction["evidence_ref"]), None)
    source = _source(receipt, direction["commit"])
    if source is None:
        return direction
    starts = [i for i, line in enumerate(source["lines"])
              if _declaration(line) == direction["symbol"]]
    if len(starts) != 1:
        return direction
    first = starts[0]
    indent = len(source["lines"][first]) - len(source["lines"][first].lstrip())
    last = len(source["lines"])
    for i in range(first + 1, last):
        line = source["lines"][i]
        if (line.strip() and len(line) - len(line.lstrip()) <= indent
                and (_declaration(line) or line.lstrip().startswith("@"))):
            last = i
            break
    text = textwrap.dedent("\n".join(source["lines"][first:last]))
    if len(text) > 16_000:
        return direction
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError, RecursionError):
        return direction
    if (len(tree.body) != 1 or not isinstance(tree.body[0], (ast.FunctionDef, ast.AsyncFunctionDef))
            or tree.body[0].name != direction["symbol"]):
        return direction
    function = tree.body[0]
    shadowed = {arg.arg for arg in (*function.args.posonlyargs, *function.args.args, *function.args.kwonlyargs)}
    shadowed.update(arg.arg for arg in (function.args.vararg, function.args.kwarg) if arg)
    calls, pending = set(), list(function.body)
    while pending:
        node = pending.pop()
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            shadowed.add(node.name)
            continue
        if isinstance(node, ast.Lambda):
            continue
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            shadowed.update(alias.asname or alias.name.split(".")[0] for alias in node.names)
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store):
            shadowed.add(node.id)
        if isinstance(node, ast.Assign) and all(isinstance(target, ast.Name) for target in node.targets):
            value = node.value.value if isinstance(node.value, ast.Await) else node.value
            if isinstance(value, ast.Call) and isinstance(value.func, ast.Name):
                calls.add(value.func.id)
        pending.extend(ast.iter_child_nodes(node))
    calls -= shadowed | {function.name, "dict", "list", "tuple", "str", "bytes", "int", "float", "bool", "set"}
    if len(calls) != 1:
        return direction
    return {**direction, "symbol": calls.pop()}


def comparison_helper_seed(receipt, comparison, receipts):
    """One same-SHA helper clue after reading a compared Python wrapper.

    Reuse the bounded AST selector; do not recursively navigate helpers or
    interpret an argument named user/owner as an implemented check. The later
    search must find the helper's actual declaration before a source read.
    """
    from .entry_navigation import _source, _declaration

    if (not isinstance(receipt, Mapping) or not isinstance(comparison, Mapping)
            or not isinstance(receipts, list) or len(receipts) > 256
            or any(not isinstance(row, Mapping) for row in receipts)):
        return None
    commit, path, symbol = (comparison.get(key) for key in ("commit", "path", "symbol"))
    identity = receipt.get("id")
    if (not isinstance(commit, str) or not _SHA.fullmatch(commit)
            or not isinstance(symbol, str) or not re.fullmatch(r"[A-Za-z_]\w{1,127}", symbol)
            or not isinstance(identity, str) or not re.fullmatch(r"E\d{4,8}", identity)):
        return None
    source = _source(receipt, commit)
    if source is None or source["path"] != path:
        return None
    matching = [row for row in receipts if row.get("id") == identity]
    if len(matching) != 1 or matching[0] != receipt:
        return None
    direction = {"commit": commit, "path": path, "symbol": symbol, "evidence_ref": identity}
    helper = _focused_assigned_helper(direction, receipts)
    if helper["symbol"] == symbol:
        return None
    if any(saved and saved["path"] == path
           and any(_declaration(line) == helper["symbol"] for line in saved["lines"])
           for saved in (_source(row, commit) for row in receipts)):
        return None
    return helper


def _focused_source_seed(review):
    """A newly completed focused read may guide comparison before self-review.

    It need not have been cited by the earlier snapshot, which could not have
    seen it. Only the controller supplies these IDs. Require one actual file
    and SHA. An explicit other inspected selection is the comparison target,
    not a reason to discard this new source. Conflicting/invalid selections stop.
    No field judgment is made or modified here.
    """
    refs = review.get("navigation_evidence_refs")
    if (not isinstance(refs, list) or not 1 <= len(refs) <= 2
            or any(not isinstance(ref, str) or not re.fullmatch(r"E\d{4,8}", ref) for ref in refs)):
        return None
    direction = _unselected_source_seed({"draft_fields": {}, "suggested_values": {},
        "field_reviews": {"commit": {"evidence_refs": refs}}, "evidence": review.get("evidence")})
    if direction is None:
        return None
    direction = _focused_assigned_helper(direction, review["evidence"])
    choices = []
    for key in ("draft_fields", "suggested_values"):
        fields = review.get(key) or {}
        if not isinstance(fields, Mapping):
            return None
        if fields.get("commit") is not None:
            choices.append(fields["commit"])
    if (any(not isinstance(value, str) or not _SHA.fullmatch(value) for value in choices)
            or len(set(choices)) > 1):
        return None
    if choices and choices[0] != direction["commit"]:
        if choices[0] not in _inspection_refs(review["evidence"]):
            return None
        direction = {**direction, "target_revision": choices[0]}
    return direction


def alternative_snapshot_read(receipt, seed):
    """Locate the declaration anew; line coordinates never cross revisions."""
    from .entry_navigation import _declaration
    from .source_refs import _positive_line

    if not isinstance(seed, Mapping) or not isinstance(receipt, Mapping):
        return None
    if (not isinstance(seed.get("commit"), str) or not _SHA.fullmatch(seed["commit"])
            or not _relative_path(seed.get("path")) or not isinstance(seed.get("symbol"), str)):
        return None
    data = receipt.get("result")
    if (receipt.get("tool") != "search_code" or receipt.get("success") is not True
            or receipt.get("error") or not isinstance(data, Mapping) or data.get("error")
            or data.get("ok") is False or data.get("success") is False
            or data.get("commit") != seed.get("commit") or data.get("query") != seed.get("symbol")
            or not isinstance(data.get("matches"), list)):
        return None
    for hit in data["matches"][:100]:
        if (not isinstance(hit, Mapping) or hit.get("file") != seed.get("path")
                or not _relative_path(hit.get("file")) or not _positive_line(hit.get("line"))
                or hit["line"] > 99_999_968 or not isinstance(hit.get("code"), str)
                or _declaration(hit["code"]) != seed.get("symbol")):
            continue
        return {"commit": seed["commit"], "path": hit["file"],
                "start_line": max(1, hit["line"] - 80), "end_line": hit["line"] + 32}
    return None
