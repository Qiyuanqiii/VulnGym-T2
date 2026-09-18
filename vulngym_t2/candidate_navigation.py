"""Locate one unread candidate file from receipts, not from guessed paths.

Proposal words rank navigation only. A changed path must come from a successful
commit/diff receipt, and the revision must already have actual source nearby.
The caller owns the original budgets and applies no field decisions here.
"""
from __future__ import annotations

from collections.abc import Mapping
from pathlib import PurePosixPath
import re

from .entry_navigation import _source
from .source_refs import _relative_path


_SHA = re.compile(r"[0-9a-f]{40}\Z")
_WORDS = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_SOURCE_SUFFIXES = frozenset({".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".go", ".java", ".rs", ".svelte", ".vue"})


def candidate_body_request(scope, evidence):
    """Return a unique, observed path/revision to inspect, or no preference.

The file's base name must occur in the proposal. For each mentioned base name,
its nearest already-read directory must be unique among the proposal's own
source citations. Only one unread winner may remain across these groups. This
keeps an already-read helper from hiding another named file, without replacing
an already-read implementation with a same-named sibling. Ambiguity preserves
normal model-directed reading.
"""
    if not isinstance(scope, Mapping) or not isinstance(scope.get("scope"), str):
        return None
    refs = scope.get("evidence_refs")
    if not isinstance(refs, list) or not isinstance(evidence, list):
        return None
    refs = {value for value in refs if isinstance(value, str)}
    words = {word.casefold() for word in _WORDS.findall(scope["scope"])}
    sources, paths = [], {}
    for receipt in evidence:
        if not isinstance(receipt, Mapping):
            continue
        data = receipt.get("result")
        if (not isinstance(receipt.get("id"), str) or receipt["id"] not in refs or receipt.get("success") is not True
                or receipt.get("error") or not isinstance(data, Mapping)
                or data.get("error") or data.get("success") is False or data.get("ok") is False):
            continue
        sha = data.get("commit")
        source = _source(receipt, sha) if isinstance(sha, str) and _SHA.fullmatch(sha) else None
        if source is not None:
            sources.append((receipt["id"], sha, source["path"]))
        if receipt.get("tool") == "inspect_commit" and isinstance(sha, str) and _SHA.fullmatch(sha):
            revisions = {sha}
            parent = data.get("changed_paths_against")
            if isinstance(parent, str) and _SHA.fullmatch(parent):
                revisions.add(parent)
            candidates = data.get("changed_paths")
        elif receipt.get("tool") == "read_diff":
            revisions = {value for value in (data.get("before"), data.get("after"))
                         if isinstance(value, str) and _SHA.fullmatch(value)}
            candidates = data.get("paths")
        else:
            continue
        if not isinstance(candidates, list):
            continue
        for path in candidates:
            if (not isinstance(path, str) or len(path) > 500 or not _relative_path(path)
                    or PurePosixPath(path).suffix not in _SOURCE_SUFFIXES):
                continue
            # Exact lexical match only. The observed source directory supplies
            # component identity; no project aliases or vulnerability labels.
            basename = PurePosixPath(path).name.split(".", 1)[0].casefold()
            if len(basename) < 3 or basename not in words:
                continue
            paths.setdefault(path, []).append((receipt["id"], revisions))

    ranked = {}
    for path, origins in paths.items():
        parent_parts = PurePosixPath(path).parent.parts
        for source_ref, sha, source_path in sources:
            allowed = [ref for ref, revisions in origins if sha in revisions]
            if not allowed:
                continue
            shared = 0
            for left, right in zip(parent_parts, PurePosixPath(source_path).parent.parts):
                if left != right:
                    break
                shared += 1
            if shared < 2:
                continue
            key = sha, path
            value = {"arguments": {"commit": sha, "path": path, "start_line": 1, "end_line": 180},
                     "evidence_refs": list(dict.fromkeys([source_ref, *allowed])),
                     "shared_directories": shared}
            if key not in ranked or shared > ranked[key]["shared_directories"]:
                ranked[key] = value
    groups = {}
    for item in ranked.values():
        basename = PurePosixPath(item["arguments"]["path"]).name.split(".", 1)[0].casefold()
        groups.setdefault(basename, []).append(item)
    unread = []
    for group in groups.values():
        best = max(item["shared_directories"] for item in group)
        winners = [item for item in group if item["shared_directories"] == best]
        if len(winners) != 1:
            return None
        selected = winners[0]
        args = selected["arguments"]
        # Keep already-read files in the ranking: removing one before ranking
        # could incorrectly select a lower-ranked, same-named sibling. Partial
        # windows belong to the existing continuation mechanism, not this one.
        if any(source and source["path"] == args["path"]
               for source in (_source(row, args["commit"]) for row in evidence)):
            continue
        unread.append(selected)
    return unread[0] if len(unread) == 1 else None
