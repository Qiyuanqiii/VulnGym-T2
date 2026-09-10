"""Bounded, offline Git object tools; target source is never executed.

The low-level Git wrapper supplies process containment, argument-list commands,
sanitized environments and rejection of external object storage. This module
adds an intentionally small JSON tool surface, not the old agent orchestrator.
Linked worktrees, partial clones and alternate object stores are unsupported;
use a complete standalone local clone (or bare repository).
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from ._vendor.git_repository import (
    GitBlobTooLarge, GitCommandError, GitDiffTooLarge, GitFactError,
    GitOutputTooLarge, GitRepository, GitTextDecodeError, GitTimeoutError,
    validate_repo_relative_path,
)

MAX_BLOB_BYTES = 1024 * 1024
MAX_TEXT_CHARS = 24000
MAX_FILE_LINES = 300
MAX_FILES = 200
MAX_TREE_BYTES = 4 * 1024 * 1024
MAX_MATCHES = 100
MAX_SEARCH_FILES = 400
MAX_SEARCH_BYTES = 4 * 1024 * 1024
TOOL_TIMEOUT_SECONDS = 20
_REF = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/\-]{0,159}(?:[~^][0-9]{0,4}){0,4}\Z")
_SHA = re.compile(r"[0-9a-f]{40}\Z")


def canonical_repo_url(value: object) -> str | None:
    """Only expose credential-free GitHub repository identity, never raw remotes."""
    if not isinstance(value, str):
        return None
    if value.startswith("git@github.com:"):
        value = "https://github.com/" + value[len("git@github.com:"):]
    try:
        parts = urlsplit(value)
    except ValueError:
        return None
    if parts.hostname != "github.com" or parts.scheme not in {"https", "ssh", "git"}:
        return None
    pieces = parts.path.strip("/").split("/")
    if len(pieces) != 2:
        return None
    owner, name = pieces
    name = name.removesuffix(".git")
    if not all(re.fullmatch(r"[A-Za-z0-9_.-]+", piece) for piece in (owner, name)):
        return None
    return f"https://github.com/{owner}/{name}"


def _number(value: object, lower: int, upper: int) -> int:
    if type(value) is not int or not lower <= value <= upper:
        raise ValueError("invalid_tool_argument")
    return value


def _path(value: object) -> str:
    try:
        return validate_repo_relative_path(value)
    except ValueError as error:
        raise ValueError("invalid_repo_path") from error


def _lines(text: str) -> list[str]:
    """Git lines use LF (optionally CRLF), not Unicode's extra line separators."""
    if not text:
        return []
    lines = text.replace("\r\n", "\n").split("\n")
    if lines[-1] == "":
        lines.pop()
    return lines


def _code(error: Exception) -> str:
    if isinstance(error, GitTimeoutError):
        return "git_timeout"
    if isinstance(error, (GitBlobTooLarge, GitOutputTooLarge, GitDiffTooLarge)):
        return "git_output_limit"
    if isinstance(error, GitTextDecodeError):
        return "non_utf8_source"
    if isinstance(error, GitCommandError):
        return "git_object_unavailable"
    return "repository_unavailable"


class RepoReader:
    """Read one explicitly supplied local repository without checkout or network."""

    _TOOLS = {
        "inspect_commit": {"commit"},
        "list_files": {"commit", "prefix", "offset", "limit"},
        "read_file": {"commit", "path", "start_line", "end_line"},
        "search_code": {"commit", "query", "paths"},
        "read_diff": {"before", "after", "path"},
    }

    def __init__(self, path: str | Path) -> None:
        try:
            self._git = GitRepository(
                path, timeout_seconds=10, max_blob_bytes=MAX_BLOB_BYTES,
                max_diff_input_bytes=2 * MAX_BLOB_BYTES,
                max_diff_output_bytes=MAX_TEXT_CHARS * 4,
            )
        except (GitFactError, OSError, TypeError, ValueError) as error:
            raise ValueError("repository_unavailable") from error
        self.path = str(self._git.path)

    def _run(self, arguments: tuple[str, ...], *, limit: int = MAX_TREE_BYTES,
             check: bool = True) -> bytes:
        try:
            return self._git._run(
                arguments, operation=arguments[0], max_stdout_bytes=limit,
                max_stderr_bytes=4096, check=check,
            ).stdout
        except GitFactError as error:
            raise ValueError(_code(error)) from error

    def resolve_commit(self, commit: object) -> str:
        """Resolve bounded local refs/abbreviations and ancestry suffixes to SHA-1."""
        if (not isinstance(commit, str) or not _REF.fullmatch(commit)
                or ".." in commit or "//" in commit):
            raise ValueError("invalid_commit_ref")
        try:
            resolved = self._run(
                ("rev-parse", "--verify", "--end-of-options", commit + "^{commit}"),
                limit=128,
            ).decode("ascii").strip()
        except (ValueError, UnicodeError) as error:
            raise ValueError("commit_unavailable") from error
        if not _SHA.fullmatch(resolved):
            raise ValueError("commit_unavailable")
        return resolved

    def info(self) -> dict[str, Any]:
        errors: list[str] = []
        try:
            head = self.resolve_commit("HEAD")
        except ValueError as error:
            head = None
            errors.append(str(error))
        remote = self._run(
            ("config", "--no-includes", "--local", "--get", "remote.origin.url"),
            limit=4096, check=False,
        ).decode("utf-8", errors="replace").strip()
        try:
            shallow = self._git.history_is_shallow()
        except GitFactError as error:
            raise ValueError(_code(error)) from error
        return {"repo_path": self.path, "repo_url": canonical_repo_url(remote),
                "head": head, "shallow": shallow, "errors": errors,
                "limits": {"blob_bytes": MAX_BLOB_BYTES,
                           "text_chars": MAX_TEXT_CHARS,
                           "process_timeout_seconds": 10,
                           "tool_timeout_seconds": TOOL_TIMEOUT_SECONDS}}

    def call(self, tool_name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        if not isinstance(tool_name, str) or tool_name not in self._TOOLS:
            raise ValueError("unknown_tool")
        if not isinstance(arguments, dict) or set(arguments) - self._TOOLS[tool_name]:
            raise ValueError("invalid_tool_argument")
        try:
            return getattr(self, tool_name)(**arguments)
        except TypeError as error:
            raise ValueError("invalid_tool_argument") from error
        except GitFactError as error:
            raise ValueError(_code(error)) from error

    def _files(self, commit: str, prefix: str | None = None) -> list[str]:
        args = ("ls-tree", "-r", "-z", "--name-only", commit, "--")
        if prefix:
            args += (prefix,)
        raw = self._run(args)
        try:
            paths = [_path(item.decode("utf-8")) for item in raw.split(b"\0") if item]
        except UnicodeError as error:
            raise ValueError("non_utf8_repo_path") from error
        return sorted(paths)

    def list_files(self, commit: str, prefix: str | None = None,
                   offset: int = 0, limit: int = 100) -> dict[str, Any]:
        commit = self.resolve_commit(commit)
        offset = _number(offset, 0, 1000000)
        limit = _number(limit, 1, MAX_FILES)
        if prefix is not None:
            prefix = _path(prefix.removesuffix("/") if isinstance(prefix, str) else prefix)
        paths = self._files(commit, prefix)
        selected = paths[offset:offset + limit]
        more = offset + len(selected) < len(paths)
        return {"commit": commit, "files": selected, "total_files": len(paths),
                "offset": offset, "next_offset": offset + len(selected) if more else None,
                "truncated": more, "limits": {"files": limit, "tree_bytes": MAX_TREE_BYTES}}

    def _source(self, commit: str, path: str) -> str:
        try:
            entry = self._git.tree_entry(commit, path)
            # Do not interpret symlink targets or submodules as source files.
            if entry is None or entry.mode not in {"100644", "100755"}:
                raise ValueError("source_file_unavailable")
            source = self._git.read_file(commit, path).decode("utf-8", errors="strict")
        except UnicodeError as error:
            raise ValueError("non_utf8_source") from error
        except GitFactError as error:
            raise ValueError(_code(error)) from error
        if "\0" in source:
            raise ValueError("binary_source")
        return source

    def read_file(self, commit: str, path: str, start_line: int = 1,
                  end_line: int | None = None) -> dict[str, Any]:
        commit, path = self.resolve_commit(commit), _path(path)
        start_line = _number(start_line, 1, 100000000)
        requested_end = (start_line + MAX_FILE_LINES - 1 if end_line is None
                         else _number(end_line, start_line, 100000000))
        lines = _lines(self._source(commit, path))
        if start_line > len(lines) and not (not lines and start_line == 1):
            raise ValueError("line_out_of_range")
        stop = min(len(lines), requested_end, start_line + MAX_FILE_LINES - 1)
        selected: list[dict[str, Any]] = []
        size = 0
        for index in range(start_line - 1, stop):
            if size + len(lines[index]) + 1 > MAX_TEXT_CHARS:
                break
            selected.append({"line": index + 1, "code": lines[index]})
            size += len(lines[index]) + 1
        last = selected[-1]["line"] if selected else start_line - 1
        return {"commit": commit, "path": path, "start_line": start_line,
                "end_line": last, "total_lines": len(lines), "lines": selected,
                "text": "\n".join(item["code"] for item in selected),
                "truncated": last < min(len(lines), requested_end),
                "has_more": last < len(lines),
                "limits": {"lines": MAX_FILE_LINES, "text_chars": MAX_TEXT_CHARS,
                           "blob_bytes": MAX_BLOB_BYTES}}

    def inspect_commit(self, commit: str) -> dict[str, Any]:
        commit = self.resolve_commit(commit)
        raw = self._run(("cat-file", "commit", commit), limit=1024 * 1024)
        header, _, message = raw.partition(b"\n\n")
        parents = [line[7:].decode("ascii") for line in header.splitlines()
                   if line.startswith(b"parent ")]
        paths = self._changed(parents[0], commit) if parents else self._files(commit)
        text = message.decode("utf-8", errors="replace")
        return {"commit": commit, "parents": parents,
                "message": text[:8000], "changed_paths": paths[:MAX_FILES],
                "changed_paths_total": len(paths),
                "changed_paths_against": parents[0] if parents else None,
                "truncated": len(text) > 8000 or len(paths) > MAX_FILES,
                "limits": {"message_chars": 8000, "changed_paths": MAX_FILES}}

    def _changed(self, before: str, after: str) -> list[str]:
        try:
            return list(self._git.changed_paths(before, after, max_paths=100000,
                                                max_output_bytes=MAX_TREE_BYTES))
        except GitFactError as error:
            raise ValueError(_code(error)) from error

    def read_diff(self, before: str, after: str,
                  path: str | None = None) -> dict[str, Any]:
        before, after = self.resolve_commit(before), self.resolve_commit(after)
        paths = self._changed(before, after)
        if path is not None:
            path = _path(path)
            paths = [item for item in paths if item == path]
        args = ("diff", "--no-ext-diff", "--no-textconv", "--no-renames",
                "--no-color", "--unified=3", before, after, "--")
        if path is not None:
            args += (path,)
        # Strict transport ceiling, followed by explicit presentation truncation.
        raw = self._run(args, limit=2 * 1024 * 1024)
        diff = raw.decode("utf-8", errors="replace")
        return {"before": before, "after": after, "paths": paths[:MAX_FILES],
                "paths_total": len(paths), "diff": diff[:MAX_TEXT_CHARS],
                "truncated": len(diff) > MAX_TEXT_CHARS or len(paths) > MAX_FILES,
                "limits": {"text_chars": MAX_TEXT_CHARS, "paths": MAX_FILES,
                           "transport_bytes": 2 * 1024 * 1024}}

    def search_code(self, commit: str, query: str,
                    paths: list[str] | None = None) -> dict[str, Any]:
        """Literal search of immutable tracked text, optionally under directories.

        Prefixes are expanded against the commit tree, not the worktree. Git's
        fixed-string search avoids hundreds of per-file subprocesses; it uses
        the same bounded transport, no textconv and no submodule recursion.
        """
        commit = self.resolve_commit(commit)
        if (not isinstance(query, str) or not query or len(query) > 256
                or any(char in query for char in "\x00\r\n")):
            raise ValueError("invalid_search_query")
        if paths is not None and (not isinstance(paths, list) or len(paths) > MAX_SEARCH_FILES
                                  or not all(isinstance(item, str) for item in paths)):
            raise ValueError("invalid_tool_argument")
        prefixes = None if paths is None else sorted(set(_path(item.removesuffix("/")) for item in paths))
        if prefixes is not None and sum(len(item) + 1 for item in prefixes) > 20000:
            raise ValueError("search_path_argument_limit")
        all_paths = self._files(commit)
        skipped: list[dict[str, str]] = []
        if prefixes is None:
            candidates = all_paths
        else:
            candidates = []
            for prefix in prefixes:
                selected = [path for path in all_paths if path == prefix or path.startswith(prefix + "/")]
                if not selected:
                    skipped.append({"path": prefix, "error": "source_path_unavailable"})
                candidates.extend(selected)
            candidates = sorted(set(candidates))
        matches: list[dict[str, Any]] = []
        chars = 0
        truncated = False
        raw = b""
        if candidates:
            args = ("-c", "grep.threads=1", "grep", "--no-textconv", "--no-recurse-submodules",
                    "--no-color", "--no-heading", "--no-break", "--no-column", "--full-name",
                    "-I", "-n", "-z", "-F", f"--max-count={MAX_MATCHES}", "-e", query, commit, "--")
            if prefixes is not None:
                args += tuple(prefixes)
            try:
                result = self._git._run(args, operation="grep", check=False,
                                        max_stdout_bytes=MAX_SEARCH_BYTES, max_stderr_bytes=4096)
            except GitFactError as error:
                raise ValueError(_code(error)) from error
            if result.returncode not in {0, 1} or result.stderr:
                raise ValueError("git_search_failed")
            raw = result.stdout
        for record in raw.split(b"\n"):
            if not record:
                continue
            try:
                header, raw_number, raw_code = record.split(b"\0", 2)
                prefix = (commit + ":").encode("ascii")
                if not header.startswith(prefix) or not raw_number.isdigit():
                    raise ValueError
                path = _path(header[len(prefix):].decode("utf-8"))
                number = int(raw_number)
                if number < 1:
                    raise ValueError
            except (ValueError, UnicodeError) as error:
                raise ValueError("git_search_response_invalid") from error
            try:
                code = raw_code.decode("utf-8").removesuffix("\r")
            except UnicodeError:
                skipped.append({"path": path, "error": "non_utf8_source"})
                continue
            if len(matches) >= MAX_MATCHES or chars + len(code) > MAX_TEXT_CHARS:
                truncated = True
                break
            matches.append({"file": path, "line": number, "code": code})
            chars += len(code)
        # -m is per file, so reaching the presentation cap is conservatively
        # incomplete even if no extra matching record was captured.
        truncated = truncated or len(matches) >= MAX_MATCHES
        return {"commit": commit, "query": query, "matches": matches,
                "scanned_files": len(candidates), "candidate_files": len(candidates),
                "paths": prefixes,
                "search_scope": "tracked text blobs; binary files and submodules excluded",
                "skipped": skipped[:20], "skipped_count": len(skipped),
                "truncated": truncated or len(skipped) > 20,
                "complete": not truncated and not skipped,
                "limits": {"matches": MAX_MATCHES, "path_arguments": MAX_SEARCH_FILES,
                           "output_bytes": MAX_SEARCH_BYTES, "text_chars": MAX_TEXT_CHARS,
                           "process_timeout_seconds": self._git.timeout_seconds}}

    def validate_location(self, commit: str, location: object) -> dict[str, Any]:
        """Check exact complete lines at this commit; preserve all indentation.

        Line endings are represented as LF in JSON. An integer anchors a snippet
        at its first line; a range must cover its exact number of complete lines.
        """
        try:
            commit = self.resolve_commit(commit)
            if not isinstance(location, dict):
                raise ValueError("invalid_location")
            path, line, code = _path(location.get("file")), location.get("line"), location.get("code")
            if not isinstance(code, str) or not code or len(code) > MAX_TEXT_CHARS:
                raise ValueError("invalid_location_code")
            if type(line) is int:
                start = _number(line, 1, 100000000)
                end = start + len(code.split("\n")) - 1
            elif isinstance(line, str) and re.fullmatch(r"[1-9][0-9]{0,8}(?:-[1-9][0-9]{0,8})?", line):
                pieces = line.split("-")
                start, end = int(pieces[0]), int(pieces[-1])
                if end < start:
                    raise ValueError("invalid_location_line")
            else:
                raise ValueError("invalid_location_line")
            lines = _lines(self._source(commit, path))
            if start < 1 or end > len(lines):
                raise ValueError("line_out_of_range")
            actual = "\n".join(lines[start - 1:end])
            if actual != code:
                raise ValueError("code_not_verbatim_at_commit")
            return {"valid": True, "commit": commit, "file": path,
                    "start_line": start, "end_line": end, "reason": "verbatim_match"}
        except (ValueError, GitFactError) as error:
            return {"valid": False, "commit": commit,
                    "reason": str(error) if isinstance(error, ValueError) else _code(error)}
