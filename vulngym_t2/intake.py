"""Small public-input loader: local advisory, report JSONL or cached GHSA URLs.

Only explicit input files, immediate advisory-bundle files and predictable GHSA
cache names are read. No network, benchmark discovery or source-path manifest is
used. Relative record paths are relative to the input JSONL (map paths to its map).
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from .repository import RepoReader, canonical_repo_url

MAX_INPUT_BYTES = 4 * 1024 * 1024
MAX_DOCUMENT_BYTES = 256 * 1024
MAX_DOCUMENT_CHARS = 24000
MAX_DOCUMENTS = 8
MAX_JOBS = 500
_GHSA = re.compile(r"\bGHSA-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4}\b", re.I)
_COMMIT_URL = re.compile(r"https://github\.com/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)/commit/([0-9a-fA-F]{7,40})(?![0-9a-fA-F])")
_SHA = re.compile(r"[0-9a-fA-F]{7,40}\Z")
_SUFFIXES = {".txt", ".md", ".json", ".html", ".patch", ".diff"}


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _input_json(text: str | bytes) -> Any:
    """Reject ambiguous or non-UTF-8 JSON before deriving input identities."""
    def object_pairs(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError("duplicate_json_key")
            value[key] = item
        return value

    value = json.loads(text, object_pairs_hook=object_pairs)
    # The decoder accepts non-finite numbers and escaped lone surrogates, but
    # neither can safely cross the later UTF-8 model/output boundary.
    json.dumps(value, ensure_ascii=False, allow_nan=False).encode("utf-8")
    return value


def _read(path: Path, limit: int) -> bytes:
    if not path.is_file():
        raise ValueError("input_file_missing")
    try:
        with path.open("rb") as stream:
            raw = stream.read(limit + 1)
    except OSError as error:
        raise ValueError("input_file_unreadable") from error
    if len(raw) > limit:
        raise ValueError("input_file_too_large")
    return raw


def _local(value: object, base: Path) -> Path:
    if not isinstance(value, (str, Path)) or not str(value):
        raise ValueError("local_path_missing")
    text = str(value)
    if "://" in text or text.startswith(("\\\\", "//")):
        raise ValueError("local_path_required")
    path = Path(text).expanduser()
    return (path if path.is_absolute() else base / path).resolve()


def _document(name: str, kind: str, text: str) -> dict[str, Any]:
    return {"name": name[:200], "kind": kind[:60],
            "text": text[:MAX_DOCUMENT_CHARS], "truncated": len(text) > MAX_DOCUMENT_CHARS,
            "limits": {"text_chars": MAX_DOCUMENT_CHARS}}


def _advisory_json_document(name: str, kind: str, value: object,
                            source_chars: int) -> dict[str, Any] | None:
    """Render known input fields, never promote JSON into annotation/output fields."""
    if (not isinstance(value, dict) or not isinstance(value.get("ghsa_id"), str)
            or not _GHSA.fullmatch(value["ghsa_id"])
            or not isinstance(value.get("summary"), str)
            or not isinstance(value.get("description"), str)
            or any(key in value and not isinstance(value[key], list)
                   for key in ("identifiers", "references", "vulnerabilities"))):
        return None
    truncated_fields: list[str] = []

    def bounded(field: str, text: str, limit: int) -> str:
        if len(text) > limit:
            truncated_fields.append(field)
        return text[:limit]

    identifiers = []
    identifier_values = [value["ghsa_id"]]
    for item in value.get("identifiers", []):
        if isinstance(item, dict) and isinstance(item.get("value"), str):
            identifiers.append(f"{_as_text(item.get('type'))}: {item['value']}")
            identifier_values.append(item["value"])
    if isinstance(value.get("cve_id"), str):
        identifiers.append("CVE: " + value["cve_id"])
        identifier_values.append(value["cve_id"])
    known_ids = {item.strip().upper() for item in identifier_values
                 if item.strip() and len(item.strip()) <= 128 and not any(char.isspace() for char in item.strip())}
    ghsa_id = value["ghsa_id"].upper()
    if any(len(item.strip()) > 128 for item in identifier_values) or len(known_ids) > 64:
        truncated_fields.append("advisory_metadata.vuln_ids")
    # Keep the report's own identity even when an unusually large identifier list
    # requires bounding. Values originate only in supplied metadata fields.
    known_ids = set(sorted(known_ids - {ghsa_id})[:63]) | {ghsa_id}
    vuln_ids = sorted(known_ids, key=lambda item: (0 if item.startswith("CVE-") else
                                                  1 if item.startswith("GHSA-") else 2, item))
    packages = []
    for item in value.get("vulnerabilities", []):
        if not isinstance(item, dict):
            continue
        selected = {key: item[key] for key in
                    ("package", "vulnerable_version_range", "first_patched_version",
                     "vulnerable_functions") if key in item}
        if selected:
            packages.append(json.dumps(selected, ensure_ascii=False, sort_keys=True))
    references = []
    for item in value.get("references", []):
        url = item if isinstance(item, str) else item.get("url") if isinstance(item, dict) else None
        if isinstance(url, str):
            references.append(url)
    # This explicit array is candidate input, not proof of a fix or vulnerable
    # revision. URLs are checked against the selected repository later, when
    # the job's local repository identity is known.
    fix_candidates = []
    candidate_warnings = []
    repository_hint = canonical_repo_url(value.get("source_code_location"))
    if value.get("source_code_location") and repository_hint is None:
        candidate_warnings.append("invalid_advisory_repository_hint")
    supplied_fixes = value.get("fix_commits", [])
    if not isinstance(supplied_fixes, list):
        candidate_warnings.append("invalid_advisory_fix_commits")
        supplied_fixes = []
    if len(supplied_fixes) > 32:
        truncated_fields.append("fix_commits")
    for item in supplied_fixes[:32]:
        if isinstance(item, str) and (_SHA.fullmatch(item) or _COMMIT_URL.fullmatch(item)):
            fix_candidates.append(item.lower() if _SHA.fullmatch(item) else item)
        else:
            candidate_warnings.append("invalid_advisory_fix_commit_ignored")
    # Keep quoted commit links available even when a long description needs a
    # presentation limit. Intake's separate same-repository filter still applies.
    quoted_commits = [match.group() for text in [*references, value["description"]]
                      for match in _COMMIT_URL.finditer(text)]
    references = list(dict.fromkeys([*quoted_commits, *references]))
    parts = ["GitHub advisory input (source material, not an annotation).",
             "GHSA: " + value["ghsa_id"],
             "Summary:\n" + bounded("summary", value["summary"], 2000)]
    if identifiers:
        parts.append("Identifiers:\n" + bounded("identifiers", "\n".join(identifiers), 1000))
    if packages:
        parts.append("Affected package facts:\n" + bounded("vulnerabilities", "\n".join(packages), 2000))
    if references:
        parts.append("References (including commit URLs quoted in the description):\n" +
                     bounded("references", "\n".join(references), 6000))
    prefix = "\n\n".join(parts) + "\n\nDescription:\n"
    body = bounded("description", value["description"], MAX_DOCUMENT_CHARS - len(prefix))
    document = _document(name, kind, prefix + body)
    selected_fields = {"ghsa_id", "summary", "description", "identifiers", "cve_id", "references", "vulnerabilities", "fix_commits", "source_code_location"}
    document.update(input_format="github_advisory_json", source_chars=source_chars,
                    omitted_metadata_fields=sorted(set(value) - selected_fields),
                    truncated_fields=truncated_fields, truncated=bool(truncated_fields),
                    advisory_metadata={"ghsa_id": ghsa_id,
                                       "title": value["summary"] if len(value["summary"]) <= 2000 else None,
                                       "vuln_ids": vuln_ids},
                    fix_commits=list(dict.fromkeys(fix_candidates)),
                    repository_hint=repository_hint,
                    input_warnings=list(dict.fromkeys(candidate_warnings)))
    return document


def _file_document(path: Path, kind: str = "advisory") -> dict[str, Any]:
    try:
        text = _read(path, MAX_DOCUMENT_BYTES).decode("utf-8-sig", errors="strict")
    except UnicodeError as error:
        raise ValueError("document_not_utf8") from error
    if path.suffix.lower() == ".json":
        # Parse only the entire bounded file, before presentation truncation.
        # Malformed or unrelated JSON remains raw input data, never a draft.
        try:
            value = _input_json(text)
        except (ValueError, RecursionError):
            document = _document(path.name, kind, text)
            document["json_parse_error"] = True
            return document
        rendered = _advisory_json_document(path.name, kind, value, len(text))
        if rendered is not None:
            return rendered
        rendered = _osv_json_document(path.name, kind, value, len(text))
        if rendered is not None:
            return rendered
    return _document(path.name, kind, text)


def _osv_json_document(name: str, kind: str, value: object,
                       source_chars: int) -> dict[str, Any] | None:
    """Render native OSV material without treating source fields as an answer.

    Formal entries currently require a unique GHSA and reviewed GitHub origin.
    Other OSV records remain inspectable material, but cannot silently acquire
    that identity or origin from prose, the filename, or an unrelated reference.
    """
    if not isinstance(value, dict) or "id" not in value or not (
            "affected" in value or "schema_version" in value
            or ("details" in value and any(key in value for key in ("aliases", "references", "database_specific")))):
        return None
    identifier = value.get("id")
    valid = (isinstance(identifier, str)
             and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", identifier)
             and all(key not in value or isinstance(value[key], str)
                     for key in ("summary", "details", "withdrawn", "modified", "published"))
             and isinstance(value.get("affected"), list)
             and all(isinstance(item, dict) for item in value["affected"])
             and isinstance(value.get("aliases", []), list)
             and all(isinstance(item, str) for item in value.get("aliases", []))
             and isinstance(value.get("references", []), list)
             and all(isinstance(item, dict) and isinstance(item.get("url"), str)
                     and ("type" not in item or isinstance(item["type"], str))
                     for item in value.get("references", []))
             and isinstance(value.get("database_specific", {}), dict))
    if not valid:
        document = _document(name, kind, "OSV source material (invalid record shape; not an annotation).\n" +
                             json.dumps(value, ensure_ascii=False, sort_keys=True))
        document.update(input_format="osv_json", source_chars=source_chars,
                        input_errors=["osv_response_invalid"])
        return document

    truncated_fields: list[str] = []

    def bounded(field: str, text: str, limit: int) -> str:
        if len(text) > limit:
            truncated_fields.append(field)
        return text[:max(0, limit)]

    aliases = value.get("aliases", [])
    references = value.get("references", [])
    identities = {item.upper() for item in [identifier, *aliases] if _GHSA.fullmatch(item)}
    for reference in references:
        try:
            parsed = urlsplit(reference["url"])
        except ValueError:
            continue
        referenced_id = parsed.path.removeprefix("/advisories/").removesuffix("/")
        if (parsed.scheme == "https" and parsed.netloc.lower() == "github.com"
                and not parsed.query and not parsed.fragment
                and parsed.path.startswith("/advisories/") and _GHSA.fullmatch(referenced_id)):
            identities.add(referenced_id.upper())
    errors = []
    if not identities:
        errors.append("osv_ghsa_missing")
    elif len(identities) > 1:
        errors.append("osv_ghsa_ambiguous")
    if value.get("withdrawn"):
        errors.append("osv_record_withdrawn")
    database_specific = value.get("database_specific", {})
    if database_specific.get("github_reviewed") is not True:
        errors.append("osv_reviewed_origin_unconfirmed")
    ghsa_id = next(iter(identities)) if len(identities) == 1 else None
    known_ids = {item.strip().upper() for item in [identifier, *aliases]
                 if item.strip() and len(item.strip()) <= 128
                 and not any(char.isspace() for char in item.strip())}
    if ghsa_id:
        known_ids.add(ghsa_id)
    if len(known_ids) > 64 or any(len(item.strip()) > 128 for item in aliases):
        truncated_fields.append("advisory_metadata.vuln_ids")
    keep = {ghsa_id} if ghsa_id else set()
    known_ids = set(sorted(known_ids - keep)[:64 - len(keep)]) | keep
    vuln_ids = sorted(known_ids, key=lambda item: (0 if item.startswith("CVE-") else
                                                 1 if item.startswith("GHSA-") else 2, item))
    summary = value.get("summary", "")
    # WEB commit links are revision clues, not a statement that they are fixes.
    # Keep them early enough to survive long reference lists so the existing
    # model-directed inspect_commit/read_diff tools can establish their roles.
    revision_links = [item for item in references if item.get("type") != "FIX"
                      and _COMMIT_URL.fullmatch(item["url"])]
    if len(revision_links) > 8:
        truncated_fields.append("revision_links")
    parts = ["OSV source material (not an annotation; not a GitHub API response).",
             "OSV record ID: " + identifier,
             "GHSA mapping: " + (ghsa_id or "unresolved; manual source review required"),
             "Summary:\n" + bounded("summary", summary, 2000),
             "Aliases:\n" + bounded("aliases", "\n".join(aliases), 1200),
             "Unclassified revision links (not supplied as fixes; validate each URL against the selected repository and inspect to establish its role):\n" +
             bounded("revision_links", "\n".join(
                 f"{item.get('type', 'UNSPECIFIED')}: {item['url']}" for item in revision_links[:8]), 1200),
             "Source database metadata (reported, not independently verified):\n" +
             bounded("database_specific", json.dumps(database_specific, ensure_ascii=False, sort_keys=True), 1800),
             "Affected package/range facts:\n" + bounded("affected", json.dumps(
                 value["affected"], ensure_ascii=False, sort_keys=True), 3000),
             "References (OSV reference type retained):\n" + bounded("references", "\n".join(
                 f"{item.get('type', 'UNSPECIFIED')}: {item['url']}" for item in references), 6000)]
    if value.get("withdrawn"):
        parts.append("Withdrawn: " + bounded("withdrawn", value["withdrawn"], 200))
    if errors:
        parts.append("Input limitations: " + ", ".join(errors))
    prefix = "\n\n".join(parts) + "\n\nDetails:\n"
    details = bounded("details", value.get("details", ""), MAX_DOCUMENT_CHARS - len(prefix))
    document = _document(name, kind, prefix + details)
    # Only explicit FIX references become candidates. Same-repository filtering
    # occurs in _make_job; details and WEB references remain unclassified prose.
    fix_commits = list(dict.fromkeys(item["url"] for item in references
                                   if item.get("type") == "FIX" and _COMMIT_URL.fullmatch(item["url"])))
    if len(fix_commits) > 32:
        truncated_fields.append("fix_commits")
    selected = {"id", "summary", "details", "aliases", "affected", "references", "database_specific", "withdrawn"}
    document.update(input_format="osv_json", source_chars=source_chars,
                    source_provider="osv", source_record_id=identifier,
                    omitted_metadata_fields=sorted(set(value) - selected),
                    truncated_fields=truncated_fields, truncated=bool(truncated_fields),
                    input_errors=errors, input_warnings=[], fix_commits=fix_commits[:32])
    if ghsa_id:
        document["advisory_metadata"] = {"ghsa_id": ghsa_id,
                                         "title": summary if summary and len(summary) <= 2000 else None,
                                         "vuln_ids": vuln_ids}
    return document


def _mapping(repo_map: object, base: Path) -> tuple[dict[str, Any], Path]:
    if repo_map is None:
        return {}, base
    if isinstance(repo_map, dict):
        return repo_map, base
    path = _local(repo_map, base)
    try:
        value = _input_json(_read(path, MAX_INPUT_BYTES))
    except (ValueError, RecursionError) as error:
        raise ValueError("invalid_repo_map") from error
    if not isinstance(value, dict):
        raise ValueError("invalid_repo_map")
    return value, path.parent


def _cache_document(cache: Path, ghsa: str) -> dict[str, Any]:
    # Predictable direct names only: no globbing arbitrary cache contents.
    for name in (ghsa.lower(), ghsa.upper()):
        for suffix in (".json", ".md", ".txt", ".html"):
            candidate = cache / (name + suffix)
            if candidate.is_file():
                resolved = candidate.resolve()
                if not resolved.is_relative_to(cache):
                    raise ValueError("cache_path_outside_root")
                return {**_file_document(resolved, "cached_advisory"), "role": "primary"}
    raise ValueError("cached_advisory_missing")


def _as_text(value: object) -> str:
    return value if isinstance(value, str) else ""


def _make_job(row: dict[str, Any], *, base: Path, default_repo: object,
              default_source: object, cache: Path | None, mapping: dict[str, Any],
              map_base: Path, identity: str) -> dict[str, Any]:
    documents: list[dict[str, Any]] = []
    errors: list[str] = []
    warnings: list[str] = []
    source = _as_text(row.get("source_link") or row.get("url") or default_source)
    original_source = source
    explicit_ghsa = _GHSA.search(source) or _GHSA.search(_as_text(row.get("ghsa_id")))
    advisory = row.get("advisory") or row.get("advisory_path")
    if advisory:
        try:
            path = _local(advisory, base)
            if path.is_dir():
                # Flat material bundles are bounded before selection and never recursive.
                selected: list[Path] = []
                with os.scandir(path) as entries:
                    for index, entry in enumerate(entries):
                        if index >= 128:
                            warnings.append("bundle_directory_listing_truncated")
                            break
                        if entry.is_file(follow_symlinks=False) and Path(entry.name).suffix.lower() in _SUFFIXES:
                            selected.append(Path(entry.path))
                for item in sorted(selected)[:MAX_DOCUMENTS]:
                    try:
                        documents.append(_file_document(item))
                    except ValueError as error:
                        errors.append(str(error))
                if len(selected) > MAX_DOCUMENTS:
                    warnings.append("document_count_truncated")
            else:
                documents.append({**_file_document(path), "role": "primary"})
        except (ValueError, OSError) as error:
            errors.append(str(error) if isinstance(error, ValueError) else "input_file_unreadable")
    supplied = row.get("documents", [])
    if not isinstance(supplied, list):
        errors.append("invalid_documents")
        supplied = []
    for item in supplied[:MAX_DOCUMENTS]:
        if len(documents) >= MAX_DOCUMENTS:
            warnings.append("document_count_truncated")
            break
        if not isinstance(item, dict):
            errors.append("invalid_document")
        elif isinstance(item.get("text"), str):
            documents.append(_document(_as_text(item.get("name")) or "material",
                                       _as_text(item.get("kind")) or "advisory", item["text"]))
        elif item.get("path"):
            try:
                documents.append(_file_document(_local(item["path"], base),
                                                _as_text(item.get("kind")) or "material"))
            except ValueError as error:
                errors.append(str(error))
        else:
            errors.append("invalid_document")
    if len(supplied) > MAX_DOCUMENTS:
        warnings.append("document_count_truncated")
    inline = "\n\n".join(_as_text(row.get(key)) for key in
                          ("title", "vuln_title", "summary", "description", "body", "text")
                          if _as_text(row.get(key)))
    if inline and len(documents) < MAX_DOCUMENTS:
        documents.append(_document("report", "advisory", inline))
    if not documents and explicit_ghsa and cache is not None:
        try:
            documents.append(_cache_document(cache, explicit_ghsa.group().upper()))
        except ValueError as error:
            errors.append(str(error))
    full_text = "\n".join(doc["text"] for doc in documents)
    primary_osv = [doc for doc in documents if doc.get("input_format") == "osv_json"
                   and (doc.get("role") == "primary"
                        or not any(item.get("role") == "primary" for item in documents))]
    if primary_osv:
        # Raw OSV identity has already been resolved from structured fields.
        # Never fall back to the first GHSA mentioned in its free-form details.
        structured_ids = {doc.get("advisory_metadata", {}).get("ghsa_id") for doc in primary_osv}
        structured_id = next(iter(structured_ids)) if len(structured_ids) == 1 else None
        if len(structured_ids - {None}) > 1:
            errors.append("osv_ghsa_ambiguous")
        report_id = explicit_ghsa.group().upper() if explicit_ghsa else structured_id
        for document in primary_osv:
            errors.extend(document.get("input_errors", []))
    else:
        ghsa = explicit_ghsa or _GHSA.search(full_text)
        report_id = ghsa.group().upper() if ghsa else None
    if report_id:
        source = "https://github.com/advisories/GHSA-" + report_id[5:].lower()
    else:
        report_id = "local-" + _digest(source or full_text or identity)[:16]
    if not documents:
        errors.append("advisory_material_missing")
    repo_url = canonical_repo_url(row.get("repo_url") or row.get("repository_url"))
    repo_identity_source = "explicit" if repo_url else "unavailable"
    map_item: object = None
    keys = [original_source, source, report_id, report_id.lower(), repo_url]
    if repo_url:
        keys.append(repo_url.removeprefix("https://github.com/"))
    # Exact identity lookup, not traversal or selection of a benchmark mapping.
    for key in keys:
        if key and key in mapping:
            map_item = mapping[key]
            break
    local_repo = row.get("repo_path") or row.get("repo") or default_repo
    local_base = base
    if isinstance(map_item, str):
        if not local_repo:
            local_repo, local_base = map_item, map_base
    elif isinstance(map_item, dict):
        if not local_repo:
            local_repo, local_base = map_item.get("repo_path") or map_item.get("path") or map_item.get("repo"), map_base
        if not repo_url:
            repo_url = canonical_repo_url(map_item.get("repo_url") or map_item.get("url"))
            if repo_url:
                repo_identity_source = "repo_map"
    if not local_repo:
        errors.append("repository_path_missing")
        repo_path = None
    else:
        try:
            repo_path = str(_local(local_repo, local_base))
            if not Path(repo_path).is_dir():
                errors.append("repository_path_missing")
            elif not repo_url:
                try:
                    repo_url = RepoReader(repo_path).info()["repo_url"]
                    if repo_url:
                        repo_identity_source = "local_remote"
                except ValueError:
                    pass
        except ValueError as error:
            repo_path = None
            errors.append(str(error))
    # Only a matching, explicitly selected primary advisory owns this hint.
    # References and support documents can name other repositories. The hint
    # enables same-repository link filtering; it does not prove any revision.
    primary_hints = {doc["repository_hint"] for doc in documents
                     if doc.get("role") == "primary" and doc.get("repository_hint")
                     and doc.get("advisory_metadata", {}).get("ghsa_id") == report_id}
    if len({hint.casefold() for hint in primary_hints}) > 1:
        errors.append("advisory_repository_identity_conflict")
    elif primary_hints:
        hint = next(iter(primary_hints))
        if repo_url and hint.casefold() != repo_url.casefold():
            errors.append("advisory_repository_identity_conflict")
        elif not repo_url:
            repo_url, repo_identity_source = hint, "primary_advisory"
            warnings.append("repository_identity_from_advisory")
    if not repo_url:
        warnings.append("repository_identity_unavailable")
    fix_commits: list[str] = []
    for document in documents:
        candidate_metadata = document.get("advisory_metadata", {})
        if candidate_metadata.get("ghsa_id") != report_id:
            continue
        warnings.extend(document.get("input_warnings", []))
        for item in document.get("fix_commits", []):
            if _SHA.fullmatch(item):
                fix_commits.append(item.lower())
                continue
            match = _COMMIT_URL.fullmatch(item)
            if match is not None:
                linked_repo = canonical_repo_url(f"https://github.com/{match[1]}/{match[2]}")
                if repo_url and linked_repo and linked_repo.casefold() == repo_url.casefold():
                    fix_commits.append(match[3].lower())
                else:
                    warnings.append("advisory_fix_commit_repository_mismatch_or_unknown")
    explicit_fixes = row.get("fix_commits", [])
    # OSV FIX references have their own explicit classification above. Do not
    # turn every commit mentioned by OSV prose or WEB references into a fix.
    commit_text = "\n".join(doc["text"] for doc in documents if doc.get("input_format") != "osv_json")
    if isinstance(explicit_fixes, str):
        explicit_fixes = [explicit_fixes]
    if not isinstance(explicit_fixes, list):
        errors.append("invalid_fix_commits")
        explicit_fixes = []
    for item in explicit_fixes[:32]:
        if isinstance(item, str) and _SHA.fullmatch(item):
            fix_commits.append(item.lower())
        elif isinstance(item, str) and _COMMIT_URL.fullmatch(item):
            full_text += "\n" + item
            commit_text += "\n" + item
        else:
            warnings.append("invalid_fix_commit_ignored")
    # Derive commit candidates only from same-repo commit URLs. Bare SHAs in prose
    # or URLs to unrelated dependencies are not implicitly classified as fixes.
    references = row.get("references", [])
    if isinstance(references, list):
        for reference in references[:64]:
            if isinstance(reference, str):
                full_text += "\n" + reference[:2000]
                commit_text += "\n" + reference[:2000]
            elif isinstance(reference, dict):
                full_text += "\n" + _as_text(reference.get("url"))[:2000]
                commit_text += "\n" + _as_text(reference.get("url"))[:2000]
    if repo_url:
        for match in _COMMIT_URL.finditer(commit_text):
            linked_repo = canonical_repo_url(f"https://github.com/{match[1]}/{match[2]}")
            if linked_repo and linked_repo.casefold() == repo_url.casefold():
                fix_commits.append(match[3].lower())
    stable = _digest(report_id + "\n" + (repo_url or repo_path or "") + "\n" + full_text)
    # Official schema has exactly five digits, so collisions must be handled by
    # the batch allocator below instead of pretending the namespace is unlimited.
    entry_id = f"entry-{int(stable[:16], 16) % 100000:05d}"
    job: dict[str, Any] = {"report_id": report_id, "entry_id": entry_id,
                           "source_link": source or None, "repo_path": repo_path,
                           "repo_url": repo_url, "repo_identity_source": repo_identity_source,
                           "documents": documents,
                           "fix_commits": list(dict.fromkeys(fix_commits))[:32],
                           "input_warnings": list(dict.fromkeys(warnings))}
    for field in ("input_source_url", "source_provider", "source_record_id"):
        if isinstance(row.get(field), str) and len(row[field]) <= 2000:
            job[field] = row[field]
    if primary_osv:
        job["source_provider"] = "osv"
        if len(primary_osv) == 1 and primary_osv[0].get("source_record_id"):
            job["source_record_id"] = primary_osv[0]["source_record_id"]
    metadata = [doc["advisory_metadata"] for doc in documents if "advisory_metadata" in doc]
    matched = [item for item in metadata if item["ghsa_id"] == report_id]
    if len(matched) != len(metadata):
        job["input_warnings"].append("advisory_metadata_report_mismatch")
    # Only an explicitly selected primary advisory file/cache owns the requested
    # identity. Supporting documents and quoted reference IDs can describe other
    # advisories; do not treat a mention in prose as an identity contradiction.
    job["input_conflicts"] = [
        {"status": "conflicting", "code": "primary_advisory_report_mismatch",
         "document": doc["name"], "expected_report_id": report_id,
         "actual_report_id": doc["advisory_metadata"]["ghsa_id"]}
        for doc in documents if doc.get("role") == "primary"
        and isinstance(doc.get("advisory_metadata"), dict)
        and doc["advisory_metadata"].get("ghsa_id") != report_id
    ]
    if job["input_conflicts"]:
        errors.append("primary_advisory_report_mismatch")
    if matched:
        titles = {item["title"] for item in matched if isinstance(item.get("title"), str) and item["title"].strip()}
        ids = sorted({identifier for item in matched for identifier in item["vuln_ids"]},
                     key=lambda item: (0 if item.startswith("CVE-") else 1 if item.startswith("GHSA-") else 2, item))
        supplied = {"ghsa_id": report_id, "title": next(iter(titles)) if len(titles) == 1 else None,
                    "vuln_ids": ids}
        job["advisory_metadata"] = supplied
        job.update(supplied)
        if len(titles) > 1:
            job["input_warnings"].append("advisory_metadata_title_conflict")
    if row.get("vulnerable_commit"):
        value = row["vulnerable_commit"]
        if isinstance(value, str) and len(value) <= 200:
            job["vulnerable_commit"] = value
        else:
            errors.append("invalid_vulnerable_commit")
    if any(doc["truncated"] for doc in documents):
        job["input_warnings"].append("document_text_truncated")
    if row.get("input_error"):
        errors.append(_as_text(row["input_error"]) or "invalid_input_record")
    if errors:
        job["input_error"] = ";".join(dict.fromkeys(errors))
    return job


def _unique_ids(jobs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Deterministic for the same batch irrespective of input order.

    Five-digit IDs cannot guarantee global uniqueness across unrelated runs.
    Resolve collisions inside this batch explicitly, including duplicate inputs.
    """
    used: set[str] = set()
    order = sorted(range(len(jobs)), key=lambda index: json.dumps(jobs[index], sort_keys=True))
    for index in order:
        job = jobs[index]
        number = int(job["entry_id"][6:])
        original = number
        while f"entry-{number:05d}" in used:
            number = (number + 1) % 100000
        job["entry_id"] = f"entry-{number:05d}"
        used.add(job["entry_id"])
        if number != original:
            job["input_warnings"].append("entry_id_collision_resolved_within_batch")
    return jobs


def load_jobs(input_path: str | Path | None = None, advisory: str | Path | None = None,
              repo: str | Path | None = None, source_link: str | None = None,
              cache_dir: str | Path | None = None,
              repo_map: str | Path | dict[str, Any] | None = None) -> list[dict[str, Any]]:
    """Load public material; preserve one error job for each invalid input record.

    JSONL example: {"source_link":"https://github.com/advisories/GHSA-...",
    "repo_path":"../repo","repo_url":"https://github.com/owner/repo",
    "description":"Advisory text (including any explicit commit URLs)"}.
    URL lists contain one GHSA URL per nonempty, non-comment line. Cache files
    are named GHSA-ID.json/.md/.txt/.html; map keys may be GHSA IDs or source URLs.
    """
    base = Path.cwd()
    mapping, map_base = _mapping(repo_map, base)
    cache = _local(cache_dir, base) if cache_dir is not None else None
    defaults = {"default_repo": repo, "default_source": source_link,
                "cache": cache, "mapping": mapping, "map_base": map_base}
    if input_path is None:
        return [_make_job({"advisory": str(advisory) if advisory is not None else None},
                          base=base, identity=str(advisory or source_link or "empty"), **defaults)]
    path = _local(input_path, base)
    base = path.parent
    # CLI defaults remain relative to invocation cwd, not the JSONL directory.
    if repo is not None:
        defaults["default_repo"] = str(_local(repo, Path.cwd()))
    try:
        text = _read(path, MAX_INPUT_BYTES).decode("utf-8-sig", errors="strict")
    except (ValueError, UnicodeError) as error:
        code = str(error) if isinstance(error, ValueError) else "input_not_utf8"
        return [_make_job({"input_error": code}, base=base, identity=str(path), **defaults)]
    jobs: list[dict[str, Any]] = []
    for number, line in enumerate(text.splitlines(), 1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if len(jobs) >= MAX_JOBS:
            jobs.append(_make_job({"input_error": "input_job_limit"}, base=base,
                                  identity=f"{path}:{number}", **defaults))
            break
        if stripped.startswith("{"):
            try:
                row = _input_json(stripped)
                if not isinstance(row, dict):
                    raise ValueError
            except (json.JSONDecodeError, ValueError, RecursionError):
                row = {"input_error": "invalid_json_record"}
        else:
            row = {"input_error": "invalid_input_record"}
            if _GHSA.search(stripped):
                try:
                    if urlsplit(stripped).hostname == "github.com":
                        row = {"source_link": stripped}
                except ValueError:
                    pass  # A malformed URL is one bad input, not a batch abort.
        jobs.append(_make_job(row, base=base, identity=f"{path}:{number}", **defaults))
    if not jobs:
        jobs.append(_make_job({"input_error": "empty_input"}, base=base, identity=str(path), **defaults))
    return _unique_ids(jobs)
