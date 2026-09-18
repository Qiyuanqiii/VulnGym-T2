"""Acquire explicitly selected public GitHub/OSV material without running models.

Only allowlisted HTTPS advisory endpoints and explicitly identified GitHub
repositories are downloaded. OSV is a separate source, never a hidden retry of
a failed GitHub request. Complete bare repositories keep later source reads
offline: partial/shallow clones, checkout, hooks and credential helpers are not
used. Failed downloads are retained, never silently retried or deleted.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import threading
import time
from typing import Any, Callable
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener
from uuid import uuid4

from ._vendor.bounded_process import _WindowsKillJob, _terminate_process_tree
from .repository import RepoReader

MAX_URLS = 20
MAX_TEXT_CHARS = 16000
MAX_ADVISORY_BYTES = 256 * 1024
HTTP_TIMEOUT_SECONDS = 30
CLONE_TIMEOUT_SECONDS = 300
MAX_REPOSITORY_BYTES = 2 * 1024**3
MAX_CACHE_BYTES = 6 * 1024**3
MIN_FREE_BYTES = 1024**3
MAX_SCAN_ENTRIES = 200000
MAX_WORKERS = 2
_GHSA = re.compile(r"GHSA-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4}", re.I)
_OSV_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,159}\Z")
_REPO_SEGMENT = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,99}\Z")
_LOCKS: dict[str, threading.Lock] = {}
_LOCKS_GUARD = threading.Lock()


class AcquisitionError(ValueError):
    """A stable, user-displayable acquisition failure (never raw network text)."""


def validate_network_mode(value: object) -> str:
    """Accept only an explicit download route, without probing or changing it."""
    if not isinstance(value, str) or value not in {"system", "direct"}:
        raise AcquisitionError("network_mode_invalid")
    return value


def _lock(name: str) -> threading.Lock:
    with _LOCKS_GUARD:
        return _LOCKS.setdefault(name, threading.Lock())


def _canonical_ghsa(value: str) -> str:
    try:
        parsed = urlsplit(value)
        identifier = parsed.path.removeprefix("/advisories/").removesuffix("/")
        valid = (parsed.scheme == "https" and parsed.netloc.lower() == "github.com"
                 and not parsed.query and not parsed.fragment
                 and parsed.path.startswith("/advisories/") and _GHSA.fullmatch(identifier))
    except ValueError:
        valid = False
    if not valid:
        raise AcquisitionError("ghsa_urls_invalid")
    return "https://github.com/advisories/GHSA-" + identifier[5:].lower()


def parse_ghsa_urls(text: str) -> list[str]:
    """Accept whitespace-separated HTTPS links or Markdown links, and deduplicate.

    Extra prose/unsupported URLs are rejected instead of silently dropping an
    input. Link text is presentation only; the actual Markdown destination wins.
    """
    if not isinstance(text, str) or not text.strip():
        raise AcquisitionError("ghsa_urls_required")
    if len(text) > MAX_TEXT_CHARS:
        raise AcquisitionError("ghsa_urls_too_large")
    plain = re.sub(r"\[[^\]\r\n]*\]\((https://[^\s()]+)\)", r"\1", text)
    plain = re.sub(r"<(https://[^\s<>]+)>", r"\1", plain)
    urls = list(dict.fromkeys(_canonical_ghsa(item) for item in plain.split()))
    if len(urls) > MAX_URLS:
        raise AcquisitionError("ghsa_url_limit")
    return urls


def _canonical_osv_id(identifier: str) -> str:
    """Keep opaque OSV IDs, normalizing only the known GHSA/CVE namespaces."""
    if (not isinstance(identifier, str) or not _OSV_ID.fullmatch(identifier)
            or ".." in identifier or identifier.endswith(".")
            or identifier.split(".")[0].upper() in {"CON", "PRN", "AUX", "NUL",
                *(f"COM{i}" for i in range(10)), *(f"LPT{i}" for i in range(10))}):
        raise AcquisitionError("advisory_urls_invalid")
    if identifier.upper().startswith("GHSA-"):
        if not _GHSA.fullmatch(identifier):
            raise AcquisitionError("advisory_urls_invalid")
        return "GHSA-" + identifier[5:].lower()
    if identifier.upper().startswith("CVE-"):
        return identifier.upper()
    return identifier


def _canonical_advisory(value: str) -> str:
    try:
        parsed = urlsplit(value)
        if parsed.netloc.lower() == "github.com":
            return _canonical_ghsa(value)
        prefix = {"osv.dev": "/vulnerability/", "api.osv.dev": "/v1/vulns/"}.get(parsed.netloc.lower())
        if (parsed.scheme != "https" or not prefix or not parsed.path.startswith(prefix)
                or parsed.query or parsed.fragment):
            raise ValueError("unsupported advisory URL")
        identifier = _canonical_osv_id(parsed.path[len(prefix):].removesuffix("/"))
        return "https://osv.dev/vulnerability/" + identifier
    except (ValueError, TypeError):
        raise AcquisitionError("advisory_urls_invalid") from None


def parse_advisory_urls(text: str) -> list[str]:
    """Parse an ordered mixed provider batch, retaining each selected source.

    OSV page/API URLs for one ID are duplicates; a GHSA URL and its OSV mirror
    remain separate inputs so selection does not silently change provenance.
    """
    if not isinstance(text, str) or not text.strip():
        raise AcquisitionError("advisory_urls_required")
    if len(text) > MAX_TEXT_CHARS:
        raise AcquisitionError("advisory_urls_too_large")
    plain = re.sub(r"\[[^\]\r\n]*\]\((https://[^\s()]+)\)", r"\1", text)
    plain = re.sub(r"<(https://[^\s<>]+)>", r"\1", plain)
    urls = list(dict.fromkeys(_canonical_advisory(item) for item in plain.split()))
    if len(urls) > MAX_URLS:
        raise AcquisitionError("advisory_url_limit")
    return urls


def _github_repo(value: object, *, reference: bool = False) -> str | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = urlsplit(value)
    except ValueError:
        return None
    if (parsed.scheme != "https" or parsed.netloc.lower() != "github.com"
            or parsed.query or parsed.fragment):
        return None
    pieces = parsed.path.strip("/").split("/")
    if len(pieces) < 2 or (not reference and len(pieces) != 2):
        return None
    owner, name = pieces[:2]
    name = name.removesuffix(".git")
    if not all(_REPO_SEGMENT.fullmatch(piece) and ".." not in piece for piece in (owner, name)):
        return None
    if owner.lower() in {"advisories", "orgs", "users", "topics", "marketplace", "settings", "features"}:
        return None
    if len(pieces) > 2 and pieces[2] not in {"commit", "commits", "pull", "issues", "security", "releases", "tree", "blob"}:
        return None
    return f"https://github.com/{owner}/{name}"


def _repository_from_advisory(advisory: dict[str, Any]) -> str:
    explicit = advisory.get("source_code_location")
    if explicit:
        repository = _github_repo(explicit)
        if repository is None:
            raise AcquisitionError("advisory_repository_unsupported")
        return repository
    candidates: dict[str, str] = {}
    for item in advisory.get("references", []):
        value = item.get("url") if isinstance(item, dict) else item
        repository = _github_repo(value, reference=True)
        if repository:
            candidates[repository.casefold()] = repository
    if not candidates:
        raise AcquisitionError("advisory_repository_missing")
    if len(candidates) != 1:
        raise AcquisitionError("advisory_repository_ambiguous")
    return next(iter(candidates.values()))


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise AcquisitionError("advisory_redirect_blocked")


def _decode_advisory(raw: bytes, identifier: str) -> dict[str, Any]:
    if len(raw) > MAX_ADVISORY_BYTES:
        raise AcquisitionError("advisory_too_large")

    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("duplicate key")
            result[key] = value
        return result

    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs)
        valid = (isinstance(value, dict) and value.get("ghsa_id", "").upper() == identifier.upper()
                 and isinstance(value.get("summary"), str) and isinstance(value.get("description"), str)
                 and isinstance(value.get("references", []), list))
        json.dumps(value, ensure_ascii=False, allow_nan=False).encode("utf-8")
    except (ValueError, TypeError, AttributeError, UnicodeError, RecursionError):
        valid = False
    if not valid:
        raise AcquisitionError("advisory_response_invalid")
    return value


def _download_advisory(identifier: str, *, network_mode: str = "system") -> bytes:
    network_mode = validate_network_mode(network_mode)
    request = Request("https://api.github.com/advisories/" + identifier.lower(), headers={
        "Accept": "application/vnd.github+json", "User-Agent": "VulnGym-T2-public-input/1.0",
        "X-GitHub-Api-Version": "2026-03-10",
    })
    handlers = [_NoRedirect()]
    if network_mode == "direct":
        # An explicit empty handler also disables platform proxy discovery.
        handlers.append(ProxyHandler({}))
    try:
        with build_opener(*handlers).open(request, timeout=HTTP_TIMEOUT_SECONDS) as response:
            if response.geturl() != request.full_url:
                raise AcquisitionError("advisory_redirect_blocked")
            length = response.headers.get("Content-Length")
            if length is not None and (not length.isdigit() or int(length) > MAX_ADVISORY_BYTES):
                raise AcquisitionError("advisory_too_large")
            raw = response.read(MAX_ADVISORY_BYTES + 1)
            _decode_advisory(raw, identifier)
            return raw
    except HTTPError as error:
        limited = error.code == 429 or (error.code == 403 and error.headers.get("X-RateLimit-Remaining") == "0")
        code = "github_rate_limited" if limited else {
            403: "advisory_access_denied", 404: "advisory_not_found",
        }.get(error.code, "advisory_http_failed")
        raise AcquisitionError(code) from None
    except (URLError, TimeoutError, OSError):
        raise AcquisitionError("advisory_download_failed") from None


def _cached_advisory(root: Path, identifier: str, *, allow_download: bool = True,
                     network_mode: str = "system"
                     ) -> tuple[Path, dict[str, Any], bool]:
    network_mode = validate_network_mode(network_mode)
    target = root / "advisories" / (identifier.upper() + ".json")
    with _lock(str(target)):
        if target.exists():
            if target.is_symlink() or not target.is_file():
                raise AcquisitionError("advisory_cache_invalid")
            with target.open("rb") as stream:
                return target, _decode_advisory(stream.read(MAX_ADVISORY_BYTES + 1), identifier), True
        if not allow_download:
            raise AcquisitionError("github_rate_limited")
        network_options = {"network_mode": network_mode} if network_mode == "direct" else {}
        raw = _download_advisory(identifier, **network_options)
        target.parent.mkdir(parents=True, exist_ok=True)
        # Exclusive publication: another process can win, but no cache is overwritten.
        try:
            with target.open("xb") as stream:
                stream.write(raw)
        except FileExistsError:
            with target.open("rb") as stream:
                raw = stream.read(MAX_ADVISORY_BYTES + 1)
        return target, _decode_advisory(raw, identifier), False


def _decode_osv(raw: bytes, identifier: str) -> dict[str, Any]:
    """Validate the raw OSV record without rewriting its provider or identity."""
    if len(raw) > MAX_ADVISORY_BYTES:
        raise AcquisitionError("osv_too_large")

    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("duplicate key")
            result[key] = value
        return result

    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs)
        valid = (isinstance(value, dict)
                 and _canonical_osv_id(value.get("id")) == _canonical_osv_id(identifier)
                 and all(isinstance(value.get(name, ""), str)
                         for name in ("summary", "details", "withdrawn"))
                 and isinstance(value.get("aliases", []), list)
                 and all(isinstance(item, str) for item in value.get("aliases", []))
                 and isinstance(value.get("references", []), list)
                 and all(isinstance(item, dict) and isinstance(item.get("url"), str)
                         and isinstance(item.get("type"), str) for item in value.get("references", []))
                 and isinstance(value.get("affected", []), list)
                 and all(isinstance(item, dict) for item in value.get("affected", []))
                 and isinstance(value.get("database_specific", {}), dict))
        json.dumps(value, ensure_ascii=False, allow_nan=False).encode("utf-8")
    except (ValueError, TypeError, AttributeError, UnicodeError, RecursionError):
        valid = False
    if not valid:
        raise AcquisitionError("osv_response_invalid")
    return value


def osv_ghsa_identifier(advisory: dict[str, Any]) -> str:
    """Require one real GHSA identity; mention text is not identity evidence."""
    identifiers = {item.upper() for item in [advisory.get("id"), *advisory.get("aliases", [])]
                   if isinstance(item, str) and _GHSA.fullmatch(item)}
    for reference in advisory.get("references", []):
        try:
            source = _canonical_ghsa(reference.get("url", ""))
        except (AcquisitionError, AttributeError, TypeError):
            continue
        identifiers.add(source.rsplit("/", 1)[1].upper())
    if not identifiers:
        raise AcquisitionError("osv_ghsa_missing")
    if len(identifiers) != 1:
        raise AcquisitionError("osv_ghsa_ambiguous")
    return next(iter(identifiers))


def require_osv_reviewed(advisory: dict[str, Any]) -> None:
    """The existing output origin is reviewed GitHub: never infer that label."""
    if advisory.get("withdrawn"):
        raise AcquisitionError("osv_record_withdrawn")
    if advisory.get("database_specific", {}).get("github_reviewed") is not True:
        raise AcquisitionError("osv_reviewed_origin_unconfirmed")


def _repository_from_osv(advisory: dict[str, Any]) -> str:
    def unique(candidates: dict[str, str]) -> str:
        if len(candidates) != 1:
            raise AcquisitionError("osv_repository_ambiguous")
        return next(iter(candidates.values()))

    explicit: dict[str, str] = {}
    for affected in advisory.get("affected", []):
        ranges = affected.get("ranges", [])
        if not isinstance(ranges, list) or any(not isinstance(item, dict) for item in ranges):
            raise AcquisitionError("osv_response_invalid")
        for item in ranges:
            if item.get("type") != "GIT":
                continue
            repository = _github_repo(item.get("repo"))
            if not repository:
                raise AcquisitionError("osv_repository_unsupported")
            explicit[repository.casefold()] = repository
    if explicit:
        return unique(explicit)

    # Database backlinks are commonly WEB references. They are not target repos.
    # Prefer explicit source/package/fix links, then the project's advisory page,
    # then reports. Genuine same-tier ambiguity needs a supplied local mapping.
    tiers: list[dict[str, str]] = [{}, {}, {}]
    ghsa = osv_ghsa_identifier(advisory)
    for reference in advisory.get("references", []):
        kind, url = reference.get("type"), reference.get("url")
        repository = _github_repo(url, reference=True)
        if not repository:
            continue
        if kind in {"SOURCE", "PACKAGE", "FIX"}:
            tiers[0][repository.casefold()] = repository
        elif kind == "ADVISORY":
            if urlsplit(url).path.rstrip("/").lower().endswith("/security/advisories/" + ghsa.lower()):
                tiers[1][repository.casefold()] = repository
        elif kind == "REPORT":
            tiers[2][repository.casefold()] = repository
    for candidates in tiers:
        if candidates:
            return unique(candidates)
    raise AcquisitionError("osv_repository_missing")


class _NoOSVRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise AcquisitionError("osv_redirect_blocked")


def _download_osv(identifier: str, *, network_mode: str = "system") -> bytes:
    network_mode = validate_network_mode(network_mode)
    identifier = _canonical_osv_id(identifier)
    request = Request("https://api.osv.dev/v1/vulns/" + identifier, headers={
        "Accept": "application/json", "User-Agent": "VulnGym-T2-public-input/1.0",
    })
    handlers = [_NoOSVRedirect()]
    if network_mode == "direct":
        handlers.append(ProxyHandler({}))
    try:
        with build_opener(*handlers).open(request, timeout=HTTP_TIMEOUT_SECONDS) as response:
            if response.geturl() != request.full_url:
                raise AcquisitionError("osv_redirect_blocked")
            length = response.headers.get("Content-Length")
            if length is not None and (not length.isdigit() or int(length) > MAX_ADVISORY_BYTES):
                raise AcquisitionError("osv_too_large")
            raw = response.read(MAX_ADVISORY_BYTES + 1)
            _decode_osv(raw, identifier)
            return raw
    except HTTPError as error:
        code = {429: "osv_rate_limited", 403: "osv_access_denied", 404: "osv_not_found"}.get(
            error.code, "osv_http_failed")
        raise AcquisitionError(code) from None
    except (URLError, TimeoutError, OSError):
        raise AcquisitionError("osv_download_failed") from None


def _cached_osv(root: Path, identifier: str, *, allow_download: bool = True,
                network_mode: str = "system"
                ) -> tuple[Path, dict[str, Any], bool]:
    network_mode = validate_network_mode(network_mode)
    identifier = _canonical_osv_id(identifier)
    target = root / "osv" / (identifier + ".json")
    with _lock(str(target)):
        if target.exists():
            if target.is_symlink() or not target.is_file():
                raise AcquisitionError("osv_cache_invalid")
            with target.open("rb") as stream:
                return target, _decode_osv(stream.read(MAX_ADVISORY_BYTES + 1), identifier), True
        if not allow_download:
            raise AcquisitionError("osv_rate_limited")
        network_options = {"network_mode": network_mode} if network_mode == "direct" else {}
        raw = _download_osv(identifier, **network_options)
        target.parent.mkdir(parents=True, exist_ok=True)
        try:
            with target.open("xb") as stream:
                stream.write(raw)
        except FileExistsError:
            with target.open("rb") as stream:
                raw = stream.read(MAX_ADVISORY_BYTES + 1)
        return target, _decode_osv(raw, identifier), False


def _tree_bytes(path: Path, limit: int) -> int:
    total, count = 0, 0
    pending = [path]
    while pending:
        current = pending.pop()
        if not current.exists():
            continue
        try:
            directory_entries = os.scandir(current)
        except FileNotFoundError:
            continue
        with directory_entries as entries:
            for entry in entries:
                count += 1
                if count > MAX_SCAN_ENTRIES:
                    raise AcquisitionError("download_file_limit")
                try:
                    stat = entry.stat(follow_symlinks=False)
                except FileNotFoundError:
                    # index-pack atomically renames its just-written pack/index.
                    continue
                if entry.is_symlink() or getattr(stat, "st_file_attributes", 0) & 1024:
                    raise AcquisitionError("download_cache_link_unsupported")
                if entry.is_dir(follow_symlinks=False):
                    pending.append(Path(entry.path))
                else:
                    total += stat.st_size
                if total > limit:
                    return total
    return total


def _git_environment(root: Path, *, network_mode: str = "system") -> dict[str, str]:
    network_mode = validate_network_mode(network_mode)
    allowed = {"SYSTEMROOT", "WINDIR", "SYSTEMDRIVE", "PATH", "PATHEXT", "COMSPEC",
               "LANG", "LC_ALL", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY"}
    environment = {key: value for key, value in os.environ.items() if key.upper() in allowed}
    if network_mode == "direct":
        # This child-only copy leaves the caller's environment and OS settings intact.
        environment = {key: value for key, value in environment.items()
                       if key.upper() not in {"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY"}}
        environment["NO_PROXY"] = "*"
    temporary = root / "temporary"
    temporary.mkdir(parents=True, exist_ok=True)
    environment.update({"GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_SYSTEM": os.devnull,
                        "GIT_CONFIG_GLOBAL": os.devnull, "GIT_TERMINAL_PROMPT": "0",
                        "GCM_INTERACTIVE": "Never", "GIT_ASKPASS": "",
                        "SSH_ASKPASS": "", "GIT_LFS_SKIP_SMUDGE": "1",
                        "TEMP": str(temporary), "TMP": str(temporary), "TMPDIR": str(temporary)})
    return environment


def _clone_repository(repository: str, target: Path, root: Path, *, network_mode: str = "system") -> None:
    network_mode = validate_network_mode(network_mode)
    git = shutil.which("git")
    if not git:
        raise AcquisitionError("git_unavailable")
    if shutil.disk_usage(root).free < MIN_FREE_BYTES:
        raise AcquisitionError("download_disk_space_low")
    if _tree_bytes(root, MAX_CACHE_BYTES) > MAX_CACHE_BYTES:
        raise AcquisitionError("download_cache_size_limit")
    command = [git, "-c", "credential.helper=", "-c", "credential.interactive=false",
               "-c", "http.sslVerify=true", "-c", "http.followRedirects=false",
               "-c", "http.schannelUseSSLCAInfo=false", "-c", "http.schannelAutoClientCert=false",
               "-c", "protocol.allow=never", "-c", "protocol.https.allow=always",
               "-c", "gc.auto=0", "-c", "maintenance.auto=false"]
    if network_mode == "direct":
        command += ["-c", "http.proxy="]
    # Git for Windows includes OpenSSL; avoid Windows client-certificate prompts.
    if os.name == "nt":
        command += ["-c", "http.sslBackend=openssl"]
    command += ["clone", "--bare", "--no-local", "--no-hardlinks", "--quiet",
                "--template=", "--config", "core.hooksPath=" + os.devnull,
                "--config", "gc.auto=0", "--", repository + ".git", str(target)]
    job = _WindowsKillJob.create() if os.name == "nt" else None
    process = None
    try:
        network_options = {"network_mode": network_mode} if network_mode == "direct" else {}
        process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                   stderr=subprocess.DEVNULL, env=_git_environment(root, **network_options), cwd=root,
                                   shell=False, start_new_session=os.name != "nt",
                                   creationflags=(0x08000000 | 0x00000004) if os.name == "nt" else 0)
        if job is not None:
            job.assign_and_resume(process)
        started = time.monotonic()
        while process.poll() is None:
            if time.monotonic() - started > CLONE_TIMEOUT_SECONDS:
                raise AcquisitionError("repository_download_timeout")
            if _tree_bytes(target, MAX_REPOSITORY_BYTES) > MAX_REPOSITORY_BYTES:
                raise AcquisitionError("repository_download_too_large")
            if _tree_bytes(root, MAX_CACHE_BYTES) > MAX_CACHE_BYTES:
                raise AcquisitionError("download_cache_size_limit")
            if shutil.disk_usage(root).free < MIN_FREE_BYTES:
                raise AcquisitionError("download_disk_space_low")
            try:
                process.wait(timeout=0.5)
            except subprocess.TimeoutExpired:
                pass
        if process.returncode != 0:
            raise AcquisitionError("repository_download_failed")
        if _tree_bytes(target, MAX_REPOSITORY_BYTES) > MAX_REPOSITORY_BYTES:
            raise AcquisitionError("repository_download_too_large")
    except (OSError, subprocess.SubprocessError):
        raise AcquisitionError("repository_download_failed") from None
    finally:
        if process is not None:
            _terminate_process_tree(process, windows_job=job)
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                pass
        if job is not None:
            job.close()


def _validate_repository(path: Path, repository: str) -> None:
    try:
        info = RepoReader(path).info()
        if (not info.get("repo_url") or info["repo_url"].casefold() != repository.casefold()
                or info.get("shallow") or info.get("errors")):
            raise ValueError("repository identity or storage invalid")
    except (ValueError, OSError):
        raise AcquisitionError("repository_cache_invalid") from None


def _cached_repository(root: Path, repository: str, *, network_mode: str = "system") -> tuple[Path, bool]:
    network_mode = validate_network_mode(network_mode)
    slug = hashlib.sha256(repository.casefold().encode("utf-8")).hexdigest()[:24]
    target = root / "repositories" / (slug + ".git")
    with _lock(str(target)):
        if target.exists():
            _validate_repository(target, repository)
            return target, True
        attempt = root / "attempts" / (slug + "-" + uuid4().hex + ".git")
        attempt.parent.mkdir(parents=True, exist_ok=True)
        network_options = {"network_mode": network_mode} if network_mode == "direct" else {}
        _clone_repository(repository, attempt, root, **network_options)
        _validate_repository(attempt, repository)
        target.parent.mkdir(parents=True, exist_ok=True)
        try:
            # Exclusive rename; a concurrent winning cache is retained unchanged.
            if target.exists():
                _validate_repository(target, repository)
            else:
                attempt.rename(target)
        except FileExistsError:
            _validate_repository(target, repository)
        return target, False


def acquire_batch(urls: list[str], root: Path,
                  progress: Callable[[dict[str, Any]], None] | None = None, *,
                  network_mode: str = "system") -> Path:
    """Download up to 20 inputs with at most two concurrent material jobs.

    ``root`` is a dedicated persistent cache. Each call creates a unique
    ``batches/<uuid>/records.jsonl`` plus ``acquisition.json`` receipt. Every input
    remains in order, including failures through its explicit ``input_error``.
    ``network_mode`` changes only these downloads: ``system`` retains existing
    proxy handling; ``direct`` explicitly disables proxy routing without fallback.
    Callers must still run the ordinary free precheck and obtain model consent.
    """
    network_mode = validate_network_mode(network_mode)
    # Preserve existing callback/monkeypatch signatures for the default mode.
    network_options = {"network_mode": network_mode} if network_mode == "direct" else {}
    if not isinstance(urls, list) or any(not isinstance(url, str) for url in urls):
        raise AcquisitionError("advisory_urls_invalid")
    canonical = parse_advisory_urls("\n".join(urls))
    root = Path(root).resolve()
    root.mkdir(parents=True, exist_ok=True)
    destination = root / "batches" / uuid4().hex
    destination.mkdir(parents=True)
    notification_lock = threading.Lock()
    rate_limited = {provider: threading.Event() for provider in ("github", "osv")}

    def emit(index: int, source: str, phase: str, **details: Any) -> None:
        if progress is not None:
            with notification_lock:
                progress({"index": index + 1, "total": len(canonical), "source_link": source,
                          "input_source_url": source,
                          "source_provider": "osv" if source.startswith("https://osv.dev/") else "github",
                          "phase": phase, **details})

    def one(item: tuple[int, str]) -> tuple[dict[str, Any], dict[str, Any]]:
        index, source = item
        provider = "osv" if source.startswith("https://osv.dev/") else "github"
        identifier = source.rsplit("/", 1)[1]
        provenance = {"input_source_url": source, "source_provider": provider,
                      "source_record_id": identifier}
        row: dict[str, Any] = {"source_link": source if provider == "github" else "", **provenance}
        receipt: dict[str, Any] = {**row, "status": "failed"}
        try:
            emit(index, source, "advisory")
            cache = _cached_osv if provider == "osv" else _cached_advisory
            advisory_path, advisory, cached = cache(
                root, identifier, allow_download=not rate_limited[provider].is_set(), **network_options)
            row["advisory"] = str(advisory_path)
            receipt.update(advisory_cached=cached, advisory=str(advisory_path))
            if provider == "osv":
                row["source_record_id"] = receipt["source_record_id"] = advisory["id"]
                ghsa = osv_ghsa_identifier(advisory)
                row["source_link"] = receipt["source_link"] = "https://github.com/advisories/GHSA-" + ghsa[5:].lower()
                require_osv_reviewed(advisory)
                repository = _repository_from_osv(advisory)
            else:
                repository = _repository_from_advisory(advisory)
            row["repo_url"] = repository
            emit(index, source, "repository", repo_url=repository)
            repository_path, cached = _cached_repository(root, repository, **network_options)
            row["repo_path"] = str(repository_path)
            receipt.update(status="ready", repository_cached=cached, repo_url=repository)
            emit(index, source, "ready", repo_url=repository)
        except AcquisitionError as error:
            if str(error) == provider + "_rate_limited":
                rate_limited[provider].set()
            row["input_error"] = str(error)
            receipt["code"] = str(error)
            emit(index, source, "failed", code=str(error))
        except OSError:
            row["input_error"] = "acquisition_storage_failed"
            receipt["code"] = row["input_error"]
            emit(index, source, "failed", code=row["input_error"])
        return row, receipt

    with ThreadPoolExecutor(max_workers=MAX_WORKERS, thread_name_prefix="t2-public-input") as executor:
        results = list(executor.map(one, enumerate(canonical)))
    manifest = destination / "records.jsonl"
    with manifest.open("x", encoding="utf-8", newline="\n") as stream:
        for row, _ in results:
            stream.write(json.dumps(row, ensure_ascii=False) + "\n")
    providers = {item["source_provider"] for _, item in results}
    receipt = {"version": 2, "source": "public_" + (next(iter(providers)) if len(providers) == 1 else "mixed"),
               "network_mode": network_mode,
               "http_model_attempts": 0,
               "inputs": [item for _, item in results],
               "ready": sum(item["status"] == "ready" for _, item in results),
               "failed": sum(item["status"] == "failed" for _, item in results),
               "limits": {"urls": MAX_URLS, "parallel_downloads": MAX_WORKERS,
                          "clone_timeout_seconds": CLONE_TIMEOUT_SECONDS,
                          "repository_bytes": MAX_REPOSITORY_BYTES, "cache_bytes": MAX_CACHE_BYTES}}
    with (destination / "acquisition.json").open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(receipt, stream, ensure_ascii=False, indent=2)
        stream.write("\n")
    return manifest
