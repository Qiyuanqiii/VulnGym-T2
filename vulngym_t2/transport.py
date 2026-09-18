"""Standalone official DeepSeek HTTPS and strict chat-JSON primitives.

Adapted from this repository's ``vulngym_agent/agents/deepseek_backend.py``;
the bounded JSON domain follows its ``model_runtime.py`` validation, without
hashing, importing either module, or retaining legacy prompts/frameworks.
Only the Python standard library is used. One invocation makes at most one
official HTTPS request: no redirects, retries, environment proxy discovery,
credential lookup, target execution, or import-time network activity.
"""

from __future__ import annotations

import http.client
import json
import math
import re
import socket
from threading import Event, Timer
import time
from typing import Any

from . import protocol


MODEL_ID = "deepseek-v4-pro"
API_HOST = "api.deepseek.com"
API_PATH = "/chat/completions"
STRICT_API_PATH = "/beta/chat/completions"
MAX_REQUEST_BYTES = 2 * 1024 * 1024
MAX_RESPONSE_BYTES = 2 * 1024 * 1024
_MAX_JSON_DEPTH = 16
_MAX_JSON_NODES = 10_000
_MAX_STRING_CHARS = 262_144
_MAX_CANONICAL_BYTES = 1_048_576


def validate_model_id(model: str) -> str:
    """Accept an exact bounded provider ID, without aliases or discovery."""
    if not isinstance(model, str) or not re.fullmatch(r"deepseek-[a-z0-9][a-z0-9.-]{0,119}", model):
        raise ValueError("provider_model_invalid")
    return model


class TransportError(RuntimeError):
    """Only a bounded machine-readable code crosses the client boundary."""

    __slots__ = ("error_code",)

    def __init__(self, error_code: str) -> None:
        if not isinstance(error_code, str) or not re.fullmatch(r"[a-z][a-z0-9_]{0,95}", error_code):
            error_code = "deepseek_transport_error"
        self.error_code = error_code
        super().__init__(error_code)


class _TransportBlocked(TransportError):
    __slots__ = ("diagnostic",)

    def __init__(self, code: str, diagnostic: dict[str, Any]) -> None:
        super().__init__(code)
        self.diagnostic = diagnostic


class _FormatBlocked(_TransportBlocked):
    """Typed format failure, independent of permission to continue another input."""

    __slots__ = ()


class _CompletionBlocked(_FormatBlocked):
    """Completion counters only; never retain answer or hidden reasoning text."""

    __slots__ = ()

    def __init__(self, diagnostic: dict[str, Any]) -> None:
        super().__init__("deepseek_output_truncated", diagnostic)


class _JSONBlocked(_FormatBlocked):
    """Only structural parser metadata; never retain the offending document."""

    __slots__ = ()

    def __init__(self, code: str, diagnostic: dict[str, Any]) -> None:
        super().__init__(code, diagnostic)


class _CompletionJSONBlocked(_JSONBlocked):
    """Format failure only after validating the completed provider envelope."""


_JSON_FAILURE_KINDS = frozenset({
    "duplicate_key", "non_finite_json", "json_structure_limit", "json_string_limit",
    "json_key_limit", "json_text_limit", "unsupported_json_type", "json_bytes_limit", "object_required",
})
_DUPLICATE_KEY_NAMES = frozenset({
    "commit", "vuln_title", "vuln_category_l1", "vuln_category_l2", "entry_point",
    "critical_operation", "trace", "vuln_ids", "value", "status", "reason", "evidence_refs",
    "revision_basis", "evidence_ref", "source_id", "start_line", "end_line", "desc", "candidates", "scope",
    "tool", "arguments", "calls", "records", "name", "path", "query", "paths", "before", "after",
})


class _DuplicateKey(ValueError):
    """Retain a known schema name only, never the repeated values or unknown key."""

    def __init__(self, key):
        super().__init__("duplicate_key")
        self.known_key = key if key in _DUPLICATE_KEY_NAMES else "unknown"


def public_failure_diagnostics(value: Any) -> dict[str, Any]:
    """Expose the failing parse layer without response text or arbitrary labels.

    Reports must not need the private request ledger to distinguish malformed
    function arguments from a network failure. Only fixed parser metadata is
    transferable; applying this filter repeatedly is harmless.
    """
    if not isinstance(value, dict):
        return {}
    enums = {
        "phase": {"parse_completion_json", "parse_completion", "validate_staged_step", "validate_submit_step"},
        "json_error_kind": {"JSONDecodeError", "UnicodeDecodeError", "ValueError", "RecursionError"} | _JSON_FAILURE_KINDS,
        "duplicate_key_name": _DUPLICATE_KEY_NAMES | {"unknown"},
        "json_decode_message": {"Expecting ',' delimiter", "Expecting ':' delimiter", "Expecting value",
                                "Expecting property name enclosed in double quotes", "Extra data",
                                "Unterminated string starting at", "Invalid control character at",
                                "Invalid \\escape", "Invalid \\uXXXX escape"},
        "finish_reason": {"stop", "length", "tool_calls", "content_filter", "insufficient_system_resource", "other"},
        "protocol_stage": {"read", "candidate_selection", "annotation", "followup", "assessment"},
        "tail_kind": {"single_object_close", "other"},
    }
    result = {key: value[key] for key, allowed in enums.items()
              if isinstance(value.get(key), str) and value[key] in allowed}
    for key in ("json_decode_line", "json_decode_column", "answer_characters", "response_bytes", "tail_length"):
        if type(value.get(key)) is int and 0 <= value[key] <= MAX_RESPONSE_BYTES:
            result[key] = value[key]
    for key in ("format_error_isolatable", "refusal_present", "model_matches"):
        if type(value.get(key)) is bool:
            result[key] = value[key]
    # The ledger already filters these counts and fixed names. Preserve the
    # same bounded metadata in public model_failure actions so a reviewer can
    # distinguish a malformed/unknown name without opening the request ledger.
    # Unknown names, argument values and response text remain excluded.
    result.update(_safe_tool_diagnostics(value))
    return result


_DIAGNOSTIC_TOOL_NAMES = frozenset({
    "inspect_commit", "list_refs", "search_history", "list_files", "read_file",
    "search_code", "read_diff", "submit_step", "submit_annotation", "submit_annotations", "propose_candidates", "finish_reading", "submit_read_plan",
})


def _tool_call_diagnostics(message: dict[str, Any]) -> dict[str, Any]:
    """Only counts and fixed known names; never retain unknown names or arguments."""
    calls = message.get("tool_calls")
    if not isinstance(calls, list):
        return {"tool_call_count": None, "tool_names": [], "unknown_tool_count": None}
    known, unknown = set(), 0
    for call in calls:
        function = call.get("function") if isinstance(call, dict) else None
        name = function.get("name") if isinstance(function, dict) else None
        if isinstance(name, str) and name in _DIAGNOSTIC_TOOL_NAMES:
            known.add(name)
        else:
            unknown += 1
    return {"tool_call_count": len(calls), "tool_names": sorted(known), "unknown_tool_count": unknown}


def _safe_tool_diagnostics(values: dict[str, Any]) -> dict[str, Any]:
    """Recheck these three fields at the error/log boundary, without generic lists."""
    result = {}
    for name in ("tool_call_count", "unknown_tool_count"):
        value = values.get(name)
        if name in values and (value is None or type(value) is int and 0 <= value <= 1_048_576):
            result[name] = value
    names = values.get("tool_names")
    if (isinstance(names, list) and len(names) <= len(_DIAGNOSTIC_TOOL_NAMES)
            and all(isinstance(name, str) and name in _DIAGNOSTIC_TOOL_NAMES for name in names)):
        result["tool_names"] = sorted(set(names))
    return result


def _json_shape(text: str | None) -> dict[str, Any]:
    stripped = text.lstrip() if isinstance(text, str) else ""
    first = stripped[:1]
    category = ({"{": "object_start", "[": "array_start", '"': "string_start",
                 "`": "backtick", "": "empty"}.get(first)
                or ("number_start" if first in "-0123456789" else
                    "literal_start" if first in "tfn" else "other"))
    return {"first_nonspace_category": category if text is not None else "undecodable",
            "contains_code_fence": isinstance(text, str) and "```" in text}


def _json_failure(code: str, text: str | None, error: Exception | None = None) -> _JSONBlocked:
    diagnostic = {"error_code": code, "phase": "parse_response_json", **_json_shape(text),
                  "json_error_kind": type(error).__name__ if error is not None else "object_required",
                  "json_decode_message": None, "json_decode_line": None, "json_decode_column": None}
    if isinstance(error, json.JSONDecodeError):
        # JSONDecodeError.msg is a parser-generated description, unlike str(error)
        # or error.doc; neither the source document nor its snippets are retained.
        diagnostic.update(json_decode_message=error.msg[:160],
                          json_decode_line=error.lineno, json_decode_column=error.colno)
    elif isinstance(error, ValueError) and str(error) in _JSON_FAILURE_KINDS:
        diagnostic["json_error_kind"] = str(error)
    if isinstance(error, _DuplicateKey):
        diagnostic["duplicate_key_name"] = error.known_key
    return _JSONBlocked(code, diagnostic)


def _unwrap_json_fence(content: str) -> tuple[str, bool]:
    """Remove only one complete outer ```json/``` wrapper, never repair JSON.

    Fence markers must occupy their own lines; any prefix/suffix prose, other
    language label, or additional fence line keeps the answer untouched and
    subject to the ordinary strict JSON parser.
    """
    match = re.fullmatch(r"```(?:json)?[ \t]*\r?\n(?P<body>[\s\S]*?)\r?\n[ \t]*```[ \t]*", content.strip())
    if match is None:
        return content, False
    body = match.group("body")
    if re.search(r"(?m)^[ \t]*```", body):
        return content, False
    return body, True


def _http_error(status: int) -> str:
    return {401: "deepseek_authentication_failed", 402: "deepseek_balance_insufficient",
            403: "deepseek_access_denied", 429: "deepseek_rate_limited"}.get(
                status, "deepseek_redirect_rejected" if 300 <= status < 400
                else "deepseek_server_error" if status >= 500 else "deepseek_http_error")


def _post_official(body: bytes, api_key: str, timeout: float, *, api_path: str = API_PATH) -> bytes:
    """One direct HTTPS POST, bounded response and total socket deadline.

    A timer shuts down the active socket during header/body waits, including
    streams of keepalive whitespace. OS DNS resolution cannot be cancelled by
    Python's socket timer; after it returns an expired request is abandoned.
    """
    if not isinstance(body, bytes) or len(body) > MAX_REQUEST_BYTES:
        raise TransportError("deepseek_request_too_large")
    if api_path not in (API_PATH, STRICT_API_PATH):
        raise TransportError("deepseek_api_path_invalid")
    if (not isinstance(api_key, str) or not 1 <= len(api_key) <= 4096
            or not all(33 <= ord(char) <= 126 for char in api_key)):
        raise TransportError("deepseek_api_key_missing_or_invalid")
    if (isinstance(timeout, bool) or not isinstance(timeout, (int, float))
            or not math.isfinite(timeout) or not 1 <= timeout <= 300):
        raise TransportError("deepseek_timeout_invalid")

    connection = http.client.HTTPSConnection(API_HOST, timeout=timeout)
    expired = Event()
    active_socket = None
    started = time.monotonic()
    deadline = started + timeout
    phase = "connect"
    request_started = False
    received_bytes = 0
    http_status = None

    def blocked(code: str) -> _TransportBlocked:
        return _TransportBlocked(code, {
            "phase": phase, "error_code": code,
            "elapsed_seconds": round(max(0, time.monotonic() - started), 3),
            "timeout_seconds": timeout, "request_started": request_started,
            "response_bytes_received": received_bytes, "http_status": http_status,
            "usage_and_billing_known": False,
        })

    def cancel() -> None:
        expired.set()
        target = active_socket or connection.sock
        if target is not None:
            try:
                target.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass

    def remaining() -> float:
        left = deadline - time.monotonic()
        if expired.is_set() or left <= 0:
            raise TransportError("deepseek_timeout")
        return left

    timer = Timer(timeout, cancel)
    timer.daemon = True
    timer.start()
    response = None
    try:
        connection.connect()
        active_socket = connection.sock
        active_socket.settimeout(remaining())
        phase = "send"
        request_started = True
        connection.request("POST", api_path, body=body, headers={
            "Authorization": "Bearer " + api_key, "Content-Type": "application/json",
            "Accept": "application/json", "Accept-Encoding": "identity",
        })
        active_socket.settimeout(remaining())
        phase = "wait_headers"
        response = connection.getresponse()
        http_status = response.status
        remaining()
        phase = "response_checks"
        if response.status != 200:
            raise TransportError(_http_error(response.status))
        if response.getheader("Content-Encoding", "identity").lower() != "identity":
            raise TransportError("deepseek_response_encoding_unsupported")
        length = response.getheader("Content-Length")
        if length is not None:
            if not length.isascii() or not length.isdecimal():
                raise TransportError("deepseek_response_invalid")
            if len(length) > 10 or int(length) > MAX_RESPONSE_BYTES:
                raise TransportError("deepseek_response_too_large")
        raw = bytearray()
        phase = "read_body"
        while not response.isclosed():
            active_socket.settimeout(remaining())
            chunk = response.read1(min(64 * 1024, MAX_RESPONSE_BYTES + 1 - len(raw)))
            received_bytes += len(chunk)
            remaining()
            if not chunk:
                break
            raw.extend(chunk)
            if len(raw) > MAX_RESPONSE_BYTES:
                raise TransportError("deepseek_response_too_large")
        if length is not None and len(raw) != int(length):
            raise TransportError("deepseek_response_incomplete")
        return bytes(raw)
    except TransportError as error:
        raise blocked(error.error_code) from None
    except TimeoutError:
        raise blocked("deepseek_timeout") from None
    except (OSError, http.client.HTTPException):
        raise blocked("deepseek_timeout" if expired.is_set() or time.monotonic() >= deadline
                      else "deepseek_transport_error") from None
    finally:
        timer.cancel()
        try:
            if response is not None:
                response.close()
        finally:
            connection.close()


def _post_official_strict(body: bytes, api_key: str, timeout: float) -> bytes:
    return _post_official(body, api_key, timeout, api_path=STRICT_API_PATH)


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateKey(key)
        result[key] = value
    return result


def _constant(_value: str) -> None:
    raise ValueError("non_finite_json")


def _finite_float(value: str) -> float:
    number = float(value)
    if not math.isfinite(number):
        raise ValueError("non_finite_json")
    return number


def _strict_object(raw: bytes, *, normalization_audit: list | None = None) -> dict[str, Any]:
    if not isinstance(raw, bytes) or len(raw) > MAX_RESPONSE_BYTES:
        raise TransportError("deepseek_response_too_large")
    text = None
    try:
        text = raw.decode("utf-8")
        from .completion_json import parse_completion_json
        decoder = json.JSONDecoder(object_pairs_hook=_pairs, parse_constant=_constant, parse_float=_finite_float)
        value, audit = parse_completion_json(text, decoder=decoder, allowed=normalization_audit is not None)
        if audit and normalization_audit is not None:
            normalization_audit.append(audit)
    except (ValueError, UnicodeError, RecursionError) as error:
        from .completion_json import extra_data_diagnostics
        failure = _json_failure("deepseek_response_invalid_json", text, error)
        failure.diagnostic.update(extra_data_diagnostics(text, error))
        raise failure from None
    if not isinstance(value, dict):
        raise _json_failure("deepseek_response_not_object", text) from None
    return value


def _validate_bounded_json(value: dict[str, Any]) -> None:
    """Validate the legacy bounded JSON domain, without a runtime/hash import."""
    nodes = 0
    text_bytes = 0

    def visit(item: Any, depth: int) -> None:
        nonlocal nodes, text_bytes
        nodes += 1
        if nodes > _MAX_JSON_NODES or depth > _MAX_JSON_DEPTH:
            raise ValueError("json_structure_limit")
        if item is None or isinstance(item, (bool, int)):
            return
        if isinstance(item, str):
            if len(item) > _MAX_STRING_CHARS:
                raise ValueError("json_string_limit")
            text_bytes += len(item.encode("utf-8"))
        elif isinstance(item, float):
            if not math.isfinite(item):
                raise ValueError("non_finite_json")
        elif isinstance(item, dict):
            for key, child in item.items():
                if not isinstance(key, str) or len(key) > 256:
                    raise ValueError("json_key_limit")
                text_bytes += len(key.encode("utf-8"))
                if text_bytes > _MAX_CANONICAL_BYTES:
                    raise ValueError("json_text_limit")
                visit(child, depth + 1)
        elif isinstance(item, list):
            for child in item:
                visit(child, depth + 1)
        else:
            raise ValueError("unsupported_json_type")
        if text_bytes > _MAX_CANONICAL_BYTES:
            raise ValueError("json_text_limit")

    visit(value, 0)
    encoded = json.dumps(value, ensure_ascii=False, allow_nan=False, sort_keys=True,
                         separators=(",", ":")).encode("utf-8")
    if len(encoded) > _MAX_CANONICAL_BYTES:
        raise ValueError("json_bytes_limit")


def _bounded_syntax_encoding_failure(content: str, diagnostic: dict[str, Any]) -> bool:
    """Classify bounded syntax only, never repair or extract rejected values.

    Called only after the native envelope, function, stage and refusal checks.
    No source read or annotation value is produced here. Non-syntax and
    resource failures stop, regardless of the selected encoding protocol.
    """
    if (diagnostic.get("json_error_kind") != "JSONDecodeError"
            or not isinstance(content, str) or not 1 <= len(content) <= _MAX_STRING_CHARS
            or not content.lstrip().startswith("{")
            or len(content.encode("utf-8")) > _MAX_CANONICAL_BYTES):
        return False
    # A malformed prefix cannot pass normal JSON resource validation. Apply
    # conservative lexical bounds without extracting any keys or values.
    depth = separators = 0
    quoted = escaped = False
    for char in content:
        if quoted:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                quoted = False
        elif char == '"':
            quoted = True
        elif char in "{[":
            depth += 1
            if depth > _MAX_JSON_DEPTH:
                return False
        elif char in "}]":
            depth -= 1
            if depth < 0:
                return False
        elif char in ",:":
            separators += 1
            if separators >= _MAX_JSON_NODES:
                return False
    return True


def _syntax_annotation_rejection(content: str, diagnostic: dict[str, Any]) -> dict[str, Any] | None:
    if not _bounded_syntax_encoding_failure(content, diagnostic):
        return None
    return {"action": "annotation_snapshot_rejected", "code": "invalid_annotation_json",
            "path": "$[0].arguments", "answer_characters": len(content)}


def _duplicate_annotation_rejection(content: str) -> dict[str, Any] | None:
    """Recognize a rejected snapshot without resolving any duplicate value.

    Strict parsing has already failed. A lossless object-pairs tree is used
    only to locate duplicate location properties or decision evidence_refs.
    Nothing from this tree becomes a field, suggestion, or model feedback.
    Other malformed shapes and resource violations remain hard failures.
    """
    from .staged_protocol import ANNOTATION_FIELDS

    class ObjectPairs(list):
        """Distinct from a JSON array; retain *every* occurrence of each key."""

    def pairs(items):
        if any(len(key) > 64 for key, _ in items):
            raise ValueError("json_key_limit")
        return ObjectPairs([list(pair) for pair in items])

    fields, keys, duplicate_count = set(), set(), 0

    def visit(item, path=()):
        nonlocal duplicate_count
        if isinstance(item, ObjectPairs):
            location = (len(path) == 2 and path[0] in ("entry_point", "critical_operation")
                        and path[1] == "value") or (
                            len(path) == 3 and path[:2] == ("trace", "value")
                            and type(path[2]) is int and 0 <= path[2] < 32)
            seen = set()
            for key, child in item:
                if key in seen:
                    decision_refs = (len(path) == 1 and path[0] in ANNOTATION_FIELDS
                                     and key == "evidence_refs")
                    location_key = location and key in {"source_id", "start_line", "end_line", "desc"}
                    if not (location_key or decision_refs):
                        raise ValueError("duplicate_outside_annotation_allowlist")
                    fields.add(path[0])
                    keys.add(key)
                    duplicate_count += 1
                seen.add(key)
                visit(child, (*path, key))
        elif isinstance(item, list):
            for index, child in enumerate(item):
                visit(child, (*path, index))

    try:
        if len(content.encode("utf-8")) > MAX_RESPONSE_BYTES:
            return None
        tree = json.loads(content, object_pairs_hook=pairs, parse_constant=_constant, parse_float=_finite_float)
        # Pair arrays conservatively consume the same node/depth/text budget;
        # this path never grants a larger JSON domain than ordinary parsing.
        _validate_bounded_json(tree)
        protocol._bounded([{"tool": "submit_annotation", "arguments": tree}], allow_json_scalars=True)
        if (not isinstance(tree, ObjectPairs) or len(tree) != len(ANNOTATION_FIELDS)
                or {key for key, _ in tree} != set(ANNOTATION_FIELDS)):
            return None
        visit(tree)
    except (ValueError, UnicodeError, RecursionError):
        return None
    if not 1 <= duplicate_count <= 128:
        return None
    code = "duplicate_reference_key" if "evidence_refs" in keys else "duplicate_location_key"
    return {"action": "annotation_snapshot_rejected", "code": code,
            "path": "$[0].arguments", "duplicate_fields": sorted(fields),
            "known_duplicate_keys": sorted(keys), "duplicate_key_count": duplicate_count}


def _truncation_metadata(envelope: dict[str, Any], choice: dict[str, Any], size: int) -> dict[str, Any]:
    message = choice.get("message")
    message = message if isinstance(message, dict) else {}
    usage = envelope.get("usage")
    usage = usage if isinstance(usage, dict) else {}

    def token_count(name: str) -> int | None:
        value = usage.get(name)
        return value if type(value) is int and 0 <= value <= 1_000_000_000 else None

    prompt, completion, total = (token_count(k) for k in ("prompt_tokens", "completion_tokens", "total_tokens"))
    return {"error_code": "deepseek_output_truncated", "phase": "parse_completion",
            "finish_reason": "length", "response_bytes": size,
            "answer_characters": len(message["content"]) if isinstance(message.get("content"), str) else None,
            "provider_reasoning_characters": len(message["reasoning_content"])
                if isinstance(message.get("reasoning_content"), str) else None,
            "prompt_tokens": prompt, "completion_tokens": completion, "total_tokens": total,
            "usage_consistent": (prompt is not None and completion is not None and total is not None
                                 and prompt + completion == total),
            "currency_cost_measured": False}


def parse_chat_response(raw: bytes, *, expected_model: str = MODEL_ID,
                        response_mode: str = "json", stage: str | None = None,
                        location_key: str = "evidence_ref", read_format: str = "native_tool") -> dict[str, Any]:
    expected_model = validate_model_id(expected_model)
    if not isinstance(response_mode, str) or response_mode not in {"json", "strict_tool", "staged_tool", "assessment_text"}:
        raise ValueError("provider_response_mode_invalid")
    if read_format not in ("native_tool", "plan_tool"):
        raise ValueError("provider_read_format_invalid")
    if read_format == "plan_tool" and (response_mode != "staged_tool" or stage not in ("read", "followup")):
        raise ValueError("read_plan_stage_invalid")
    if response_mode == "staged_tool":
        from . import staged_protocol
        allowed_names = {item["function"]["name"] for item in staged_protocol.tool_definitions(
            stage, location_key=location_key, read_format=read_format)}
    elif location_key != "evidence_ref":
        raise ValueError("location_reference_key_invalid")
    envelope = _strict_object(raw)
    if envelope.get("object") != "chat.completion":
        raise TransportError("deepseek_response_invalid")
    if envelope.get("model") != expected_model:
        raise TransportError("deepseek_response_model_mismatch")
    choices = envelope.get("choices")
    if not isinstance(choices, list) or len(choices) != 1 or not isinstance(choices[0], dict):
        raise TransportError("deepseek_response_invalid")
    choice = choices[0]
    if type(choice.get("index")) is not int or choice["index"] != 0:
        raise TransportError("deepseek_response_invalid")
    finish = choice.get("finish_reason")
    expected_finish = "tool_calls" if response_mode in {"strict_tool", "staged_tool"} else "stop"
    if finish != expected_finish:
        if finish == "length":
            raise _CompletionBlocked(_truncation_metadata(envelope, choice, len(raw)))
        if finish == "stop" and response_mode in {"strict_tool", "staged_tool"}:
            raise _FormatBlocked("deepseek_completion_incomplete", {"phase": "parse_completion"})
        raise TransportError({"content_filter": "deepseek_content_filtered",
                              "insufficient_system_resource": "deepseek_resource_unavailable"}.get(
                                  finish if isinstance(finish, str) else "", "deepseek_completion_incomplete"))
    message = choice.get("message")
    if not isinstance(message, dict) or message.get("role") != "assistant":
        raise TransportError("deepseek_response_invalid")
    if message.get("refusal"):
        raise TransportError("deepseek_refusal")
    if response_mode in {"strict_tool", "staged_tool"}:
        calls = message.get("tool_calls")
        call_diagnostics = _tool_call_diagnostics(message)
        call_limit = (staged_protocol.MAX_READ_CALLS if response_mode == "staged_tool"
                      and stage == "read" and read_format == "native_tool" else 1)
        if not isinstance(calls, list) or not 1 <= len(calls) <= call_limit:
            raise _FormatBlocked("deepseek_strict_tool_call_invalid", call_diagnostics)
        content = message.get("content")
        if content is not None and not isinstance(content, str):
            raise _FormatBlocked("deepseek_strict_tool_call_invalid", call_diagnostics)
        # Validate every envelope and parse every argument object before returning
        # a batch. A bad later call can never cause an earlier read to execute.
        parsed_calls = []
        completion_normalizations = []
        for call in calls:
            function = call.get("function") if isinstance(call, dict) else None
            if (not isinstance(call, dict) or call.get("type") != "function" or not isinstance(function, dict)
                    or not isinstance(function.get("name"), str)
                    or function.get("name") not in (allowed_names if response_mode == "staged_tool" else {protocol.STRICT_TOOL_NAME})
                    or set(function) != {"name", "arguments"}
                    or not isinstance(call.get("id"), str) or not 1 <= len(call["id"]) <= 256):
                raise _FormatBlocked("deepseek_strict_tool_call_invalid", call_diagnostics)
            arguments = function.get("arguments")
            if not isinstance(arguments, str) or not arguments.strip():
                raise _FormatBlocked("deepseek_strict_tool_arguments_invalid", call_diagnostics)
            # Only tools-closed annotation/selection may tolerate one redundant
            # object close or trailing separator. Read arguments and provider
            # envelopes remain strict. Values still face the full same schema.
            audit = completion_normalizations if (response_mode == "staged_tool" and
                function["name"] in {"submit_annotation", "propose_candidates"}) else None
            try:
                parsed = _parse_completion_json(arguments, unwrap_fence=False, normalization_audit=audit)
            except _CompletionJSONBlocked as error:
                # The tools-closed assessed encoder may reject its whole answer
                # for one same-assessment correction. No failed text is repaired
                # or reused; reads, refusals and outer failures cannot enter it.
                if (response_mode == "staged_tool" and stage == "annotation" and location_key == "source_id"
                        and len(calls) == 1 and function["name"] == "submit_annotation"):
                    if error.diagnostic.get("json_error_kind") == "duplicate_key":
                        rejection = _duplicate_annotation_rejection(arguments)
                    else:
                        rejection = _syntax_annotation_rejection(arguments, error.diagnostic)
                    if rejection:
                        return rejection
                if (read_format == "plan_tool" and len(calls) == 1
                        and _bounded_syntax_encoding_failure(arguments, error.diagnostic)):
                    # The single named read-plan envelope has already passed
                    # every provider/stage/function check. Reject it in full:
                    # no argument decoding, local repair or partial execution.
                    return {"action": "read_plan_rejected", "code": "invalid_plan_json",
                            "path": "$[0].arguments", "answer_characters": len(arguments)}
                raise
            parsed_calls.append({"tool": function["name"], "arguments": parsed})
        if response_mode == "staged_tool":
            try:
                if read_format == "plan_tool":
                    from .read_plan_protocol import normalize
                    return normalize(parsed_calls[0]["arguments"], stage)
                result = staged_protocol.normalize_calls(parsed_calls, stage, location_key=location_key)
                if completion_normalizations:
                    from .completion_json import public_normalizations
                    result["completion_json_normalizations"] = public_normalizations(completion_normalizations)
                return result
            except staged_protocol.ProtocolError as error:
                raise _FormatBlocked(error.error_code, dict(error.diagnostic)) from None
        try:
            return protocol.normalize_step(parsed_calls[0]["arguments"])
        except protocol.ProtocolError as error:
            # Fixed reason codes and schema-only paths, never response values.
            # Remains a global stop, not a resumable JSON syntax failure.
            raise _FormatBlocked("deepseek_strict_protocol_invalid", dict(error.diagnostic)) from None
    if message.get("tool_calls"):
        raise TransportError("deepseek_response_invalid")
    content = message.get("content")
    if not isinstance(content, str) or not content.strip():
        raise TransportError("deepseek_empty_content")
    if response_mode == "assessment_text":
        from .annotation_rules import ASSESSMENT_MAX_CHARS
        if len(content) > ASSESSMENT_MAX_CHARS:
            raise _FormatBlocked("deepseek_assessment_limit", {
                "phase": "parse_completion", "answer_characters": len(content)})
        # Only the public answer is retained, never reasoning_content. This is
        # not parsed as a draft, accepted as evidence, or used to execute tools.
        return {"action": "assessment", "text": content}
    return _parse_completion_json(content, unwrap_fence=True)


def _parse_completion_json(content: str, *, unwrap_fence: bool,
                           normalization_audit: list | None = None) -> dict[str, Any]:
    json_content, unwrapped = _unwrap_json_fence(content) if unwrap_fence else (content, False)
    try:
        result = _strict_object(json_content.encode("utf-8"), normalization_audit=normalization_audit)
        _validate_bounded_json(result)
    except _JSONBlocked as error:
        diagnostic = dict(error.diagnostic, phase="parse_completion_json",
                          answer_characters=len(content), outer_code_fence_unwrapped=unwrapped,
                          answer_first_nonspace_category=_json_shape(content)["first_nonspace_category"],
                          answer_contains_code_fence=_json_shape(content)["contains_code_fence"])
        raise _CompletionJSONBlocked(error.error_code, diagnostic) from None
    except (ValueError, UnicodeError, RecursionError) as error:
        failure = _json_failure("deepseek_response_invalid_json", json_content, error)
        failure.diagnostic.update(phase="parse_completion_json", answer_characters=len(content),
                                  outer_code_fence_unwrapped=unwrapped,
                                  answer_first_nonspace_category=_json_shape(content)["first_nonspace_category"],
                                  answer_contains_code_fence=_json_shape(content)["contains_code_fence"])
        raise _CompletionJSONBlocked(failure.error_code, failure.diagnostic) from None
    # Only the structured answer is returned, never provider hidden reasoning.
    return result
