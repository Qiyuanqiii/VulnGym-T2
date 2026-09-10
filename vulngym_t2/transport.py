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


class _CompletionBlocked(TransportError):
    """Completion counters only; never retain answer or hidden reasoning text."""

    __slots__ = ("diagnostic",)

    def __init__(self, diagnostic: dict[str, Any]) -> None:
        super().__init__("deepseek_output_truncated")
        self.diagnostic = diagnostic


class _JSONBlocked(TransportError):
    """Only structural parser metadata; never retain the offending document."""

    __slots__ = ("diagnostic",)

    def __init__(self, code: str, diagnostic: dict[str, Any]) -> None:
        super().__init__(code)
        self.diagnostic = diagnostic


class _CompletionJSONBlocked(_JSONBlocked):
    """Format failure only after validating the completed provider envelope."""


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
    elif isinstance(error, ValueError) and str(error) in {
            "duplicate_key", "non_finite_json", "json_structure_limit", "json_string_limit",
            "json_key_limit", "json_text_limit", "unsupported_json_type", "json_bytes_limit"}:
        diagnostic["json_error_kind"] = str(error)
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
        if response is not None:
            response.close()
        connection.close()


def _post_official_strict(body: bytes, api_key: str, timeout: float) -> bytes:
    return _post_official(body, api_key, timeout, api_path=STRICT_API_PATH)


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate_key")
        result[key] = value
    return result


def _constant(_value: str) -> None:
    raise ValueError("non_finite_json")


def _finite_float(value: str) -> float:
    number = float(value)
    if not math.isfinite(number):
        raise ValueError("non_finite_json")
    return number


def _strict_object(raw: bytes) -> dict[str, Any]:
    if not isinstance(raw, bytes) or len(raw) > MAX_RESPONSE_BYTES:
        raise TransportError("deepseek_response_too_large")
    text = None
    try:
        text = raw.decode("utf-8")
        value = json.loads(text, object_pairs_hook=_pairs,
                           parse_constant=_constant, parse_float=_finite_float)
    except (ValueError, UnicodeError, RecursionError) as error:
        raise _json_failure("deepseek_response_invalid_json", text, error) from None
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
                        response_mode: str = "json") -> dict[str, Any]:
    expected_model = validate_model_id(expected_model)
    if not isinstance(response_mode, str) or response_mode not in {"json", "strict_tool"}:
        raise ValueError("provider_response_mode_invalid")
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
    expected_finish = "tool_calls" if response_mode == "strict_tool" else "stop"
    if finish != expected_finish:
        if finish == "length":
            raise _CompletionBlocked(_truncation_metadata(envelope, choice, len(raw)))
        raise TransportError({"content_filter": "deepseek_content_filtered",
                              "insufficient_system_resource": "deepseek_resource_unavailable"}.get(
                                  finish if isinstance(finish, str) else "", "deepseek_completion_incomplete"))
    message = choice.get("message")
    if not isinstance(message, dict) or message.get("role") != "assistant":
        raise TransportError("deepseek_response_invalid")
    if message.get("refusal"):
        raise TransportError("deepseek_refusal")
    if response_mode == "strict_tool":
        calls = message.get("tool_calls")
        if not isinstance(calls, list) or len(calls) != 1 or not isinstance(calls[0], dict):
            raise TransportError("deepseek_strict_tool_call_invalid")
        call = calls[0]
        function = call.get("function")
        if (call.get("type") != "function" or not isinstance(function, dict)
                or function.get("name") != protocol.STRICT_TOOL_NAME
                or set(function) != {"name", "arguments"}
                or not isinstance(call.get("id"), str) or not 1 <= len(call["id"]) <= 256):
            raise TransportError("deepseek_strict_tool_call_invalid")
        content = message.get("content")
        if content is not None and not isinstance(content, str):
            raise TransportError("deepseek_strict_tool_call_invalid")
        # Native tool messages may also contain prose. Only the sole typed
        # container is authoritative; ancillary content is never returned.
        arguments = function.get("arguments")
        if not isinstance(arguments, str) or not arguments.strip():
            raise TransportError("deepseek_strict_tool_arguments_invalid")
        value = _parse_completion_json(arguments, unwrap_fence=False)
        try:
            return protocol.normalize_step(value)
        except protocol.ProtocolError:
            raise TransportError("deepseek_strict_protocol_invalid") from None
    if message.get("tool_calls"):
        raise TransportError("deepseek_response_invalid")
    content = message.get("content")
    if not isinstance(content, str) or not content.strip():
        raise TransportError("deepseek_empty_content")
    return _parse_completion_json(content, unwrap_fence=True)


def _parse_completion_json(content: str, *, unwrap_fence: bool) -> dict[str, Any]:
    json_content, unwrapped = _unwrap_json_fence(content) if unwrap_fence else (content, False)
    try:
        result = _strict_object(json_content.encode("utf-8"))
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
