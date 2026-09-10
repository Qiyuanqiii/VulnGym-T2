"""Small JSON client with a shared, persistent HTTP-attempt ceiling.

Uses the already-working official HTTPS transport, not the legacy agent prompt
or orchestrator. Provider hidden reasoning and credentials are never recorded.
"""
from __future__ import annotations

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import time
from typing import Any

from . import protocol, transport

MODEL = transport.MODEL_ID
MAX_AUTHORIZED_REQUESTS = 500


class ProviderError(RuntimeError):
    pass


def _wire(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=False, allow_nan=False, separators=(",", ":")) + "\n").encode("utf-8")


class RequestLedger:
    """One exclusive writer across all runs using this temporary authorization."""

    def __init__(self, path: Path, *, limit: int = MAX_AUTHORIZED_REQUESTS, model: str = MODEL):
        if type(limit) is not int or not 1 <= limit <= MAX_AUTHORIZED_REQUESTS:
            raise ValueError("request_limit_invalid")
        self.model = transport.validate_model_id(model)
        self.path = Path(path)
        if not self.path.is_absolute() or not self.path.parent.is_dir():
            raise ValueError("ledger_requires_existing_absolute_parent")
        self.limit = limit
        self.started = 0
        self.usage = {key: 0 for key in ("prompt_tokens", "completion_tokens", "total_tokens")}
        self.usage_unknown = 0
        self._lock = self.path.with_suffix(self.path.suffix + ".lock").open("a+b")
        try:
            if self._lock.seek(0, os.SEEK_END) == 0:
                self._lock.write(b"0")
                self._lock.flush()
            self._lock.seek(0)
            if os.name == "nt":
                import msvcrt
                msvcrt.locking(self._lock.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(self._lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            self._read_existing()
        except BaseException:
            self._lock.close()
            raise

    def _read_existing(self):
        if not self.path.exists():
            self._append({"event": "authorization", "request_limit": self.limit,
                          "model": self.model, "automatic_retries": 0})
            return
        if self.path.stat().st_size > 2_000_000:
            raise ValueError("ledger_too_large")
        lines = self.path.read_text(encoding="utf-8").splitlines()
        rows = [json.loads(line) for line in lines]
        if not rows or rows[0] != {"event": "authorization", "request_limit": self.limit,
                                  "model": self.model, "automatic_retries": 0}:
            raise ValueError("ledger_authorization_mismatch")
        starts, finishes = set(), set()
        for row in rows[1:]:
            number = row.get("request")
            if row.get("event") == "http_started":
                if type(number) is not int or number != len(starts) + 1:
                    raise ValueError("ledger_sequence_invalid")
                starts.add(number)
            elif row.get("event") == "http_finished":
                if number not in starts or number in finishes:
                    raise ValueError("ledger_finish_invalid")
                finishes.add(number)
                self._count_usage(row.get("usage"))
            else:
                raise ValueError("ledger_event_invalid")
        self.started = len(starts)
        if starts - finishes:
            # A past attempt might have reached the service. Do not replay it.
            raise ValueError("ledger_has_unfinished_request_preserve_and_inspect")
        if self.started > self.limit:
            raise ValueError("ledger_limit_exceeded")

    def _append(self, row):
        with self.path.open("ab") as stream:
            stream.write(_wire(row))
            stream.flush()
            os.fsync(stream.fileno())

    def reserve(self, *, run_id: str, case_id: str) -> int:
        if self.started >= self.limit:
            raise ProviderError("authorization_request_limit_reached")
        number = self.started + 1
        self._append({"event": "http_started", "request": number,
                      "run_id": run_id, "case_id": case_id,
                      "at": datetime.now(timezone.utc).isoformat()})
        self.started = number
        return number

    def _count_usage(self, usage):
        if not isinstance(usage, dict) or any(type(usage.get(key)) is not int or usage[key] < 0 for key in self.usage):
            self.usage_unknown += 1
            return
        for key in self.usage:
            self.usage[key] += usage[key]

    def finish(self, number, *, status, usage, seconds, code=None, diagnostics=None):
        self._append({"event": "http_finished", "request": number, "status": status,
                      "usage": usage, "seconds": round(seconds, 3), "code": code,
                      "diagnostics": diagnostics})
        self._count_usage(usage)

    def summary(self):
        return {"authorization_model": self.model,
                "authorization_limit": self.limit, "authorization_http_attempts": self.started,
                "authorization_usage": dict(self.usage), "unknown_usage_attempts": self.usage_unknown,
                "currency_cost_measured": False}

    def close(self):
        self._lock.close()


class DeepSeekClient:
    def __init__(self, api_key: str, ledger: RequestLedger, *, run_id: str,
                 max_requests: int = 80, max_tokens: int = 8192,
                 reasoning_effort: str = "high", timeout: float = 300, send=None, progress=None,
                 model: str = MODEL, response_mode: str = "json", thinking: str = "enabled"):
        if not isinstance(api_key, str) or not api_key or not all(33 <= ord(c) <= 126 for c in api_key):
            raise ValueError("api_key_missing_or_invalid")
        if type(max_requests) is not int or not 1 <= max_requests <= MAX_AUTHORIZED_REQUESTS:
            raise ValueError("run_request_limit_invalid")
        if type(max_tokens) is not int or not 256 <= max_tokens <= 32768:
            raise ValueError("output_token_limit_invalid")
        if reasoning_effort not in {"low", "high", "max"} or not 1 <= timeout <= 300:
            raise ValueError("provider_settings_invalid")
        if not isinstance(response_mode, str) or response_mode not in {"json", "strict_tool"}:
            raise ValueError("provider_response_mode_invalid")
        if not isinstance(thinking, str) or thinking not in {"enabled", "disabled"}:
            raise ValueError("provider_thinking_invalid")
        if thinking == "disabled" and response_mode != "strict_tool":
            raise ValueError("thinking_disabled_requires_strict_tool")
        self.model = transport.validate_model_id(model)
        if self.model != ledger.model:
            raise ValueError("ledger_authorization_mismatch")
        self._key, self.ledger, self.run_id = api_key, ledger, run_id
        self.max_requests, self.max_tokens = max_requests, max_tokens
        self.thinking = thinking
        self.reasoning_effort = reasoning_effort if thinking == "enabled" else None
        self.timeout = timeout
        self.response_mode = response_mode
        self._send = send or (transport._post_official_strict if response_mode == "strict_tool" else transport._post_official)
        self.calls = 0
        self.case_id = "unassigned"
        self.halted = None
        self.events: list[dict] = []
        self._progress = progress
        self._attempted_cases: set[str] = set()
        self._failed_format_cases: set[str] = set()
        self._format_failure = None
        self.format_failure_continuations: list[dict] = []

    @property
    def can_continue_after_format_error(self) -> bool:
        return bool(self._format_failure is not None and self.halted == self._format_failure["code"])

    def start_next_case(self, case_id: str, continue_on_format_error: bool = False) -> bool:
        """Optionally isolate one finished format failure, never retry its case."""
        if not isinstance(case_id, str) or not 1 <= len(case_id) <= 256 or any(ord(c) < 32 for c in case_id):
            raise ValueError("case_id_invalid")
        if type(continue_on_format_error) is not bool:
            raise ValueError("continue_on_format_error_invalid")
        if case_id in self._failed_format_cases:
            raise ProviderError("format_failure_case_cannot_be_retried")
        resumed = False
        if self.halted:
            if not continue_on_format_error or not self.can_continue_after_format_error:
                raise ProviderError(self.halted)
            if case_id == self._format_failure["case_id"] or case_id in self._attempted_cases:
                raise ProviderError("format_failure_case_cannot_be_retried")
            self.format_failure_continuations.append(dict(self._format_failure, next_case_id=case_id))
            self.halted = None
            self._format_failure = None
            resumed = True
        self.case_id = case_id
        return resumed

    def _notify(self, event, number, **detail):
        if self._progress:
            try:
                self._progress({"event": event, "request": number, "report_id": self.case_id, **detail})
            except Exception:
                pass  # Progress display must never turn a completed HTTP call into a retry.

    def complete(self, messages):
        if self.halted:
            raise ProviderError(self.halted)
        if self.case_id in self._failed_format_cases:
            self.halted = "format_failure_case_cannot_be_retried"
            raise ProviderError(self.halted)
        if self.calls >= self.max_requests:
            self.halted = "run_request_limit_reached"
            raise ProviderError(self.halted)
        if not isinstance(messages, list) or not messages:
            raise ValueError("messages_required")
        payload = {"model": self.model, "messages": messages,
                   "thinking": {"type": self.thinking}, "reasoning_effort": self.reasoning_effort,
                   "max_tokens": self.max_tokens, "stream": False}
        if self.thinking == "disabled":
            del payload["reasoning_effort"]
        if self.response_mode == "strict_tool":
            # The normalized reply remains ordinary text history. Native calls
            # and hidden reasoning are neither replayed nor executed here.
            payload["messages"] = list(messages) + [{"role": "system", "content": protocol.STRICT_PROTOCOL_INSTRUCTION}]
            payload["tools"] = [protocol.strict_tool_definition()]
            # Official thinking mode rejects required/named tool choices;
            # explicitly disabled thinking permits a mandatory native call.
            payload["tool_choice"] = "required" if self.thinking == "disabled" else "auto"
        else:
            payload["response_format"] = {"type": "json_object"}
        body = _wire(payload)
        if len(body) > transport.MAX_REQUEST_BYTES:
            raise ProviderError("request_context_too_large")
        try:
            number = self.ledger.reserve(run_id=self.run_id, case_id=self.case_id)
        except ProviderError as exc:
            self.halted = str(exc)
            raise
        self.calls += 1
        self._attempted_cases.add(self.case_id)
        self._notify("http_started", number)
        start = time.monotonic()
        usage = None
        diagnostics = None
        parsing_response = False
        try:
            raw = self._send(body, self._key, self.timeout)
            envelope = transport._strict_object(raw)
            choices = envelope.get("choices")
            if isinstance(choices, list) and choices and isinstance(choices[0], dict):
                choice = choices[0]
                message = choice.get("message")
                if isinstance(message, dict):
                    content = message.get("content")
                    finish = choice.get("finish_reason")
                    diagnostics = {"response_bytes": len(raw), "content_type": type(content).__name__,
                                   "content_characters": len(content) if isinstance(content, str) else None,
                                   "non_whitespace_content_characters": len(content.strip()) if isinstance(content, str) else None,
                                   "refusal_present": bool(message.get("refusal")),
                                   "finish_reason": finish if finish in {"stop", "length", "tool_calls", "content_filter", "insufficient_system_resource"} else "other",
                                   "model_matches": envelope.get("model") == self.model}
            reported = envelope.get("usage", {})
            if isinstance(reported, dict):
                keys = ("prompt_tokens", "completion_tokens", "total_tokens")
                if all(type(reported.get(key)) is int and 0 <= reported[key] <= 1_000_000_000 for key in keys):
                    usage = {key: reported[key] for key in keys}
            parsing_response = True
            result = dict(transport.parse_chat_response(raw, expected_model=self.model, response_mode=self.response_mode))
        except Exception as exc:
            code = getattr(exc, "error_code", None)
            if not isinstance(code, str) or not re.fullmatch(r"[a-z][a-z0-9_]{0,95}", code):
                code = "provider_request_failed"
            # Stop this client after any transport/format error: no implicit
            # retries, repeated authentication prompts or silent account changes.
            self.halted = code
            self._format_failure = ({"request": number, "case_id": self.case_id, "code": code}
                                    if parsing_response and isinstance(exc, transport._CompletionJSONBlocked) else None)
            if self._format_failure is not None:
                self._failed_format_cases.add(self.case_id)
            safe_detail = getattr(exc, "diagnostic", None)
            if isinstance(safe_detail, dict):
                allowed = {"phase", "json_error_kind", "json_decode_message", "json_decode_line", "json_decode_column",
                           "first_nonspace_category", "contains_code_fence", "answer_characters",
                           "answer_first_nonspace_category", "answer_contains_code_fence", "outer_code_fence_unwrapped"}
                diagnostics = {**(diagnostics or {}), **{name: value for name, value in safe_detail.items()
                    if name in allowed and (value is None or type(value) in (bool, int) or isinstance(value, str) and len(value) <= 200)}}
            diagnostics = {**(diagnostics or {}), "response_mode": self.response_mode,
                           "format_error_isolatable": self.can_continue_after_format_error}
            self.ledger.finish(number, status="error", usage=usage,
                               seconds=time.monotonic() - start, code=code, diagnostics=diagnostics)
            self.events.append({"request": number, "case_id": self.case_id,
                                "status": "error", "code": code, "usage": usage, "diagnostics": diagnostics})
            self._notify("http_finished", number, status="error", code=code)
            raise ProviderError(code) from None
        elapsed = time.monotonic() - start
        self.ledger.finish(number, status="success", usage=usage, seconds=elapsed)
        self.events.append({"request": number, "case_id": self.case_id, "status": "success",
                            "usage": usage, "seconds": round(elapsed, 3)})
        self._notify("http_finished", number, status="success", seconds=round(elapsed, 3))
        return result

    def close(self):
        self._key = ""

    def summary(self):
        usage = {key: sum((row.get("usage") or {}).get(key, 0) for row in self.events)
                 for key in ("prompt_tokens", "completion_tokens", "total_tokens")}
        return {"model": self.model, "http_attempts": self.calls, "run_request_limit": self.max_requests,
                "response_mode": self.response_mode,
                "thinking": self.thinking,
                "tool_choice": ("required" if self.thinking == "disabled" else "auto")
                    if self.response_mode == "strict_tool" else None,
                "api_path": transport.STRICT_API_PATH if self.response_mode == "strict_tool" else transport.API_PATH,
                "format_failure_continuations": list(self.format_failure_continuations),
                "max_tokens_per_request": self.max_tokens, "reasoning_effort": self.reasoning_effort,
                "timeout_seconds": self.timeout, "automatic_retries": 0,
                "usage": usage, "halted": self.halted, **self.ledger.summary()}
