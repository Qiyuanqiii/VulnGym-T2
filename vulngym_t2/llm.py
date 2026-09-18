"""Small JSON client with a shared, persistent HTTP-attempt ceiling.

Uses the already-working official HTTPS transport, not the legacy agent prompt
or orchestrator. Provider hidden reasoning and credentials are never recorded.
"""
from __future__ import annotations

from datetime import datetime, timezone
import json
import math
import os
from pathlib import Path
import re
import time
from typing import Any

from . import protocol, transport

MODEL = transport.MODEL_ID
# Raised from 2600 to 3000 by explicit user authorization (2026-09-14);
# the shared ledger only accepts an upward --extend-authorization to this ceiling.
MAX_AUTHORIZED_REQUESTS = 3000
MAX_RUN_REQUESTS = 500


class ProviderError(RuntimeError):
    pass


def effective_request_limit(limit: int, effective_limit: int | None = None) -> int:
    """A process-local restriction, never a replacement ledger authorization."""
    if effective_limit is None:
        return limit
    if type(effective_limit) is not int or not 1 <= effective_limit <= limit:
        raise ValueError("effective_request_limit_invalid")
    return effective_limit


def _wire(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=False, allow_nan=False, separators=(",", ":")) + "\n").encode("utf-8")


class RequestLedger:
    """One exclusive writer across all runs using this temporary authorization."""

    def __init__(self, path: Path, *, limit: int = 500, model: str = MODEL,
                 extend_authorization: bool = False, effective_limit: int | None = None):
        if type(limit) is not int or not 1 <= limit <= MAX_AUTHORIZED_REQUESTS:
            raise ValueError("request_limit_invalid")
        self.effective_limit = effective_request_limit(limit, effective_limit)
        self._effective_limit_configured = effective_limit is not None
        self.model = transport.validate_model_id(model)
        self.path = Path(path)
        if not self.path.is_absolute() or not self.path.parent.is_dir():
            raise ValueError("ledger_requires_existing_absolute_parent")
        self.limit = limit
        self._extend_authorization = extend_authorization is True
        self.started = 0
        self.usage = {key: 0 for key in ("prompt_tokens", "completion_tokens", "total_tokens")}
        self.usage_unknown = 0
        self._pending: set[int] = set()
        self._write_failed = False
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
            if self._extend_authorization:
                raise ValueError("authorization_extension_requires_existing_ledger")
            self._append({"event": "authorization", "request_limit": self.limit,
                          "model": self.model, "automatic_retries": 0})
            return
        if self.path.stat().st_size > 2_000_000:
            raise ValueError("ledger_too_large")
        lines = self.path.read_text(encoding="utf-8").splitlines()
        try:
            rows = [json.loads(line, object_pairs_hook=transport._pairs,
                               parse_constant=transport._constant) for line in lines]
        except ValueError:
            raise ValueError("ledger_invalid_json") from None
        recorded_limit = rows[0].get("request_limit") if rows and isinstance(rows[0], dict) else None
        if (type(recorded_limit) is not int or not 1 <= recorded_limit <= MAX_AUTHORIZED_REQUESTS
                or rows[0] != {"event": "authorization", "request_limit": recorded_limit,
                               "model": self.model, "automatic_retries": 0}):
            raise ValueError("ledger_authorization_mismatch")
        starts, finishes = set(), set()
        for row in rows[1:]:
            if not isinstance(row, dict):
                raise ValueError("ledger_event_invalid")
            number = row.get("request")
            if row.get("event") == "http_started":
                if type(number) is not int or number != len(starts) + 1:
                    raise ValueError("ledger_sequence_invalid")
                if number > recorded_limit:
                    raise ValueError("ledger_limit_exceeded")
                starts.add(number)
            elif row.get("event") == "http_finished":
                if type(number) is not int or number not in starts or number in finishes:
                    raise ValueError("ledger_finish_invalid")
                finishes.add(number)
                self._count_usage(row.get("usage"))
            elif row.get("event") == "authorization_extended":
                new_limit = row.get("request_limit")
                if (type(new_limit) is not int or not recorded_limit < new_limit <= MAX_AUTHORIZED_REQUESTS
                        or starts != finishes or row != {"event": "authorization_extended",
                            "previous_limit": recorded_limit, "request_limit": new_limit,
                            "requests_used": len(starts)}):
                    raise ValueError("ledger_extension_invalid")
                recorded_limit = new_limit
            else:
                raise ValueError("ledger_event_invalid")
        self.started = len(starts)
        if starts - finishes:
            # A past attempt might have reached the service. Do not replay it.
            raise ValueError("ledger_has_unfinished_request_preserve_and_inspect")
        if self.started > self.limit:
            raise ValueError("ledger_limit_exceeded")
        if recorded_limit != self.limit:
            if not self._extend_authorization or self.limit < recorded_limit:
                raise ValueError("ledger_authorization_mismatch")
            # Explicit user-authorized extension only. Keep the original header
            # and every attempt; never reset usage or amend past records.
            self._append({"event": "authorization_extended", "previous_limit": recorded_limit,
                          "request_limit": self.limit, "requests_used": self.started})

    def _append(self, row):
        self._ensure_writable()
        data = _wire(row)
        try:
            with self.path.open("ab") as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
        except BaseException as error:
            # A partial durable record must never be followed by an automatic
            # retry or another reservation through this same ledger instance.
            self._write_failed = True
            if isinstance(error, OSError):
                raise ProviderError("ledger_write_failed_preserve_and_inspect") from None
            raise

    def _ensure_writable(self):
        if self._lock.closed:
            raise ProviderError("ledger_closed")
        if self._write_failed:
            raise ProviderError("ledger_write_failed_preserve_and_inspect")

    def reserve(self, *, run_id: str, case_id: str) -> int:
        self._ensure_writable()
        if self._pending:
            raise ProviderError("ledger_has_unfinished_request_preserve_and_inspect")
        if self.started >= self.effective_limit:
            raise ProviderError("authorization_request_limit_reached")
        number = self.started + 1
        self._append({"event": "http_started", "request": number,
                      "run_id": run_id, "case_id": case_id,
                      "at": datetime.now(timezone.utc).isoformat()})
        self.started = number
        self._pending.add(number)
        return number

    def _count_usage(self, usage):
        if not isinstance(usage, dict) or any(type(usage.get(key)) is not int or usage[key] < 0 for key in self.usage):
            self.usage_unknown += 1
            return
        for key in self.usage:
            self.usage[key] += usage[key]

    def finish(self, number, *, status, usage, seconds, code=None, diagnostics=None, failure_kind=None):
        self._ensure_writable()
        if type(number) is not int or number not in self._pending:
            raise ProviderError("ledger_finish_invalid")
        row = {"event": "http_finished", "request": number, "status": status,
                      "usage": usage, "seconds": round(seconds, 3), "code": code,
                      "diagnostics": diagnostics}
        if failure_kind is not None:
            row["failure_kind"] = failure_kind
        self._append(row)
        self._pending.remove(number)
        self._count_usage(usage)

    @property
    def remaining_requests(self):
        return max(0, self.effective_limit - self.started)

    def summary(self):
        summary = {"authorization_model": self.model,
                "authorization_limit": self.limit, "authorization_http_attempts": self.started,
                "authorization_usage": dict(self.usage), "unknown_usage_attempts": self.usage_unknown + len(self._pending),
                "currency_cost_measured": False}
        if self._effective_limit_configured:
            summary.update(effective_authorization_limit=self.effective_limit,
                           effective_authorization_remaining=self.remaining_requests)
        return summary

    def close(self):
        self._lock.close()


class DeepSeekClient:
    def __init__(self, api_key: str, ledger: RequestLedger, *, run_id: str,
                 max_requests: int = 80, max_tokens: int = 8192,
                 reasoning_effort: str = "high", timeout: float = 300, send=None, progress=None,
                 model: str = MODEL, response_mode: str = "json", thinking: str = "enabled",
                 multi_entry: bool = False, annotation_format: str = "native_tool",
                 read_format: str = "native_tool"):
        if not isinstance(api_key, str) or not 1 <= len(api_key) <= 4096 or not all(33 <= ord(c) <= 126 for c in api_key):
            raise ValueError("api_key_missing_or_invalid")
        if type(max_requests) is not int or not 1 <= max_requests <= MAX_RUN_REQUESTS:
            raise ValueError("run_request_limit_invalid")
        if type(max_tokens) is not int or not 256 <= max_tokens <= 32768:
            raise ValueError("output_token_limit_invalid")
        if (not isinstance(reasoning_effort, str) or reasoning_effort not in {"low", "high", "max"}
                or type(timeout) not in (int, float) or not 1 <= timeout <= 300 or not math.isfinite(timeout)):
            raise ValueError("provider_settings_invalid")
        if not isinstance(response_mode, str) or response_mode not in {"json", "strict_tool", "staged_tool"}:
            raise ValueError("provider_response_mode_invalid")
        if not isinstance(thinking, str) or thinking not in {"enabled", "disabled"}:
            raise ValueError("provider_thinking_invalid")
        if thinking == "disabled" and response_mode not in {"strict_tool", "staged_tool"}:
            raise ValueError("thinking_disabled_requires_strict_tool")
        if type(multi_entry) is not bool:
            raise ValueError("multi_entry_invalid")
        if multi_entry and response_mode != "staged_tool":
            raise ValueError("multi_entry_requires_staged_tool")
        if annotation_format not in ("native_tool", "snapshot_json", "snapshot_tool", "assessed_tool"):
            raise ValueError("annotation_format_invalid")
        if annotation_format == "snapshot_json" and (response_mode != "staged_tool" or thinking != "enabled"):
            raise ValueError("snapshot_json_requires_staged_thinking")
        if annotation_format == "snapshot_tool" and (response_mode != "staged_tool" or thinking != "enabled"):
            raise ValueError("snapshot_tool_requires_staged_thinking")
        if annotation_format == "assessed_tool" and (response_mode != "staged_tool" or thinking != "enabled"):
            raise ValueError("assessed_tool_requires_staged_thinking")
        if read_format not in ("native_tool", "plan_tool"):
            raise ValueError("provider_read_format_invalid")
        if read_format == "plan_tool" and response_mode != "staged_tool":
            raise ValueError("plan_tool_requires_staged_tool")
        self.model = transport.validate_model_id(model)
        if self.model != ledger.model:
            raise ValueError("ledger_authorization_mismatch")
        self._key, self.ledger, self.run_id = api_key, ledger, run_id
        self._closed = False
        self.max_requests, self.max_tokens = max_requests, max_tokens
        self.thinking = thinking
        self.reasoning_effort = reasoning_effort if thinking == "enabled" else None
        self.timeout = timeout
        self.response_mode = response_mode
        self.annotation_format = annotation_format
        self.read_format = read_format
        self.multi_entry = multi_entry
        self._send = send or (transport._post_official_strict if response_mode in {"strict_tool", "staged_tool"} else transport._post_official)
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
        if self._closed:
            raise ProviderError("provider_client_closed")
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

    @property
    def remaining_requests(self):
        return min(self.max_requests - self.calls, self.ledger.remaining_requests)

    def complete(self, messages, *, stage=None):
        if self._closed:
            raise ProviderError("provider_client_closed")
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
        snapshot_json = self.annotation_format == "snapshot_json" and stage == "annotation"
        assessment = self.annotation_format == "assessed_tool" and stage == "assessment"
        read_format = self.read_format if stage in ("read", "followup") else "native_tool"
        location_key = "source_id" if self.annotation_format == "assessed_tool" and stage == "annotation" else "evidence_ref"
        if assessment:
            from .annotation_rules import ASSESSMENT_INSTRUCTION
            payload["messages"] = list(messages) + [{"role": "system", "content": ASSESSMENT_INSTRUCTION}]
            # Intentionally plain conclusions, not a failed JSON answer being
            # repaired. The controller separately budgets the native next call.
        elif self.response_mode == "staged_tool":
            from . import staged_protocol
            # Candidate discovery is multi-only; each candidate thereafter uses
            # the same single snapshot schema for drafting and self-review.
            # Reject the old multi container before reserving any paid attempt.
            if (stage == "annotation_multi"
                    or stage == "candidate_selection" and not self.multi_entry):
                raise ValueError("staged_annotation_mode_mismatch")
            if not isinstance(stage, str) or stage not in {"read", "followup", "candidate_selection", "annotation"}:
                raise ValueError("staged_protocol_stage_invalid")
            definitions = staged_protocol.tool_definitions(stage, location_key=location_key, read_format=read_format)
            if snapshot_json:
                # Explicit alternate wire, selected before the request; never a
                # fallback for a failed native response. The same snapshot
                # validator still owns all fields, references and uncertainty.
                schema = definitions[0]["function"]["parameters"]
                instruction = ("This tools-closed annotation stage uses JSON output, not a function call. "
                    "Return ONE JSON object containing exactly the eight decision fields specified below. "
                    "These are the parameters of submit_annotation, without any function wrapper, action, "
                    "arguments, fields, summary or code fence. All evidence and uncertainty rules still apply. "
                    "Provide short evidence-based conclusions, not hidden reasoning. JSON schema: " + _wire(schema).decode("utf-8"))
                payload["messages"] = list(messages) + [{"role": "system", "content": instruction}]
                payload["response_format"] = {"type": "json_object"}
            else:
                payload["messages"] = list(messages) + [{"role": "system", "content": staged_protocol.instruction(
                    stage, location_key=location_key, read_format=read_format)}]
                payload["tools"] = definitions
                if self.annotation_format in {"snapshot_json", "snapshot_tool"} and stage != "annotation":
                    # Read/selection decisions retain the validated mandatory
                    # native protocol. Reasoning is used for annotation only.
                    payload["thinking"] = {"type": "disabled"}
                    payload.pop("reasoning_effort", None)
                if self.annotation_format == "assessed_tool":
                    payload["thinking"] = {"type": "disabled"}
                    payload.pop("reasoning_effort", None)
                    # Constrain non-reasoning planning/encoding variability.
                    # This is not a schema guarantee or an error retry; the
                    # reasoning assessment keeps its original configuration.
                    payload["temperature"] = 0
                payload["tool_choice"] = "required" if payload["thinking"]["type"] == "disabled" else "auto"
                if read_format == "plan_tool":
                    # Explicitly selected before sending; never a fallback for
                    # a failed native batch. Operations are strict enum values.
                    payload["thinking"] = {"type": "disabled"}
                    payload.pop("reasoning_effort", None)
                    payload["tool_choice"] = {"type": "function", "function": {"name": definitions[0]["function"]["name"]}}
        elif self.response_mode == "strict_tool":
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
                                   "finish_reason": finish if isinstance(finish, str) and finish in {"stop", "length", "tool_calls", "content_filter", "insufficient_system_resource"} else "other",
                                   "model_matches": envelope.get("model") == self.model}
                    if self.response_mode in {"strict_tool", "staged_tool"}:
                        diagnostics.update(transport._safe_tool_diagnostics(transport._tool_call_diagnostics(message)))
            reported = envelope.get("usage", {})
            if isinstance(reported, dict):
                keys = ("prompt_tokens", "completion_tokens", "total_tokens")
                if all(type(reported.get(key)) is int and 0 <= reported[key] <= 1_000_000_000 for key in keys):
                    usage = {key: reported[key] for key in keys}
            parsing_response = True
            result = dict(transport.parse_chat_response(raw, expected_model=self.model, response_mode=(
                "assessment_text" if assessment else "json" if snapshot_json else self.response_mode),
                **({"stage": stage, "location_key": location_key, "read_format": read_format}
                   if self.response_mode == "staged_tool" else {})))
            if snapshot_json:
                try:
                    result = staged_protocol.normalize_calls([{"tool": "submit_annotation", "arguments": result}], "annotation")
                except staged_protocol.ProtocolError as error:
                    raise transport._FormatBlocked(error.error_code, dict(error.diagnostic)) from None
        except KeyboardInterrupt:
            self._interrupt_attempt(number)
            raise
        except Exception as exc:
            code = getattr(exc, "error_code", None)
            if not isinstance(code, str) or not re.fullmatch(r"[a-z][a-z0-9_]{0,95}", code):
                code = "provider_request_failed"
            # Stop this client after any transport/format error: no implicit
            # retries, repeated authentication prompts or silent account changes.
            self.halted = code
            failure_kind = "format" if parsing_response and isinstance(exc, transport._FormatBlocked) else "transport"
            self._format_failure = ({"request": number, "case_id": self.case_id, "code": code}
                                    if parsing_response and isinstance(exc, transport._CompletionJSONBlocked) else None)
            if self._format_failure is not None:
                self._failed_format_cases.add(self.case_id)
            safe_detail = getattr(exc, "diagnostic", None)
            if isinstance(safe_detail, dict):
                allowed = {"phase", "json_error_kind", "json_decode_message", "json_decode_line", "json_decode_column",
                           "first_nonspace_category", "contains_code_fence", "answer_characters",
                           "answer_first_nonspace_category", "answer_contains_code_fence", "outer_code_fence_unwrapped",
                           "protocol_reason", "protocol_path"}
                diagnostics = {**(diagnostics or {}), **{name: value for name, value in safe_detail.items()
                    if name in allowed and (value is None or type(value) in (bool, int) or isinstance(value, str) and len(value) <= 200)
                    and (name not in {"protocol_reason", "protocol_path"} or
                         (staged_protocol.is_safe_diagnostic_item(name, value) if self.response_mode == "staged_tool"
                          else protocol.is_safe_diagnostic_item(name, value)))}}
                diagnostics.update(transport._safe_tool_diagnostics(safe_detail))
                diagnostics.update(transport.public_failure_diagnostics(safe_detail))
            diagnostics = {**(diagnostics or {}), "response_mode": self.response_mode,
                           "format_error_isolatable": self.can_continue_after_format_error}
            diagnostics["annotation_format"] = self.annotation_format
            diagnostics["read_format"] = self.read_format
            diagnostics["response_wire"] = ("assessment_text" if assessment else "snapshot_json" if snapshot_json
                                            else "read_plan" if read_format == "plan_tool" else self.response_mode)
            if self.response_mode == "staged_tool":
                diagnostics["protocol_stage"] = stage
            self._finish_attempt(number, status="error", usage=usage,
                                 seconds=time.monotonic() - start, code=code, diagnostics=diagnostics,
                                 failure_kind=failure_kind)
            self.events.append({"request": number, "case_id": self.case_id,
                                "status": "error", "code": code, "failure_kind": failure_kind,
                                "usage": usage, "diagnostics": diagnostics})
            self._notify("http_finished", number, status="error", code=code)
            raise ProviderError(code) from None
        elapsed = time.monotonic() - start
        event = {"request": number, "case_id": self.case_id, "status": "success",
                 "usage": usage, "seconds": round(elapsed, 3)}
        if self.response_mode == "staged_tool":
            errors = [dict(error) for error in result.get("annotation_errors", [])]
            event["diagnostics"] = {"response_mode": self.response_mode, "protocol_stage": stage,
                                    "annotation_format": self.annotation_format,
                                    "read_format": self.read_format,
                                    "response_wire": ("assessment_text" if assessment else "snapshot_json" if snapshot_json
                                                      else "read_plan" if read_format == "plan_tool" else "native_tool"),
                                    "annotation_error_count": len(errors), "annotation_errors": errors}
            if result.get("action") == "read_request_rejected":
                # Generated by the strict stage validator; no rejected values
                # or source are stored, and the batch has not reached a reader.
                event["diagnostics"]["read_request_rejections"] = result["errors"]
            from .staged_protocol import public_snapshot_rejection
            if rejection := public_snapshot_rejection(result):
                event["diagnostics"]["annotation_snapshot_rejection"] = rejection
            from .read_plan_protocol import public_rejection as public_plan_rejection
            if rejection := public_plan_rejection(result):
                event["diagnostics"]["read_plan_rejection"] = rejection
            from .staged_protocol import public_normalizations
            normalizations = public_normalizations(result.get("annotation_normalizations"))
            if normalizations:
                event["diagnostics"]["annotation_normalizations"] = normalizations
            from .staged_protocol import public_error_shapes
            shapes = public_error_shapes(result.get("annotation_error_shapes"))
            if shapes:
                event["diagnostics"]["annotation_error_shapes"] = shapes
            from .completion_json import public_normalizations as public_json_normalizations
            json_normalizations = public_json_normalizations(result.get("completion_json_normalizations"))
            if json_normalizations:
                event["diagnostics"]["completion_json_normalizations"] = json_normalizations
        self._finish_attempt(number, status="success", usage=usage, seconds=elapsed,
                             diagnostics=event.get("diagnostics"))
        self.events.append(event)
        self._notify("http_finished", number, status="success", seconds=round(elapsed, 3))
        return result

    def _finish_attempt(self, number, **detail):
        try:
            self.ledger.finish(number, **detail)
        except KeyboardInterrupt:
            self._interrupt_attempt(number)
            raise
        except ProviderError as error:
            self.halted = str(error)
            self._format_failure = None
            raise

    def _interrupt_attempt(self, number):
        # Delivery/billing or durable completion is uncertain. Never append a
        # synthetic success or allow this client to issue another request.
        self.halted = "provider_request_interrupted"
        self._format_failure = None
        self.events.append({"request": number, "case_id": self.case_id, "status": "error",
                            "code": self.halted, "failure_kind": "interrupted", "usage": None})
        self._notify("http_finished", number, status="interrupted", code=self.halted)

    def close(self):
        self._closed = True
        self._key = ""

    def summary(self):
        from . import staged_protocol
        from .read_plan_protocol import TOOL_NAME, VERSION, MAX_ENCODING_REVIEWS_PER_INPUT, public_rejection

        usage = {key: sum((row.get("usage") or {}).get(key, 0) for row in self.events)
                 for key in ("prompt_tokens", "completion_tokens", "total_tokens")}
        rejected = [detail for row in self.events
                    if (detail := staged_protocol.public_snapshot_rejection(
                        (row.get("diagnostics") or {}).get("annotation_snapshot_rejection")))]
        return {"model": self.model, "http_attempts": self.calls, "run_request_limit": self.max_requests,
                "read_plan_rejection_count": sum(bool(public_rejection(
                    (row.get("diagnostics") or {}).get("read_plan_rejection"))) for row in self.events),
                "max_read_plan_encoding_reviews_per_input": MAX_ENCODING_REVIEWS_PER_INPUT if self.read_format == "plan_tool" else 0,
                "encoding_rejection_count": len(rejected),
                "encoding_json_rejection_count": sum(row["code"] == "invalid_annotation_json" for row in rejected),
                "encoding_missing_root_rejection_count": sum(row["code"] == "missing_root_fields" for row in rejected),
                "response_mode": self.response_mode,
                "annotation_format": self.annotation_format,
                "read_format": self.read_format,
                "read_wire_version": VERSION if self.read_format == "plan_tool" else "native-read-v1",
                "stage_settings": ({"read": {"thinking": "disabled", "temperature": 0, "tool_choice":
                    {"type": "function", "function": {"name": TOOL_NAME}} if self.read_format == "plan_tool" else "required"},
                                    "assessment": {"thinking": "enabled", "response_format": "plain_text"},
                                    "annotation": {"thinking": "disabled", "temperature": 0, "tool_choice": "required", "strict": True},
                                    "requests_per_snapshot": 2,
                                    "max_encoding_shape_reviews_per_snapshot": 1}
                                   if self.annotation_format == "assessed_tool" else
                                   {"read": {"thinking": "disabled", "tool_choice":
                                       {"type": "function", "function": {"name": TOOL_NAME}} if self.read_format == "plan_tool" else "required"},
                                    "annotation": ({"thinking": "enabled", "response_format": "json_object"}
                                                   if self.annotation_format == "snapshot_json" else
                                                   {"thinking": "enabled", "tool_choice": "auto", "strict": True})}
                                   if self.annotation_format in {"snapshot_json", "snapshot_tool"} else
                                   {"read": {"thinking": "disabled", "tool_choice":
                                       {"type": "function", "function": {"name": TOOL_NAME}}},
                                    "annotation": {"thinking": self.thinking, "tool_choice":
                                                   "required" if self.thinking == "disabled" else "auto"}}
                                   if self.read_format == "plan_tool" else None),
                "multi_entry": self.multi_entry,
                "staged_wire_version": (("candidate-serial-assessed-snapshot-v1" if self.multi_entry else "assessed-snapshot-v1")
                                        if self.annotation_format == "assessed_tool" else
                                        (staged_protocol.MULTI_STAGED_WIRE_VERSION if self.multi_entry
                                         else staged_protocol.STAGED_WIRE_VERSION)
                                        if self.response_mode == "staged_tool" else None),
                "prompt_revision": staged_protocol.PROMPT_REVISION if self.response_mode == "staged_tool" else None,
                "location_reference_key": "source_id" if self.annotation_format == "assessed_tool" else "evidence_ref",
                "thinking": self.thinking,
                "tool_choice": ("stage_specific" if self.read_format == "plan_tool"
                                or self.annotation_format in {"snapshot_json", "snapshot_tool", "assessed_tool"} else
                                "required" if self.thinking == "disabled" else "auto")
                    if self.response_mode in {"strict_tool", "staged_tool"} else None,
                "api_path": transport.STRICT_API_PATH if self.response_mode in {"strict_tool", "staged_tool"} else transport.API_PATH,
                "format_failure_continuations": list(self.format_failure_continuations),
                "max_tokens_per_request": self.max_tokens, "reasoning_effort": self.reasoning_effort,
                "timeout_seconds": self.timeout, "automatic_retries": 0,
                "usage": usage, "halted": self.halted, **self.ledger.summary()}
