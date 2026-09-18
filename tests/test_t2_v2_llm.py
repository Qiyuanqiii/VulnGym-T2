"""Small paid-transport boundary checks; every response here is synthetic."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from vulngym_t2.llm import DeepSeekClient, MODEL, ProviderError, RequestLedger
from vulngym_t2 import staged_protocol, transport
from tests.test_t2_v2_protocol import record, step, tool_envelope


def reply(value=None, finish="stop", *, model=MODEL):
    return json.dumps({"object": "chat.completion", "model": model,
                       "choices": [{"index": 0, "finish_reason": finish,
                                    "message": {"role": "assistant", "content": json.dumps(value or {"action": "draft"})}}],
                       "usage": {"prompt_tokens": 10, "completion_tokens": 20, "total_tokens": 30}}).encode()


def malformed_reply(content='{"unfinished":'):
    value = json.loads(reply())
    value["choices"][0]["message"]["content"] = content
    return json.dumps(value).encode()


def staged_reply(name, arguments):
    envelope = json.loads(tool_envelope(arguments=json.dumps(arguments)))
    envelope["choices"][0]["message"]["tool_calls"][0]["function"]["name"] = name
    return json.dumps(envelope).encode()


class ClientTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="t2-client-")
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name).resolve() / "requests.jsonl"
        self.ledger = RequestLedger(self.path, limit=2)

    def tearDown(self):
        self.ledger.close()

    def client(self, send):
        return DeepSeekClient("dummy-not-a-real-key", self.ledger, run_id="synthetic", send=send)

    def test_strict_mode_uses_beta_auto_choice_and_preserves_thinking_without_fallback(self):
        messages = [{"role": "user", "content": "test"}]
        with patch.object(transport, "_post_official", return_value=tool_envelope(step([record()]))) as send:
            client = DeepSeekClient("dummy-not-a-real-key", self.ledger, run_id="synthetic", response_mode="strict_tool")
            result = client.complete(messages)
        payload = json.loads(send.call_args.args[0])
        self.assertEqual(send.call_args.kwargs, {"api_path": "/beta/chat/completions"})
        self.assertEqual(payload["thinking"], {"type": "enabled"})
        self.assertEqual(payload["reasoning_effort"], "high")
        self.assertEqual(payload["tool_choice"], "auto")
        self.assertEqual(len(payload["tools"]), 1)
        self.assertEqual(payload["tools"][0]["function"]["name"], "submit_step")
        self.assertIs(payload["tools"][0]["function"]["strict"], True)
        self.assertNotIn("response_format", payload)
        self.assertNotIn("parallel_tool_calls", payload)
        self.assertEqual(len(messages), 1)
        self.assertEqual(result["fields"]["commit"], "a" * 40)
        self.assertEqual(client.summary()["response_mode"], "strict_tool")
        self.assertNotIn("private hidden reasoning", self.path.read_text())
        send.assert_called_once()

    def test_strict_text_fallback_is_not_accepted_or_retried(self):
        sent = []
        client = DeepSeekClient("dummy-not-a-real-key", self.ledger, run_id="synthetic", response_mode="strict_tool",
                                send=lambda *_: sent.append(True) or reply())
        for _ in range(2):
            with self.assertRaises(ProviderError):
                client.complete([{"role": "user", "content": "test"}])
        self.assertEqual(len(sent), 1)
        self.assertFalse(client.can_continue_after_format_error)

    def test_protocol_diagnostics_reach_ledger_without_allowing_resume(self):
        sent = []
        value = step()
        value["private_unknown_name"] = "private response value"
        client = DeepSeekClient("dummy-not-a-real-key", self.ledger, run_id="synthetic", response_mode="strict_tool",
                                send=lambda *_: sent.append(True) or tool_envelope(value))
        with self.assertRaisesRegex(ProviderError, "deepseek_strict_protocol_invalid"):
            client.complete([{"role": "user", "content": "test"}])
        diagnostic = client.events[0]["diagnostics"]
        self.assertEqual(diagnostic["phase"], "validate_submit_step")
        self.assertIn("protocol_reason", diagnostic)
        self.assertIn("protocol_path", diagnostic)
        self.assertFalse(diagnostic["format_error_isolatable"])
        self.assertFalse(client.can_continue_after_format_error)
        with self.assertRaises(ProviderError):
            client.start_next_case("different-case", continue_on_format_error=True)
        self.assertEqual(len(sent), 1)
        self.assertNotIn("private", self.path.read_text())

    def test_staged_tool_shape_diagnostics_reach_ledger_without_raw_names_or_retry(self):
        body = json.loads(tool_envelope())
        calls = body["choices"][0]["message"]["tool_calls"]
        calls[0]["function"].update(name="read_file", arguments=json.dumps({
            "commit": "a" * 40, "path": "service/handler.py", "start_line": 1, "end_line": 2}))
        calls.append({"type": "function", "id": "private-call-id", "function": {
            "name": "private-unknown-function", "arguments": "private-response"}})
        sent = []
        client = DeepSeekClient("private-synthetic-key", self.ledger, run_id="synthetic",
                                response_mode="staged_tool", thinking="disabled",
                                send=lambda *_: sent.append(True) or json.dumps(body).encode())
        for _ in range(2):
            with self.assertRaisesRegex(ProviderError, "deepseek_strict_tool_call_invalid"):
                client.complete([{"role": "user", "content": "synthetic"}], stage="read")
        diagnostic = client.events[0]["diagnostics"]
        self.assertEqual(diagnostic["tool_call_count"], 2)
        self.assertEqual(diagnostic["tool_names"], ["read_file"])
        self.assertEqual(diagnostic["unknown_tool_count"], 1)
        self.assertEqual(diagnostic["protocol_stage"], "read")
        self.assertFalse(client.can_continue_after_format_error)
        self.assertEqual((len(sent), client.calls, self.ledger.started), (1, 1, 1))
        stored = self.path.read_text()
        self.assertNotIn("private", stored)
        self.assertEqual(json.loads(stored.splitlines()[-1])["diagnostics"]["tool_names"], ["read_file"])
        client.close()

    def test_staged_single_and_multi_use_the_same_direct_snapshot_annotation(self):
        payloads = []
        snapshot = staged_protocol.snapshot_from_state({}, {})
        messages = [{"role": "user", "content": "Synthetic candidate only."}]
        original_header = self.path.read_text().splitlines()[0]
        for multi in (False, True):
            client = DeepSeekClient("synthetic-key", self.ledger, run_id="synthetic",
                                    response_mode="staged_tool", thinking="disabled", multi_entry=multi,
                                    send=lambda body, *_: payloads.append(json.loads(body)) or staged_reply("submit_annotation", snapshot))
            result = client.complete(messages, stage="annotation")
            self.assertEqual(result["action"], "draft")
            self.assertEqual(client.calls, 1)
            self.assertEqual(client.summary()["staged_wire_version"],
                             "candidate-serial-snapshot-v2" if multi else "snapshot-v2")
            client.close()
        for payload in payloads:
            self.assertEqual(payload["model"], MODEL)
            self.assertEqual(payload["tool_choice"], "required")
            self.assertEqual(payload["thinking"], {"type": "disabled"})
            self.assertNotIn("reasoning_effort", payload)
            self.assertNotIn("response_format", payload)
            self.assertEqual([tool["function"]["name"] for tool in payload["tools"]], ["submit_annotation"])
            definition = payload["tools"][0]["function"]
            self.assertTrue(definition["strict"])
            schema = definition["parameters"]
            self.assertEqual(set(schema["properties"]), set(staged_protocol.ANNOTATION_FIELDS))
            self.assertEqual(set(schema["required"]), set(schema["properties"]))
            self.assertFalse(schema["additionalProperties"])
            for field in staged_protocol.ANNOTATION_FIELDS:
                self.assertEqual(schema["properties"][field]["type"], "object")
            self.assertNotIn("summary", schema["properties"])
            self.assertNotIn("entries", schema["properties"])
            self.assertNotIn("slot", schema["properties"])
        self.assertEqual(payloads[0]["tools"], payloads[1]["tools"])
        self.assertEqual(len(messages), 1)
        self.assertEqual(self.ledger.started, 2)
        self.assertEqual(self.path.read_text().splitlines()[0], original_header)

    def test_candidate_selection_is_multi_only_then_annotation_uses_shared_budget(self):
        replies = iter((staged_reply("propose_candidates", {"candidates": []}),
                        staged_reply("submit_annotation", staged_protocol.snapshot_from_state({}, {}))))
        payloads = []
        client = DeepSeekClient("synthetic-key", self.ledger, run_id="synthetic",
                                response_mode="staged_tool", thinking="disabled", multi_entry=True,
                                max_requests=2, send=lambda body, *_: payloads.append(json.loads(body)) or next(replies))
        result = client.complete([{"role": "user", "content": "Choose candidates."}], stage="candidate_selection")
        self.assertEqual(result, {"action": "candidates", "candidates": []})
        self.assertEqual([tool["function"]["name"] for tool in payloads[0]["tools"]], ["propose_candidates"])
        self.assertEqual(client.complete([{"role": "user", "content": "Snapshot."}], stage="annotation")["action"], "draft")
        with self.assertRaisesRegex(ProviderError, "run_request_limit_reached"):
            client.complete([{"role": "user", "content": "No extra budget."}], stage="annotation")
        self.assertEqual((len(payloads), client.calls, self.ledger.started), (2, 2, 2))
        self.assertEqual(client.summary()["automatic_retries"], 0)
        client.close()

    def test_old_multi_stage_and_single_candidate_selection_fail_before_reserve(self):
        sent = []
        for multi, stage in ((False, "annotation_multi"), (True, "annotation_multi"),
                             (False, "candidate_selection"), (True, "unknown"),
                             (False, None), (True, [])):
            client = DeepSeekClient("synthetic-key", self.ledger, run_id="synthetic",
                                    response_mode="staged_tool", thinking="disabled", multi_entry=multi,
                                    send=lambda *_: sent.append(True))
            with self.subTest(multi=multi, stage=stage), self.assertRaises(ValueError):
                client.complete([{"role": "user", "content": "Must stay local."}], stage=stage)
            self.assertEqual(client.calls, 0)
            self.assertIsNone(client.halted)
            client.close()
        self.assertEqual(sent, [])
        self.assertEqual(self.ledger.started, 0)

    def test_multi_read_and_followup_still_use_existing_read_functions(self):
        payloads = []
        client = DeepSeekClient("synthetic-key", self.ledger, run_id="synthetic",
                                response_mode="staged_tool", thinking="disabled", multi_entry=True,
                                send=lambda body, *_: payloads.append(json.loads(body)) or staged_reply("inspect_commit", {"commit": "a" * 40}))
        for stage in ("read", "followup"):
            result = client.complete([{"role": "user", "content": "Existing read."}], stage=stage)
            self.assertEqual(result["action"], "tools")
            self.assertEqual(result["calls"][0]["tool"], "inspect_commit")
        for payload in payloads:
            names = {tool["function"]["name"] for tool in payload["tools"]}
            self.assertIn("inspect_commit", names)
            self.assertNotIn("submit_annotation", names)
            self.assertNotIn("propose_candidates", names)
            self.assertNotIn("submit_annotations", names)
        self.assertEqual(self.ledger.started, 2)
        client.close()

    def test_old_multi_response_container_is_not_a_fallback_for_snapshot(self):
        sent = []
        client = DeepSeekClient("synthetic-key", self.ledger, run_id="synthetic",
                                response_mode="staged_tool", thinking="disabled", multi_entry=True,
                                send=lambda *_: sent.append(True) or staged_reply("submit_annotations", {"entries": []}))
        for _ in range(2):
            with self.assertRaises(ProviderError):
                client.complete([{"role": "user", "content": "Single candidate snapshot."}], stage="annotation")
        self.assertEqual((len(sent), client.calls, self.ledger.started), (1, 1, 1))
        self.assertFalse(client.can_continue_after_format_error)
        self.assertEqual(client.events[0]["diagnostics"]["protocol_stage"], "annotation")
        client.close()

    def test_disabled_thinking_requires_strict_tool_and_omits_reasoning_effort(self):
        sent = []
        client = DeepSeekClient("dummy-not-a-real-key", self.ledger, run_id="synthetic",
                                response_mode="strict_tool", thinking="disabled", reasoning_effort="max",
                                send=lambda body, *_: sent.append(json.loads(body)) or tool_envelope())
        self.assertEqual(client.complete([{"role": "user", "content": "test"}])["action"], "draft")
        self.assertEqual(sent[0]["thinking"], {"type": "disabled"})
        self.assertEqual(sent[0]["tool_choice"], "required")
        self.assertNotIn("reasoning_effort", sent[0])
        self.assertNotIn("response_format", sent[0])
        self.assertEqual(len(sent[0]["tools"]), 1)
        self.assertIs(sent[0]["tools"][0]["function"]["strict"], True)
        summary = client.summary()
        self.assertEqual(summary["thinking"], "disabled")
        self.assertEqual(summary["tool_choice"], "required")
        self.assertIsNone(summary["reasoning_effort"])
        self.assertEqual(summary["api_path"], "/beta/chat/completions")
        self.assertEqual((client.calls, self.ledger.started), (1, 1))

    def test_disabled_thinking_still_rejects_plain_text_without_retry_or_fallback(self):
        sent = []
        client = DeepSeekClient("dummy-not-a-real-key", self.ledger, run_id="synthetic",
                                response_mode="strict_tool", thinking="disabled",
                                send=lambda *_: sent.append(True) or reply())
        for _ in range(2):
            with self.assertRaisesRegex(ProviderError, "deepseek_completion_incomplete"):
                client.complete([{"role": "user", "content": "test"}])
        self.assertEqual(len(sent), 1)
        self.assertFalse(client.can_continue_after_format_error)

    def test_invalid_thinking_or_disabled_json_is_rejected_before_send(self):
        for thinking in (None, True, [], "auto", "Disabled"):
            with self.subTest(thinking=thinking), self.assertRaisesRegex(ValueError, "provider_thinking_invalid"):
                DeepSeekClient("dummy-not-a-real-key", self.ledger, run_id="synthetic", thinking=thinking)
        with self.assertRaisesRegex(ValueError, "thinking_disabled_requires_strict_tool"):
            DeepSeekClient("dummy-not-a-real-key", self.ledger, run_id="synthetic", thinking="disabled")
        self.assertEqual(self.ledger.started, 0)

    def test_format_failure_is_only_resumed_explicitly_on_a_new_case_without_budget_reset(self):
        replies = iter([malformed_reply(), reply()])
        client = self.client(lambda *_: next(replies))
        self.assertFalse(client.start_next_case("case-a"))
        with self.assertRaises(ProviderError):
            client.complete([{"role": "user", "content": "test"}])
        self.assertTrue(client.can_continue_after_format_error)
        with self.assertRaises(AttributeError):
            client.can_continue_after_format_error = False
        with self.assertRaises(ProviderError):
            client.start_next_case("case-b")
        with self.assertRaisesRegex(ProviderError, "format_failure_case_cannot_be_retried"):
            client.start_next_case("case-a", continue_on_format_error=True)
        self.assertTrue(client.start_next_case("case-b", continue_on_format_error=True))
        self.assertEqual((client.calls, self.ledger.started), (1, 1))
        self.assertFalse(client.can_continue_after_format_error)
        self.assertEqual(client.complete([{"role": "user", "content": "next"}]), {"action": "draft"})
        self.assertEqual((client.calls, self.ledger.started), (2, 2))
        self.assertEqual(client.summary()["usage"]["total_tokens"], 60)
        self.assertEqual(len(client.events), 2)
        self.assertEqual(len(client.summary()["format_failure_continuations"]), 1)
        with self.assertRaisesRegex(ProviderError, "format_failure_case_cannot_be_retried"):
            client.start_next_case("case-a")
        client.start_next_case("case-c")
        with self.assertRaisesRegex(ProviderError, "authorization_request_limit_reached"):
            client.complete([{"role": "user", "content": "beyond budget"}])
        self.assertEqual(self.ledger.started, 2)

    def test_isolation_cannot_return_to_an_already_processed_different_case(self):
        replies = iter([reply(), malformed_reply()])
        client = self.client(lambda *_: next(replies))
        client.start_next_case("case-a")
        client.complete([{"role": "user", "content": "first"}])
        client.start_next_case("case-b")
        with self.assertRaises(ProviderError):
            client.complete([{"role": "user", "content": "bad"}])
        with self.assertRaisesRegex(ProviderError, "format_failure_case_cannot_be_retried"):
            client.start_next_case("case-a", continue_on_format_error=True)
        self.assertEqual(client.calls, 2)

    def test_resume_does_not_reset_run_limit_or_legacy_ledger_header(self):
        original_header = self.path.read_text().splitlines()[0]
        client = DeepSeekClient("dummy-not-a-real-key", self.ledger, run_id="synthetic", max_requests=1,
                                send=lambda *_: malformed_reply())
        client.start_next_case("case-a")
        with self.assertRaises(ProviderError):
            client.complete([{"role": "user", "content": "bad"}])
        client.start_next_case("case-b", continue_on_format_error=True)
        with self.assertRaisesRegex(ProviderError, "run_request_limit_reached"):
            client.complete([{"role": "user", "content": "over limit"}])
        self.assertEqual((client.calls, self.ledger.started), (1, 1))
        self.assertEqual(self.path.read_text().splitlines()[0], original_header)

    def test_unsafe_failures_never_allow_case_continuation(self):
        refused = json.loads(reply())
        refused["choices"][0]["message"].update(refusal="refused", content='{"bad":')
        failures = [b'{"outer":', reply(model="another-model"), reply(finish="length"),
                    json.dumps(refused).encode(), transport.TransportError("deepseek_authentication_failed"),
                    transport.TransportError("deepseek_access_denied"), transport.TransportError("deepseek_timeout"),
                    RuntimeError("private exception"), transport._CompletionJSONBlocked("deepseek_response_invalid_json", {"phase": "parse_completion_json"})]
        for index, failure in enumerate(failures):
            def send(*_):
                if isinstance(failure, Exception):
                    raise failure
                return failure
            ledger = RequestLedger(self.path.with_name(f"unsafe-{index}.jsonl"), limit=2)
            try:
                client = DeepSeekClient("dummy-not-a-real-key", ledger, run_id="synthetic", send=send)
                client.start_next_case("case-a")
                with self.subTest(index=index), self.assertRaises(ProviderError):
                    client.complete([{"role": "user", "content": "test"}])
                self.assertFalse(client.can_continue_after_format_error)
                with self.assertRaises(ProviderError):
                    client.start_next_case("case-b", continue_on_format_error=True)
                self.assertEqual(client.calls, 1)
            finally:
                ledger.close()

    def test_strict_argument_json_failure_can_be_isolated_but_schema_failure_cannot(self):
        for index, arguments in enumerate(('{"bad":', '{"action":"draft"}')):
            ledger = RequestLedger(self.path.with_name(f"strict-{index}.jsonl"), limit=2)
            try:
                client = DeepSeekClient("dummy-not-a-real-key", ledger, run_id="synthetic", response_mode="strict_tool",
                                        send=lambda *_: tool_envelope(arguments=arguments))
                client.start_next_case("case-a")
                with self.assertRaises(ProviderError):
                    client.complete([{"role": "user", "content": "test"}])
                self.assertEqual(client.can_continue_after_format_error, index == 0)
            finally:
                ledger.close()

    def test_success_records_actual_usage_without_key(self):
        sent = []
        c = self.client(lambda body, key, timeout: sent.append(json.loads(body)) or reply())
        self.assertEqual(c.complete([{"role": "user", "content": "test"}])["action"], "draft")
        self.assertEqual(c.summary()["usage"]["total_tokens"], 30)
        self.assertEqual(sent[0]["model"], MODEL)
        self.assertEqual(sent[0]["thinking"], {"type": "enabled"})
        self.assertEqual(sent[0]["reasoning_effort"], "high")
        self.assertEqual(sent[0]["response_format"], {"type": "json_object"})
        self.assertNotIn("tools", sent[0])
        self.assertNotIn("tool_choice", sent[0])
        self.assertEqual(c.summary()["thinking"], "enabled")
        self.assertIsNone(c.summary()["tool_choice"])
        self.assertNotIn("dummy-not-a-real-key", self.path.read_text())
        c.close()
        self.assertEqual(c._key, "")

    def test_persistent_ceiling_survives_reopen(self):
        c = self.client(lambda *_: reply())
        c.complete([{"role": "user", "content": "1"}])
        self.ledger.close()
        self.ledger = RequestLedger(self.path, limit=2)
        c = self.client(lambda *_: reply())
        c.complete([{"role": "user", "content": "2"}])
        with self.assertRaisesRegex(ProviderError, "authorization_request_limit_reached"):
            c.complete([{"role": "user", "content": "3"}])
        self.assertEqual(self.ledger.started, 2)

    def test_transport_failure_stops_without_retry_or_exception_leak(self):
        def failed(*_):
            raise RuntimeError("dummy-not-a-real-key PRIVATE EXCEPTION")
        c = self.client(failed)
        for _ in range(2):
            with self.assertRaisesRegex(ProviderError, "provider_request_failed"):
                c.complete([{"role": "user", "content": "test"}])
        self.assertEqual(c.calls, 1)
        self.assertNotIn("PRIVATE", self.path.read_text())

    def test_truncation_is_counted_and_usage_preserved(self):
        c = self.client(lambda *_: reply(finish="length"))
        with self.assertRaises(ProviderError):
            c.complete([{"role": "user", "content": "test"}])
        self.assertEqual(self.ledger.started, 1)
        self.assertEqual(self.ledger.usage["total_tokens"], 30)
        self.assertTrue(c.halted)

    def test_unfinished_attempt_not_replayed(self):
        self.ledger.reserve(run_id="unknown", case_id="case")
        self.ledger.close()
        with self.assertRaisesRegex(ValueError, "unfinished_request"):
            RequestLedger(self.path, limit=2)

    def test_selected_model_is_bound_to_request_response_summary_and_ledger(self):
        selected = "deepseek-flash"
        self.ledger.close()
        self.path = self.path.with_name("selected.jsonl")
        self.ledger = RequestLedger(self.path, limit=2, model=selected)
        sent = []
        client = DeepSeekClient("dummy-not-a-real-key", self.ledger, run_id="synthetic",
                                model=selected, send=lambda body, *_: sent.append(json.loads(body)) or reply(model=selected))
        self.assertEqual(client.complete([{"role": "user", "content": "test"}]), {"action": "draft"})
        self.assertEqual(sent[0]["model"], selected)
        self.assertEqual(client.summary()["model"], selected)
        self.assertEqual(client.summary()["authorization_model"], selected)
        self.assertEqual(json.loads(self.path.read_text().splitlines()[0]), {
            "event": "authorization", "request_limit": 2, "model": selected, "automatic_retries": 0})
        self.ledger.close()
        self.ledger = RequestLedger(self.path, limit=2, model=selected)
        self.assertEqual(self.ledger.started, 1)
        client.close()

    def test_existing_ledger_model_cannot_be_changed(self):
        self.ledger.close()
        original = self.path.read_bytes()
        with self.assertRaisesRegex(ValueError, "ledger_authorization_mismatch"):
            RequestLedger(self.path, limit=2, model="deepseek-flash")
        self.assertEqual(self.path.read_bytes(), original)
        self.ledger = RequestLedger(self.path, limit=2)
        self.assertEqual(self.ledger.model, MODEL)

    def test_client_model_must_match_ledger_before_any_send(self):
        sent = []
        with self.assertRaisesRegex(ValueError, "ledger_authorization_mismatch"):
            DeepSeekClient("dummy-not-a-real-key", self.ledger, run_id="synthetic",
                           model="deepseek-flash", send=lambda *_: sent.append(True))
        self.assertEqual(sent, [])
        self.assertEqual(self.ledger.started, 0)

    def test_selected_response_model_mismatch_halts_without_retry(self):
        self.ledger.close()
        self.path = self.path.with_name("selected.jsonl")
        self.ledger = RequestLedger(self.path, limit=2, model="deepseek-flash")
        sent = []
        client = DeepSeekClient("dummy-not-a-real-key", self.ledger, run_id="synthetic",
                                model=self.ledger.model, send=lambda *_: sent.append(True) or reply())
        for _ in range(2):
            with self.assertRaisesRegex(ProviderError, "deepseek_response_model_mismatch"):
                client.complete([{"role": "user", "content": "test"}])
        self.assertEqual(len(sent), 1)
        self.assertEqual(self.ledger.started, 1)
        self.assertFalse(client.events[0]["diagnostics"]["model_matches"])
        client.close()

    def test_invalid_model_is_rejected_before_ledger_creation_or_send(self):
        invalid_path = self.path.with_name("invalid.jsonl")
        for model in (None, "", "deepseek-", "DEEPSEEK-v4-pro", "deepseek-model\n", "deepseek-model/path",
                      "deepseek-model?key=value", "deepseek-" + "x" * 121):
            with self.subTest(model=model):
                with self.assertRaisesRegex(ValueError, "provider_model_invalid"):
                    RequestLedger(invalid_path, model=model)
                self.assertFalse(invalid_path.exists())
                self.assertFalse(invalid_path.with_suffix(".jsonl.lock").exists())
                with self.assertRaisesRegex(ValueError, "provider_model_invalid"):
                    DeepSeekClient("dummy-not-a-real-key", self.ledger, run_id="synthetic", model=model)
        self.assertEqual(self.ledger.started, 0)

    def test_model_selection_does_not_raise_authorization_or_run_caps(self):
        from vulngym_t2.llm import MAX_AUTHORIZED_REQUESTS
        with self.assertRaisesRegex(ValueError, "request_limit_invalid"):
            RequestLedger(self.path.with_name("over-limit.jsonl"), limit=MAX_AUTHORIZED_REQUESTS + 1,
                          model="deepseek-flash")
        with self.assertRaisesRegex(ValueError, "run_request_limit_invalid"):
            DeepSeekClient("dummy-not-a-real-key", self.ledger, run_id="synthetic", max_requests=501)

    def test_partial_snapshot_is_successful_transport_with_structured_field_diagnostics(self):
        from tests.test_t2_v2_staged_protocol import decision
        snapshot = staged_protocol.snapshot_from_state({}, {})
        snapshot["vuln_title"] = decision("Legal sibling")
        del snapshot["entry_point"]
        client = DeepSeekClient("synthetic-key", self.ledger, run_id="synthetic", response_mode="staged_tool",
                                thinking="disabled", send=lambda *_: staged_reply("submit_annotation", snapshot))
        self.addCleanup(client.close)
        result = client.complete([{"role": "user", "content": "Synthetic draft."}], stage="annotation")
        self.assertEqual(result["fields"], {"vuln_title": "Legal sibling"})
        event = client.events[0]
        self.assertEqual(event["status"], "success")
        self.assertNotIn("failure_kind", event)
        self.assertEqual(event["diagnostics"]["annotation_error_count"], 1)
        self.assertEqual(event["diagnostics"]["annotation_errors"], [{"field": "entry_point",
            "code": "missing_property", "path": "$[0].arguments.entry_point"}])
        self.assertEqual(json.loads(self.path.read_text().splitlines()[-1])["diagnostics"], event["diagnostics"])
        result["annotation_errors"][0]["code"] = "caller_mutation"
        self.assertEqual(event["diagnostics"]["annotation_errors"][0]["code"], "missing_property")
        self.assertIsNone(client.halted)
        self.assertEqual((client.calls, self.ledger.started), (1, 1))

    def test_failure_kind_is_typed_not_permission_to_continue(self):
        bad_arguments = json.loads(staged_reply("submit_annotation", {}))
        bad_arguments["choices"][0]["message"]["tool_calls"][0]["function"]["arguments"] = '{"unfinished":'
        cases = [(staged_reply("submit_annotation", {"extra": "private-value"}), "format", False),
                 (staged_reply("unrecognized", {}), "format", False),
                 (json.dumps(bad_arguments).encode(), "format", True),
                 (reply(finish="length"), "format", False),
                 (reply(), "format", False),
                 (reply(model="another-model"), "transport", False),
                 (b'{"outer":', "transport", False)]
        for index, (response, kind, may_continue) in enumerate(cases):
            ledger = RequestLedger(self.path.with_name(f"typed-{index}.jsonl"), limit=2)
            self.addCleanup(ledger.close)
            client = DeepSeekClient("synthetic-key", ledger, run_id="synthetic", response_mode="staged_tool",
                                    thinking="disabled", send=lambda *_: response)
            self.addCleanup(client.close)
            with self.subTest(index=index), self.assertRaises(ProviderError):
                client.complete([{"role": "user", "content": "Synthetic."}], stage="annotation")
            self.assertEqual(client.events[0]["failure_kind"], kind)
            self.assertEqual(json.loads(ledger.path.read_text().splitlines()[-1])["failure_kind"], kind)
            self.assertEqual(client.can_continue_after_format_error, may_continue)
            self.assertEqual(client.calls, 1)
            self.assertNotIn("private-value", ledger.path.read_text())

    def test_malformed_finish_reason_preserves_usage_and_transport_error_kind(self):
        body = json.loads(reply())
        body["choices"][0]["finish_reason"] = []
        client = self.client(lambda *_: json.dumps(body).encode())
        self.addCleanup(client.close)
        with self.assertRaisesRegex(ProviderError, "deepseek_completion_incomplete"):
            client.complete([{"role": "user", "content": "Synthetic."}])
        self.assertEqual(client.events[0]["usage"]["total_tokens"], 30)
        self.assertEqual(client.events[0]["failure_kind"], "transport")
        self.assertEqual(client.events[0]["diagnostics"]["finish_reason"], "other")

    def test_closed_client_cannot_consume_a_request_with_cleared_credentials(self):
        sent = []
        client = self.client(lambda *_: sent.append(True) or reply())
        client.close()
        client.close()
        with self.assertRaisesRegex(ProviderError, "provider_client_closed"):
            client.complete([{"role": "user", "content": "Must not send."}])
        with self.assertRaisesRegex(ProviderError, "provider_client_closed"):
            client.start_next_case("next")
        self.assertEqual(client._key, "")
        self.assertEqual(sent, [])
        self.assertEqual(self.ledger.started, 0)

    def test_closed_ledger_cannot_write_after_another_writer_acquires_its_lock(self):
        sent = []
        stale_ledger = self.ledger
        client = self.client(lambda *_: sent.append(True) or reply())
        self.addCleanup(client.close)
        stale_ledger.close()
        self.ledger = RequestLedger(self.path, limit=2)
        before = self.path.read_bytes()
        with self.assertRaisesRegex(ProviderError, "ledger_closed"):
            client.complete([{"role": "user", "content": "Must not send."}])
        self.assertEqual(sent, [])
        self.assertEqual(self.path.read_bytes(), before)
        self.assertEqual(self.ledger.started, 0)

    def test_finish_requires_one_pending_integer_request_and_does_not_double_count(self):
        number = self.ledger.reserve(run_id="synthetic", case_id="one")
        self.assertEqual(self.ledger.summary()["unknown_usage_attempts"], 1)
        before = self.path.read_bytes()
        for invalid in (True, 0, 2, [], None):
            with self.subTest(number=invalid), self.assertRaisesRegex(ProviderError, "ledger_finish_invalid"):
                self.ledger.finish(invalid, status="success", usage=None, seconds=0)
        with self.assertRaisesRegex(ProviderError, "unfinished_request"):
            self.ledger.reserve(run_id="synthetic", case_id="two")
        self.assertEqual(self.path.read_bytes(), before)
        self.ledger.finish(number, status="success", usage={"prompt_tokens": 1, "completion_tokens": 2, "total_tokens": 3}, seconds=0)
        with self.assertRaisesRegex(ProviderError, "ledger_finish_invalid"):
            self.ledger.finish(number, status="success", usage=None, seconds=0)
        self.assertEqual(self.ledger.summary()["unknown_usage_attempts"], 0)
        self.assertEqual(self.ledger.usage["total_tokens"], 3)

    def test_reservation_write_failure_stops_before_send_and_preserves_uncertain_record(self):
        sent = []
        client = self.client(lambda *_: sent.append(True) or reply())
        self.addCleanup(client.close)
        with patch("vulngym_t2.llm.os.fsync", side_effect=OSError("private disk detail")):
            with self.assertRaisesRegex(ProviderError, "ledger_write_failed_preserve_and_inspect"):
                client.complete([{"role": "user", "content": "Must not send."}])
        before = self.path.read_bytes()
        with self.assertRaisesRegex(ProviderError, "ledger_write_failed_preserve_and_inspect"):
            client.complete([{"role": "user", "content": "Still must not send."}])
        self.assertEqual(sent, [])
        self.assertEqual(self.path.read_bytes(), before)
        self.assertNotIn("private disk", before.decode())
        self.ledger.close()
        with self.assertRaisesRegex(ValueError, "unfinished_request"):
            RequestLedger(self.path, limit=2)

    def test_finish_write_failure_halts_after_one_attempt_without_claiming_success(self):
        sent = []
        client = self.client(lambda *_: sent.append(True) or reply())
        self.addCleanup(client.close)
        with patch("vulngym_t2.llm.os.fsync", side_effect=[None, OSError("private disk detail")]):
            with self.assertRaisesRegex(ProviderError, "ledger_write_failed_preserve_and_inspect"):
                client.complete([{"role": "user", "content": "Synthetic."}])
        with self.assertRaisesRegex(ProviderError, "ledger_write_failed_preserve_and_inspect"):
            client.complete([{"role": "user", "content": "Must not send again."}])
        self.assertEqual((len(sent), client.calls), (1, 1))
        self.assertEqual(client.events, [])
        self.assertEqual(self.ledger.summary()["unknown_usage_attempts"], 1)

    def test_keyboard_interrupt_preserves_unfinished_attempt_and_unknown_usage(self):
        sent = []
        def interrupted(*_):
            sent.append(True)
            raise KeyboardInterrupt
        client = self.client(interrupted)
        self.addCleanup(client.close)
        with self.assertRaises(KeyboardInterrupt):
            client.complete([{"role": "user", "content": "Synthetic."}])
        self.assertEqual((client.calls, self.ledger.started), (1, 1))
        self.assertEqual(client.events[0]["failure_kind"], "interrupted")
        self.assertEqual(client.events[0]["status"], "error")
        self.assertIsNone(client.events[0]["usage"])
        self.assertEqual(self.ledger.summary()["unknown_usage_attempts"], 1)
        self.assertEqual([json.loads(line)["event"] for line in self.path.read_text().splitlines()],
                         ["authorization", "http_started"])
        with self.assertRaisesRegex(ProviderError, "provider_request_interrupted"):
            client.complete([{"role": "user", "content": "Must not retry."}])
        self.assertEqual(sent, [True])
        self.ledger.close()
        with self.assertRaisesRegex(ValueError, "unfinished_request"):
            RequestLedger(self.path, limit=2)

    def test_invalid_provider_settings_are_rejected_before_reservation(self):
        for settings in ({"timeout": None}, {"timeout": True}, {"timeout": "5"},
                         {"timeout": float("nan")}, {"timeout": float("inf")}, {"timeout": 10 ** 1000},
                         {"reasoning_effort": []}):
            with self.subTest(settings=settings), self.assertRaisesRegex(ValueError, "provider_settings_invalid"):
                DeepSeekClient("synthetic-key", self.ledger, run_id="synthetic", **settings)
        with self.assertRaisesRegex(ValueError, "api_key_missing_or_invalid"):
            DeepSeekClient("x" * 4097, self.ledger, run_id="synthetic")
        self.assertEqual(self.ledger.started, 0)

    def test_interrupt_during_completion_persistence_is_not_a_success_or_retry(self):
        sent = []
        client = self.client(lambda *_: sent.append(True) or reply())
        self.addCleanup(client.close)
        with patch("vulngym_t2.llm.os.fsync", side_effect=[None, KeyboardInterrupt]):
            with self.assertRaises(KeyboardInterrupt):
                client.complete([{"role": "user", "content": "Synthetic."}])
        self.assertEqual((client.calls, self.ledger.started), (1, 1))
        self.assertEqual(client.events[0]["failure_kind"], "interrupted")
        self.assertIsNone(client.events[0]["usage"])
        self.assertEqual(self.ledger.summary()["unknown_usage_attempts"], 1)
        with self.assertRaisesRegex(ProviderError, "provider_request_interrupted"):
            client.complete([{"role": "user", "content": "Must not retry."}])
        self.assertEqual(sent, [True])

    def test_malformed_existing_rows_are_rejected_and_release_the_writer_lock(self):
        header = self.path.read_text().splitlines()[0]
        self.ledger.close()
        for rows, code in (([None], "ledger_event_invalid"), ([[]], "ledger_event_invalid"),
                ([{"event": "http_started", "request": 1}, {"event": "http_finished", "request": True}], "ledger_finish_invalid")):
            text = "\n".join([header, *(json.dumps(row) for row in rows)])
            with self.subTest(code=code), patch.object(Path, "read_text", return_value=text):
                with self.assertRaisesRegex(ValueError, code):
                    RequestLedger(self.path, limit=2)
        with patch.object(Path, "read_text", return_value=header + '\n{"event":"http_started","event":"http_finished"}'):
            with self.assertRaisesRegex(ValueError, "ledger_invalid_json"):
                RequestLedger(self.path, limit=2)
        # Every failed constructor must release its lock; original bytes stay intact.
        self.ledger = RequestLedger(self.path, limit=2)
        self.assertEqual(self.ledger.started, 0)


if __name__ == "__main__":
    unittest.main()
