"""Small paid-transport boundary checks; every response here is synthetic."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from vulngym_t2.llm import DeepSeekClient, MODEL, ProviderError, RequestLedger
from vulngym_t2 import transport
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


class ClientTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="t2-client-")
        self.path = Path(self.temp.name).resolve() / "requests.jsonl"
        self.ledger = RequestLedger(self.path, limit=2)

    def tearDown(self):
        self.ledger.close()
        self.temp.cleanup()

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

    def test_model_selection_does_not_raise_the_500_request_cap(self):
        with self.assertRaisesRegex(ValueError, "request_limit_invalid"):
            RequestLedger(self.path.with_name("over-limit.jsonl"), limit=501, model="deepseek-flash")
        with self.assertRaisesRegex(ValueError, "run_request_limit_invalid"):
            DeepSeekClient("dummy-not-a-real-key", self.ledger, run_id="synthetic", max_requests=501)


if __name__ == "__main__":
    unittest.main()
