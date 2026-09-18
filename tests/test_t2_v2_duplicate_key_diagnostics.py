"""Duplicate JSON remains rejected, with transferable non-content diagnostics."""
import json
from pathlib import Path
import tempfile
import unittest

from vulngym_t2 import transport
from vulngym_t2.llm import DeepSeekClient, MODEL, ProviderError, RequestLedger


class DuplicateKeyDiagnosticsTests(unittest.TestCase):
    def failure(self, content):
        with self.assertRaises(transport.TransportError) as caught:
            transport._parse_completion_json(content, unwrap_fence=False)
        return caught.exception.diagnostic

    def test_known_field_and_nested_property_names_survive_public_export(self):
        for content, key in (("{\"entry_point\":{},\"entry_point\":{}}", "entry_point"),
                             ('{"entry_point":{"value":1,"value":2}}', "value")):
            with self.subTest(key=key):
                diagnostic = transport.public_failure_diagnostics(self.failure(content))
                self.assertEqual(diagnostic["json_error_kind"], "duplicate_key")
                self.assertEqual(diagnostic["duplicate_key_name"], key)
                self.assertEqual(diagnostic["phase"], "parse_completion_json")
                self.assertEqual(transport.public_failure_diagnostics(diagnostic), diagnostic)

    def test_identical_repeated_values_still_fail_without_choosing_a_value(self):
        self.assertEqual(self.failure('{"status":"uncertain","status":"uncertain"}')
                         ["json_error_kind"], "duplicate_key")

    def test_unknown_names_and_values_never_enter_diagnostics(self):
        diagnostic = self.failure('{"confidential_marker":"first_secret","confidential_marker":"second_secret"}')
        self.assertEqual(diagnostic["duplicate_key_name"], "unknown")
        text = json.dumps(diagnostic)
        for secret in ("confidential_marker", "first_secret", "second_secret"):
            self.assertNotIn(secret, text)
        self.assertNotIn("duplicate_key_name", transport.public_failure_diagnostics({"duplicate_key_name": "confidential_marker"}))

    def test_nonfinite_error_kind_is_not_silently_lost_in_public_diagnostics(self):
        self.assertEqual(transport.public_failure_diagnostics(self.failure('{"value":NaN}'))
                         ["json_error_kind"], "non_finite_json")

    def test_client_ledger_retains_known_key_without_retry_or_raw_response(self):
        def send(_body, _dummy_key, _timeout):
            return json.dumps({"object": "chat.completion", "model": MODEL, "choices": [{"index": 0,
                "finish_reason": "tool_calls", "message": {"role": "assistant", "content": None,
                "tool_calls": [{"id": "fixture", "type": "function", "function": {
                    "name": "submit_annotation", "arguments": '{"entry_point":"secret_one","entry_point":"secret_two"}'}}]}}],
                "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2}}).encode()
        with tempfile.TemporaryDirectory(prefix="t2-duplicate-key-") as temp:
            path = Path(temp).resolve() / "ledger.jsonl"
            ledger = RequestLedger(path, limit=2)
            client = DeepSeekClient("dummy-not-a-real-key", ledger, send=send, max_requests=1,
                                    run_id="synthetic", response_mode="staged_tool", thinking="disabled")
            try:
                client.start_next_case("synthetic")
                with self.assertRaises(ProviderError):
                    client.complete([{"role": "user", "content": "Synthetic parser test"}], stage="annotation")
                self.assertEqual(client.calls, 1)
                self.assertEqual(client.halted, "deepseek_response_invalid_json")
                diagnostic = client.events[-1]["diagnostics"]
                self.assertEqual(diagnostic["duplicate_key_name"], "entry_point")
                self.assertEqual(client.summary()["automatic_retries"], 0)
            finally:
                client.close()
                ledger.close()
            saved = path.read_text(encoding="utf-8")
            self.assertIn('"duplicate_key_name":"entry_point"', saved.replace(" ", ""))
            self.assertNotIn("secret_one", saved)
            self.assertNotIn("secret_two", saved)


if __name__ == "__main__":
    unittest.main()
