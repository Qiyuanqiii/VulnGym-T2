"""Explicit reasoning configuration preserves native-output validation/budgets."""
import json
from pathlib import Path
import tempfile
import unittest

from vulngym_t2.llm import DeepSeekClient, MODEL, ProviderError, RequestLedger


def response(native=True):
    message = {"role": "assistant", "content": None if native else "plain answer must not be used",
               "reasoning_content": "private synthetic reasoning must not be retained"}
    if native:
        message["tool_calls"] = [{"id": "call_fixture", "type": "function", "function": {
            "name": "finish_reading", "arguments": json.dumps({"reason": "enough_evidence"})}}]
    return json.dumps({"object": "chat.completion", "model": MODEL,
        "choices": [{"index": 0, "finish_reason": "tool_calls" if native else "stop", "message": message}],
        "usage": {"prompt_tokens": 10, "completion_tokens": 20, "total_tokens": 30}}).encode()


class StagedThinkingTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="t2-thinking-")
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name).resolve() / "requests.jsonl"
        self.ledger = RequestLedger(self.path, limit=4)
        self.addCleanup(self.ledger.close)

    def client(self, send, thinking="enabled"):
        client = DeepSeekClient("dummy-not-a-real-key", self.ledger, run_id="synthetic", max_requests=4,
                                response_mode="staged_tool", thinking=thinking, send=send)
        self.addCleanup(client.close)
        return client

    def test_enabled_uses_auto_and_same_phase_schema_without_retaining_reasoning(self):
        payloads = []
        client = self.client(lambda body, *_: payloads.append(json.loads(body)) or response())
        answer = client.complete([{"role": "user", "content": "fixture"}], stage="read")
        self.assertEqual(answer["action"], "finish_reading")
        self.assertEqual(payloads[0]["thinking"], {"type": "enabled"})
        self.assertEqual(payloads[0]["tool_choice"], "auto")
        self.assertEqual(payloads[0]["reasoning_effort"], "high")
        self.assertTrue(all(row["function"]["strict"] for row in payloads[0]["tools"]))
        self.assertEqual((client.calls, self.ledger.started), (1, 1))
        self.assertEqual(client.summary()["tool_choice"], "auto")
        self.assertNotIn("private synthetic reasoning", json.dumps(answer) + self.path.read_text())

    def test_enabled_plain_answer_stops_without_fallback_or_auto_retry(self):
        sends = []
        client = self.client(lambda *_: sends.append(True) or response(native=False))
        for _ in range(2):
            with self.assertRaisesRegex(ProviderError, "deepseek_completion_incomplete"):
                client.complete([{"role": "user", "content": "fixture"}], stage="read")
        self.assertEqual(sends, [True])
        self.assertEqual(self.ledger.started, 1)
        self.assertFalse(client.can_continue_after_format_error)

    def test_disabled_remains_required_without_reasoning_effort(self):
        payloads = []
        client = self.client(lambda body, *_: payloads.append(json.loads(body)) or response(), thinking="disabled")
        client.complete([{"role": "user", "content": "fixture"}], stage="read")
        self.assertEqual(payloads[0]["tool_choice"], "required")
        self.assertNotIn("reasoning_effort", payloads[0])


if __name__ == "__main__":
    unittest.main()
