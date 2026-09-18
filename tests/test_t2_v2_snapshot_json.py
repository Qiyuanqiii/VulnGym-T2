"""Explicit JSON annotation wire; not a fallback for invalid native responses."""
import json
from pathlib import Path
import tempfile
import unittest

from vulngym_t2.llm import DeepSeekClient, MODEL, ProviderError, RequestLedger
from vulngym_t2.pipeline import produce
from vulngym_t2.output import finalize_result
from vulngym_t2.annotation_rules import (TRACE_DECISION_GUIDANCE, BRANCH_DECISION_GUIDANCE,
                                        COARSE_CATEGORY_DECISION_GUIDANCE)
from tests import test_t2_v2_staged_pipeline as fixture
from tests.test_t2_v2_pipeline import job


def envelope(*, content=None, call=None):
    message = {"role": "assistant", "content": content, "reasoning_content": "synthetic private reasoning"}
    if call:
        name, arguments = call
        message["tool_calls"] = [{"id": "fixture-call", "type": "function",
            "function": {"name": name, "arguments": json.dumps(arguments)}}]
    return json.dumps({"object": "chat.completion", "model": MODEL,
        "choices": [{"index": 0, "finish_reason": "tool_calls" if call else "stop", "message": message}],
        "usage": {"prompt_tokens": 10, "completion_tokens": 20, "total_tokens": 30}}).encode()


class SnapshotJsonTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="t2-snapshot-json-")
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name).resolve() / "ledger.jsonl"
        self.ledger = RequestLedger(self.path, limit=10)
        self.addCleanup(self.ledger.close)

    def client(self, send):
        client = DeepSeekClient("dummy-not-a-real-key", self.ledger, run_id="synthetic", max_requests=10,
            response_mode="staged_tool", thinking="enabled", annotation_format="snapshot_json", send=send)
        self.addCleanup(client.close)
        return client

    def test_wire_is_chosen_before_request_with_different_read_and_annotation_settings(self):
        payloads = []
        def send(body, *_):
            payload = json.loads(body)
            payloads.append(payload)
            return (envelope(content=json.dumps(fixture.annotation()[1])) if "response_format" in payload
                    else envelope(call=fixture.FINISH))
        client = self.client(send)
        read = client.complete([{"role": "user", "content": "fixture"}], stage="read")
        draft = client.complete([{"role": "user", "content": "fixture"}], stage="annotation")
        self.assertEqual(read["action"], "finish_reading")
        self.assertEqual(draft["action"], "draft")
        self.assertEqual(payloads[0]["thinking"], {"type": "disabled"})
        self.assertEqual(payloads[0]["tool_choice"], "required")
        self.assertNotIn("response_format", payloads[0])
        self.assertEqual(payloads[1]["thinking"], {"type": "enabled"})
        self.assertEqual(payloads[1]["response_format"], {"type": "json_object"})
        self.assertNotIn("tools", payloads[1])
        self.assertNotIn("tool_choice", payloads[1])
        self.assertEqual(client.summary()["tool_choice"], "stage_specific")
        self.assertEqual(self.ledger.started, 2)
        self.assertNotIn("synthetic private reasoning", self.path.read_text() + json.dumps(draft))

    def test_invalid_json_stops_without_conversion_to_a_native_call_or_retry(self):
        sends = []
        client = self.client(lambda *_: sends.append(True) or envelope(content='{"broken":'))
        for _ in range(2):
            with self.assertRaisesRegex(ProviderError, "deepseek_response_invalid_json"):
                client.complete([{"role": "user", "content": "fixture"}], stage="annotation")
        self.assertEqual(sends, [True])
        self.assertEqual(self.ledger.started, 1)

    def test_native_tool_is_rejected_in_json_annotation_not_executed(self):
        client = self.client(lambda *_: envelope(call=fixture.READ))
        with self.assertRaises(ProviderError):
            client.complete([{"role": "user", "content": "fixture"}], stage="annotation")
        self.assertEqual(self.ledger.started, 1)

    def test_full_controller_uses_same_source_expansion_review_and_verify_zero(self):
        payloads = []
        def send(body, *_):
            payload = json.loads(body)
            payloads.append(payload)
            if "response_format" in payload:
                return envelope(content=json.dumps(fixture.full_annotation(payload)[1]))
            return envelope(call=fixture.READ if len(payloads) == 1 else fixture.FINISH)
        client = self.client(send)
        supplied, repo = job(False), fixture.MemoryRepo()
        result = produce(supplied, client, repo, max_calls=5)
        final = finalize_result(supplied, result, repo)
        self.assertIsNotNone(final["entry"])
        self.assertEqual(final["entry"]["verify"], 0)
        self.assertEqual(result["self_review_status"], "completed")
        self.assertEqual(result["model_calls"], 5)
        self.assertEqual(result["tool_calls"], 1)
        self.assertEqual(sum("response_format" in row for row in payloads), 2)
        for payload in payloads:
            if "response_format" in payload:
                self.assertIn(TRACE_DECISION_GUIDANCE, json.dumps(payload))
                self.assertIn(BRANCH_DECISION_GUIDANCE, json.dumps(payload))
                self.assertIn(COARSE_CATEGORY_DECISION_GUIDANCE, json.dumps(payload))
        self.assertEqual(client.summary()["automatic_retries"], 0)


if __name__ == "__main__":
    unittest.main()
