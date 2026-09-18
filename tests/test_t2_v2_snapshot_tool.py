"""Explicit phase-split native annotation; no fallback or duplicate-key bypass."""
import json
import unittest

from vulngym_t2.llm import DeepSeekClient, ProviderError
from vulngym_t2.pipeline import produce
from vulngym_t2.output import finalize_result
from tests import test_t2_v2_staged_pipeline as fixture
from tests.test_t2_v2_pipeline import job
from tests import test_t2_v2_snapshot_json as json_fixture

envelope = json_fixture.envelope


class SnapshotToolTests(unittest.TestCase):
    setUp = json_fixture.SnapshotJsonTests.setUp

    def client(self, send):
        client = DeepSeekClient("dummy-not-a-real-key", self.ledger, run_id="synthetic", max_requests=10,
            response_mode="staged_tool", thinking="enabled", annotation_format="snapshot_tool", send=send)
        self.addCleanup(client.close)
        return client

    def test_reads_require_native_calls_and_annotation_requests_strict_native_with_reasoning(self):
        payloads = []
        def send(body, *_):
            payload = json.loads(body)
            payloads.append(payload)
            names = [row["function"]["name"] for row in payload["tools"]]
            return envelope(call=fixture.annotation() if names == ["submit_annotation"] else fixture.FINISH)
        client = self.client(send)
        client.complete([{"role": "user", "content": "fixture"}], stage="read")
        result = client.complete([{"role": "user", "content": "fixture"}], stage="annotation")
        self.assertEqual(result["action"], "draft")
        self.assertEqual(payloads[0]["thinking"], {"type": "disabled"})
        self.assertEqual(payloads[0]["tool_choice"], "required")
        self.assertEqual(payloads[1]["thinking"], {"type": "enabled"})
        self.assertEqual(payloads[1]["tool_choice"], "auto")
        self.assertTrue(payloads[1]["tools"][0]["function"]["strict"])
        self.assertTrue(all("response_format" not in payload for payload in payloads))
        self.assertEqual(self.ledger.started, 2)
        self.assertEqual(client.summary()["stage_settings"]["annotation"]["tool_choice"], "auto")

    def test_plain_json_does_not_become_a_fallback_native_call(self):
        sends = []
        client = self.client(lambda *_: sends.append(True) or envelope(content=json.dumps(fixture.annotation()[1])))
        for _ in range(2):
            with self.assertRaisesRegex(ProviderError, "deepseek_completion_incomplete"):
                client.complete([{"role": "user", "content": "fixture"}], stage="annotation")
        self.assertEqual(sends, [True])

    def test_ambiguous_duplicate_reference_is_still_rejected_without_retry(self):
        raw = json.loads(envelope(call=fixture.annotation()))
        raw["choices"][0]["message"]["tool_calls"][0]["function"]["arguments"] = (
            '{"entry_point":{"value":{"evidence_ref":"E0001","evidence_ref":"E0002"}}}')
        client = self.client(lambda *_: json.dumps(raw).encode())
        with self.assertRaisesRegex(ProviderError, "deepseek_response_invalid_json"):
            client.complete([{"role": "user", "content": "fixture"}], stage="annotation")
        self.assertEqual(self.ledger.started, 1)

    def test_full_controller_keeps_same_snapshot_validation_and_verify_zero(self):
        payloads = []
        def send(body, *_):
            payload = json.loads(body)
            payloads.append(payload)
            names = [row["function"]["name"] for row in payload["tools"]]
            return envelope(call=(fixture.full_annotation(payload) if names == ["submit_annotation"] else
                                  fixture.READ if len(payloads) == 1 else fixture.FINISH))
        client = self.client(send)
        supplied, repo = job(False), fixture.MemoryRepo()
        result = produce(supplied, client, repo, max_calls=5)
        self.assertEqual(finalize_result(supplied, result, repo)["entry"]["verify"], 0)
        self.assertEqual(result["self_review_status"], "completed")
        self.assertEqual(result["model_calls"], 5)
        self.assertEqual(client.summary()["automatic_retries"], 0)


if __name__ == "__main__":
    unittest.main()
