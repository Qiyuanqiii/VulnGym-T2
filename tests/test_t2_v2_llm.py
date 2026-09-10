"""Small paid-transport boundary checks; every response here is synthetic."""
import json
from pathlib import Path
import tempfile
import unittest

from vulngym_t2.llm import DeepSeekClient, MODEL, ProviderError, RequestLedger


def reply(value=None, finish="stop"):
    return json.dumps({"object": "chat.completion", "model": MODEL,
                       "choices": [{"index": 0, "finish_reason": finish,
                                    "message": {"role": "assistant", "content": json.dumps(value or {"action": "draft"})}}],
                       "usage": {"prompt_tokens": 10, "completion_tokens": 20, "total_tokens": 30}}).encode()


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


if __name__ == "__main__":
    unittest.main()
