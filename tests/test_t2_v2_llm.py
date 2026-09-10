"""Small paid-transport boundary checks; every response here is synthetic."""
import json
from pathlib import Path
import tempfile
import unittest

from vulngym_t2.llm import DeepSeekClient, MODEL, ProviderError, RequestLedger


def reply(value=None, finish="stop", *, model=MODEL):
    return json.dumps({"object": "chat.completion", "model": model,
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
