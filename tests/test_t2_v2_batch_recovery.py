"""Real client/ledger orchestration with fake HTTP and synthetic source only."""
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest

from vulngym_t2.cli import run_batch
from vulngym_t2.llm import DeepSeekClient, RequestLedger
from vulngym_t2.transport import MODEL_ID, TransportError
from tests.test_t2_v2_cli import Repo
from tests.test_t2_v2_pipeline import job, choose_source, source_draft, retain_review


def envelope(content):
    return json.dumps({"object": "chat.completion", "model": MODEL_ID,
                       "choices": [{"index": 0, "finish_reason": "stop",
                                    "message": {"role": "assistant", "content": content}}],
                       "usage": {"prompt_tokens": 10, "completion_tokens": 20, "total_tokens": 30}}).encode()


class BatchRecoveryTests(unittest.TestCase):
    def batch(self, first_failure, *, stop=False, limit=10, fail_review=False):
        with tempfile.TemporaryDirectory(prefix="t2-batch-recovery-") as temporary:
            root = Path(temporary)
            ledger = RequestLedger(root / "requests.jsonl", limit=limit)
            replies = [choose_source, source_draft, retain_review]
            payloads = []

            def send(body, _key, _timeout):
                payload = json.loads(body)
                payloads.append(payload)
                if len(payloads) == 1 and not fail_review:
                    if isinstance(first_failure, Exception):
                        raise first_failure
                    return envelope(first_failure)
                if fail_review and len(payloads) == 3:
                    return envelope('{"action": "draft", "fields": "unfinished')
                return envelope(json.dumps(replies.pop(0)(payload["messages"])))

            client = DeepSeekClient("synthetic-not-a-key", ledger, run_id="synthetic-batch", send=send)
            first = job()
            second = {**job(), "entry_id": "entry-00002", "report_id": "GHSA-3333-4444-5555",
                      "source_link": "https://github.com/advisories/GHSA-3333-4444-5555"}
            jobs = [first] if fail_review else [first, second]
            try:
                with contextlib.redirect_stderr(io.StringIO()):
                    summary, code = run_batch(jobs, {0: Repo(), 1: Repo()}, client, root / "output",
                                             continue_on_format_error=not stop)
                reviews = [json.loads(row) for row in (root / "output/review.jsonl").read_text().splitlines()]
                rows = [json.loads(row) for row in ledger.path.read_text().splitlines()]
                return summary, code, reviews, rows, len(payloads)
            finally:
                client.close()
                ledger.close()

    def test_malformed_answer_does_not_repeat_or_block_next_input(self):
        summary, code, reviews, rows, sent = self.batch('[{"ok": true}] {"extra": true}')
        self.assertEqual((summary["status"], code), ("completed_with_errors", 2))
        self.assertEqual([row["status"] for row in reviews], ["draft", "complete"])
        self.assertEqual((summary["format_failure_count"], summary["unprocessed_input_count"], sent), (1, 0, 4))
        starts = [row for row in rows if row["event"] == "http_started"]
        self.assertEqual([row["request"] for row in starts], [1, 2, 3, 4])
        self.assertEqual(sum(row["case_id"] == job()["report_id"] for row in starts), 1)
        self.assertEqual(summary["provider"]["authorization_http_attempts"], 4)
        self.assertEqual(summary["provider"]["authorization_usage"]["total_tokens"], 120)

    def test_auth_permission_and_network_errors_still_stop(self):
        for error in ("deepseek_authentication_failed", "deepseek_access_denied", "deepseek_transport_error"):
            with self.subTest(error=error):
                summary, code, reviews, _rows, sent = self.batch(TransportError(error))
                self.assertEqual((summary["status"], code, sent), ("provider_stopped", 2, 1))
                self.assertEqual(summary["unprocessed_input_count"], 1)
                self.assertEqual(len(reviews), 1)

    def test_old_stop_option_and_shared_limit_are_not_bypassed(self):
        for options in ({"stop": True}, {"limit": 1}):
            with self.subTest(options=options):
                summary, code, _reviews, _rows, sent = self.batch('{"broken":', **options)
                self.assertEqual(code, 2)
                self.assertEqual(sent, 1)
                self.assertEqual(summary["provider"]["authorization_http_attempts"], 1)
                self.assertEqual(summary["status"], "provider_stopped")

    def test_self_review_failure_retains_full_draft_but_no_complete_entry(self):
        summary, code, reviews, _rows, sent = self.batch(None, fail_review=True)
        self.assertEqual((summary["status"], code, sent), ("completed_with_errors", 2, 3))
        self.assertEqual(summary["entry_count"], 0)
        self.assertEqual(reviews[0]["status"], "draft")
        self.assertEqual(reviews[0]["self_review_status"], "failed")
        self.assertTrue(reviews[0]["draft_fields"]["commit"])
        self.assertIn("self_review_incomplete", [row["code"] for row in reviews[0]["errors"]])


if __name__ == "__main__":
    unittest.main()
