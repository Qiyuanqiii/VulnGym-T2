"""Explicit budget extensions append history and never reset counted attempts."""
import json
from pathlib import Path
import tempfile
import unittest

from vulngym_t2.llm import RequestLedger, ProviderError


class AuthorizationExtensionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="t2-authorization-")
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name).resolve() / "requests.jsonl"

    def initial(self, pending=False):
        ledger = RequestLedger(self.path, limit=2)
        number = ledger.reserve(run_id="synthetic", case_id="example")
        if not pending:
            ledger.finish(number, status="success", usage={"prompt_tokens": 3, "completion_tokens": 4, "total_tokens": 7}, seconds=1)
        ledger.close()
        return self.path.read_bytes()

    def test_explicit_extension_keeps_bytes_counts_usage_and_next_number(self):
        original = self.initial()
        ledger = RequestLedger(self.path, limit=699, extend_authorization=True)
        self.addCleanup(ledger.close)
        self.assertEqual(ledger.started, 1)
        self.assertEqual(ledger.usage["total_tokens"], 7)
        self.assertTrue(self.path.read_bytes().startswith(original))
        extension = json.loads(self.path.read_text().splitlines()[-1])
        self.assertEqual(extension, {"event": "authorization_extended", "previous_limit": 2,
                                     "request_limit": 699, "requests_used": 1})
        self.assertEqual(ledger.reserve(run_id="same-authorization", case_id="next"), 2)
        ledger.finish(2, status="success", usage=None, seconds=0)
        ledger.close()
        with self.reopened(699) as current:
            self.assertEqual(current.started, 2)
            self.assertEqual(current.usage_unknown, 1)

    def reopened(self, limit):
        from contextlib import closing
        return closing(RequestLedger(self.path, limit=limit))

    def test_no_implicit_extension_or_shrink(self):
        original = self.initial()
        for limit, explicit in ((3, False), (1, True)):
            with self.subTest(limit=limit, explicit=explicit), self.assertRaisesRegex(ValueError, "ledger_authorization_mismatch"):
                RequestLedger(self.path, limit=limit, extend_authorization=explicit)
            self.assertEqual(self.path.read_bytes(), original)

    def test_second_explicit_extension_to_999_preserves_699_history(self):
        self.initial()
        RequestLedger(self.path, limit=699, extend_authorization=True).close()
        original = self.path.read_bytes()
        with self.assertRaisesRegex(ValueError, "ledger_authorization_mismatch"):
            RequestLedger(self.path, limit=999)
        self.assertEqual(self.path.read_bytes(), original)
        ledger = RequestLedger(self.path, limit=999, extend_authorization=True)
        self.addCleanup(ledger.close)
        self.assertTrue(self.path.read_bytes().startswith(original))
        self.assertEqual(json.loads(self.path.read_text().splitlines()[-1]), {
            "event": "authorization_extended", "previous_limit": 699,
            "request_limit": 999, "requests_used": 1})
        self.assertEqual(ledger.started, 1)
        self.assertEqual(ledger.usage["total_tokens"], 7)
        self.assertEqual(ledger.reserve(run_id="same-authorization", case_id="next"), 2)
        ledger.finish(2, status="success", usage=None, seconds=0)

    def test_extension_to_1299_keeps_prior_authorization_and_usage(self):
        self.initial()
        RequestLedger(self.path, limit=999, extend_authorization=True).close()
        original = self.path.read_bytes()
        with self.reopened(999) as previous:
            self.assertEqual(previous.started, 1)
        ledger = RequestLedger(self.path, limit=1299, extend_authorization=True)
        self.addCleanup(ledger.close)
        self.assertTrue(self.path.read_bytes().startswith(original))
        self.assertEqual(json.loads(self.path.read_text().splitlines()[-1]), {
            "event": "authorization_extended", "previous_limit": 999,
            "request_limit": 1299, "requests_used": 1})
        self.assertEqual(ledger.started, 1)
        self.assertEqual(ledger.usage["total_tokens"], 7)
        self.assertEqual(ledger.reserve(run_id="same-authorization", case_id="next"), 2)
        ledger.finish(2, status="success", usage=None, seconds=0)

    def test_pending_request_blocks_extension_without_writing(self):
        original = self.initial(pending=True)
        with self.assertRaisesRegex(ValueError, "ledger_has_unfinished_request"):
            RequestLedger(self.path, limit=699, extend_authorization=True)
        self.assertEqual(self.path.read_bytes(), original)

    def test_extension_to_1599_keeps_1299_history_and_requires_explicit_approval(self):
        self.initial()
        RequestLedger(self.path, limit=1299, extend_authorization=True).close()
        original = self.path.read_bytes()
        with self.assertRaisesRegex(ValueError, "ledger_authorization_mismatch"):
            RequestLedger(self.path, limit=1599)
        self.assertEqual(self.path.read_bytes(), original)
        ledger = RequestLedger(self.path, limit=1599, extend_authorization=True)
        self.addCleanup(ledger.close)
        self.assertTrue(self.path.read_bytes().startswith(original))
        self.assertEqual(json.loads(self.path.read_text().splitlines()[-1]), {
            "event": "authorization_extended", "previous_limit": 1299,
            "request_limit": 1599, "requests_used": 1})
        self.assertEqual(ledger.started, 1)
        self.assertEqual(ledger.usage["total_tokens"], 7)
        self.assertEqual(ledger.reserve(run_id="same-authorization", case_id="next"), 2)
        ledger.finish(2, status="success", usage=None, seconds=0)

    def test_extension_flag_requires_existing_ledger(self):
        with self.assertRaisesRegex(ValueError, "extension_requires_existing"):
            RequestLedger(self.path, limit=699, extend_authorization=True)
        self.assertFalse(self.path.exists())

    def test_extension_to_1999_keeps_1599_history_and_requires_explicit_approval(self):
        self.initial()
        RequestLedger(self.path, limit=1599, extend_authorization=True).close()
        original = self.path.read_bytes()
        with self.assertRaisesRegex(ValueError, "ledger_authorization_mismatch"):
            RequestLedger(self.path, limit=1999)
        self.assertEqual(self.path.read_bytes(), original)
        ledger = RequestLedger(self.path, limit=1999, extend_authorization=True)
        self.addCleanup(ledger.close)
        self.assertTrue(self.path.read_bytes().startswith(original))
        self.assertEqual(json.loads(self.path.read_text().splitlines()[-1]), {
            "event": "authorization_extended", "previous_limit": 1599,
            "request_limit": 1999, "requests_used": 1})
        self.assertEqual(ledger.started, 1)
        self.assertEqual(ledger.usage["total_tokens"], 7)
        self.assertEqual(ledger.reserve(run_id="same-authorization", case_id="next"), 2)
        ledger.finish(2, status="success", usage=None, seconds=0)

    def test_repeating_same_extension_does_not_append_or_reset(self):
        self.initial()
        RequestLedger(self.path, limit=699, extend_authorization=True).close()
        extended = self.path.read_bytes()
        RequestLedger(self.path, limit=699, extend_authorization=True).close()
        self.assertEqual(self.path.read_bytes(), extended)

    def test_extension_to_2299_is_parsed_and_preserves_the_1999_ledger(self):
        from vulngym_t2.cli import parser

        options = parser().parse_args([
            "--input", "synthetic.jsonl", "--authorization-limit", "2299",
            "--extend-authorization",
        ])
        self.assertEqual(options.authorization_limit, 2299)
        self.initial()
        RequestLedger(self.path, limit=1999, extend_authorization=True).close()
        original = self.path.read_bytes()
        with self.assertRaisesRegex(ValueError, "ledger_authorization_mismatch"):
            RequestLedger(self.path, limit=options.authorization_limit)
        self.assertEqual(self.path.read_bytes(), original)
        ledger = RequestLedger(self.path, limit=options.authorization_limit,
                               extend_authorization=options.extend_authorization)
        self.addCleanup(ledger.close)
        self.assertTrue(self.path.read_bytes().startswith(original))
        self.assertEqual(json.loads(self.path.read_text().splitlines()[-1]), {
            "event": "authorization_extended", "previous_limit": 1999,
            "request_limit": 2299, "requests_used": 1})
        self.assertEqual(ledger.started, 1)
        self.assertEqual(ledger.usage["total_tokens"], 7)
        self.assertEqual(ledger.reserve(run_id="same-authorization", case_id="next"), 2)
        ledger.finish(2, status="success", usage=None, seconds=0)

    def test_limit_remains_enforced_after_extension(self):
        self.initial()
        ledger = RequestLedger(self.path, limit=3, extend_authorization=True)
        self.addCleanup(ledger.close)
        for expected in (2, 3):
            self.assertEqual(ledger.reserve(run_id="synthetic", case_id="example"), expected)
            ledger.finish(expected, status="success", usage=None, seconds=0)
        with self.assertRaisesRegex(ProviderError, "authorization_request_limit_reached"):
            ledger.reserve(run_id="synthetic", case_id="excess")

    def test_2600_total_ceiling_keeps_the_one_historical_request(self):
        from vulngym_t2.cli import parser
        from vulngym_t2.web_runtime import budget_snapshot

        options = parser().parse_args([
            "--input", "synthetic.jsonl", "--authorization-limit", "2599",
            "--extend-authorization",
        ])
        model = "deepseek-flash"
        ledger = RequestLedger(self.path, limit=2299, model=model)
        number = ledger.reserve(run_id="synthetic", case_id="example")
        ledger.finish(number, status="success", usage=None, seconds=0)
        ledger.close()
        original = self.path.read_bytes()
        with self.assertRaisesRegex(ValueError, "ledger_authorization_mismatch"):
            RequestLedger(self.path, limit=options.authorization_limit, model=model)
        RequestLedger(self.path, limit=options.authorization_limit,
                      model=model, extend_authorization=options.extend_authorization).close()
        self.assertTrue(self.path.read_bytes().startswith(original))
        snapshot = budget_snapshot(self.path, 2599, 1)
        self.assertTrue(snapshot["available"])
        self.assertEqual((snapshot["limit"], snapshot["used"], snapshot["remaining"]),
                         (2600, 2, 2598))


if __name__ == "__main__":
    unittest.main()
