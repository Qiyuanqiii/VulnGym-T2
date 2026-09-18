"""A stricter process ceiling preserves the shared ledger's historical truth."""
from contextlib import redirect_stderr, redirect_stdout
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from vulngym_t2 import cli, web
from vulngym_t2.llm import DeepSeekClient, MODEL, ProviderError, RequestLedger
from vulngym_t2.web_runtime import Run, RunManager, budget_snapshot
from tests.test_t2_v2_llm import reply


class EffectiveRequestLimitTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="t2-effective-limit-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.path = self.root / "requests.jsonl"

    def seed(self, *, limit=3, attempts=1, model=MODEL):
        with_ledger = RequestLedger(self.path, limit=limit, model=model)
        try:
            for _ in range(attempts):
                number = with_ledger.reserve(run_id="synthetic", case_id="fixture")
                with_ledger.finish(number, status="success", usage=None, seconds=0)
        finally:
            with_ledger.close()

    def test_effective_ceiling_blocks_send_and_append_without_rewriting_authorization(self):
        self.seed()
        original = self.path.read_bytes()
        ledger = RequestLedger(self.path, limit=3, effective_limit=2)
        self.addCleanup(ledger.close)
        self.assertEqual(self.path.read_bytes(), original)
        sent = []
        client = DeepSeekClient("synthetic-key", ledger, run_id="synthetic",
                                send=lambda *_: sent.append(True) or reply(), max_requests=3)
        self.addCleanup(client.close)
        self.assertEqual(client.remaining_requests, 1)
        client.complete([{"role": "user", "content": "fixture"}])
        self.assertEqual(client.remaining_requests, 0)
        finished = self.path.read_bytes()
        with self.assertRaisesRegex(ProviderError, "authorization_request_limit_reached"):
            client.complete([{"role": "user", "content": "not sent"}])
        self.assertEqual(sent, [True])
        self.assertEqual(self.path.read_bytes(), finished)
        self.assertTrue(finished.startswith(original))
        summary = client.summary()
        self.assertEqual(summary["authorization_limit"], 3)
        self.assertEqual(summary["effective_authorization_limit"], 2)
        self.assertEqual(summary["effective_authorization_remaining"], 0)
        self.assertEqual(summary["authorization_http_attempts"], 2)

    def test_existing_extension_stays_byte_identical_on_reopen_with_a_lower_effective_cap(self):
        self.seed(limit=2)
        RequestLedger(self.path, limit=3, extend_authorization=True).close()
        original = self.path.read_bytes()
        for _ in range(2):
            ledger = RequestLedger(self.path, limit=3, effective_limit=2)
            self.assertEqual(ledger.remaining_requests, 1)
            ledger.close()
            self.assertEqual(self.path.read_bytes(), original)
        events = [json.loads(line)["event"] for line in original.splitlines()]
        self.assertEqual(events.count("authorization_extended"), 1)

    def test_effective_cap_below_used_usage_stops_without_hiding_or_resetting_usage(self):
        self.seed(attempts=2)
        original = self.path.read_bytes()
        ledger = RequestLedger(self.path, limit=3, effective_limit=1)
        self.addCleanup(ledger.close)
        self.assertEqual(ledger.remaining_requests, 0)
        self.assertEqual(ledger.summary()["authorization_http_attempts"], 2)
        with self.assertRaisesRegex(ProviderError, "authorization_request_limit_reached"):
            ledger.reserve(run_id="synthetic", case_id="fixture")
        self.assertEqual(self.path.read_bytes(), original)

    def test_no_effective_cap_preserves_legacy_limit_and_summary(self):
        self.seed()
        ledger = RequestLedger(self.path, limit=3)
        self.addCleanup(ledger.close)
        self.assertEqual(ledger.remaining_requests, 2)
        self.assertNotIn("effective_authorization_limit", ledger.summary())
        number = ledger.reserve(run_id="synthetic", case_id="fixture")
        ledger.finish(number, status="success", usage=None, seconds=0)
        number = ledger.reserve(run_id="synthetic", case_id="fixture")
        ledger.finish(number, status="success", usage=None, seconds=0)
        self.assertEqual(ledger.started, 3)

    def test_invalid_effective_caps_fail_before_lock_or_ledger_creation(self):
        for cap in (0, -1, 4, True, "2", 2.5):
            with self.subTest(cap=cap), self.assertRaisesRegex(ValueError, "effective_request_limit_invalid"):
                RequestLedger(self.path, limit=3, effective_limit=cap)
            self.assertFalse(self.path.exists())
            self.assertFalse(self.path.with_suffix(".jsonl.lock").exists())

    def test_cli_rejects_a_wider_effective_cap_before_material_or_credential_reads(self):
        with patch.object(cli, "load_jobs", side_effect=AssertionError("must not load")), \
                patch.object(cli.getpass, "getpass", side_effect=AssertionError("must not prompt")), \
                redirect_stdout(io.StringIO()) as output:
            code = cli.main(["--input", "missing.jsonl", "--authorization-limit", "3",
                             "--effective-request-limit", "4"])
        self.assertEqual(code, 2)
        self.assertEqual(json.loads(output.getvalue())["code"], "effective_request_limit_invalid")

    def test_cli_passes_the_effective_cap_to_the_only_request_writer(self):
        self.seed()
        with patch.object(cli, "load_jobs", return_value=[{}]), \
                patch.object(cli, "prepare", return_value=({}, [])), \
                patch.object(cli, "RequestLedger") as ledger, \
                patch.object(cli, "DeepSeekClient"), \
                patch.object(cli, "run_batch", return_value=({"status": "completed"}, 0)), \
                patch.dict(cli.os.environ, {"DEEPSEEK_API_KEY": "synthetic-key"}), \
                redirect_stdout(io.StringIO()):
            code = cli.main(["--input", "synthetic.jsonl", "--authorization-limit", "3",
                             "--effective-request-limit", "2", "--request-ledger", str(self.path),
                             "--output", str(self.root / "unused-output")])
        self.assertEqual(code, 0)
        self.assertEqual(ledger.call_args.kwargs["limit"], 3)
        self.assertEqual(ledger.call_args.kwargs["effective_limit"], 2)
        self.assertFalse(ledger.call_args.kwargs["extend_authorization"])

    def test_web_counts_history_against_effective_generation_cap_without_writing(self):
        self.seed(limit=3000, model="deepseek-flash")
        original = self.path.read_bytes()
        budget = budget_snapshot(self.path, 3000, 1, effective_limit=2999)
        self.assertEqual((budget["used"], budget["limit"], budget["remaining"]), (2, 3000, 2998))
        self.assertEqual(budget["authorization_limit"], 3000)
        self.assertEqual(budget["effective_authorization_limit"], 2999)
        self.assertEqual(self.path.read_bytes(), original)
        legacy = budget_snapshot(self.path, 3000, 1)
        self.assertEqual(legacy["limit"], 3001)
        self.assertNotIn("effective_authorization_limit", legacy)
        self.assertFalse(budget_snapshot(self.path, 3000, 1, effective_limit=3001)["available"])

    def test_web_start_checks_and_forwards_effective_cap_to_cli(self):
        self.seed(model="deepseek-flash")
        original = self.path.read_bytes()
        manager = RunManager(self.root / "runs", self.path, 3, 1, effective_limit=2)
        run = Run("fixture", self.root / "runs" / "fixture", self.root / "unused-output", state="prepared")
        manager.runs[run.id] = run
        with patch.object(manager, "_launch", return_value=True) as launch:
            with self.assertRaisesRegex(ValueError, "request_cap_exceeds_remaining"):
                manager.start(run.id, "synthetic-key", 2, True)
            launch.assert_not_called()
            manager.start(run.id, "synthetic-key", 1, True)
        args = launch.call_args.args[1]
        self.assertEqual(args[args.index("--authorization-limit") + 1], "3")
        self.assertEqual(args[args.index("--effective-request-limit") + 1], "2")
        self.assertEqual(args[args.index("--max-requests") + 1], "1")
        self.assertNotIn("--extend-authorization", args)
        self.assertEqual(self.path.read_bytes(), original)

    def test_invalid_web_effective_cap_stops_before_manager_or_server(self):
        with patch.object(web, "RunManager") as manager, \
                patch.object(web, "LocalServer") as server, redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as raised:
                web.main(["--runs-root", str(self.root / "absent"), "--request-ledger", str(self.path),
                          "--authorization-limit", "3", "--effective-request-limit", "4"])
        self.assertEqual(raised.exception.code, 2)
        manager.assert_not_called()
        server.assert_not_called()
        self.assertFalse((self.root / "absent").exists())


if __name__ == "__main__":
    unittest.main()
