"""CLI wiring for opt-in review/read cycles; no target reads or real HTTP."""

import contextlib
import io
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from vulngym_t2.cli import main, parser, run_batch


def synthetic_job():
    return {
        "entry_id": "entry-00001",
        "report_id": "GHSA-2222-3333-4444",
        "repo_url": "https://github.com/example/synthetic",
        "documents": [],
        "fix_commits": [],
    }


def synthetic_client():
    return SimpleNamespace(
        halted=None, calls=0, events=[], response_mode="staged_tool",
        summary=lambda: {"http_attempts": 0, "synthetic": True},
    )


class ReviewReadCycleCliTests(unittest.TestCase):
    def test_defaults_keep_legacy_mode_and_budgets(self):
        options = parser().parse_args(["--advisory", "synthetic.txt"])
        self.assertEqual(options.review_read_cycles, 0)
        self.assertEqual(options.response_mode, "json")
        self.assertEqual(options.max_calls_per_report, 8)
        self.assertEqual(options.max_tool_calls, 24)
        self.assertEqual(options.max_requests, 80)
        self.assertEqual(options.authorization_limit, 500)

    def test_parser_accepts_each_cycle_count(self):
        for cycles in (0, 1, 2):
            with self.subTest(cycles=cycles):
                options = parser().parse_args([
                    "--advisory", "synthetic.txt", "--review-read-cycles", str(cycles),
                ])
                self.assertEqual(options.review_read_cycles, cycles)

    def test_parser_rejects_nonintegers_and_out_of_range_cycles(self):
        for value in ("-1", "3", "1000", "1.5", "not-an-integer"):
            with self.subTest(value=value), contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as caught:
                    parser().parse_args([
                        "--advisory", "synthetic.txt", "--review-read-cycles", value,
                    ])
                self.assertEqual(caught.exception.code, 2)

    def test_opt_in_does_not_raise_the_sixteen_call_ceiling(self):
        prefix = ["--advisory", "synthetic.txt", "--response-mode", "staged_tool",
                  "--review-read-cycles", "2", "--max-calls-per-report"]
        self.assertEqual(parser().parse_args([*prefix, "16"]).max_calls_per_report, 16)
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as caught:
            parser().parse_args([*prefix, "17"])
        self.assertEqual(caught.exception.code, 2)

    def test_nonzero_nonstaged_rejected_before_inputs_credentials_or_clients(self):
        for mode in ("json", "strict_tool"):
            for cycles in (1, 2):
                for prepare_only in (False, True):
                    with self.subTest(mode=mode, cycles=cycles, prepare=prepare_only), \
                         patch("vulngym_t2.cli.load_jobs") as load, \
                         patch("vulngym_t2.cli.prepare") as prepare, \
                         patch("vulngym_t2.cli.os.environ.get", return_value="") as env_get, \
                         patch("vulngym_t2.cli.getpass.getpass") as prompt, \
                         patch("vulngym_t2.cli.RequestLedger") as ledger, \
                         patch("vulngym_t2.cli.DeepSeekClient") as client, \
                         patch("vulngym_t2.cli.run_batch") as batch, \
                         patch("vulngym_t2.cli._emit") as emit:
                        args = ["--advisory", "synthetic.txt", "--response-mode", mode,
                                "--review-read-cycles", str(cycles)]
                        if prepare_only:
                            args.append("--prepare-only")
                        self.assertEqual(main(args), 2)
                        self.assertEqual(emit.call_args.args[0], {
                            "status": "error", "code": "review_read_cycles_requires_staged_tool",
                        })
                        load.assert_not_called()
                        prepare.assert_not_called()
                        self.assertNotIn("DEEPSEEK_API_KEY", [call.args[0] for call in env_get.call_args_list])
                        prompt.assert_not_called()
                        ledger.assert_not_called()
                        client.assert_not_called()
                        batch.assert_not_called()

    def _prepare_configuration(self, extra_args):
        capture = io.StringIO()
        with patch("vulngym_t2.cli.load_jobs", return_value=[synthetic_job()]), \
             patch("vulngym_t2.cli.prepare", return_value=({}, [{"input_error": None}])) as prepare, \
             patch("vulngym_t2.cli.os.environ.get", return_value="") as env_get, \
             patch("vulngym_t2.cli.getpass.getpass") as prompt, \
             patch("vulngym_t2.cli.RequestLedger") as ledger, \
             patch("vulngym_t2.cli.DeepSeekClient") as client, \
             patch("vulngym_t2.cli.run_batch") as batch, \
             contextlib.redirect_stdout(capture):
            self.assertEqual(main(["--advisory", "synthetic.txt", "--prepare-only", *extra_args]), 0)
            prepare.assert_called_once()
            self.assertNotIn("DEEPSEEK_API_KEY", [call.args[0] for call in env_get.call_args_list])
            prompt.assert_not_called()
            ledger.assert_not_called()
            client.assert_not_called()
            batch.assert_not_called()
        result = json.loads(capture.getvalue())
        self.assertEqual((result["status"], result["http_attempts"]), ("prepared", 0))
        self.assertFalse(result["configuration"]["authorization_checked"])
        self.assertFalse(result["configuration"]["provider_checked"])
        return result["configuration"]

    def test_zero_is_allowed_and_reported_in_legacy_prepare_modes(self):
        for mode in ("json", "strict_tool"):
            for explicit_zero in (False, True):
                with self.subTest(mode=mode, explicit_zero=explicit_zero):
                    args = ["--response-mode", mode]
                    if explicit_zero:
                        args.extend(["--review-read-cycles", "0"])
                    configuration = self._prepare_configuration(args)
                    self.assertEqual(configuration["review_read_cycles"], 0)
                    self.assertEqual(configuration["response_mode"], mode)

    def test_prepare_round_trips_all_staged_cycle_counts(self):
        for cycles in (0, 1, 2):
            with self.subTest(cycles=cycles):
                configuration = self._prepare_configuration([
                    "--response-mode", "staged_tool", "--review-read-cycles", str(cycles),
                    "--max-calls-per-report", "16", "--max-requests", "12",
                ])
                self.assertEqual(configuration["review_read_cycles"], cycles)
                self.assertEqual(configuration["max_calls_per_report"], 16)
                self.assertEqual(configuration["max_requests"], 12)

    def test_main_forwards_cycles_to_batch_without_changing_provider_or_ledger_limits(self):
        with tempfile.TemporaryDirectory(prefix="t2-review-cycle-cli-") as temp:
            for cycles in (0, 1, 2):
                with self.subTest(cycles=cycles), \
                     patch("vulngym_t2.cli.load_jobs", return_value=[synthetic_job()]), \
                     patch("vulngym_t2.cli.prepare", return_value=({}, [{"input_error": None}])), \
                     patch("vulngym_t2.cli.RequestLedger") as ledger, \
                     patch("vulngym_t2.cli.DeepSeekClient") as client, \
                     patch("vulngym_t2.cli.run_batch", return_value=({"status": "synthetic"}, 0)) as batch, \
                     patch("vulngym_t2.cli._emit"), \
                     patch("vulngym_t2.cli.sys.stdin", io.StringIO("synthetic-not-a-real-key\n")):
                    self.assertEqual(main([
                        "--advisory", "synthetic.txt", "--response-mode", "staged_tool",
                        "--review-read-cycles", str(cycles), "--max-calls-per-report", "16",
                        "--max-tool-calls", "64", "--max-requests", "12",
                        "--authorization-limit", "3000", "--effective-request-limit", "2999",
                        "--output", str(Path(temp) / "out"),
                        "--request-ledger", str(Path(temp) / "synthetic-ledger.jsonl"), "--key-stdin",
                    ]), 0)
                    self.assertEqual(batch.call_args.kwargs["review_read_cycles"], cycles)
                    self.assertEqual(batch.call_args.kwargs["max_calls"], 16)
                    self.assertEqual(batch.call_args.kwargs["max_tool_calls"], 64)
                    self.assertEqual(client.call_args.kwargs["max_requests"], 12)
                    self.assertNotIn("review_read_cycles", client.call_args.kwargs)
                    self.assertEqual(ledger.call_args.kwargs["limit"], 3000)
                    self.assertEqual(ledger.call_args.kwargs["effective_limit"], 2999)
                    client.return_value.close.assert_called_once()
                    ledger.return_value.close.assert_called_once()

    def _batch_call(self, *, options=None, input_error=None):
        input_job = synthetic_job()
        if input_error is not None:
            input_job["input_error"] = input_error
        repo = object()
        client = synthetic_client()
        with patch("vulngym_t2.cli.BatchWriter") as writer, \
             patch("vulngym_t2.cli.produce", return_value={"model_calls": 0, "tool_calls": 0}) as produce, \
             patch("vulngym_t2.cli.finalize_result", return_value={"entry": None}), \
             patch("vulngym_t2.cli._emit"):
            writer.return_value.finish.side_effect = lambda summary: summary
            summary, code = run_batch([input_job], {0: repo}, client, Path("synthetic-unused-output"),
                                      max_calls=16, max_tool_calls=64, **(options or {}))
            self.assertEqual(code, 0)
            self.assertEqual(summary["status"], "completed")
            self.assertEqual(summary["provider"]["http_attempts"], 0)
            writer.return_value.record.assert_called_once()
            return produce, input_job, client, repo

    def test_batch_default_and_explicit_zero_keep_original_produce_signature(self):
        for options in ({}, {"review_read_cycles": 0}):
            with self.subTest(options=options):
                produce, input_job, client, repo = self._batch_call(options=options)
                produce.assert_called_once_with(input_job, client, repo, max_calls=16, max_tool_calls=64)

    def test_batch_forwards_only_enabled_cycles_to_produce(self):
        for cycles in (1, 2):
            with self.subTest(cycles=cycles):
                produce, input_job, client, repo = self._batch_call(options={"review_read_cycles": cycles})
                produce.assert_called_once_with(input_job, client, repo, max_calls=16, max_tool_calls=64,
                                                review_read_cycles=cycles)

    def test_enabled_cycles_do_not_invoke_produce_for_failed_input(self):
        produce, _, _, _ = self._batch_call(options={"review_read_cycles": 2}, input_error="synthetic_input_failure")
        produce.assert_not_called()


if __name__ == "__main__":
    unittest.main()
