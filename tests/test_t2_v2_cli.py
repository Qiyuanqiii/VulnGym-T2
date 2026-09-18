"""Narrow cross-module checks with synthetic model/source, never a paid call."""
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from vulngym_t2.cli import main, parser, run_batch
from vulngym_t2.intake import load_jobs
from vulngym_t2.llm import MODEL
from tests.test_t2_v2_pipeline import StubRepo, job, choose_source, source_draft, retain_review


class Repo(StubRepo):
    def validate_location(self, commit, location):
        return {"valid": True, "commit": commit}


class Client:
    halted = None
    calls = 0
    case_id = ""

    def __init__(self):
        self.responses = [choose_source, source_draft, retain_review]
        self.events = []

    def complete(self, messages):
        self.calls += 1
        return self.responses.pop(0)(messages)

    def summary(self):
        return {"http_attempts": self.calls, "synthetic": True}


class CliTests(unittest.TestCase):
    def test_exact_model_argument_preserves_default_and_rejects_invalid_ids(self):
        self.assertEqual(parser().parse_args(["--advisory", "synthetic.txt"]).model, MODEL)
        self.assertEqual(parser().parse_args(["--advisory", "synthetic.txt", "--model", "deepseek-flash"]).model,
                         "deepseek-flash")
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as caught:
            parser().parse_args(["--advisory", "synthetic.txt", "--model", "https://elsewhere.invalid"])
        self.assertEqual(caught.exception.code, 2)

    def test_strict_response_and_legacy_stop_switch_are_explicit(self):
        options = parser().parse_args(["--advisory", "synthetic.txt", "--response-mode", "strict_tool",
                                       "--thinking", "disabled", "--stop-on-format-error"])
        self.assertEqual(options.response_mode, "strict_tool")
        self.assertEqual(options.thinking, "disabled")
        self.assertTrue(options.stop_on_format_error)
        defaults = parser().parse_args(["--advisory", "synthetic.txt"])
        self.assertEqual(defaults.response_mode, "json")
        self.assertEqual(defaults.thinking, "enabled")
        self.assertFalse(defaults.stop_on_format_error)

    def test_exact_model_is_forwarded_to_ledger_and_client(self):
        selected = "deepseek-flash"
        with tempfile.TemporaryDirectory(prefix="t2-cli-") as temp:
            with patch("vulngym_t2.cli.load_jobs", return_value=[job()]), patch("vulngym_t2.cli.RepoReader", return_value=Repo()), \
                 patch("vulngym_t2.cli.RequestLedger") as ledger, patch("vulngym_t2.cli.DeepSeekClient") as client, \
                 patch("vulngym_t2.cli.run_batch", return_value=({"status": "synthetic"}, 0)), \
                 patch("vulngym_t2.cli._emit"), patch("vulngym_t2.cli.sys.stdin", io.StringIO("dummy-not-a-real-key\n")):
                code = main(["--advisory", "synthetic.txt", "--output", str(Path(temp) / "out"),
                             "--request-ledger", str(Path(temp) / "requests.jsonl"), "--key-stdin", "--model", selected,
                             "--response-mode", "strict_tool", "--thinking", "disabled"])
                self.assertEqual(code, 0)
                self.assertEqual(ledger.call_args.kwargs["model"], selected)
                self.assertEqual(client.call_args.kwargs["model"], selected)
                self.assertEqual(client.call_args.kwargs["response_mode"], "strict_tool")
                self.assertEqual(client.call_args.kwargs["thinking"], "disabled")
                ledger.return_value.close.assert_called_once()
                client.return_value.close.assert_called_once()

    def test_disabled_thinking_with_json_is_rejected_before_input_or_key_access(self):
        with patch("vulngym_t2.cli.load_jobs") as load, patch("vulngym_t2.cli.os.environ.get", return_value="") as env_get, \
             patch("vulngym_t2.cli.getpass.getpass") as prompt, patch("vulngym_t2.cli._emit") as emit:
            self.assertEqual(main(["--advisory", "synthetic.txt", "--thinking", "disabled"]), 2)
        self.assertEqual(emit.call_args.args[0]["code"], "thinking_disabled_requires_strict_tool")
        load.assert_not_called()
        self.assertNotIn("DEEPSEEK_API_KEY", [call.args[0] for call in env_get.call_args_list])
        prompt.assert_not_called()

    def test_staged_mode_accepts_explicit_thinking_configuration(self):
        for thinking in ("enabled", "disabled"):
            args = parser().parse_args(["--advisory", "synthetic.txt", "--response-mode", "staged_tool", "--thinking", thinking])
            self.assertEqual((args.response_mode, args.thinking), ("staged_tool", thinking))

    def test_pipeline_output_connection_retains_bad_input(self):
        with tempfile.TemporaryDirectory(prefix="t2-cli-") as temp:
            output = Path(temp) / "out"
            good = job()
            bad = {**job(), "entry_id": "entry-00002", "input_error": "advisory_material_missing"}
            with contextlib.redirect_stderr(io.StringIO()):
                summary, code = run_batch([good, bad], {0: Repo()}, Client(), output)
            self.assertEqual(code, 0)
            self.assertEqual(summary["entry_count"], 1)
            self.assertEqual(summary["input_failure_count"], 1)
            entry = json.loads((output / "entries.jsonl").read_text())
            self.assertEqual(entry["verify"], 0)
            self.assertEqual(len(entry), 15)
            self.assertEqual(len((output / "review.jsonl").read_text().splitlines()), 2)
            self.assertEqual(json.loads((output / "reports.jsonl").read_text())["entry_ids"], [entry["entry_id"]])
            self.assertNotIn("D:/unused", (output / "review.jsonl").read_text())

    def test_prepare_only_never_opens_ledger_or_client(self):
        with patch("vulngym_t2.cli.load_jobs", return_value=[job()]), patch("vulngym_t2.cli.RepoReader", return_value=Repo()), \
             patch("vulngym_t2.cli.RequestLedger") as ledger, patch("vulngym_t2.cli.DeepSeekClient") as client:
            # _emit uses sys.stdout explicitly; silence by patching the helper.
            with patch("vulngym_t2.cli._emit") as emit:
                self.assertEqual(main(["--advisory", "synthetic.txt", "--prepare-only"]), 0)
            ledger.assert_not_called()
            client.assert_not_called()
            self.assertEqual(emit.call_args.args[0]["http_attempts"], 0)

    def test_prepare_displays_exact_selected_settings_without_accessing_credentials(self):
        with patch("vulngym_t2.cli.load_jobs", return_value=[job()]), \
             patch("vulngym_t2.cli.RepoReader", return_value=Repo()), \
             patch("vulngym_t2.cli.RequestLedger") as ledger, \
             patch("vulngym_t2.cli.DeepSeekClient") as client, \
             patch("vulngym_t2.cli.getpass.getpass") as prompt, \
             patch("vulngym_t2.cli.os.environ.get") as env_get, \
             patch("vulngym_t2.cli._emit") as emit:
            self.assertEqual(main(["--advisory", "synthetic.txt", "--prepare-only",
                "--model", "deepseek-flash", "--response-mode", "staged_tool",
                "--thinking", "enabled", "--annotation-format", "snapshot_json",
                "--reasoning-effort", "low", "--max-tokens", "16384",
                "--max-requests", "16", "--max-calls-per-report", "12",
                "--max-tool-calls", "32", "--authorization-limit", "699", "--stop-on-format-error"]), 0)
        self.assertEqual(emit.call_args.args[0]["configuration"], {
            "model": "deepseek-flash", "response_mode": "staged_tool", "thinking": "enabled",
            "annotation_format": "snapshot_json", "read_format": "native_tool", "review_read_cycles": 0,
            "reasoning_effort": "low", "multi_entry": False,
            "max_tokens_per_request": 16384, "max_requests": 16, "max_calls_per_report": 12,
            "max_tool_calls_per_report": 32, "stop_on_format_error": True,
            "requested_authorization_limit": 699, "authorization_checked": False, "provider_checked": False})
        ledger.assert_not_called()
        client.assert_not_called()
        prompt.assert_not_called()
        self.assertNotIn("DEEPSEEK_API_KEY", [call.args[0] for call in env_get.call_args_list])

    def test_too_small_token_limit_fails_prepare_before_inputs_credentials_or_ledger(self):
        for prepare_args in (["--prepare-only"], []):
            with self.subTest(prepare=bool(prepare_args)), \
                 patch("vulngym_t2.cli.load_jobs") as load, \
                 patch("vulngym_t2.cli.RequestLedger") as ledger, \
                 patch("vulngym_t2.cli.DeepSeekClient") as client, \
                 patch("vulngym_t2.cli.getpass.getpass") as prompt, \
                 patch("vulngym_t2.cli._emit") as emit:
                self.assertEqual(main(["--advisory", "synthetic.txt", "--max-tokens", "255", *prepare_args]), 2)
            self.assertEqual(emit.call_args.args[0]["code"], "output_token_limit_invalid")
            load.assert_not_called()
            ledger.assert_not_called()
            client.assert_not_called()
            prompt.assert_not_called()

    def test_provider_stop_leaves_remaining_jobs_unprocessed(self):
        class FailedClient(Client):
            def complete(self, messages):
                self.calls += 1
                self.halted = "synthetic_provider_failed"
                raise RuntimeError("synthetic_provider_failed")
        with tempfile.TemporaryDirectory(prefix="t2-cli-") as temp:
            with contextlib.redirect_stderr(io.StringIO()):
                summary, code = run_batch([job(), job()], {0: Repo(), 1: Repo()}, FailedClient(), Path(temp) / "out")
            self.assertEqual(code, 2)
            self.assertEqual(summary["status"], "provider_stopped")
            self.assertEqual(summary["unprocessed_input_count"], 1)
            self.assertEqual(summary["provider"]["http_attempts"], 1)

    def test_format_failure_keeps_draft_and_continues_unstarted_case_only(self):
        class FormatClient(Client):
            can_continue_after_format_error = False

            def __init__(self):
                super().__init__()
                self.visited = []
                self.request_cases = []

            def start_next_case(self, case_id, continue_on_format_error=False):
                if case_id in self.visited:
                    raise ValueError("case_already_started")
                recovered = bool(self.halted and continue_on_format_error and self.can_continue_after_format_error)
                if self.halted and not recovered:
                    return False
                self.visited.append(case_id)
                self.case_id = case_id
                self.halted = None
                self.can_continue_after_format_error = False
                return recovered

            def complete(self, messages):
                self.request_cases.append(self.case_id)
                if self.calls == 0:
                    self.calls += 1
                    self.halted = "deepseek_response_invalid_json"
                    self.can_continue_after_format_error = True
                    self.events.append({"status": "error", "failure_kind": "format", "code": self.halted})
                    raise RuntimeError(self.halted)
                return super().complete(messages)

        first = job()
        second = {**job(), "report_id": "GHSA-3333-4444-5555", "entry_id": "entry-00002",
                  "source_link": "https://github.com/advisories/GHSA-3333-4444-5555"}
        for continue_format in (True, False):
            with self.subTest(continue_format=continue_format), tempfile.TemporaryDirectory(prefix="t2-isolate-") as temp:
                client = FormatClient()
                with contextlib.redirect_stderr(io.StringIO()):
                    summary, code = run_batch([first, second], {0: Repo(), 1: Repo()}, client,
                                             Path(temp) / "out", continue_on_format_error=continue_format)
                self.assertEqual(code, 2)
                self.assertEqual(summary["status"], "completed_with_errors" if continue_format else "provider_stopped")
                self.assertEqual(summary["unprocessed_input_count"], 0 if continue_format else 1)
                self.assertEqual(summary["format_failure_count"], 1)
                self.assertEqual(summary["case_failures"][0]["continued"], continue_format)
                self.assertEqual(client.request_cases.count(first["report_id"]), 1)
                self.assertEqual(client.calls, 4 if continue_format else 1)
                reviews = [json.loads(line) for line in (Path(temp) / "out/review.jsonl").read_text().splitlines()]
                self.assertEqual(reviews[0]["status"], "draft")
                self.assertEqual(len(reviews), 2 if continue_format else 1)

    def test_final_format_failure_is_finished_with_errors_not_success(self):
        class FinalFormatClient(Client):
            can_continue_after_format_error = False

            def complete(self, messages):
                self.calls += 1
                self.halted = "deepseek_response_invalid_json"
                self.can_continue_after_format_error = True
                self.events.append({"status": "error", "failure_kind": "format", "code": self.halted})
                raise RuntimeError(self.halted)

        with tempfile.TemporaryDirectory(prefix="t2-last-format-") as temp:
            with contextlib.redirect_stderr(io.StringIO()):
                summary, code = run_batch([job()], {0: Repo()}, FinalFormatClient(), Path(temp) / "out")
            self.assertEqual((summary["status"], code), ("completed_with_errors", 2))
            self.assertEqual(summary["draft_count"], 1)
            self.assertEqual(summary["unprocessed_input_count"], 0)

    def test_typed_format_failure_counts_without_permission_to_continue(self):
        class FormatClient(Client):
            can_continue_after_format_error = False

            def complete(self, messages):
                self.calls += 1
                self.halted = "synthetic_native_shape_error"
                self.events.append({"status": "error", "failure_kind": "format", "code": self.halted})
                raise RuntimeError(self.halted)

        with tempfile.TemporaryDirectory(prefix="t2-native-format-") as temp, patch("vulngym_t2.cli._emit"):
            summary, code = run_batch([job(), job()], {0: Repo(), 1: Repo()}, FormatClient(), Path(temp) / "out")
        self.assertEqual((code, summary["status"]), (2, "provider_stopped"))
        self.assertEqual(summary["format_failure_count"], 1)
        self.assertEqual(summary["case_failures"][0]["input_index"], 1)
        self.assertEqual(summary["unprocessed_input_count"], 1)

    def test_transport_failure_is_not_format_even_with_format_like_code(self):
        class TransportClient(Client):
            def complete(self, messages):
                self.calls += 1
                self.halted = "deepseek_response_invalid_json"
                self.events.append({"status": "error", "failure_kind": "transport", "code": self.halted})
                raise RuntimeError(self.halted)

        with tempfile.TemporaryDirectory(prefix="t2-typed-error-") as temp, patch("vulngym_t2.cli._emit"):
            summary, code = run_batch([job()], {0: Repo()}, TransportClient(), Path(temp) / "out")
        self.assertEqual(code, 2)
        self.assertEqual(summary["format_failure_count"], 0)

    def test_interrupted_partial_result_is_written_once_and_stops_batch(self):
        partial = {"fields": {}, "field_reviews": {}, "evidence": [], "actions": [],
                   "model_calls": 1, "tool_calls": 0, "errors": [], "interrupted": True}
        with tempfile.TemporaryDirectory(prefix="t2-interrupted-") as temp, \
             patch("vulngym_t2.cli.produce", return_value=partial) as produce, patch("vulngym_t2.cli._emit"):
            summary, code = run_batch([job(), job()], {0: Repo(), 1: Repo()}, Client(), Path(temp) / "out")
            reviews = (Path(temp) / "out/review.jsonl").read_text(encoding="utf-8").splitlines()
        self.assertEqual((code, summary["status"]), (130, "interrupted"))
        self.assertEqual(summary["unprocessed_input_count"], 1)
        self.assertEqual(len(reviews), 1)
        produce.assert_called_once()

    def test_emit_uses_current_stdout_not_import_time_stream(self):
        from vulngym_t2.cli import _emit
        stream = io.StringIO()
        with contextlib.redirect_stdout(stream):
            _emit({"status": "synthetic"})
        self.assertEqual(json.loads(stream.getvalue()), {"status": "synthetic"})

    def test_closed_stdout_does_not_attempt_another_error_write(self):
        with patch("vulngym_t2.cli.load_jobs", return_value=[job()]), \
             patch("vulngym_t2.cli.RepoReader", return_value=Repo()), \
             patch("vulngym_t2.cli._emit", side_effect=BrokenPipeError) as emit:
            self.assertEqual(main(["--advisory", "synthetic.txt", "--prepare-only"]), 2)
        emit.assert_called_once()


    def test_primary_advisory_mismatch_is_visible_and_never_requests_model(self):
        with tempfile.TemporaryDirectory(prefix="t2-primary-conflict-", dir=Path(__file__).resolve().parents[2]) as temp:
            root = Path(temp)
            (root / "repo").mkdir()
            (root / "wrong.json").write_text(json.dumps({
                "ghsa_id": "GHSA-2345-6789-cfgh", "summary": "Different advisory",
                "description": "Synthetic primary material for another GHSA.",
            }), encoding="utf-8")
            batch = root / "input.jsonl"
            batch.write_text(json.dumps({
                "source_link": "https://github.com/advisories/GHSA-2345-6789-jmpq",
                "repo_path": "repo", "repo_url": "https://github.com/example/fixture",
                "advisory": "wrong.json",
            }) + "\n", encoding="utf-8")
            with patch("vulngym_t2.cli.RepoReader") as reader, \
                 patch("vulngym_t2.cli.RequestLedger") as ledger, \
                 patch("vulngym_t2.cli.DeepSeekClient") as provider, \
                 patch("vulngym_t2.cli._emit") as emit:
                self.assertEqual(main(["--input", str(batch), "--prepare-only"]), 1)
            reader.assert_not_called()
            ledger.assert_not_called()
            provider.assert_not_called()
            prepared = emit.call_args.args[0]
            self.assertEqual(prepared["http_attempts"], 0)
            check = prepared["inputs"][0]
            self.assertIn("primary_advisory_report_mismatch", check["input_error"])
            self.assertIn("advisory_metadata_report_mismatch", check["input_warnings"])
            self.assertEqual(check["input_conflicts"][0]["status"], "conflicting")
            client = Client()
            with patch.object(client, "complete", side_effect=AssertionError("No model call allowed")) as complete, \
                 contextlib.redirect_stderr(io.StringIO()):
                summary, code = run_batch(load_jobs(input_path=batch), {}, client, root / "output")
            complete.assert_not_called()
            self.assertEqual(code, 0)
            self.assertEqual(summary["input_failure_count"], 1)
            self.assertEqual(summary["entry_count"], 0)
            self.assertEqual(summary["provider"]["http_attempts"], 0)
            review = json.loads((root / "output" / "review.jsonl").read_text(encoding="utf-8"))
            self.assertEqual(review["status"], "input_failure")
            self.assertEqual(review["input_conflicts"], check["input_conflicts"])


if __name__ == "__main__":
    unittest.main()
