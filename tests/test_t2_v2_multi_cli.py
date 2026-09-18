"""Opt-in CLI wiring only; no model requests, credentials or target reads."""
import io
from pathlib import Path
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from vulngym_t2.cli import main, parser, run_batch
from tests.test_t2_v2_cli import Repo
from tests.test_t2_v2_pipeline import job


class MultiCliTests(unittest.TestCase):
    def test_one_input_is_recorded_once_when_producer_returns_two_candidates(self):
        from tests.test_t2_v2_multi_entry import multi_fixture
        from tests.test_t2_v2_output import StubRepoReader
        material, result = multi_fixture()
        client = SimpleNamespace(multi_entry=True, halted=None, calls=3, case_id="",
                                 summary=lambda: {"http_attempts": 3, "multi_entry": True, "synthetic": True})
        with tempfile.TemporaryDirectory(prefix="t2-multi-cli-") as temp, \
             patch("vulngym_t2.cli.produce", return_value=result), patch("vulngym_t2.cli._emit"):
            summary, code = run_batch([material], {0: StubRepoReader()}, client, Path(temp) / "out")
        self.assertEqual(code, 0)
        self.assertEqual((summary["input_count"], summary["entry_count"], summary["review_count"]), (1, 2, 2))
        self.assertEqual(summary["counting_version"], "input-review-v2")
        self.assertEqual(summary["model_calls"], 3)
        self.assertEqual(summary["complete_input_count"], 1)

    def test_multi_is_explicit_and_incompatible_mode_stops_before_inputs_or_key(self):
        self.assertFalse(parser().parse_args(["--advisory", "synthetic.txt"]).multi_entry)
        with patch("vulngym_t2.cli.load_jobs") as load, \
             patch("vulngym_t2.cli.os.environ.get", return_value="") as key, \
             patch("vulngym_t2.cli._emit") as emit:
            self.assertEqual(main(["--advisory", "synthetic.txt", "--multi-entry"]), 2)
        self.assertEqual(emit.call_args.args[0]["code"], "multi_entry_requires_staged_tool")
        load.assert_not_called()
        self.assertFalse(any(call.args and call.args[0] == "DEEPSEEK_API_KEY" for call in key.call_args_list))

    def test_explicit_multi_flag_reaches_client_without_changing_authorization(self):
        with tempfile.TemporaryDirectory(prefix="t2-multi-cli-") as temp, \
             patch("vulngym_t2.cli.load_jobs", return_value=[job()]), \
             patch("vulngym_t2.cli.RepoReader", return_value=Repo()), \
             patch("vulngym_t2.cli.RequestLedger") as ledger, \
             patch("vulngym_t2.cli.DeepSeekClient") as client, \
             patch("vulngym_t2.cli.run_batch", return_value=({"status": "synthetic"}, 0)), \
             patch("vulngym_t2.cli._emit"), \
             patch("vulngym_t2.cli.sys.stdin", io.StringIO("dummy-not-a-real-key\n")):
            code = main(["--advisory", "synthetic.txt", "--multi-entry",
                         "--response-mode", "staged_tool", "--thinking", "disabled",
                         "--model", "deepseek-flash", "--authorization-limit", "499",
                         "--max-requests", "12", "--key-stdin", "--output", str(Path(temp) / "out"),
                         "--request-ledger", str(Path(temp) / "requests.jsonl")])
            self.assertEqual(code, 0)
            self.assertTrue(client.call_args.kwargs["multi_entry"])
            self.assertEqual(client.call_args.kwargs["max_requests"], 12)
            self.assertEqual(ledger.call_args.kwargs["limit"], 499)


if __name__ == "__main__":
    unittest.main()
