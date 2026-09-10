"""Narrow cross-module checks with synthetic model/source, never a paid call."""
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from vulngym_t2.cli import main, run_batch
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

    def complete(self, messages):
        self.calls += 1
        return self.responses.pop(0)(messages)

    def summary(self):
        return {"http_attempts": self.calls, "synthetic": True}


class CliTests(unittest.TestCase):
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


if __name__ == "__main__":
    unittest.main()
