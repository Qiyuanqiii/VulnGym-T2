"""Stop at input boundaries, without killing a paid request or losing output."""
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from vulngym_t2.cli import run_batch
from tests.test_t2_v2_cli import Client, Repo, job


class CooperativeStopTests(unittest.TestCase):
    def test_initial_stop_makes_no_model_call_and_preserves_unprocessed_count(self):
        with tempfile.TemporaryDirectory(prefix="t2-stop-") as temp, patch("vulngym_t2.cli._emit"):
            client = Client()
            summary, code = run_batch([job()], {0: Repo()}, client, Path(temp) / "output", should_stop=lambda: True)
        self.assertEqual(code, 130)
        self.assertEqual(summary["status"], "stopped_by_user")
        self.assertEqual(summary["unprocessed_input_count"], 1)
        self.assertEqual(client.calls, 0)

    def test_completed_first_input_is_published_second_never_starts(self):
        with tempfile.TemporaryDirectory(prefix="t2-stop-") as temp, patch("vulngym_t2.cli._emit"):
            client = Client()
            summary, code = run_batch([job(), {**job(), "entry_id": "entry-00002"}], {0: Repo(), 1: Repo()},
                                      client, Path(temp) / "output", should_stop=lambda: client.calls > 0)
            entries = (Path(temp) / "output" / "entries.jsonl").read_text(encoding="utf-8").splitlines()
        self.assertEqual(code, 130)
        self.assertEqual(summary["status"], "stopped_by_user")
        self.assertEqual(summary["unprocessed_input_count"], 1)
        self.assertEqual(len(entries), 1)
        self.assertEqual(client.calls, 3)


if __name__ == "__main__":
    unittest.main()
