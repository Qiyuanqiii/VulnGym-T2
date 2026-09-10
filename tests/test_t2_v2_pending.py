"""Focused offline URL-suffix checks using synthetic public batch receipts."""
import contextlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from vulngym_t2.pending import export_pending, main, plan_pending


IDS = ["GHSA-2345-6789-CFGH", "GHSA-3456-789C-FGHJ", "GHSA-4567-89CF-GHJM", "GHSA-5678-9CFG-HJMP"]
URLS = ["https://github.com/advisories/GHSA-" + value[5:].lower() for value in IDS]


class PendingTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="t2-pending-", dir="D:/Temp" if os.name == "nt" else None)
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.input = self.root / "original.txt"
        self.input.write_text("# Original public reports\n\n" + "\n".join(URLS) + "\n", encoding="utf-8")
        self.run = self.root / "run"
        self.run.mkdir()
        self.output = self.root / "remaining.txt"
        self.reviews = [{"report_id": IDS[index], "entry_id": f"entry-{index:05d}",
                         "source_link": URLS[index], "status": status}
                        for index, status in enumerate(("complete", "draft", "input_failure"))]
        self.summary = {"status": "provider_stopped", "requested_input_count": 4, "input_count": 3,
                        "unprocessed_input_count": 1, "candidate_count": 1, "entry_count": 1,
                        "schema_entry_count": 1, "draft_count": 1, "input_failure_count": 1}
        self.write_run()

    def write_run(self):
        (self.run / "summary.json").write_text(json.dumps(self.summary), encoding="utf-8")
        (self.run / "review.jsonl").write_text("".join(json.dumps(row) + "\n" for row in self.reviews), encoding="utf-8")

    def test_provider_failure_draft_and_input_failure_are_skipped_without_execution(self):
        originals = {path: path.read_bytes() for path in (self.input, self.run / "summary.json", self.run / "review.jsonl")}
        with patch("socket.socket", side_effect=AssertionError("network forbidden")), \
             patch("subprocess.run", side_effect=AssertionError("execution forbidden")):
            plan = export_pending(self.input, self.run, self.output)
        self.assertEqual(self.output.read_text(), URLS[3] + "\n")
        self.assertEqual(plan["processed_input_count"], 3)
        self.assertEqual(plan["pending"][0]["input_index"], 4)
        self.assertEqual(plan["http_attempts"], 0)
        self.assertTrue(plan["requires_separate_run_authorization"])
        self.assertNotIn(str(self.root), json.dumps(plan))
        self.assertEqual(originals, {path: path.read_bytes() for path in originals})

    def test_completed_run_exports_empty_list_without_overwriting(self):
        self.reviews.append({"report_id": IDS[3], "entry_id": "entry-00003", "source_link": URLS[3], "status": "draft"})
        self.summary.update(status="completed", input_count=4, unprocessed_input_count=0, draft_count=2)
        self.write_run()
        self.assertEqual(export_pending(self.input, self.run, self.output)["pending_input_count"], 0)
        self.assertEqual(self.output.read_bytes(), b"")
        with self.assertRaisesRegex(ValueError, "^pending_output_exists$"):
            export_pending(self.input, self.run, self.output)

    def test_wrong_order_or_source_cannot_prove_prefix(self):
        self.reviews[0], self.reviews[1] = self.reviews[1], self.reviews[0]
        self.write_run()
        with self.assertRaisesRegex(ValueError, "^pending_processed_prefix_mismatch$"):
            export_pending(self.input, self.run, self.output)
        self.assertFalse(self.output.exists())
        self.reviews[0], self.reviews[1] = self.reviews[1], self.reviews[0]
        self.reviews[0]["source_link"] = URLS[3]
        self.write_run()
        with self.assertRaisesRegex(ValueError, "^pending_processed_prefix_mismatch$"):
            plan_pending(self.input, self.run)

    def test_duplicate_report_or_entry_ids_are_refused(self):
        self.input.write_text("\n".join(URLS + [URLS[0]]), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "^pending_duplicate_input_report_id$"):
            plan_pending(self.input, self.run)
        self.input.write_text("\n".join(URLS), encoding="utf-8")
        self.reviews[1]["entry_id"] = self.reviews[0]["entry_id"]
        self.write_run()
        with self.assertRaisesRegex(ValueError, "^pending_duplicate_review_id$"):
            plan_pending(self.input, self.run)

    def test_missing_summary_and_uncertain_stop_are_refused(self):
        (self.run / "summary.json").unlink()
        with self.assertRaisesRegex(ValueError, "^pending_summary_unavailable$"):
            plan_pending(self.input, self.run)
        for status in ("interrupted", "batch_processing_failed"):
            with self.subTest(status=status):
                self.summary["status"] = status
                self.write_run()
                with self.assertRaisesRegex(ValueError, "^pending_run_boundary_uncertain$"):
                    plan_pending(self.input, self.run)

    def test_inconsistent_counts_and_truncated_review_are_refused(self):
        self.summary["unprocessed_input_count"] = 2
        self.write_run()
        with self.assertRaisesRegex(ValueError, "^pending_summary_count_mismatch$"):
            plan_pending(self.input, self.run)
        self.summary["unprocessed_input_count"] = 1
        self.summary["draft_count"] = 0
        self.write_run()
        with self.assertRaisesRegex(ValueError, "^pending_summary_status_count_mismatch$"):
            plan_pending(self.input, self.run)
        self.summary["draft_count"] = 1
        self.write_run()
        with (self.run / "review.jsonl").open("a", encoding="utf-8") as stream:
            stream.write('{"report_id":')
        with self.assertRaisesRegex(ValueError, "^pending_review_json_invalid$"):
            plan_pending(self.input, self.run)

    def test_cli_accepts_public_advisory_alias_but_rejects_jsonl_with_safe_error(self):
        alias = "https://github.com/example/project/security/advisories/" + IDS[3]
        self.input.write_text("\n".join(URLS[:3] + [alias]), encoding="utf-8")
        stream = io.StringIO()
        with contextlib.redirect_stdout(stream):
            self.assertEqual(main(["--input", str(self.input), "--run-dir", str(self.run), "--output", str(self.output)]), 0)
        self.assertEqual(json.loads(stream.getvalue())["pending_input_count"], 1)
        self.assertEqual(self.output.read_text(), alias + "\n")
        self.input.write_text(json.dumps({"source_link": URLS[0]}), encoding="utf-8")
        stream = io.StringIO()
        with contextlib.redirect_stdout(stream):
            code = main(["--input", str(self.input), "--run-dir", str(self.run), "--output", str(self.root / "other.txt")])
        self.assertEqual(code, 2)
        self.assertEqual(json.loads(stream.getvalue()), {"status": "error", "code": "pending_ghsa_url_list_required", "http_attempts": 0})
        self.assertFalse((self.root / "other.txt").exists())


if __name__ == "__main__":
    unittest.main()
