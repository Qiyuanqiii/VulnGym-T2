"""Synthetic output durability, long explanations and bad-public-file checks."""
from copy import deepcopy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from tests.test_t2_v2_output import fixture, StubRepoReader
from tests.test_t2_v2_multi_entry import multi_fixture
from vulngym_t2 import output, report, review_export
from vulngym_t2.multi_entry import allocate_entry_ids


class OutputResilienceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="t2-output-resilience-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def finalized(self, identity="entry-00001", *, draft=False):
        job, result = fixture(identity)
        if draft:
            result["field_reviews"]["vuln_title"]["status"] = "uncertain"
        return job, output.finalize_result(job, result, StubRepoReader())

    def saved(self, name="run"):
        job, result = self.finalized()
        writer = output.BatchWriter(self.root / name)
        writer.record(job, result)
        summary = writer.finish({"status": "completed", "requested_input_count": 1,
                                 "unprocessed_input_count": 0})
        return writer.directory, summary, [result["entry"]], [result["review"]]

    def test_reason_boundary_and_upstream_truncation_survive_finalization_and_readback(self):
        for length in (1601, 2000, 2001):
            with self.subTest(length=length):
                job, result = fixture()
                result["field_reviews"]["commit"]["reason"] = "x" * (length - 4) + "TAIL"
                original = deepcopy(result)
                finalized = output.finalize_result(job, result, StubRepoReader())
                assessment = finalized["review"]["field_reviews"]["commit"]
                self.assertEqual(assessment["reason"], original["field_reviews"]["commit"]["reason"][:2000])
                self.assertEqual(assessment.get("reason_truncated", False), length > 2000)
                self.assertEqual(result, original)
        result["field_reviews"]["commit"].update(reason="Already shortened", reason_truncated=True)
        finalized = output.finalize_result(job, result, StubRepoReader())
        self.assertTrue(finalized["review"]["field_reviews"]["commit"]["reason_truncated"])
        writer = output.BatchWriter(self.root / "reason")
        writer.record(job, finalized)
        summary = writer.finish({"status": "completed"})
        for text in (report._assessment(summary, [finalized["review"]]),
                     review_export.render_packet(summary, [finalized["entry"]], [finalized["review"]])):
            self.assertIn("原始理由已截短", text)

    def test_single_duplicate_draft_is_refused_without_corrupting_a_later_good_record(self):
        job, finalized = self.finalized(draft=True)
        writer = output.BatchWriter(self.root / "duplicates")
        writer.record(job, finalized)
        before = (writer.directory / "review.jsonl").read_bytes()
        with self.assertRaisesRegex(ValueError, "duplicate_entry_id"):
            writer.record(job, finalized)
        self.assertEqual((writer.directory / "review.jsonl").read_bytes(), before)
        other, complete = self.finalized("entry-00002")
        writer.record(other, complete)
        summary = writer.finish({"status": "completed"})
        self.assertEqual((summary["input_count"], summary["candidate_count"], summary["draft_count"]), (2, 1, 1))

    def test_entry_review_disagreement_is_refused_before_any_single_write(self):
        job, finalized = self.finalized()
        writer = output.BatchWriter(self.root / "mismatch")
        wrong = deepcopy(finalized)
        wrong["review"]["draft_fields"]["vuln_title"] = "Different title"
        with self.assertRaisesRegex(ValueError, "entry_review_mismatch"):
            writer.record(job, wrong)
        self.assertEqual((writer.directory / "entries.jsonl").read_bytes(), b"")
        writer.record(job, finalized)
        self.assertEqual(writer.finish()["candidate_count"], 1)

    def test_one_damaged_child_keeps_its_slot_and_does_not_erase_a_good_sibling(self):
        for key in ("fields", "field_reviews"):
            with self.subTest(key=key):
                job, result = multi_fixture()
                result["annotation_mode"] = "snapshot"
                for row in result["entry_results"]:
                    row.update(self_review_status="completed", evidence_followup_status="not_requested",
                               initial_draft_status="accepted", errors=[], actions=[])
                result["entry_results"][1][key] = None
                original = deepcopy(result)
                finalized = output.finalize_job(job, result, StubRepoReader(), entry_ids=allocate_entry_ids([job])[0])
                self.assertEqual(result, original)
                self.assertEqual(finalized["status"], "partial")
                self.assertEqual(len(finalized["items"]), 2)
                self.assertIsNotNone(finalized["items"][0]["entry"])
                self.assertIsNone(finalized["items"][1]["entry"])
                self.assertIn("entry_result_invalid", [row["code"] for row in finalized["items"][1]["review"]["errors"]])
                writer = output.BatchWriter(self.root / key, multi_entry=True)
                writer.record_job(job, finalized)
                summary = writer.finish({"status": "completed", "requested_input_count": 1, "unprocessed_input_count": 0})
                entries = review_export._rows((writer.directory / "entries.jsonl").read_text(encoding="utf-8"))
                reviews = review_export._rows((writer.directory / "review.jsonl").read_text(encoding="utf-8"))
                self.assertEqual((summary["input_count"], summary["candidate_count"], summary["draft_count"]), (1, 1, 1))
                self.assertEqual(summary["model_calls"], result["model_calls"])
                review_export.render_packet(summary, entries, reviews)

    def test_missing_snapshot_field_diagnostic_survives_writer_and_both_renderers(self):
        job, result = fixture()
        result["fields"].pop("trace")
        error = {"field": "trace", "code": "missing_property", "path": "$[0].arguments.trace"}
        result.update(annotation_errors=[error], annotation_mode="snapshot", self_review_status="completed")
        finalized = output.finalize_result(job, result, StubRepoReader())
        self.assertIsNone(finalized["entry"])
        self.assertEqual(finalized["review"]["field_reviews"]["trace"]["status"], "uncertain")
        self.assertEqual(finalized["review"]["field_reviews"]["critical_operation"]["status"], "supported")
        writer = output.BatchWriter(self.root / "missing")
        writer.record(job, finalized)
        summary = writer.finish({"status": "completed"})
        reviews = review_export._rows((writer.directory / "review.jsonl").read_text(encoding="utf-8"))
        self.assertEqual(reviews[0]["annotation_errors"], [error])
        self.assertEqual((summary["annotation_error_count"], summary["jobs_with_annotation_errors"]), (1, 1))
        for rendered in (report._assessment(summary, reviews), review_export.render_packet(summary, [], reviews)):
            self.assertIn("missing", rendered)
            self.assertIn("field | code | path", rendered)

    def test_record_append_failure_or_interrupt_preserves_prefix_and_refuses_false_finish(self):
        for multi, error in ((False, OSError("disk unavailable")), (True, KeyboardInterrupt())):
            with self.subTest(multi=multi):
                writer = output.BatchWriter(self.root / str(multi), multi_entry=multi)
                if multi:
                    job, result = multi_fixture()
                    finalized = output.finalize_job(job, result, StubRepoReader(), entry_ids=allocate_entry_ids([job])[0])
                    record = writer.record_job
                else:
                    job, finalized = self.finalized()
                    record = writer.record
                record(job, finalized)
                prefix = {name: (writer.directory / name).read_bytes() for name in ("entries.jsonl", "review.jsonl")}
                if multi:
                    job = dict(job, entry_id="entry-00999")
                    result["entry_results"] = result["entry_results"][:1]
                    finalized = output.finalize_job(job, result, StubRepoReader(), entry_ids={1: job["entry_id"]})
                else:
                    job, finalized = self.finalized("entry-00999")
                append = writer._append
                def fail(name, value):
                    if name == "review.jsonl":
                        raise error
                    return append(name, value)
                with patch.object(writer, "_append", side_effect=fail), self.assertRaises(type(error)):
                    record(job, finalized)
                for name, content in prefix.items():
                    self.assertTrue((writer.directory / name).read_bytes().startswith(content))
                self.assertEqual(writer._counts["input_count"], 1)
                with self.assertRaisesRegex(RuntimeError, "batch_write_failed"):
                    writer.finish({"status": "completed"})
                self.assertFalse((writer.directory / "summary.json").exists())

    def test_finish_serialization_failure_does_not_truncate_already_written_entries(self):
        writer = output.BatchWriter(self.root / "serialize")
        for identity in ("entry-00002", "entry-00001"):
            writer.record(*self.finalized(identity))
        before = {path.name: path.read_bytes() for path in writer.directory.iterdir()}
        with patch.object(output, "_json", side_effect=ValueError("serialization failed")), self.assertRaises(ValueError):
            writer.finish()
        self.assertEqual({path.name: path.read_bytes() for path in writer.directory.iterdir()}, before)
        self.assertEqual(writer.finish()["candidate_count"], 2)

    def test_finish_replace_failure_preserves_existing_jsonl_and_no_summary(self):
        writer = output.BatchWriter(self.root / "replace")
        writer.record(*self.finalized())
        before = {path.name: path.read_bytes() for path in writer.directory.iterdir()}
        with patch("os.replace", side_effect=OSError("replace unavailable")), self.assertRaises(OSError):
            writer.finish()
        self.assertTrue(all((writer.directory / name).read_bytes() == data for name, data in before.items()))
        self.assertFalse((writer.directory / "summary.json").exists())

    def test_finish_staging_write_failure_leaves_all_published_files_unchanged(self):
        writer = output.BatchWriter(self.root / "stage")
        writer.record(*self.finalized())
        before = {path.name: path.read_bytes() for path in writer.directory.iterdir()}
        with patch("os.fsync", side_effect=OSError("disk full")), self.assertRaises(OSError):
            writer.finish()
        self.assertTrue(all((writer.directory / name).read_bytes() == data for name, data in before.items()))
        self.assertFalse((writer.directory / "summary.json").exists())
        with self.assertRaisesRegex(RuntimeError, "batch_write_failed"):
            writer.finish()

    def test_bad_actions_are_diagnosed_before_export_and_original_files_survive(self):
        run, summary, entries, reviews = self.saved()
        for bad in (None, {}, 1):
            with self.subTest(bad=bad):
                altered = deepcopy(reviews)
                altered[0]["actions"] = bad
                with self.assertRaisesRegex(review_export.ExportError, "review_actions_invalid"):
                    review_export.render_packet(summary, entries, altered)
        self.assertFalse((run / "assessment.md").exists())

    def test_interrupted_snapshot_exports_only_saved_rows_with_explicit_counts(self):
        run, summary, entries, reviews = self.saved()
        summary.update(status="interrupted", requested_input_count=2, unprocessed_input_count=1)
        original = deepcopy((summary, entries, reviews))
        self.assertIn("本地中断", review_export.render_packet(summary, entries, reviews))
        self.assertEqual((summary, entries, reviews), original)
        summary.pop("requested_input_count")
        summary.pop("unprocessed_input_count")
        with self.assertRaisesRegex(review_export.ExportError, "incomplete_input_counts"):
            review_export.render_packet(summary, entries, reviews)
        self.assertFalse((run / "assessment.md").exists())

    def test_report_rejects_ambiguous_or_nonfinite_json_without_creating_artifact(self):
        for name, text, code in (
            ("summary.json", '{"status":"completed","status":"provider_stopped"}', "summary_json_invalid"),
            ("review.jsonl", '{"entry_id":"one","entry_id":"two"}\n', "review_json_invalid_line_1"),
            ("review.jsonl", '{"entry_id":"one","unknown":1e999}\n', "review_json_invalid_line_1"),
        ):
            with self.subTest(name=name, text=text):
                run, _, _, _ = self.saved(str(len(list(self.root.iterdir()))))
                (run / name).write_text(text, encoding="utf-8")
                original = (run / name).read_bytes()
                with self.assertRaisesRegex(ValueError, code):
                    report.build_assessment(run)
                self.assertEqual((run / name).read_bytes(), original)
                self.assertFalse((run / "assessment.md").exists())


if __name__ == "__main__":
    unittest.main()
