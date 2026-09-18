"""Offline incomplete-result export: blank fields never imply completion."""
from copy import deepcopy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from tests.test_t2_v2_output import fixture, StubRepoReader
from tests.test_t2_v2_serial_output import serial_fixture
from vulngym_t2._vendor.schema_adapter import ENTRY_FIELDS, SchemaAdapter
from vulngym_t2.multi_entry import allocate_entry_ids
from vulngym_t2 import output, review_export


class DraftExportTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="t2-draft-export-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def rows(self, run, name):
        return [json.loads(line) for line in (run / name).read_text(encoding="utf-8").splitlines()]

    def incomplete(self, identity="entry-00002"):
        job, result = fixture(identity)
        for field in ("critical_operation", "vuln_ids"):
            result["fields"].pop(field)
        result["field_reviews"]["vuln_title"].update(status="uncertain", reason="Needs independent comparison.")
        return job, output.finalize_result(job, result, StubRepoReader())

    def test_complete_draft_and_input_failure_keep_distinct_rows_and_counts(self):
        writer = output.BatchWriter(self.root / "run")
        job, draft = self.incomplete()
        original = deepcopy(draft)
        writer.record(job, draft)
        job, result = fixture("entry-00001")
        complete = output.finalize_result(job, result, StubRepoReader())
        writer.record(job, complete)
        failed_job, _ = fixture("entry-00003")
        failed_job.update(input_error="Input metadata unavailable", report_id=None, source_link=None, repo_url=None)
        failure = output.finalize_result(failed_job, None, StubRepoReader())
        writer.record(failed_job, failure)
        # Append progress is already useful before deterministic finalization.
        self.assertEqual(len(self.rows(writer.directory, "drafts.jsonl")), 2)
        summary = writer.finish({"status": "completed", "draft_export_count": 999,
                                 "draft_export_version": "untrusted-override"})
        entries, drafts, reviews = [self.rows(writer.directory, name) for name in
                                    ("entries.jsonl", "drafts.jsonl", "review.jsonl")]
        self.assertEqual([row["entry_id"] for row in entries], ["entry-00001"])
        self.assertEqual([row["entry_id"] for row in drafts], ["entry-00002", "entry-00003"])
        self.assertTrue(SchemaAdapter().validate(entries[0], formal_t2=True).valid)
        self.assertEqual((summary["candidate_count"], summary["draft_count"], summary["input_failure_count"],
                          summary["draft_export_count"]), (1, 1, 1, 2))
        self.assertEqual(summary["draft_export_version"], output.DRAFT_EXPORT_VERSION)
        self.assertIn("not a schema-valid completed dataset", summary["draft_export_definition"])
        self.assertIn("drafts.jsonl", summary["files"])
        for row in drafts:
            self.assertEqual(tuple(row), ENTRY_FIELDS)
            self.assertEqual(row["verify"], 0)
            self.assertNotIn(None, row.values())
            self.assertFalse(SchemaAdapter().validate(row, formal_t2=True).valid)
        self.assertEqual((drafts[0]["vuln_title"], drafts[0]["critical_operation"], drafts[0]["vuln_ids"]), ("", "", []))
        self.assertEqual(drafts[0]["entry_point"], original["review"]["draft_fields"]["entry_point"])
        self.assertEqual((drafts[1]["commit"], drafts[1]["source_link"], drafts[1]["entry_point"]), ("", "", ""))
        self.assertEqual(draft, original)
        self.assertEqual(reviews[0], original["review"])
        self.assertIsNone(reviews[0]["draft_fields"]["critical_operation"])
        self.assertTrue(reviews[0]["suggested_values"]["vuln_title"])
        before = {path.name: path.read_bytes() for path in writer.directory.iterdir()}
        with patch("socket.socket", side_effect=AssertionError("network forbidden")):
            exported = review_export.export_review(writer.directory, self.root / "packet.md")
        self.assertEqual((exported["http_attempts"], exported["draft_export_count"]), (0, 2))
        packet = (self.root / "packet.md").read_text(encoding="utf-8")
        self.assertIn("空值草稿（drafts.jsonl；不是完整数据集）", packet)
        self.assertIn("字段齐全但自查等过程未完成", packet)
        self.assertEqual({path.name: path.read_bytes() for path in writer.directory.iterdir()}, before)

    def test_serial_full_fields_with_failed_self_review_stay_only_in_drafts(self):
        job, result = serial_fixture()
        finalized = output.finalize_job(job, result, StubRepoReader(), entry_ids=allocate_entry_ids([job])[0])
        original = deepcopy(finalized)
        writer = output.BatchWriter(self.root / "serial", multi_entry=True)
        writer.record_job(job, finalized)
        summary = writer.finish({"status": "completed", "requested_input_count": 1, "unprocessed_input_count": 0})
        entries, drafts, reviews = [self.rows(writer.directory, name) for name in
                                    ("entries.jsonl", "drafts.jsonl", "review.jsonl")]
        self.assertEqual((len(entries), len(drafts), summary["draft_export_count"]), (1, 1, 1))
        self.assertTrue(SchemaAdapter().validate(drafts[0], formal_t2=True).valid)
        self.assertEqual(drafts[0], reviews[1]["draft_fields"])
        self.assertEqual(reviews[1]["status"], "draft")
        self.assertEqual(reviews[1]["self_review_status"], "failed")
        self.assertEqual(finalized, original)
        review_export.render_packet(summary, entries, reviews, drafts)

    def test_draft_export_is_deterministic_and_empty_for_complete_only_runs(self):
        outputs = []
        for number, order in enumerate(((2, 1), (1, 2))):
            writer = output.BatchWriter(self.root / str(number))
            for identity in order:
                writer.record(*self.incomplete(f"entry-{identity:05d}"))
            writer.finish({"status": "completed"})
            outputs.append((writer.directory / "drafts.jsonl").read_bytes())
        self.assertEqual(*outputs)
        writer = output.BatchWriter(self.root / "complete")
        job, result = fixture()
        writer.record(job, output.finalize_result(job, result, StubRepoReader()))
        self.assertEqual(writer.finish()["draft_export_count"], 0)
        self.assertEqual((writer.directory / "drafts.jsonl").read_bytes(), b"")

    def test_projection_uses_only_accepted_fields_and_redacts_public_values(self):
        job, finalized = self.incomplete()
        review = finalized["review"]
        review["draft_fields"]["vuln_category_l2"] = (
            r"D:\private\source.py /home/person/secret.py sk-syntheticsecret123 "
            "Bearer syntheticbearer password=syntheticpassword1234567890123456")
        review["draft_fields"]["private_extra"] = "EXTRA_FIELD_NOT_EXPORTED"
        review["suggested_values"]["vuln_title"] = "SUGGESTION_NOT_ADOPTED"
        original = deepcopy(finalized)
        writer = output.BatchWriter(self.root / "public")
        writer.record(job, finalized)
        writer.finish({"status": "completed"})
        text = (writer.directory / "drafts.jsonl").read_text(encoding="utf-8")
        for secret in ("source.py", "person", "syntheticsecret", "syntheticbearer", "syntheticpassword",
                       "EXTRA_FIELD_NOT_EXPORTED", "SUGGESTION_NOT_ADOPTED"):
            self.assertNotIn(secret, text)
        self.assertIn("redacted-secret", text)
        self.assertEqual(finalized, original)

    def test_exporter_rejects_missing_tampered_duplicate_or_promoted_drafts(self):
        writer = output.BatchWriter(self.root / "checked")
        writer.record(*self.incomplete())
        summary = writer.finish({"status": "completed"})
        reviews = self.rows(writer.directory, "review.jsonl")
        drafts = self.rows(writer.directory, "drafts.jsonl")
        for mutate in (lambda rows: rows.clear(), lambda rows: rows.append(deepcopy(rows[0])),
                       lambda rows: rows[0].update(verify=1),
                       lambda rows: rows[0].update(verify=False),
                       lambda rows: rows[0].update(verify=0.0),
                       lambda rows: rows[0].update(vuln_title="SUGGESTED_PROMOTION"),
                       lambda rows: rows[0].update(critical_operation={"file": "made-up", "line": 1, "code": ""}),
                       lambda rows: rows[0].update(extra="not official")):
            altered = deepcopy(drafts)
            mutate(altered)
            with self.assertRaises(review_export.ExportError):
                review_export.render_packet(summary, [], reviews, altered)
        with patch.object(review_export, "_read", side_effect=lambda run, name:
                          (_ for _ in ()).throw(review_export.ExportError("source_file_unavailable"))
                          if name == "drafts.jsonl" else (run / name).read_text(encoding="utf-8")):
            with self.assertRaisesRegex(review_export.ExportError, "source_file_unavailable"):
                review_export.export_review(writer.directory, self.root / "missing.md")
        self.assertFalse((self.root / "missing.md").exists())

    def test_draft_publication_failure_keeps_review_and_refuses_summary(self):
        writer = output.BatchWriter(self.root / "failed-publication")
        writer.record(*self.incomplete())
        saved_review = (writer.directory / "review.jsonl").read_bytes()
        original_replace = output._replace_final_output
        def replace(source, destination):
            if destination.name == "drafts.jsonl":
                raise OSError("PRIVATE_PUBLICATION_DETAIL")
            return original_replace(source, destination)
        with patch.object(output, "_replace_final_output", side_effect=replace):
            with self.assertRaises(output.OutputPublicationError) as caught:
                writer.finish({"status": "completed"})
        self.assertEqual(caught.exception.diagnostics["target"], "drafts.jsonl")
        self.assertNotIn("PRIVATE_PUBLICATION_DETAIL", str(caught.exception))
        self.assertEqual((writer.directory / "review.jsonl").read_bytes(), saved_review)
        self.assertFalse((writer.directory / "summary.json").exists())
        with self.assertRaisesRegex(RuntimeError, "batch_write_failed"):
            writer.finish()


if __name__ == "__main__":
    unittest.main()
