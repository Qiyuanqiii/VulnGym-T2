"""Synthetic multi-entry export checks; no provider or target repository."""
from copy import deepcopy
import json
from pathlib import Path
import tempfile
import unittest

from tests.test_t2_v2_output import fixture, StubRepoReader, REPORT
from vulngym_t2._vendor.schema_adapter import ENTRY_FIELDS
from vulngym_t2.multi_entry import allocate_entry_ids
from vulngym_t2.output import BatchWriter, finalize_job, finalize_result


def multi_fixture(count=2):
    job, result = fixture()
    result.update(self_review_status="completed", evidence_followup_status="completed")
    result["entry_results"] = [
        {"slot": slot, "fields": deepcopy(result["fields"]),
         "field_reviews": deepcopy(result["field_reviews"])}
        for slot in range(1, count + 1)
    ]
    return job, result


class MultiEntryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="t2-multi-entry-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def finalize(self, job, result, entry_ids=None):
        return finalize_job(job, result, StubRepoReader(),
                            entry_ids=entry_ids or allocate_entry_ids([job])[0])

    def save(self, job, finalized):
        writer = BatchWriter(self.root / "run")
        writer.record_job(job, finalized)
        summary = writer.finish({"status": "completed", "requested_input_count": 1,
                                 "unprocessed_input_count": 0})
        def rows(name):
            return [json.loads(line) for line in (writer.directory / name).read_text(encoding="utf-8").splitlines()]
        return summary, rows

    def test_two_complete_entries_keep_schema_report_links_and_shared_budget(self):
        job, result = multi_fixture()
        result["errors"] = ["Recovered earlier model format error."]
        result["actions"].extend([
            {"action": "draft_validation", "entries": [{"slot": 1, "errors": []}, {"slot": 2, "errors": []}]},
            {"action": "self_review", "slots": [1, 2]},
        ])
        original = deepcopy((job, result))
        finalized = self.finalize(job, result)
        self.assertEqual((job, result), original)
        self.assertEqual(finalized["status"], "complete")
        self.assertEqual(finalized["items"][0]["entry"]["entry_id"], job["entry_id"])
        for item in finalized["items"]:
            self.assertEqual(set(item["entry"]), set(ENTRY_FIELDS))
            self.assertEqual(item["entry"]["verify"], 0)
            self.assertEqual(item["review"]["input_id"], job["entry_id"])
            self.assertEqual(item["review"]["process_metadata_scope"], "shared_input")
        summary, rows = self.save(job, finalized)
        self.assertEqual((summary["input_count"], summary["entry_count"], summary["draft_count"]), (1, 2, 0))
        self.assertEqual((summary["complete_input_count"], summary["partial_input_count"], summary["draft_input_count"]), (1, 0, 0))
        self.assertEqual(summary["counting_version"], "input-review-v2")
        self.assertEqual(summary["review_count"], 2)
        self.assertEqual((summary["model_calls"], summary["tool_calls"], summary["model_error_count"]), (3, 1, 1))
        self.assertEqual(summary["jobs_with_model_errors"], 1)
        self.assertTrue(summary["report_linkage_complete"])
        entries, reports, reviews, actions = (rows(name) for name in
            ("entries.jsonl", "reports.jsonl", "review.jsonl", "actions.jsonl"))
        self.assertEqual(reports[0]["entry_ids"], sorted(entry["entry_id"] for entry in entries))
        self.assertEqual(reports[0]["num_entries"], 2)
        self.assertEqual(len(actions), len(result["actions"]))
        self.assertEqual(actions[0]["input_id"], job["entry_id"])
        self.assertEqual(actions[-2]["action"]["entries"][1]["slot"], 2)
        self.assertEqual(actions[-1]["action"]["slots"], [1, 2])
        self.assertEqual(sum(review["model_calls"] for review in reviews), 3)
        self.assertEqual(reviews[1]["actions"], [])
        self.assertEqual(reviews[1]["model_errors"], [])
        mapping = summary["input_reviews"][0]
        self.assertEqual(mapping["review_entry_ids"], [item["review"]["entry_id"] for item in finalized["items"]])
        self.assertEqual(mapping["entry_ids"], mapping["review_entry_ids"])
        self.assertEqual((mapping["input_id"], mapping["report_id"], mapping["source_link"]),
                         (job["entry_id"], REPORT, job["source_link"]))

    def test_complete_and_uncertain_are_independent(self):
        job, result = multi_fixture()
        uncertain = result["entry_results"][1]
        value = uncertain["fields"].pop("critical_operation")
        uncertain["field_reviews"]["critical_operation"].update(
            status="uncertain", suggested_value=value, reason="This operation remains uncertain.")
        finalized = self.finalize(job, result)
        self.assertEqual(finalized["status"], "partial")
        self.assertIsNotNone(finalized["items"][0]["entry"])
        second = finalized["items"][1]
        self.assertIsNone(second["entry"])
        self.assertEqual(second["review"]["suggested_values"]["critical_operation"], value)
        self.assertIsNone(second["review"]["draft_fields"]["critical_operation"])
        summary, _ = self.save(job, finalized)
        self.assertEqual((summary["input_count"], summary["candidate_count"], summary["draft_count"]), (1, 1, 1))
        self.assertEqual(summary["partial_input_count"], 1)
        self.assertEqual(len(summary["input_reviews"][0]["entry_ids"]), 1)

    def test_no_valid_candidates_preserves_one_draft_without_promoting_parent(self):
        for supplied in (None, [], [{"slot": True, "fields": {}, "field_reviews": {}}],
                         [{"slot": 2, "fields": {}, "field_reviews": {}}]):
            with self.subTest(supplied=supplied):
                job, result = multi_fixture()
                result["entry_results"] = supplied
                finalized = self.finalize(job, result)
                self.assertEqual(finalized["status"], "draft")
                self.assertEqual(len(finalized["items"]), 1)
                item = finalized["items"][0]
                self.assertIsNone(item["entry"])
                self.assertEqual(item["review"]["draft_fields"]["project"], "sample")
                self.assertEqual(len(item["review"]["evidence"]), len(result["evidence"]))
                self.assertIn("entry_results_unavailable", [error["code"] for error in item["review"]["errors"]])

    def test_shared_failed_self_review_retains_every_draft(self):
        job, result = multi_fixture()
        result["self_review_status"] = "failed"
        finalized = self.finalize(job, result)
        self.assertEqual(finalized["status"], "draft")
        for item in finalized["items"]:
            self.assertIsNone(item["entry"])
            self.assertTrue(all(value is not None for value in item["review"]["draft_fields"].values()))
            self.assertIn("self_review_incomplete", [error["code"] for error in item["review"]["errors"]])
        summary, _ = self.save(job, finalized)
        self.assertEqual((summary["input_count"], summary["draft_count"], summary["draft_input_count"]), (1, 2, 1))
        self.assertEqual(summary["model_calls"], 3)

    def test_input_failure_remains_one_input_and_one_review(self):
        job, _ = multi_fixture()
        job["input_error"] = "materials_unavailable"
        job.update(report_id=None, source_link=None)
        finalized = self.finalize(job, {})
        self.assertEqual(finalized["status"], "input_failure")
        summary, rows = self.save(job, finalized)
        self.assertEqual((summary["input_count"], summary["input_failure_count"], summary["draft_count"], summary["review_count"]), (1, 1, 0, 1))
        self.assertEqual(rows("review.jsonl")[0]["status"], "input_failure")
        self.assertEqual(summary["model_calls"], 0)

    def test_allocator_reserves_every_input_and_is_order_independent(self):
        jobs = [{"entry_id": "entry-00001"}, {"entry_id": "entry-00000"}]
        original = deepcopy(jobs)
        assigned = allocate_entry_ids(jobs)
        self.assertEqual(jobs, original)
        self.assertEqual([mapping[1] for mapping in assigned], [job["entry_id"] for job in jobs])
        self.assertEqual(len({value for mapping in assigned for value in mapping.values()}), 8)
        self.assertEqual(allocate_entry_ids(list(reversed(jobs))), list(reversed(assigned)))
        for value in (value for mapping in assigned for value in mapping.values()):
            self.assertRegex(value, r"^entry-[0-9]{5}$")
        with self.assertRaisesRegex(ValueError, "duplicate_input_entry_id"):
            allocate_entry_ids([jobs[0], jobs[0]])
        with self.assertRaisesRegex(ValueError, "max_entries_invalid"):
            allocate_entry_ids(jobs, max_entries=True)
        job, result = multi_fixture()
        with self.assertRaisesRegex(ValueError, "duplicate_entry_id"):
            self.finalize(job, result, {1: job["entry_id"], 2: job["entry_id"]})

    def test_writer_refuses_cross_input_id_collision_before_writing_rows(self):
        job, result = multi_fixture()
        first = self.finalize(job, result)
        writer = BatchWriter(self.root / "collision")
        writer.record_job(job, first)
        other, other_result = multi_fixture(1)
        other["entry_id"] = first["items"][1]["review"]["entry_id"]
        collision = self.finalize(other, other_result)
        before = (writer.directory / "review.jsonl").read_bytes()
        with self.assertRaisesRegex(ValueError, "duplicate_entry_id"):
            writer.record_job(other, collision)
        self.assertEqual((writer.directory / "review.jsonl").read_bytes(), before)

    def test_report_conflict_keeps_canonical_report_and_warning(self):
        job, result = multi_fixture()
        result["entry_results"][1]["fields"]["vuln_title"] = "Different advisory title"
        summary, rows = self.save(job, self.finalize(job, result))
        self.assertEqual(summary["entry_count"], 2)
        self.assertEqual(summary["report_count"], 1)
        self.assertEqual(summary["report_conflict_count"], 1)
        self.assertTrue(summary["report_linkage_complete"])
        self.assertEqual(len(rows("report_conflicts.jsonl")), 1)
        entries = rows("entries.jsonl")
        self.assertEqual(rows("reports.jsonl")[0]["vuln_title"], entries[0]["vuln_title"])

    def test_empty_multi_batch_still_declares_its_counting_version(self):
        writer = BatchWriter(self.root / "empty", multi_entry=True)
        summary = writer.finish()
        self.assertEqual(summary["counting_version"], "input-review-v2")
        self.assertEqual(summary["input_reviews"], [])
        self.assertEqual(summary["review_count"], 0)
        self.assertTrue(summary["report_linkage_complete"])

    def test_legacy_record_keeps_its_counting_contract(self):
        job, result = fixture()
        writer = BatchWriter(self.root / "legacy")
        writer.record(job, finalize_result(job, result, StubRepoReader()))
        summary = writer.finish()
        self.assertNotIn("counting_version", summary)
        self.assertNotIn("input_reviews", summary)
        self.assertEqual((summary["input_count"], summary["candidate_count"], summary["draft_count"]), (1, 1, 0))
        self.assertEqual((summary["model_calls"], summary["tool_calls"]), (3, 1))
        self.assertTrue(summary["report_linkage_complete"])


if __name__ == "__main__":
    unittest.main()
