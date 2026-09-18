"""Offline serial snapshot finalization and public-output regression checks."""
from copy import deepcopy
import json
from pathlib import Path
import tempfile
import unittest

from tests.test_t2_v2_output import fixture, StubRepoReader, COMMIT
from tests.test_t2_v2_multi_entry import multi_fixture
from vulngym_t2.multi_entry import allocate_entry_ids
from vulngym_t2.output import BatchWriter, finalize_job, finalize_result
from vulngym_t2.report import _assessment, _entry_diagnostic, build_review_template
from vulngym_t2.review_export import ExportError, _process_record, render_packet
from vulngym_t2.source_refs import revision_consistency


def serial_fixture():
    job, result = multi_fixture()
    result.update(annotation_mode="snapshot", model_calls=8, tool_calls=5,
                  self_review_status="failed", evidence_followup_status="failed",
                  errors=["list_files failed: ValueError"], actions=[{
                      "action": "candidate_plan", "proposed_count": 3, "selected_count": 2,
                      "omitted_count": 1, "duplicate_count": 1, "budget_slots": 2,
                      "reason": "RAW_SCOPE_PRIVATE", "scope": "RAW_SCOPE_PRIVATE"}])
    for row in result["entry_results"]:
        row.update(initial_draft_status="accepted", self_review_status="completed",
                   evidence_followup_status="not_requested", errors=[], actions=[{
                       "action": "self_review", "slot": row["slot"]}])
    second = result["entry_results"][1]
    second.update(self_review_status="failed", errors=["Model request failed during self_review: ProviderError"])
    second["actions"].append({"action": "model_failure", "stage": "self_review",
                              "code": "deepseek_staged_protocol_invalid",
                              "protocol_reason": "unexpected_properties",
                              "protocol_path": "$[0].arguments.summary"})
    return job, result


class SerialOutputTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="t2-serial-output-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def finalize(self, job, result):
        return finalize_job(job, result, StubRepoReader(), entry_ids=allocate_entry_ids([job])[0])

    def save(self, job, result, name="run"):
        finalized = self.finalize(job, result)
        writer = BatchWriter(self.root / name, multi_entry=True)
        writer.record_job(job, finalized)
        summary = writer.finish({"status": "provider_stopped", "requested_input_count": 1,
                                 "unprocessed_input_count": 0})
        def rows(name):
            return [json.loads(line) for line in (writer.directory / name).read_text(encoding="utf-8").splitlines()]
        return writer.directory, summary, rows("entries.jsonl"), rows("review.jsonl"), rows("actions.jsonl")

    def test_snapshot_requires_completed_self_review_but_legacy_is_unchanged(self):
        job, result = fixture()
        self.assertIsNotNone(finalize_result(job, result, StubRepoReader())["entry"])
        result["annotation_mode"] = "snapshot"
        for state in ("not_requested", "failed", "completed"):
            with self.subTest(state=state):
                result["self_review_status"] = state
                checked = finalize_result(job, result, StubRepoReader())
                self.assertEqual(checked["entry"] is not None, state == "completed")
                self.assertEqual(checked["review"]["annotation_mode"], "snapshot")
                self.assertTrue(all(value is not None for value in checked["review"]["draft_fields"].values()))
                if state == "not_requested":
                    self.assertIn("self_review_required", [item["code"] for item in checked["review"]["errors"]])

    def test_later_failure_does_not_retroactively_demote_completed_child(self):
        job, result = serial_fixture()
        original = deepcopy(result)
        finalized = self.finalize(job, result)
        self.assertEqual(result, original)
        self.assertEqual(finalized["status"], "partial")
        first, second = finalized["items"]
        self.assertEqual(len(first["entry"]), 15)
        self.assertEqual(first["entry"]["verify"], 0)
        self.assertEqual(first["review"]["self_review_status"], "completed")
        self.assertEqual(first["review"]["pipeline_errors"], [])
        self.assertEqual(first["review"]["input_errors"], result["errors"])
        self.assertIsNone(second["entry"])
        self.assertEqual(second["review"]["self_review_status"], "failed")
        self.assertEqual(second["review"]["pipeline_errors"], result["entry_results"][1]["errors"])
        self.assertEqual(second["review"]["actions"][-1]["protocol_path"], "$[0].arguments.summary")
        self.assertEqual(second["review"]["input_errors"], [])
        self.assertEqual([item["review"]["model_calls"] for item in finalized["items"]], [8, 0])

    def test_writer_consumers_keep_child_diagnostics_and_shared_usage_once(self):
        job, result = serial_fixture()
        run, summary, entries, reviews, actions = self.save(job, result)
        self.assertEqual((summary["input_count"], summary["entry_count"], summary["draft_count"]), (1, 1, 1))
        self.assertEqual((summary["model_calls"], summary["tool_calls"]), (8, 5))
        self.assertEqual((summary["pipeline_error_count"], summary["model_error_count"], summary["tool_error_count"]), (2, 1, 1))
        self.assertEqual(summary["jobs_with_model_errors"], 1)
        self.assertEqual(actions[0]["scope"], "input")
        self.assertEqual(actions[-1]["entry_id"], reviews[1]["entry_id"])
        self.assertNotIn("RAW_SCOPE_PRIVATE", json.dumps((reviews, actions)))
        first = _process_record(reviews[0], reviews)
        second = _process_record(reviews[1], reviews)
        self.assertEqual(_entry_diagnostic(reviews[0], first)["category"], "complete")
        self.assertEqual(_entry_diagnostic(reviews[1], second)["category"], "draft_with_technical_anomaly")
        self.assertEqual(second["model_calls"], 8)
        for text in (render_packet(summary, entries, reviews), _assessment(summary, reviews)):
            self.assertIn("不倒推否定先前已完成候选", text)
            self.assertIn("selected_count", text)
            self.assertIn("不证明入口独立性", text)
            self.assertIn("protocol_reason | protocol_path", text)
        template = build_review_template(run, self.root / "form.json")
        self.assertEqual(len(json.loads(template.read_text(encoding="utf-8"))["entries"]), 2)

    def test_budget_deferred_candidate_cannot_export_full_unreviewed_fields(self):
        job, result = serial_fixture()
        result["entry_results"][1].update(self_review_status="not_requested", errors=["Candidate not reviewed: budget exhausted."])
        _, summary, entries, reviews, _ = self.save(job, result)
        self.assertEqual((len(entries), summary["draft_count"]), (1, 1))
        self.assertIn("self_review_required", [error["code"] for error in reviews[1]["errors"]])
        self.assertIn("未完成必需自查", render_packet(summary, entries, reviews))
        bad = deepcopy(reviews)
        bad[0]["self_review_status"] = "not_requested"
        with self.assertRaisesRegex(ExportError, "snapshot_self_review_required"):
            render_packet(summary, entries, bad)

    def test_single_feedback_persists_safe_bounded_revision_and_field_diagnostics(self):
        job, result = fixture()
        checked = finalize_result(job, result, StubRepoReader())
        feedback = revision_consistency(checked["review"])
        feedback.update(commit_reason="UNTRUSTED_PROSE", note="UNTRUSTED_PROSE", arbitrary_private="UNTRUSTED_PROSE")
        error = {"field": "trace", "code": "unexpected_properties", "path": "$[0].arguments.trace"}
        result["actions"] = [{"action": "draft_validation", "annotation_errors": [error],
                              "revision_consistency": feedback}]
        saved = finalize_result(job, result, StubRepoReader())["review"]["actions"][0]
        self.assertEqual(saved["annotation_errors"], [error])
        self.assertEqual(saved["revision_consistency"]["selected_commit"], COMMIT)
        self.assertEqual(saved["revision_consistency"]["location_references"][0]["receipt_commit"], COMMIT)
        self.assertTrue(saved["revision_consistency"]["prose_omitted"])
        self.assertNotIn("UNTRUSTED_PROSE", json.dumps(saved))
        self.assertLess(len(json.dumps(saved)), 16000)
        self.assertIn("UNTRUSTED_PROSE", json.dumps(result))

    def test_model_failure_drops_unsafe_codes_paths_and_extra_properties(self):
        job, result = fixture()
        result["actions"] = [{"action": "model_failure", "stage": "self_review", "code": "RAW_PRIVATE",
                              "protocol_reason": "RAW_PRIVATE", "protocol_path": "$.RAW_PRIVATE", "reason": "RAW_PRIVATE"}]
        saved = finalize_result(job, result, StubRepoReader())["review"]["actions"]
        self.assertEqual(saved, [{"action": "model_failure", "stage": "self_review", "code": "unrecorded_error"}])

    def test_snapshot_child_field_error_is_not_broadcast(self):
        job, result = serial_fixture()
        result["entry_results"][1].update(self_review_status="completed", errors=[], annotation_errors=[{
            "field": "trace", "code": "unexpected_properties", "path": "$[0].arguments.trace"}])
        _, summary, entries, reviews, _ = self.save(job, result)
        self.assertEqual((len(entries), summary["annotation_error_count"], summary["jobs_with_annotation_errors"]), (1, 1, 1))
        self.assertEqual(reviews[0]["annotation_errors"], [])
        render_packet(summary, entries, reviews)


if __name__ == "__main__":
    unittest.main()
