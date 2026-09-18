"""Complete snapshots preserve sibling fields; no legacy no-update wire."""
import copy
import json
import unittest

from vulngym_t2 import staged_protocol
from tests import test_t2_v2_staged_pipeline as fixture
from tests.test_t2_v2_staged_pipeline import READ, FINISH, annotation, full_annotation


def bad_operation(payload):
    name, args = full_annotation(payload)
    args["critical_operation"]["unexpected"] = "discard-this-invalid-value"
    return name, args


class AnnotationRecoveryTests(unittest.TestCase):
    setUp = fixture.StagedPipelineTests.setUp
    run_script = fixture.StagedPipelineTests.run_script

    def test_bad_field_keeps_siblings_and_recovers_in_original_review(self):
        def review(payload):
            feedback = next(json.loads(row["content"])["draft_validation"] for row in payload["messages"]
                            if row["content"].startswith('{"draft_validation":'))
            self.assertEqual(feedback["annotation_errors"][0]["field"], "critical_operation")
            self.assertLessEqual(len(json.dumps(feedback["revision_consistency"])), 4_000)
            snapshots = [json.loads(row["content"])["prior_draft_to_check"] for row in payload["messages"]
                         if row["role"] == "user" and row["content"].startswith("{")
                         and "prior_draft_to_check" in json.loads(row["content"])]
            self.assertEqual(set(snapshots[-1]), set(staged_protocol.ANNOTATION_FIELDS))
            self.assertEqual(snapshots[-1]["entry_point"]["status"], "supported")
            self.assertNotEqual(snapshots[-1]["critical_operation"]["status"], "supported")
            return full_annotation(payload)
        result, final, client, _, _ = self.run_script([READ, FINISH, bad_operation, FINISH, review])
        self.assertIsNone(client.halted)
        self.assertEqual(result["model_calls"], 5)
        self.assertEqual(result["initial_draft_status"], "partial")
        self.assertEqual(result["annotation_errors"], [])
        self.assertEqual(final["review"]["status"], "complete")
        self.assertEqual(final["entry"]["verify"], 0)
        self.assertNotIn("discard-this-invalid-value", json.dumps(result))
        actions = [item["action"] for item in result["actions"]]
        self.assertIn("annotation_field_rejected", actions)
        self.assertIn("annotation_field_recovered", actions)

    def test_old_empty_update_array_cannot_clear_a_rejected_field(self):
        def legacy_review(payload):
            tool, snapshot = full_annotation(payload)
            snapshot["critical_operation"] = []
            return tool, snapshot
        result, final, client, _, _ = self.run_script(
            [READ, FINISH, bad_operation, FINISH, legacy_review])
        self.assertIsNone(client.halted)
        self.assertIsNone(final["entry"])
        self.assertEqual(result["field_reviews"]["entry_point"]["status"], "supported")
        self.assertEqual(result["annotation_errors"][0]["code"], "expected_object")

    def test_bad_review_revokes_old_supported_field_not_its_siblings(self):
        result, final, _, _, _ = self.run_script([READ, FINISH, full_annotation, FINISH, bad_operation])
        self.assertEqual(result["initial_draft_status"], "accepted")
        self.assertIsNone(final["entry"])
        self.assertEqual(result["field_reviews"]["critical_operation"]["status"], "uncertain")
        self.assertIn("suggested_value", result["field_reviews"]["critical_operation"])
        self.assertEqual(result["field_reviews"]["entry_point"]["status"], "supported")

    def test_all_bad_fields_skip_followup_but_allow_the_original_review(self):
        bad = ("submit_annotation", {name: None for name in staged_protocol.ANNOTATION_FIELDS})
        result, final, client, _, _ = self.run_script([READ, FINISH, bad, full_annotation])
        self.assertIsNone(client.halted)
        self.assertEqual(result["initial_draft_status"], "no_valid_updates")
        self.assertEqual(result["evidence_followup_status"], "not_requested")
        self.assertEqual(result["model_calls"], 4)
        self.assertEqual(result["annotation_errors"], [])
        self.assertEqual(final["review"]["status"], "complete")

    def test_unknown_complete_snapshot_clears_format_error_not_uncertainty(self):
        def uncertain(payload):
            tool, snapshot = full_annotation(payload)
            snapshot["critical_operation"] = copy.deepcopy(annotation()[1]["critical_operation"])
            return tool, snapshot
        result, final, _, _, _ = self.run_script([READ, FINISH, bad_operation, FINISH, uncertain])
        self.assertEqual(result["annotation_errors"], [])
        self.assertIsNone(final["entry"])
        self.assertNotEqual(result["field_reviews"]["critical_operation"]["status"], "supported")

    def test_small_budget_reserves_review_instead_of_spending_all_on_reads(self):
        result, final, _, _, _ = self.run_script([READ, full_annotation, full_annotation], max_calls=3)
        self.assertEqual(result["self_review_status"], "completed")
        self.assertEqual(result["model_calls"], 3)
        self.assertEqual(final["review"]["status"], "complete")

    def test_missing_each_field_recovers_in_original_review_without_retry(self):
        # Synthetic equivalents of run-25's missing EP and run-26's missing
        # title, extended across the same eight-field contract. Not raw replay.
        for field in staged_protocol.ANNOTATION_FIELDS:
            with self.subTest(field=field):
                def incomplete(payload):
                    tool, snapshot = full_annotation(payload)
                    snapshot.pop(field)
                    return tool, snapshot
                result, final, client, _, _ = self.run_script(
                    [READ, FINISH, incomplete, FINISH, full_annotation])
                self.assertIsNone(client.halted)
                self.assertEqual(result["initial_draft_status"], "partial")
                self.assertEqual(result["annotation_errors"], [])
                self.assertEqual(result["model_calls"], 5)
                self.assertEqual(final["review"]["status"], "complete")
                self.assertEqual(final["entry"]["verify"], 0)
                rejected = [item for item in result["actions"]
                            if item["action"] == "annotation_field_rejected"]
                self.assertEqual([(row["field"], row["code"]) for row in rejected],
                                 [(field, "missing_property")])

    def test_missing_review_field_never_inherits_old_approval(self):
        for field in staged_protocol.ANNOTATION_FIELDS:
            with self.subTest(field=field):
                def incomplete(payload):
                    tool, snapshot = full_annotation(payload)
                    snapshot.pop(field)
                    return tool, snapshot
                result, final, client, _, _ = self.run_script(
                    [READ, FINISH, full_annotation, FINISH, incomplete])
                self.assertIsNone(client.halted)
                self.assertEqual(result["self_review_status"], "completed")
                self.assertEqual(result["annotation_errors"][0]["field"], field)
                self.assertEqual(result["field_reviews"][field]["status"], "uncertain")
                self.assertNotIn(field, result["fields"])
                self.assertIsNone(final["entry"])
                self.assertEqual(result["fields"]["verify"], 0)
                self.assertTrue(result["fields"]["entry_id"])

    def test_empty_snapshots_keep_evidence_and_errors_without_false_success(self):
        empty = ("submit_annotation", {})
        # Empty decisions skip follow-up, leaving one original-budget call for
        # targeted reassessment. A further empty response still proves nothing.
        result, final, client, _, _ = self.run_script([READ, FINISH, empty, empty, empty])
        self.assertIsNone(client.halted)
        self.assertEqual(result["model_calls"], 5)
        self.assertEqual([action["summary"] for action in result["actions"]
                          if action["action"] == "annotation_field_recovery"], ["unresolved"])
        self.assertEqual(result["initial_draft_status"], "no_valid_updates")
        self.assertEqual(result["evidence_followup_status"], "not_requested")
        self.assertEqual(result["self_review_status"], "completed")
        self.assertEqual(len(result["annotation_errors"]), 8)
        self.assertIsNone(final["entry"])
        self.assertTrue(any(item.get("tool") == "read_file" for item in result["evidence"]))

    def test_long_allowed_explanation_preserves_late_caveat(self):
        reason = "Observed source. " * 60 + "Caveat: this is not independently verified."
        self.assertGreater(len(reason), 600)
        self.assertLess(len(reason), 2000)
        def with_caveat(payload):
            tool, snapshot = full_annotation(payload)
            snapshot["commit"]["reason"] = reason
            return tool, snapshot
        result, final, _, _, _ = self.run_script([READ, FINISH, with_caveat, FINISH, with_caveat])
        self.assertEqual(result["field_reviews"]["commit"]["reason"], reason)
        self.assertEqual(final["review"]["field_reviews"]["commit"]["reason"], reason)
        self.assertNotIn("reason_truncated", result["field_reviews"]["commit"])


if __name__ == "__main__":
    unittest.main()
