"""Bounded failed-field reassessment uses fake responses and fixture reads."""
import json
import unittest

from tests import test_t2_v2_staged_pipeline as fixture
from tests.test_t2_v2_pipeline import job
from tests.test_t2_v2_staged_multi import full_for_scope, proposals
from tests.test_t2_v2_staged_pipeline import READ, FINISH, full_annotation
from vulngym_t2.output import finalize_job


def bad_operation(payload):
    tool, snapshot = full_annotation(payload)
    snapshot["critical_operation"]["value"]["file"] = "unverified-copy.py"
    return tool, snapshot


def bad_scoped_operation(payload):
    tool, snapshot = full_for_scope(payload)
    snapshot["critical_operation"]["value"]["file"] = "unverified-copy.py"
    return tool, snapshot


class TargetedRecoveryTests(unittest.TestCase):
    setUp = fixture.StagedPipelineTests.setUp
    run_script = fixture.StagedPipelineTests.run_script

    def test_last_field_error_can_be_reassessed_without_changing_healthy_siblings(self):
        def recovery(payload):
            packet = next(json.loads(row["content"])["targeted_field_review"]
                          for row in payload["messages"] if row["content"].startswith('{"targeted_field_review":'))
            self.assertEqual(packet["fields"], ["critical_operation"])
            self.assertEqual(packet["error_shapes"][-1]["known_extra_keys"], ["file"])
            self.assertNotIn("unverified-copy.py", json.dumps(packet))
            tool, snapshot = full_annotation(payload)
            # Valid wire changes outside the requested field must be ignored.
            snapshot["entry_point"]["status"] = "uncertain"
            snapshot["commit"]["value"] = "b" * 40
            return tool, snapshot

        result, finalized, client, _, _ = self.run_script(
            [READ, full_annotation, bad_operation, recovery], max_calls=4, max_tool_calls=1)
        self.assertIsNone(client.halted)
        self.assertEqual(result["model_calls"], 4)
        self.assertEqual(result["tool_calls"], 1)
        self.assertEqual(result["annotation_errors"], [])
        self.assertIsNotNone(finalized["entry"])
        self.assertEqual(result["field_reviews"]["entry_point"]["status"], "supported")
        self.assertNotEqual(finalized["entry"]["commit"], "b" * 40)
        actions = [row for row in finalized["review"]["actions"] if row["action"] == "annotation_field_recovery"]
        self.assertEqual(actions, [{"action": "annotation_field_recovery", "fields": ["critical_operation"], "summary": "recovered"}])
        self.assertEqual(client.summary()["automatic_retries"], 0)

    def test_unsuccessful_field_recovery_is_not_repeated_even_with_budget_left(self):
        result, finalized, client, _, _ = self.run_script(
            [READ, full_annotation, bad_operation, bad_operation], max_calls=5, max_tool_calls=1)
        self.assertIsNone(client.halted)
        self.assertEqual(result["model_calls"], 4)
        self.assertEqual(len(result["annotation_errors"]), 1)
        self.assertIsNone(finalized["entry"])
        self.assertEqual([row["summary"] for row in result["actions"]
                          if row["action"] == "annotation_field_recovery"], ["unresolved"])

    def test_no_remaining_budget_keeps_the_original_error_without_a_request(self):
        result, finalized, _, _, _ = self.run_script(
            [READ, full_annotation, bad_operation], max_calls=3, max_tool_calls=1)
        self.assertEqual(result["model_calls"], 3)
        self.assertEqual(len(result["annotation_errors"]), 1)
        self.assertFalse(any(row["action"] == "annotation_field_recovery" for row in result["actions"]))
        self.assertIsNone(finalized["entry"])

    def test_commit_error_is_not_repaired_without_cross_field_review(self):
        def bad_commit(payload):
            tool, snapshot = full_annotation(payload)
            snapshot["commit"]["extra"] = "unknown qualification"
            return tool, snapshot

        result, finalized, _, _, _ = self.run_script(
            [READ, full_annotation, bad_commit], max_calls=4, max_tool_calls=1)
        self.assertEqual(result["model_calls"], 3)
        self.assertEqual(result["annotation_errors"][0]["field"], "commit")
        self.assertFalse(any(row["action"] == "annotation_field_recovery" for row in result["actions"]))
        self.assertIsNone(finalized["entry"])

    def test_recovery_cannot_spend_later_candidates_reserved_draft_and_review_calls(self):
        # One read + one plan + three draft/review pairs leaves no recovery call.
        result, _, client, repo, payloads = self.run_script(
            [READ, lambda p: proposals(p, 3), full_for_scope, bad_scoped_operation,
             full_for_scope, full_for_scope, full_for_scope, full_for_scope],
            multi_entry=True, max_calls=8, max_tool_calls=1)
        self.assertIsNone(client.halted)
        self.assertEqual((result["model_calls"], len(payloads), result["tool_calls"], len(repo.calls)), (8, 8, 1, 1))
        entries = result["entry_results"]
        self.assertEqual([entry["slot"] for entry in entries], [1, 2, 3])
        self.assertEqual([len(entry["annotation_errors"]) for entry in entries], [1, 0, 0])
        for entry in entries:
            self.assertEqual(entry["initial_draft_status"], "accepted")
            self.assertEqual(entry["self_review_status"], "completed")
            self.assertEqual([a["stage"] for a in entry["actions"] if a["action"] == "model_call"],
                             ["draft", "self_review"])
            self.assertFalse(any(a["action"] == "annotation_field_recovery" for a in entry["actions"]))
        group = finalize_job(job(False), result, repo,
                             entry_ids={1: job(False)["entry_id"], 2: "entry-00002", 3: "entry-00003"})
        self.assertEqual(group["status"], "partial")
        self.assertEqual([item["review"]["status"] for item in group["items"]], ["draft", "complete", "complete"])
        self.assertEqual(client.summary()["run_request_limit"], 8)
        self.assertEqual(client.summary()["automatic_retries"], 0)

    def test_one_extra_call_recovers_first_candidate_without_displacing_later_reviews(self):
        # Exhaust the read allowance so the single surplus call can reassess the
        # rejected field instead of being consumed by an optional evidence read.
        result, _, client, repo, payloads = self.run_script(
            [READ, lambda p: proposals(p, 3), full_for_scope, bad_scoped_operation,
             full_for_scope, full_for_scope, full_for_scope, full_for_scope, full_for_scope],
            multi_entry=True, max_calls=9, max_tool_calls=1)
        self.assertIsNone(client.halted)
        self.assertEqual((result["model_calls"], len(payloads), result["tool_calls"], len(repo.calls)), (9, 9, 1, 1))
        entries = result["entry_results"]
        self.assertEqual([entry["slot"] for entry in entries], [1, 2, 3])
        self.assertEqual([[a["stage"] for a in entry["actions"] if a["action"] == "model_call"]
                          for entry in entries],
                         [["draft", "self_review", "field_recovery"],
                          ["draft", "self_review"], ["draft", "self_review"]])
        self.assertEqual([a["call"] for a in entries[2]["actions"] if a["action"] == "model_call"], [8, 9])
        self.assertEqual([a["summary"] for entry in entries for a in entry["actions"]
                          if a["action"] == "annotation_field_recovery"], ["recovered"])
        for entry in entries:
            self.assertEqual(entry["initial_draft_status"], "accepted")
            self.assertEqual(entry["self_review_status"], "completed")
            self.assertEqual(entry["annotation_errors"], [])
        # Each later candidate still has its own scope, not the recovered one.
        self.assertEqual([entry["fields"]["vuln_title"] for entry in entries],
                         [f"Independent synthetic scope {index}" for index in range(3)])
        group = finalize_job(job(False), result, repo,
                             entry_ids={1: job(False)["entry_id"], 2: "entry-00002", 3: "entry-00003"})
        self.assertEqual(group["status"], "complete")
        self.assertTrue(all(item["entry"]["verify"] == 0 for item in group["items"]))
        self.assertEqual(client.summary()["run_request_limit"], 9)
        self.assertEqual(client.summary()["automatic_retries"], 0)


if __name__ == "__main__":
    unittest.main()
