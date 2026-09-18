"""Cycle receipts remain independently readable without altering entries."""
import copy
import unittest

from tests.test_t2_v2_output import fixture, StubRepoReader
from vulngym_t2.output import finalize_result


class ReviewCycleReceiptTests(unittest.TestCase):
    def test_late_cycle_history_survives_general_action_preview_limit(self):
        job, result = fixture()
        original = finalize_result(job, result, StubRepoReader())
        result["actions"] = [{"action": "plan", "summary": "synthetic earlier plan"}] * 100
        history = [
            {"action": "review_cycle_policy", "summary": "review-gap-loop-v1", "requested_calls": 2},
            {"action": "review_cycle_gap", "slot": 1, "field": "commit",
             "reason": "Need the observed implementation at the selected revision.", "evidence_refs": ["E0003"]},
            {"action": "review_cycle_result", "slot": 1, "summary": "completed", "evidence_refs": ["E0003"]},
            {"action": "review_cycle_stopped", "slot": 2, "reason": "no_required_gaps"},
        ]
        result["actions"].extend(copy.deepcopy(history))
        finalized = finalize_result(job, result, StubRepoReader())
        self.assertEqual(finalized["review"]["review_cycle_history"], history)
        self.assertEqual(len(finalized["review"]["actions"]), 96)
        self.assertEqual(finalized["entry"], original["entry"])
        self.assertEqual(finalized["entry"]["verify"], 0)

    def test_default_results_do_not_gain_a_cycle_history(self):
        job, result = fixture()
        self.assertNotIn("review_cycle_history", finalize_result(job, result, StubRepoReader())["review"])

    def test_cycle_history_uses_existing_public_redaction_and_allowlist(self):
        job, result = fixture()
        result["actions"].append({"action": "review_cycle_policy", "summary": "review-gap-loop-v1"})
        result["actions"].append({"action": "review_cycle_gap", "field": "commit",
                                  "reason": job["repo_path"], "api_key": "synthetic-not-a-key"})
        history = finalize_result(job, result, StubRepoReader())["review"]["review_cycle_history"]
        self.assertEqual(history[-1]["reason"], "<local-repository>")
        self.assertNotIn("api_key", history[-1])


if __name__ == "__main__":
    unittest.main()
