"""Candidate scope provenance uses synthetic receipts and no external calls."""
import copy
import json
import unittest

from tests import test_t2_v2_staged_pipeline as fixture
from tests.test_t2_v2_pipeline import evidence_from, job
from tests.test_t2_v2_staged_multi import proposals, full_for_scope, bad_container
from tests.test_t2_v2_staged_pipeline import READ, FINISH, CALLER
from vulngym_t2.output import finalize_job


def candidate_context(payload):
    return next(json.loads(row["content"])["candidate_scope"] for row in payload["messages"]
                if row["content"].startswith("{") and "candidate_scope" in json.loads(row["content"]))


class CandidateProvenanceTests(unittest.TestCase):
    setUp = fixture.StagedPipelineTests.setUp
    run_script = fixture.StagedPipelineTests.run_script

    def finalize(self, result, repo):
        return finalize_job(job(False), result, repo,
                            entry_ids={1: job(False)["entry_id"], 2: "entry-00002", 3: "entry-00003", 4: "entry-00004"})

    def test_original_proposal_and_shared_locations_do_not_merge_candidates(self):
        result, _, client, repo, payloads = self.run_script(
            [READ, FINISH, proposals, full_for_scope, full_for_scope, full_for_scope, full_for_scope],
            multi_entry=True, max_calls=7)
        self.assertIsNone(client.halted)
        group = self.finalize(result, repo)
        self.assertEqual(len(group["items"]), 2)
        for index, item in enumerate(group["items"]):
            original = item["review"]["candidate_provenance"]["original_proposal"]
            self.assertEqual(original, {"scope": f"Independent synthetic scope {index}", "evidence_refs": ["E0004"]})
            self.assertEqual(item["entry"]["verify"], 0)
            self.assertEqual(len(item["entry"]), 15)
        prior = candidate_context(payloads[-1])["previous_candidates_context"]["candidates"]
        self.assertEqual(len(prior), 1)
        self.assertEqual(prior[0]["proposed_scope"], "Independent synthetic scope 0")
        self.assertEqual({row["field"] for row in prior[0]["locations"]}, {"entry_point", "critical_operation"})
        self.assertTrue(all(row["evidence_ref"] == "E0004" for row in prior[0]["locations"]))
        self.assertEqual((result["model_calls"], result["tool_calls"]), (7, 1))

    def test_each_call_cutoff_precedes_its_reads_and_later_sibling_reads_stay_distinct(self):
        result, _, _, repo, _ = self.run_script(
            [READ, FINISH, proposals, full_for_scope, FINISH, full_for_scope,
             full_for_scope, CALLER, full_for_scope], multi_entry=True, max_calls=9)
        items = self.finalize(result, repo)["items"]
        first, second = [item["review"]["candidate_provenance"] for item in items]
        initial = [f"E{number:04d}" for number in range(1, 5)]
        self.assertEqual(first["slot_end"]["evidence_refs"], initial)
        self.assertEqual(first["later_shared_evidence_refs"], ["E0005"])
        self.assertEqual(second["later_shared_evidence_refs"], [])
        self.assertEqual([row["call"] for row in first["model_call_evidence"]], [4, 5, 6])
        self.assertEqual([row["evidence_refs"] for row in first["model_call_evidence"]], [initial] * 3)
        calls = second["model_call_evidence"]
        self.assertEqual([row["stage"] for row in calls], ["draft", "evidence_followup", "self_review"])
        self.assertEqual([row["evidence_count"] for row in calls], [4, 4, 5])
        self.assertEqual(calls[-1]["evidence_refs"], initial + ["E0005"])
        # Retained shared receipts are not retroactively described as available.
        self.assertIn("E0005", [row["id"] for row in items[0]["review"]["evidence"]])

    def test_earlier_followup_receipt_is_available_at_later_slot_start(self):
        result, _, _, _, payloads = self.run_script(
            [READ, FINISH, proposals, full_for_scope, CALLER, full_for_scope,
             full_for_scope, full_for_scope], multi_entry=True, max_calls=8)
        first, second = [row["candidate_provenance"] for row in result["entry_results"]]
        self.assertEqual(first["model_call_evidence"][-1]["evidence_count"], 5)
        self.assertEqual(second["slot_start"]["evidence_count"], 5)
        self.assertEqual(second["model_call_evidence"][0]["evidence_count"], 5)
        self.assertIn("E0005", [row["id"] for row in evidence_from(payloads[-1]["messages"])])

    def test_context_is_bounded_and_does_not_copy_generated_titles(self):
        def long_proposals(payload):
            tool, arguments = proposals(payload, 3)
            for index, candidate in enumerate(arguments["candidates"]):
                candidate["scope"] = f"Branch {index}: " + "proposed premise " * 70
            return tool, arguments

        def generated_title(payload):
            tool, snapshot = fixture.full_annotation(payload)
            snapshot["vuln_title"]["value"] = "Generated title not proposal"
            return tool, snapshot

        result, _, _, _, payloads = self.run_script(
            [READ, FINISH, long_proposals] + [generated_title] * 6, multi_entry=True, max_calls=9)
        second_initial = payloads[5]
        context = candidate_context(second_initial)
        self.assertNotIn("Generated title not proposal", json.dumps(context))
        self.assertTrue(context["previous_candidates_context"]["candidates"][0]["scope_truncated"])
        for payload in payloads[3:]:
            self.assertLessEqual(len(json.dumps(candidate_context(payload)["previous_candidates_context"], ensure_ascii=False)), 6000)
        self.assertIn("retain that uncertainty", context["scope_guidance"])
        self.assertIn("Shared source ranges or a shared sink", context["scope_guidance"])
        self.assertGreater(len(result["entry_results"][0]["candidate_provenance"]["original_proposal"]["scope"]), 600)

    def test_invalid_prior_coordinates_are_not_promoted_to_actual_locations(self):
        def invalid_location(payload):
            tool, snapshot = full_for_scope(payload)
            for field in ("entry_point", "critical_operation"):
                snapshot[field]["value"].update(start_line=40, end_line=41)
                snapshot[field].update(status="uncertain", reason="Requested source coordinates are not established.")
            return tool, snapshot

        result, _, _, _, payloads = self.run_script(
            [READ, FINISH, proposals, invalid_location, invalid_location, full_for_scope, full_for_scope],
            multi_entry=True, max_calls=7)
        prior = candidate_context(payloads[5])["previous_candidates_context"]["candidates"][0]
        self.assertEqual(prior["locations"], [])
        self.assertTrue(result["entry_results"][0]["candidate_provenance"]["original_proposal"]["scope"])

    def test_skipped_slot_records_no_model_assessment(self):
        result, _, _, repo, _ = self.run_script(
            [READ, FINISH, proposals, full_for_scope, bad_container], multi_entry=True, max_calls=7)
        second = self.finalize(result, repo)["items"][1]["review"]
        metadata = second["candidate_provenance"]
        self.assertEqual(metadata["model_call_evidence"], [])
        self.assertEqual(metadata["slot_start"], metadata["slot_end"])
        self.assertEqual(second["initial_draft_status"], "not_received")
        self.assertEqual(second["self_review_status"], "not_requested")

    def test_public_proposal_is_redacted_and_unknown_boundary_is_not_invented(self):
        result, _, _, repo, _ = self.run_script(
            [READ, FINISH, proposals, full_for_scope, full_for_scope, full_for_scope, full_for_scope],
            multi_entry=True, max_calls=7)
        damaged = copy.deepcopy(result)
        metadata = damaged["entry_results"][0]["candidate_provenance"]
        metadata["original_proposal"]["scope"] = "D:\\private\\scope.txt sk-secretfixture123456"
        metadata["slot_end"]["evidence_count"] = True
        public = self.finalize(damaged, repo)["items"][0]["review"]["candidate_provenance"]
        self.assertNotIn("private", public["original_proposal"]["scope"])
        self.assertNotIn("sk-secret", public["original_proposal"]["scope"])
        self.assertIsNone(public["later_shared_evidence_refs"])
        self.assertEqual(public["later_shared_evidence_status"], "unknown_boundary")
        legacy = copy.deepcopy(result)
        for row in legacy["entry_results"]:
            row.pop("candidate_provenance")
        self.assertTrue(all("candidate_provenance" not in row["review"] for row in self.finalize(legacy, repo)["items"]))


if __name__ == "__main__":
    unittest.main()
