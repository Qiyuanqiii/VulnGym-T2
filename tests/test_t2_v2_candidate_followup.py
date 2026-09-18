"""Use saved synthetic reads and the same bounded serial-candidate budget."""
import json
import unittest

from tests import test_t2_v2_staged_pipeline as fixture
from tests.test_t2_v2_staged_pipeline import READ, FINISH, CALLER
from tests.test_t2_v2_staged_multi import proposals, full_for_scope
from tests.test_t2_v2_staged_pipeline import full_annotation


def feedback_packets(payload):
    packets = []
    for row in payload["messages"]:
        if not row["content"].startswith("{"):
            continue
        value = json.loads(row["content"])
        if "visible_source_locations" in value:
            packets.append(value)
    return packets


class CandidateFollowupTests(unittest.TestCase):
    setUp = fixture.StagedPipelineTests.setUp
    run_script = fixture.StagedPipelineTests.run_script

    def test_each_candidate_can_follow_up_without_reusing_previous_candidate_state(self):
        result, _, client, _, payloads = self.run_script(
            [READ, FINISH, proposals, full_for_scope, CALLER, full_for_scope,
             full_for_scope, FINISH, full_for_scope], multi_entry=True, max_calls=9)
        self.assertIsNone(client.halted)
        self.assertEqual(result["model_calls"], 9)
        self.assertEqual(result["tool_calls"], 2)
        for entry in result["entry_results"]:
            self.assertEqual(entry["evidence_followup_status"], "completed")
            self.assertEqual(entry["self_review_status"], "completed")
            self.assertEqual(sum(row["action"] == "evidence_followup" for row in entry["actions"]), 1)
        followup_payloads = [payload for payload in payloads
                             if {item["function"]["name"] for item in payload["tools"]} ==
                             {"read_file", "search_code", "inspect_commit", "search_history", "read_diff", "finish_reading"}]
        self.assertEqual(len(followup_payloads), 2)
        scope = next(json.loads(row["content"])["candidate_scope"] for row in payloads[-1]["messages"]
                     if row["content"].startswith("{") and "candidate_scope" in json.loads(row["content"]))
        self.assertEqual(scope["scope"], "Independent synthetic scope 1")
        self.assertEqual(scope["previous_candidates_context"]["candidates"][0]["proposed_scope"],
                         "Independent synthetic scope 0")

    def test_optional_followup_never_steals_later_candidate_review(self):
        result, _, client, _, _ = self.run_script(
            [READ, FINISH, proposals, full_for_scope, CALLER, full_for_scope,
             full_for_scope, full_for_scope], multi_entry=True, max_calls=8)
        self.assertIsNone(client.halted)
        self.assertEqual(result["model_calls"], 8)
        self.assertEqual([entry["evidence_followup_status"] for entry in result["entry_results"]],
                         ["completed", "not_requested"])
        self.assertEqual([entry["self_review_status"] for entry in result["entry_results"]],
                         ["completed", "completed"])

    def test_catalog_is_present_for_initial_draft_and_review_but_not_accumulated(self):
        result, _, client, _, payloads = self.run_script(
            [READ, FINISH, proposals, full_for_scope, full_for_scope,
             full_for_scope, full_for_scope], multi_entry=True, max_calls=7)
        self.assertIsNone(client.halted)
        for payload in payloads[3:]:
            catalogs = [row["visible_source_locations"] for row in feedback_packets(payload)]
            self.assertEqual(len(catalogs), 1)
            self.assertTrue(catalogs[0]["ranges"])
            self.assertNotIn('"code":', json.dumps(catalogs[0]))
        for entry in result["entry_results"]:
            actions = [row for row in entry["actions"] if row["action"] == "source_location_feedback"]
            self.assertEqual([row["stage"] for row in actions], ["draft", "self_review"])
            self.assertTrue(all(row["summary"] == "attached" for row in actions))

    def test_unresolved_reference_reaches_existing_review_as_exact_range_feedback(self):
        def out_of_bounds(payload):
            tool, snapshot = full_annotation(payload)
            snapshot["entry_point"]["value"].update(start_line=2, end_line=3)
            return tool, snapshot

        def correct_from_saved_evidence(payload):
            packet = feedback_packets(payload)[0]["visible_source_locations"]
            rejected = next(row for row in packet["references"] if row["field"] == "entry_point")
            self.assertEqual((rejected["start_line"], rejected["end_line"]), (2, 3))
            self.assertEqual((rejected["visible_start_line"], rejected["visible_end_line"]), (1, 2))
            self.assertEqual(rejected["coverage_error"], "source_ref_out_of_bounds")
            self.assertEqual(rejected["available_receipts"], [])
            return full_annotation(payload)  # Explicit model correction, never automatic clamping.

        result, finalized, client, _, _ = self.run_script(
            [READ, FINISH, out_of_bounds, correct_from_saved_evidence], max_calls=4)
        self.assertIsNone(client.halted)
        self.assertEqual(result["model_calls"], 4)
        self.assertEqual(result["tool_calls"], 1)
        self.assertIsNotNone(finalized["entry"])

    def test_lossless_normalization_remains_auditable_after_pipeline_and_export(self):
        def redundant(payload):
            tool, snapshot = full_annotation(payload)
            snapshot["entry_point"]["value"]["reason"] = snapshot["entry_point"]["reason"]
            return tool, snapshot

        result, finalized, client, _, _ = self.run_script(
            [READ, FINISH, redundant, full_annotation], max_calls=4)
        self.assertIsNone(client.halted)
        self.assertEqual(result["annotation_errors"], [])
        self.assertIsNotNone(finalized["entry"])
        audits = [row for row in finalized["review"]["actions"]
                  if row["action"] == "annotation_properties_normalized"]
        self.assertEqual(len(audits), 1)
        self.assertEqual(audits[0]["normalizations"][0]["removed_keys"], ["reason"])
        self.assertEqual(audits[0]["normalizations"][0]["path"], "$[0].arguments.entry_point.value")
        self.assertTrue(any(event.get("diagnostics", {}).get("annotation_normalizations")
                            for event in client.events))

    def test_unknown_extra_has_exact_allowed_shape_in_existing_review(self):
        def malformed(payload):
            tool, snapshot = full_annotation(payload)
            snapshot["critical_operation"]["value"]["unknown_qualification"] = "must not be discarded"
            return tool, snapshot

        def explicit_review(payload):
            feedback = feedback_packets(payload)[0]["annotation_shape_feedback"]
            self.assertEqual(len(feedback), 1)
            self.assertEqual(feedback[0]["field"], "critical_operation")
            self.assertEqual(set(feedback[0]["allowed_keys"]),
                             {"evidence_ref", "start_line", "end_line", "desc"})
            self.assertNotIn("unknown_qualification", json.dumps(feedback))
            return full_annotation(payload)

        result, finalized, client, _, _ = self.run_script(
            [READ, FINISH, malformed, explicit_review], max_calls=4)
        self.assertIsNone(client.halted)
        self.assertEqual(result["annotation_errors"], [])
        self.assertIsNotNone(finalized["entry"])
        self.assertEqual([row["action"] for row in result["actions"]
                          if row["action"].startswith("annotation_field_")],
                         ["annotation_field_rejected", "annotation_field_recovered"])


if __name__ == "__main__":
    unittest.main()
