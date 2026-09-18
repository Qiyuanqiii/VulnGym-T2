"""A model, not the controller, may correct a rejected source reference once."""
import copy
import json
import unittest
from unittest.mock import patch

from tests import test_t2_v2_staged_pipeline as fixture
from tests.test_t2_v2_pipeline import evidence_from


class WindowedRepo(fixture.MemoryRepo):
    def call(self, tool, arguments):
        result = super().call(tool, arguments)
        if tool == "read_file":
            first, last = arguments["start_line"], arguments["end_line"]
            rows = [row for row in result["lines"] if first <= row["line"] <= last]
            result.update(lines=rows, start_line=rows[0]["line"], end_line=rows[-1]["line"],
                          text="\n".join(row["code"] for row in rows))
        return result


class ReferenceRecoveryTests(unittest.TestCase):
    setUp = fixture.StagedPipelineTests.setUp
    run_script = fixture.StagedPipelineTests.run_script

    def complete_annotation(self, payload):
        # The generic fixture assumes its first read includes both source lines.
        # Select the actual full receipt for the synthetic response, without
        # changing the production request, saved evidence or its identifiers.
        records = evidence_from(payload["messages"])
        records.sort(key=lambda row: row.get("tool") == "read_file" and row["result"]["end_line"] < 2)
        return fixture.full_annotation({"messages": [{"role": "user", "content": json.dumps({"evidence": records})}]})

    def run_case(self, recovery=None):
        first = copy.deepcopy(fixture.READ)
        first[1]["end_line"] = 1
        def rejected(payload):
            tool, snapshot = self.complete_annotation(payload)
            reads = [row for row in evidence_from(payload["messages"]) if row.get("tool") == "read_file"]
            snapshot["critical_operation"]["value"]["evidence_ref"] = reads[0]["id"]
            snapshot["critical_operation"]["evidence_refs"] = [reads[0]["id"]]
            return tool, snapshot
        script = [[first, fixture.READ], rejected, rejected]
        if recovery:
            script.append(recovery)
        with patch.object(fixture, "MemoryRepo", WindowedRepo):
            return self.run_script(script, max_calls=len(script), max_tool_calls=2)

    def recover(self, payload, uncertain=False):
        packet = next(json.loads(row["content"])["targeted_field_review"] for row in payload["messages"]
                      if row["content"].startswith('{"targeted_field_review":'))
        self.assertEqual(packet["fields"], ["critical_operation"])
        packets = [json.loads(row["content"]) for row in payload["messages"]
                   if row["content"].startswith("{")]
        feedback = next(row["visible_source_locations"] for row in reversed(packets)
                        if "visible_source_locations" in row)
        self.assertNotIn("source_reference_feedback", packet)  # one fresh directory, not a duplicate
        reference = next(row for row in feedback["references"]
                         if row["field"] == "critical_operation")
        self.assertEqual(reference["coverage_error"], "source_ref_out_of_bounds")
        self.assertTrue(reference["available_receipts"])
        reads = [row for row in evidence_from(payload["messages"]) if row.get("tool") == "read_file"]
        tool, snapshot = self.complete_annotation(payload)
        snapshot["critical_operation"]["value"]["evidence_ref"] = reads[1]["id"]
        snapshot["critical_operation"]["evidence_refs"] = [reads[1]["id"]]
        if uncertain:
            snapshot["critical_operation"].update(status="uncertain", reason="Corrected range, but a necessary semantic premise remains unknown.")
        snapshot["entry_point"]["status"] = "uncertain"  # healthy sibling must stay unchanged
        return tool, snapshot

    def test_bad_receipt_id_is_reassessed_against_actual_alternative_not_automatically_switched(self):
        result, final, client, repo, _ = self.run_case(self.recover)
        self.assertIsNone(client.halted)
        self.assertEqual(result["model_calls"], 4)
        self.assertEqual(result["tool_calls"], 2)
        self.assertEqual(len(repo.calls), 2)
        self.assertEqual(result["self_review_status"], "completed")
        self.assertEqual(result["field_reviews"]["entry_point"]["status"], "supported")
        self.assertEqual(result["field_reviews"]["critical_operation"]["status"], "supported")
        self.assertIsNotNone(final["entry"])

    def test_valid_reference_does_not_force_semantic_support(self):
        result, final, _, _, _ = self.run_case(lambda payload: self.recover(payload, uncertain=True))
        self.assertEqual(result["field_reviews"]["critical_operation"]["status"], "uncertain")
        self.assertIsNone(final["entry"])
        self.assertEqual(final["review"]["suggested_values"]["critical_operation"]["line"], 2)

    def test_no_spare_call_preserves_original_reference_failure_and_draft(self):
        result, final, _, _, _ = self.run_case()
        self.assertEqual(result["model_calls"], 3)
        self.assertIsNone(final["entry"])
        self.assertIn("source_ref_out_of_bounds", result["field_reviews"]["critical_operation"]["reason"])
        self.assertFalse(any(row["action"] == "annotation_field_recovery" for row in result["actions"]))


if __name__ == "__main__":
    unittest.main()
