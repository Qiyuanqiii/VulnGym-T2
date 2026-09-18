"""Previously read adjacent source must remain usable for lexical navigation."""
import copy
import unittest
from unittest.mock import patch

from vulngym_t2.entry_navigation import entry_navigation_seed, public_navigation_report
from tests import test_t2_v2_staged_pipeline as fixture
from tests.test_t2_v2_entry_navigation import SOURCES, NavigationRepo, review_fixture, source_record
from tests.test_t2_v2_pipeline import FIXED, VULNERABLE, evidence_from


PADDED_HELPER = ["export function gate(ctx) {"] + ["  // fixture context"] * 20 + [
    "  return ctx.allowed;", "}"]


def fragmented_review():
    review = review_fixture()
    review["suggested_values"]["entry_point"].update(start_line=22, end_line=22)
    review["evidence"] = [source_record("E0001", "src/helper.ts", 20, 23),
                          source_record("E0002", "src/helper.ts", 1, 19)]
    return review


class PrefixJoinTests(unittest.TestCase):
    def setUp(self):
        self.patch = patch.dict(SOURCES, {"src/helper.ts": PADDED_HELPER})
        self.patch.start()
        self.addCleanup(self.patch.stop)

    def test_adjacent_receipt_supplies_the_actual_declaration_without_mutation(self):
        review = fragmented_review()
        original = copy.deepcopy(review)
        seed = entry_navigation_seed(review)
        self.assertEqual((seed["symbol"], seed["line"], seed["evidence_ref"]), ("gate", 1, "E0002"))
        self.assertEqual(seed["selected_evidence_ref"], "E0001")
        self.assertEqual(review, original)
        report = public_navigation_report({"version": "entry-navigation-v4", "seed": seed, "steps": []})
        self.assertEqual(report["seed"]["selected_evidence_ref"], "E0001")
        self.assertFalse(report["semantic_approval"])

    def test_gap_other_revision_failure_or_conflicting_overlap_cannot_bridge(self):
        def overlap(review):
            row = source_record("E0003", "src/helper.ts", 19, 22)
            row["result"]["lines"][1]["code"] = "  different_byte;"
            row["result"]["text"] = "\n".join(item["code"] for item in row["result"]["lines"])
            review["evidence"].append(row)

        for change in (
            lambda row: row["evidence"].__setitem__(1, source_record("E0002", "src/helper.ts", 1, 18)),
            lambda row: row["evidence"][1]["result"].update(commit=FIXED),
            lambda row: row["evidence"][1].update(success=False),
            overlap,
        ):
            review = fragmented_review()
            change(review)
            with self.subTest(change=change):
                self.assertIsNone(entry_navigation_seed(review))

    def test_unseen_selected_line_and_closed_declaration_are_not_inferred(self):
        review = fragmented_review()
        review["suggested_values"]["entry_point"].update(start_line=24, end_line=24)
        self.assertIsNone(entry_navigation_seed(review))
        with patch.dict(SOURCES, {"src/helper.ts": ["export function gate(ctx) {}"] + ["// closed"] * 20 + ["  other();"]}):
            review = fragmented_review()
            # Put an explicit closing boundary into the continuous preceding view.
            review["evidence"][1]["result"]["lines"][1]["code"] = "}"
            review["evidence"][1]["result"]["text"] = "\n".join(
                row["code"] for row in review["evidence"][1]["result"]["lines"])
            self.assertIsNone(entry_navigation_seed(review))


class PrefixJoinIntegrationTests(unittest.TestCase):
    setUp = fixture.StagedPipelineTests.setUp
    run_script = fixture.StagedPipelineTests.run_script

    @staticmethod
    def unresolved(payload):
        tool, snapshot = fixture.full_annotation(payload)
        for name in ("entry_point", "critical_operation"):
            snapshot[name]["value"].update(start_line=22, end_line=22)
        snapshot["entry_point"].update(status="uncertain", reason="The helper's external caller is not established.")
        return tool, snapshot

    def test_prefix_read_reaches_caller_navigation_in_same_session_budget(self):
        def review(payload):
            reads = [row for row in evidence_from(payload["messages"]) if row.get("tool") == "read_file"]
            self.assertTrue(any(row["result"]["path"] == "src/provider.ts" for row in reads))
            return self.unresolved(payload)

        read = ("read_file", {"commit": VULNERABLE, "path": "src/helper.ts", "start_line": 20, "end_line": 23})
        with patch.dict(SOURCES, {"src/helper.ts": PADDED_HELPER}), patch.object(fixture, "MemoryRepo", NavigationRepo):
            result, final, client, repo, _ = self.run_script(
                [read, fixture.FINISH, self.unresolved, fixture.FINISH, review])
        self.assertIsNone(client.halted)
        self.assertEqual(result["model_calls"], 5)
        self.assertEqual(result["tool_calls"], len(repo.calls))
        self.assertIsNone(final["entry"])
        self.assertTrue(any(row["action"] == "entry_context_read" for row in result["actions"]))
        self.assertTrue(any(row["action"] == "entry_navigation" for row in result["actions"]))
        self.assertEqual(final["review"]["field_reviews"]["entry_point"]["status"], "uncertain")

    def test_rejected_entry_is_recovered_before_navigation_with_one_total_recovery(self):
        def rejected(payload):
            tool, snapshot = self.unresolved(payload)
            snapshot["entry_point"]["value"]["unexpected_property"] = "not retained"
            return tool, snapshot

        def review(payload):
            reads = evidence_from(payload["messages"])
            self.assertTrue(any(row.get("tool") == "read_file" and row["result"]["path"] == "src/provider.ts" for row in reads))
            return rejected(payload)  # No second recovery after final review.

        read = ("read_file", {"commit": VULNERABLE, "path": "src/helper.ts", "start_line": 20, "end_line": 23})
        with patch.dict(SOURCES, {"src/helper.ts": PADDED_HELPER}), patch.object(fixture, "MemoryRepo", NavigationRepo):
            result, final, client, _, _ = self.run_script(
                [read, fixture.FINISH, rejected, self.unresolved, fixture.FINISH, review], max_calls=8)
        actions = [row["action"] for row in result["actions"]]
        self.assertEqual(actions.count("annotation_field_recovery"), 1)
        self.assertLess(actions.index("annotation_field_recovery"), actions.index("entry_navigation"))
        self.assertEqual(result["model_calls"], 6)
        self.assertEqual(result["self_review_status"], "completed")
        self.assertIsNone(client.halted)
        self.assertIsNone(final["entry"])
        self.assertTrue(any(row["field"] == "entry_point" for row in result["annotation_errors"]))


if __name__ == "__main__":
    unittest.main()
