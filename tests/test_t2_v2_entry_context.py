"""In-memory adjacent-entry-context navigation, never a source inspection."""
from copy import deepcopy
import unittest

from vulngym_t2.source_refs import entry_context_request
from tests.test_t2_v2_visible_location_feedback import PATH, SHA, OTHER_SHA, receipt


def fixture():
    return {"draft_fields": {"commit": SHA}, "suggested_values": {
                "entry_point": {"evidence_ref": "E0008", "start_line": 535, "end_line": 539,
                                "desc": "Candidate fragment; external declaration not established."}},
            "field_reviews": {"entry_point": {"status": "uncertain", "evidence_refs": ["E0008"],
                                              "reason": "Still needs evidence."}},
            "evidence": [receipt("E0008", 520, 642)]}


class EntryContextRequestTests(unittest.TestCase):
    def test_returns_only_explicit_same_revision_adjacent_read_arguments_without_mutation(self):
        review = fixture()
        original = deepcopy(review)
        self.assertEqual(entry_context_request(review), {
            "commit": SHA, "path": PATH, "start_line": 400, "end_line": 519})
        self.assertEqual(review, original)

    def test_navigation_is_not_affected_revision_selection_or_a_reason_keyword_rule(self):
        review = fixture()
        review["draft_fields"]["commit"] = None
        review["suggested_values"]["commit"] = SHA
        review["field_reviews"]["entry_point"]["reason"] = "No keyword that identifies a declaration."
        self.assertEqual(entry_context_request(review)["commit"], SHA)
        del review["suggested_values"]["commit"]
        self.assertEqual(entry_context_request(review)["commit"], SHA)
        self.assertIsNone(review["draft_fields"]["commit"])

    def test_only_unresolved_ep_or_explicit_entry_support_conflict_requests_context(self):
        for status in ("uncertain", "missing", "conflicting"):
            review = fixture()
            review["field_reviews"]["entry_point"]["status"] = status
            with self.subTest(status=status):
                self.assertIsNotNone(entry_context_request(review))
        review = fixture()
        assessment = review["field_reviews"]["entry_point"]
        assessment.update(status="supported", reason="The entry point role is not established.")
        self.assertIsNone(entry_context_request(review))  # This function does not interpret prose.
        assessment["validation_errors"] = ["supported_reason_conflict"]
        self.assertIsNotNone(entry_context_request(review))
        del assessment["validation_errors"]
        issue = {"version": "declared-support-v1", "issues": [{"code": "supported_reason_conflict",
                 "prerequisite": "external_entry_role", "rule": "entry_role_disclaimed"}], "truncated": False}
        assessment["support_consistency"] = issue
        self.assertIsNotNone(entry_context_request(review))
        del assessment["support_consistency"]
        review["support_consistency_checks"] = {"trace": issue}
        self.assertIsNone(entry_context_request(review))
        review["support_consistency_checks"] = {"entry_point": issue}
        self.assertIsNotNone(entry_context_request(review))

    def test_window_start_and_candidate_distance_have_explicit_bounds(self):
        for candidate_start, expected in ((400, True), (399, False), (599, True), (600, False)):
            review = fixture()
            review["suggested_values"]["entry_point"].update(start_line=candidate_start, end_line=candidate_start)
            with self.subTest(candidate_start=candidate_start):
                self.assertEqual(entry_context_request(review) is not None, expected)
        review = fixture()
        review["evidence"] = [receipt("E0008", 1, 90)]
        review["suggested_values"]["entry_point"].update(start_line=10, end_line=10)
        self.assertIsNone(entry_context_request(review))
        review["evidence"] = [receipt("E0008", 20, 100)]
        review["suggested_values"]["entry_point"].update(start_line=25, end_line=25)
        self.assertEqual(entry_context_request(review), {"commit": SHA, "path": PATH, "start_line": 1, "end_line": 19})

    def test_old_out_of_bounds_suggestion_remains_unchanged_while_navigation_stays_known(self):
        review = fixture()
        review["suggested_values"]["entry_point"].update(start_line=497, end_line=508)
        original = deepcopy(review)
        self.assertEqual(entry_context_request(review)["start_line"], 400)
        self.assertEqual(review, original)

    def test_existing_same_sha_coverage_prevents_repeated_context_read(self):
        review = fixture()
        request = entry_context_request(review)
        review["evidence"].append(receipt("E0010", request["start_line"], request["end_line"]))
        self.assertIsNone(entry_context_request(review))
        review["evidence"].pop()
        review["evidence"].extend([receipt("E0010", 400, 459), receipt("E0011", 460, 519)])
        self.assertIsNone(entry_context_request(review))

    def test_partial_coverage_requests_only_nearest_unread_gap_not_overlapping_source(self):
        review = fixture()
        review["evidence"].extend([receipt("E0010", 460, 522), receipt("E0011", 400, 429)])
        self.assertEqual(entry_context_request(review), {
            "commit": SHA, "path": PATH, "start_line": 430, "end_line": 459})
        review["evidence"].append(receipt("E0012", 440, 449))
        self.assertEqual(entry_context_request(review), {
            "commit": SHA, "path": PATH, "start_line": 450, "end_line": 459})

    def test_other_file_or_revision_does_not_count_as_preceding_coverage(self):
        review = fixture()
        review["evidence"].extend([receipt("E0010", 400, 519, commit=OTHER_SHA),
                                   receipt("E0011", 400, 519, path="src/other.py")])
        self.assertEqual(entry_context_request(review), {"commit": SHA, "path": PATH, "start_line": 400, "end_line": 519})
        review["draft_fields"]["commit"] = OTHER_SHA
        self.assertIsNone(entry_context_request(review))
        review["draft_fields"]["commit"] = SHA
        review["suggested_values"]["commit"] = OTHER_SHA
        self.assertIsNone(entry_context_request(review))

    def test_failed_unknown_duplicate_nonread_or_malformed_anchor_is_not_navigation(self):
        for kind in ("failed", "unknown", "duplicate", "nonread", "invalid_path", "invalid_rows", "partial_rows"):
            review = fixture()
            anchor = review["evidence"][0]
            if kind == "failed":
                anchor["success"] = False
            elif kind == "unknown":
                review["suggested_values"]["entry_point"]["evidence_ref"] = "E9999"
            elif kind == "duplicate":
                review["evidence"].append(deepcopy(anchor))
            elif kind == "nonread":
                anchor["tool"] = "read_diff"
            elif kind == "invalid_path":
                anchor["result"]["path"] = "../outside.py"
            elif kind == "invalid_rows":
                anchor["result"]["lines"].pop(1)
            else:
                anchor["result"]["end_line"] = 700
            with self.subTest(kind=kind):
                self.assertIsNone(entry_context_request(review))

    def test_covering_failed_attempt_is_not_retried_or_treated_as_successful_coverage(self):
        review = fixture()
        failure = {"id": "E0010", "tool": "read_file", "success": False,
                   "arguments": entry_context_request(review), "result": {"error": "failed"}}
        review["evidence"].append(failure)
        self.assertIsNone(entry_context_request(review))
        failure["arguments"]["end_line"] = 450
        self.assertIsNotNone(entry_context_request(review))  # Not the same/covering attempted range.

    def test_expanded_location_requires_cited_same_path_unique_sha_not_a_guessed_file(self):
        review = fixture()
        review["suggested_values"]["entry_point"] = {"file": PATH, "line": "535-539", "code": "not inspected"}
        self.assertEqual(entry_context_request(review)["path"], PATH)
        review["field_reviews"]["entry_point"]["evidence_refs"] = []
        self.assertIsNone(entry_context_request(review))
        review["field_reviews"]["entry_point"]["evidence_refs"] = ["E0008", "E0010"]
        review["evidence"].append(receipt("E0010", 520, 642, commit=OTHER_SHA))
        self.assertIsNone(entry_context_request(review))
        review["evidence"].pop()
        review["suggested_values"]["entry_point"]["file"] = "src/invented.py"
        self.assertIsNone(entry_context_request(review))

    def test_public_receipt_text_is_sufficient_only_for_navigation(self):
        review = fixture()
        anchor = review["evidence"][0]
        del anchor["result"]["lines"]
        anchor["result"]["text"] = "\n".join("saved public line" for _ in range(123))
        self.assertEqual(entry_context_request(review), {"commit": SHA, "path": PATH, "start_line": 400, "end_line": 519})

    def test_ambiguous_candidate_or_incomplete_directory_fails_closed(self):
        review = fixture()
        review["draft_fields"]["entry_point"] = {**review["suggested_values"]["entry_point"], "start_line": 536}
        self.assertIsNone(entry_context_request(review))
        review = fixture()
        review["evidence"].extend(receipt(f"E{number:04}", 1, 2) for number in range(20, 60))
        self.assertIsNone(entry_context_request(review))

    def test_malformed_or_absent_inputs_do_not_trigger_reads(self):
        for review in (None, [], {}, {"field_reviews": {"entry_point": None}},
                       {"field_reviews": {"entry_point": {"status": "supported", "validation_errors": 12}}}):
            with self.subTest(review=review):
                self.assertIsNone(entry_context_request(review))
        for coordinate in (True, -1, "535", None):
            review = fixture()
            review["suggested_values"]["entry_point"]["start_line"] = coordinate
            with self.subTest(coordinate=coordinate):
                self.assertIsNone(entry_context_request(review))
        for evidence in (None, 3, {}, "not an inventory"):
            review = fixture()
            review["evidence"] = evidence
            with self.subTest(evidence=evidence):
                self.assertIsNone(entry_context_request(review))


if __name__ == "__main__":
    unittest.main()
