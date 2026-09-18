"""Pure regression checks for the identity of omitted trace suggestions."""
from copy import deepcopy
import json
import unittest
from unittest.mock import patch

from vulngym_t2.source_refs import review_locations


def location(line):
    return {"file": "src/example.py", "line": line, "code": "saved_snippet()",
            "desc": "A retained suggestion; no connection is independently established."}


def fixture():
    return {
        "draft_fields": {"entry_point": location(1), "critical_operation": location(9), "trace": []},
        "suggested_values": {"trace": [location(3), location(7)]},
        "field_reviews": {
            "entry_point": {"status": "supported", "reason": "Existing entry assessment."},
            "critical_operation": {"status": "supported", "reason": "Existing operation assessment."},
            "trace": {
                "status": "supported", "reason": "Empty optional trace makes no source-flow claim.",
                "omitted_assessment": {
                    "status": "uncertain", "reason": "The proposed bridge is not established.",
                    "evidence_refs": ["E0003"],
                },
            },
        },
    }


class TracePreviewTests(unittest.TestCase):
    def test_omitted_trace_suggestions_keep_original_uncertainty_and_reason(self):
        review = fixture()
        original = deepcopy(review)
        with patch("builtins.open", side_effect=AssertionError("file access forbidden")):
            packet = review_locations(review)
        self.assertEqual(review, original)
        self.assertEqual([row["field"] for row in packet["locations"]],
                         ["entry_point", "critical_operation", "trace[0]", "trace[1]"])
        self.assertEqual([row["line"] for row in packet["locations"]], [1, 9, 3, 7])
        for row in packet["locations"][2:]:
            self.assertTrue(row["from_suggestion"])
            self.assertEqual(row["status"], "uncertain")
            self.assertEqual(row["reason"], "The proposed bridge is not established.")
            self.assertNotIn("Empty optional trace", row["reason"])
            self.assertFalse({"connected", "verified", "valid"} & set(row))
        self.assertTrue(all(row["status"] == "supported" and not row["from_suggestion"]
                            for row in packet["locations"][:2]))
        self.assertFalse(packet["truncated"])
        self.assertLessEqual(len(json.dumps(packet)), 12000)

    def test_legacy_without_omitted_assessment_uses_existing_outer_assessment(self):
        for status in ("uncertain", "supported", "conflicting"):
            with self.subTest(status=status):
                review = fixture()
                review["field_reviews"]["trace"] = {"status": status, "reason": "Legacy saved trace assessment."}
                original = deepcopy(review)
                rows = review_locations(review)["locations"][2:]
                self.assertEqual(len(rows), 2)
                self.assertTrue(all(row["from_suggestion"] for row in rows))
                self.assertTrue(all(row["status"] == status and row["reason"] == "Legacy saved trace assessment."
                                    for row in rows))
                self.assertEqual(review, original)

    def test_nonempty_selected_trace_does_not_inherit_suggestion_assessment(self):
        review = fixture()
        review["draft_fields"]["trace"] = [location(20)]
        review["field_reviews"]["trace"]["reason"] = "Existing selected trace assessment."
        original = deepcopy(review)
        rows = review_locations(review)["locations"][2:]
        self.assertEqual((rows[0]["line"], rows[0]["status"], rows[0]["from_suggestion"]), (20, "supported", False))
        self.assertEqual(rows[0]["reason"], "Existing selected trace assessment.")
        self.assertTrue(all(row["status"] == "uncertain" and row["from_suggestion"] for row in rows[1:]))
        self.assertEqual(review, original)

    def test_explicit_truncation_marker_follows_the_chosen_assessment(self):
        for outer, omitted in ((False, True), (True, False)):
            with self.subTest(outer=outer, omitted=omitted):
                review = fixture()
                assessment = review["field_reviews"]["trace"]
                assessment["reason_truncated"] = outer
                assessment["omitted_assessment"].update(reason="Short retained prefix.", reason_truncated=omitted)
                original = deepcopy(review)
                packet = review_locations(review)
                for row in packet["locations"][2:]:
                    self.assertEqual(row["reason"], "Short retained prefix.")
                    self.assertEqual(row["truncated"], ["reason"] if omitted else [])
                self.assertEqual(packet["truncated"], omitted)
                self.assertEqual(review, original)

    def test_long_omitted_reason_is_bounded_and_marked_without_modifying_source(self):
        review = fixture()
        review["field_reviews"]["trace"]["omitted_assessment"]["reason"] = "r" * 601
        original = deepcopy(review)
        packet = review_locations(review)
        self.assertTrue(packet["truncated"])
        for row in packet["locations"][2:]:
            self.assertEqual(row["reason"], "r" * 600)
            self.assertIn("reason", row["truncated"])
        self.assertEqual(review, original)


if __name__ == "__main__":
    unittest.main()
