"""Bounded saved-receipt feedback, using synthetic dictionaries only."""
from copy import deepcopy
import json
import unittest
from unittest.mock import patch

from vulngym_t2.source_refs import revision_consistency


FIX, PARENT = "a" * 40, "b" * 40


def receipt(identity, commit, path="src/handler.py"):
    return {"id": identity, "tool": "read_file", "success": True,
            "arguments": {"commit": "c" * 40},
            "result": {"commit": commit, "path": path, "start_line": 10, "end_line": 30,
                       "text": "SOURCE BODY MUST NOT BE COPIED"}}


def fixture():
    reference = {"evidence_ref": "E0008", "start_line": 12, "end_line": 14, "desc": "Claim"}
    return {"draft_fields": {"commit": FIX, "entry_point": None, "critical_operation": None, "trace": []},
            "suggested_values": {"entry_point": deepcopy(reference), "critical_operation": deepcopy(reference),
                                 "trace": [deepcopy(reference)]},
            "field_reviews": {"commit": {"status": "supported", "revision_basis": "behavior_at_revision",
                                           "reason": "No affected revision is claimed."},
                              "entry_point": {"status": "uncertain", "evidence_refs": ["E0008"]},
                              "critical_operation": {"status": "uncertain", "evidence_refs": ["E0008"]},
                              "trace": {"status": "supported", "evidence_refs": ["controller:optional_trace"],
                                        "omitted_assessment": {"status": "uncertain", "evidence_refs": ["E0008"]}}},
            "evidence": [receipt("E0006", FIX), receipt("E0008", PARENT)]}


class RevisionFeedbackTests(unittest.TestCase):
    def test_fix_parent_mismatch_is_explicit_and_never_changes_saved_values(self):
        review = fixture()
        before = deepcopy(review)
        with patch("socket.socket", side_effect=AssertionError("no network")), patch("builtins.open", side_effect=AssertionError("no files")):
            packet = revision_consistency(review)
        self.assertEqual(review, before)
        self.assertEqual(packet["selected_commit"], FIX)
        self.assertIsNone(packet["suggested_commit"])
        self.assertEqual(packet["required_review_fields"], ["commit", "entry_point", "critical_operation", "trace"])
        self.assertEqual(len(packet["location_references"]), 3)
        for row in packet["location_references"]:
            self.assertTrue(row["from_suggestion"])
            self.assertEqual(row["receipt_commit"], PARENT)
            self.assertIs(row["matches_selected_commit"], False)
            self.assertEqual(row["resolution_error"], "source_ref_commit_mismatch")
            self.assertEqual(row["status"], "uncertain")
        self.assertNotIn("SOURCE BODY", json.dumps(packet))
        self.assertNotIn("desc", packet["location_references"][0])

    def test_missing_or_failed_receipts_do_not_use_requested_commit(self):
        for mutation in (lambda r: r.update(evidence=[]),
                         lambda r: r["evidence"][1].update(success=False),
                         lambda r: r["evidence"][1]["result"].pop("commit"),
                         lambda r: r["evidence"].append(deepcopy(r["evidence"][1]))):
            review = fixture()
            mutation(review)
            packet = revision_consistency(review)
            for row in packet["location_references"]:
                self.assertIsNone(row["receipt_commit"])
                self.assertIsNone(row["matches_selected_commit"])
                self.assertIsNotNone(row["resolution_error"])

    def test_suggested_commit_is_not_treated_as_selected(self):
        review = fixture()
        review["draft_fields"]["commit"] = None
        review["suggested_values"]["commit"] = PARENT
        review["field_reviews"]["commit"]["status"] = "uncertain"
        packet = revision_consistency(review)
        self.assertIsNone(packet["selected_commit"])
        self.assertEqual(packet["suggested_commit"], PARENT)
        for row in packet["location_references"]:
            self.assertEqual(row["receipt_commit"], PARENT)
            self.assertIsNone(row["matches_selected_commit"])
            self.assertEqual(row["resolution_error"], "source_ref_selected_commit_unknown")

    def test_expanded_multi_revision_references_remain_unknown_not_first_or_selected(self):
        for refs in (["E0006", "E0008"], ["E0008", "E0006"]):
            review = fixture()
            review["suggested_values"]["entry_point"] = {"file": "src/handler.py", "line": "12-14", "code": "not copied"}
            review["field_reviews"]["entry_point"]["evidence_refs"] = refs
            row = revision_consistency(review)["location_references"][0]
            self.assertIsNone(row["receipt_commit"])
            self.assertIsNone(row["evidence_ref"])
            self.assertIsNone(row["matches_selected_commit"])
            self.assertEqual(row["resolution_error"], "source_ref_ambiguous_revision")

    def test_expanded_reference_uses_only_cited_same_file_covering_receipts(self):
        review = fixture()
        review["suggested_values"]["entry_point"] = {"file": "src/handler.py", "line": 12, "code": "not copied"}
        review["field_reviews"]["entry_point"]["evidence_refs"] = ["E0006", "E0008", "E0009"]
        review["evidence"][0]["result"]["path"] = "src/other.py"
        extra = receipt("E0009", FIX)
        extra["result"].update(start_line=20, end_line=30)
        review["evidence"].append(extra)
        row = revision_consistency(review)["location_references"][0]
        self.assertEqual(row["evidence_ref"], "E0008")
        self.assertEqual(row["receipt_commit"], PARENT)
        self.assertFalse(row["matches_selected_commit"])

    def test_valid_same_sha_is_association_only_not_semantic_approval(self):
        review = fixture()
        review["draft_fields"]["commit"] = PARENT
        packet = revision_consistency(review)
        self.assertEqual(packet["commit_status"], "supported")
        self.assertTrue(all(row["matches_selected_commit"] is True for row in packet["location_references"]))
        self.assertTrue(all(row["status"] == "uncertain" for row in packet["location_references"]))
        self.assertIn("not proof", packet["note"])

    def test_output_is_bounded_redacted_and_keeps_unknown_for_invalid_shapes(self):
        review = fixture()
        review["field_reviews"]["commit"]["reason"] = "See D:/target/root/file and /workspace/private/file. " + "长" * 2000
        review["suggested_values"]["trace"] *= 1000
        review["evidence"][1]["result"]["path"] = "D:/target/root/source.py"
        packet = revision_consistency(review)
        self.assertLessEqual(len(packet["commit_reason"]), 800)
        self.assertLessEqual(len(packet["location_references"]), 16)
        self.assertLessEqual(len(json.dumps(packet)), 16000)
        self.assertTrue(packet["truncated"])
        self.assertGreater(packet["omitted"]["item_limit"], 0)
        self.assertNotIn("D:/target", json.dumps(packet))
        self.assertNotIn("/workspace/private", json.dumps(packet))
        for value in (None, [], {"draft_fields": [], "field_reviews": {"commit": []}, "evidence": [None]}):
            packet = revision_consistency(value)
            self.assertEqual(packet["commit_status"], "unknown")
            self.assertIsNone(packet["selected_commit"])

    def test_small_budget_preserves_diagnostics_and_omits_whole_location_rows(self):
        review = fixture()
        review["suggested_values"]["commit"] = PARENT
        review["suggested_values"]["trace"] *= 100
        review["field_reviews"]["commit"]["reason"] = "解释" * 400
        original = deepcopy(review)
        full = revision_consistency(review)
        for budget in (1024, 2000, 4000):
            with self.subTest(budget=budget):
                small = revision_consistency(review, max_chars=budget)
                self.assertLessEqual(len(json.dumps(small)), budget)
                self.assertTrue(small["truncated"])
                for key in ("selected_commit", "suggested_commit", "commit_status", "revision_basis",
                            "required_review_fields", "unresolved_fields"):
                    self.assertEqual(small[key], full[key])
                self.assertEqual(small["omitted"]["item_limit"], full["omitted"]["item_limit"])
                self.assertEqual(small["omitted"]["budget"], len(full["location_references"]) - len(small["location_references"]))
                self.assertEqual(small["commit_reason"], "")
                self.assertEqual(small["omitted"]["commit_reason_chars"], 800)
                self.assertEqual(small["location_references"], full["location_references"][:len(small["location_references"])])
        self.assertEqual(review, original)

    def test_budget_trims_display_reason_before_locations(self):
        review = fixture()
        review["suggested_values"] = {}
        review["field_reviews"]["commit"]["reason"] = "Display reason " * 50
        full = revision_consistency(review)
        small = revision_consistency(review, max_chars=1024)
        self.assertLessEqual(len(json.dumps(small)), 1024)
        self.assertGreater(len(small["commit_reason"]), 0)
        self.assertLess(len(small["commit_reason"]), len(full["commit_reason"]))
        self.assertTrue(full["commit_reason"].startswith(small["commit_reason"]))
        self.assertTrue(small["truncated"])
        self.assertEqual(small["omitted"]["budget"], 0)

    def test_invalid_budget_is_rejected_without_changing_review(self):
        review = fixture()
        original = deepcopy(review)
        for budget in (None, True, False, "2000", 2000.0, 0, -1, 1023, 16001):
            with self.subTest(budget=budget):
                with self.assertRaisesRegex(ValueError, "^revision_feedback_budget_invalid$"):
                    revision_consistency(review, max_chars=budget)
        self.assertEqual(review, original)


if __name__ == "__main__":
    unittest.main()
