"""Synthetic saved-window feedback: no repository, model or network access."""
from copy import deepcopy
import json
import unittest

from vulngym_t2.source_refs import resolve_location, visible_location_feedback


SHA = "a" * 40
OTHER_SHA = "b" * 40
PATH = "src/handler.py"


def receipt(identity, first, last, *, commit=SHA, path=PATH):
    return {"id": identity, "tool": "read_file", "success": True,
            "arguments": {"commit": "HEAD", "path": path, "start_line": first, "end_line": last + 100},
            "result": {"commit": commit, "path": path, "start_line": first, "end_line": last,
                       "lines": [{"line": number, "code": f"synthetic source {number}"}
                                 for number in range(first, last + 1)],
                       "text": "not authoritative when line rows exist", "truncated": True}}


def fixture(*, selected=SHA):
    return {"draft_fields": {"commit": selected}, "suggested_values": {
                "entry_point": {"evidence_ref": "E0008", "start_line": 497, "end_line": 508,
                                "desc": "An unverified candidate, not an instruction."}},
            "field_reviews": {"commit": {"status": "supported", "revision_basis": "behavior_at_revision"},
                              "entry_point": {"status": "uncertain", "reason": "Candidate needs review.",
                                              "evidence_refs": ["E0008"]}},
            "evidence": [receipt("E0008", 520, 642), receipt("E0010", 460, 522)]}


class VisibleLocationFeedbackTests(unittest.TestCase):
    def test_real_lower_bound_shape_reports_the_correct_id_window_without_repair(self):
        review = fixture()
        original = deepcopy(review)
        for first in (497, 505):
            review["suggested_values"]["entry_point"]["start_line"] = first
            packet = visible_location_feedback(review)
            self.assertEqual(packet["version"], "visible-location-v1")
            self.assertEqual(packet["selected_commit"], SHA)
            row = packet["references"][0]
            self.assertEqual((row["field"], row["from_suggestion"]), ("entry_point", True))
            self.assertEqual((row["evidence_ref"], row["start_line"], row["end_line"]), ("E0008", first, 508))
            self.assertEqual((row["visible_start_line"], row["visible_end_line"]), (520, 642))
            self.assertEqual(row["resolution_error"], "source_ref_out_of_bounds")
            self.assertEqual(row["coverage_error"], "source_ref_out_of_bounds")
            self.assertEqual(row["available_receipts"], [{"evidence_ref": "E0010", "visible_start_line": 460,
                "visible_end_line": 522, "visibility_basis": "line_rows", "reference_usable": True}])
            with self.assertRaisesRegex(ValueError, "^source_ref_out_of_bounds$"):
                resolve_location(review["suggested_values"]["entry_point"], review["evidence"], SHA)
        review["suggested_values"]["entry_point"]["start_line"] = 497
        self.assertEqual(review, original)

    def test_explicit_new_selection_can_resolve_but_feedback_never_changes_the_original(self):
        review = fixture()
        reference = review["suggested_values"]["entry_point"]
        original = deepcopy(reference)
        visible_location_feedback(review)
        chosen = {**reference, "evidence_ref": "E0010"}
        resolved = resolve_location(chosen, review["evidence"], SHA)
        self.assertEqual(resolved["line"], "497-508")
        self.assertEqual(resolved["file"], PATH)
        self.assertEqual(resolved["code"], "\n".join(f"synthetic source {n}" for n in range(497, 509)))
        self.assertEqual(reference, original)

    def test_requested_end_and_total_lines_never_expand_the_visible_directory(self):
        review = fixture()
        review["evidence"][0]["arguments"]["end_line"] = 720
        review["evidence"][0]["result"]["total_lines"] = 9_999
        review["suggested_values"]["entry_point"].update(start_line=640, end_line=650)
        packet = visible_location_feedback(review)
        row = packet["references"][0]
        self.assertEqual(row["visible_end_line"], 642)
        self.assertEqual(row["coverage_error"], "source_ref_out_of_bounds")
        self.assertEqual(row["available_receipts"], [])
        self.assertTrue(packet["ranges"][0]["receipt_truncated"])

    def test_public_text_visibility_is_navigation_not_a_resolver_source_fallback(self):
        saved = receipt("E0008", 520, 642)
        del saved["result"]["lines"]
        saved["result"]["text"] = "one complete line\nsecond complete line\nclipped<truncated>"
        packet = visible_location_feedback({"evidence": [saved]})
        self.assertEqual(len(packet["ranges"]), 1)
        row = packet["ranges"][0]
        self.assertEqual((row["visible_start_line"], row["visible_end_line"]), (520, 521))
        self.assertEqual(row["visibility_basis"], "public_text")
        self.assertIsNone(row["reference_usable"])
        with self.assertRaisesRegex(ValueError, "^source_ref_source_missing$"):
            resolve_location({"evidence_ref": "E0008", "start_line": 520, "end_line": 521}, [saved], SHA)

    def test_malformed_rows_never_fall_back_to_plausible_text(self):
        for kind in ("gap", "bool", "multiline", "empty"):
            saved = receipt("E0008", 520, 522)
            saved["result"]["text"] = "one\ntwo\nthree"
            if kind == "gap":
                saved["result"]["lines"].pop(1)
            elif kind == "bool":
                saved["result"]["lines"][0]["line"] = True
            elif kind == "multiline":
                saved["result"]["lines"][0]["code"] = "two\nlines"
            else:
                saved["result"]["lines"] = []
            with self.subTest(kind=kind):
                packet = visible_location_feedback({"evidence": [saved]})
                self.assertEqual(packet["ranges"], [])
                self.assertEqual(packet["omitted"]["invalid_receipts"], 1)

    def test_partial_live_rows_report_only_visible_prefix_and_are_not_offered_as_repairs(self):
        review = fixture()
        review["evidence"][1]["result"]["end_line"] = 700
        packet = visible_location_feedback(review)
        alternative = next(row for row in packet["ranges"] if row["evidence_ref"] == "E0010")
        self.assertEqual(alternative["visible_end_line"], 522)
        self.assertFalse(alternative["reference_usable"])
        self.assertEqual(packet["references"][0]["available_receipts"], [])
        review["suggested_values"]["entry_point"].update(evidence_ref="E0010", start_line=497, end_line=508)
        row = visible_location_feedback(review)["references"][0]
        self.assertEqual(row["coverage_error"], "source_ref_noncontiguous_source")
        with self.assertRaisesRegex(ValueError, "^source_ref_noncontiguous_source$"):
            resolve_location(review["suggested_values"]["entry_point"], review["evidence"], SHA)

    def test_alternatives_require_unique_successful_same_file_same_revision_receipts(self):
        review = fixture()
        failed = receipt("E0011", 460, 522)
        failed["success"] = False
        duplicate = receipt("E0014", 460, 522)
        review["evidence"].extend([failed, receipt("E0012", 460, 522, commit=OTHER_SHA),
                                   receipt("E0013", 460, 522, path="src/other.py"), duplicate, deepcopy(duplicate)])
        packet = visible_location_feedback(review)
        self.assertEqual([row["evidence_ref"] for row in packet["references"][0]["available_receipts"]], ["E0010"])
        self.assertNotIn("E0011", [row["evidence_ref"] for row in packet["ranges"]])
        self.assertNotIn("E0014", [row["evidence_ref"] for row in packet["ranges"]])
        self.assertEqual(packet["omitted"]["ambiguous_receipts"], 2)
        review["evidence"].append(deepcopy(review["evidence"][0]))
        row = visible_location_feedback(review)["references"][0]
        self.assertEqual(row["resolution_error"], "source_ref_ambiguous_evidence")
        self.assertIsNone(row["visible_start_line"])
        self.assertEqual(row["available_receipts"], [])

    def test_selected_revision_conflict_never_offers_parent_receipts_as_a_repair(self):
        packet = visible_location_feedback(fixture(selected=OTHER_SHA))
        self.assertEqual(packet["selected_commit"], OTHER_SHA)
        self.assertEqual(packet["references"][0]["receipt_commit"], SHA)
        self.assertEqual(packet["references"][0]["available_receipts"], [])

    def test_nearby_disjoint_windows_are_not_joined_or_clamped(self):
        review = fixture()
        review["evidence"][1:] = [receipt("E0010", 497, 502), receipt("E0011", 503, 508)]
        packet = visible_location_feedback(review)
        self.assertEqual(packet["references"][0]["available_receipts"], [])
        self.assertEqual(packet["references"][0]["start_line"], 497)
        self.assertEqual(packet["references"][0]["end_line"], 508)

    def test_trace_and_entry_references_keep_separate_field_and_suggestion_identities(self):
        review = fixture()
        review["suggested_values"]["trace"] = [deepcopy(review["suggested_values"]["entry_point"])]
        review["draft_fields"]["trace"] = []
        review["field_reviews"]["trace"] = {"status": "supported", "omitted_assessment": {
            "status": "uncertain", "evidence_refs": ["E0008"]}}
        packet = visible_location_feedback(review)
        self.assertEqual([row["field"] for row in packet["references"]], ["entry_point", "trace[0]"])
        self.assertTrue(all(row["from_suggestion"] for row in packet["references"]))
        self.assertTrue(all(row["evidence_ref"] == "E0008" for row in packet["references"]))

    def test_initial_directory_has_no_source_text_request_root_or_claim_prose(self):
        review = fixture()
        saved = review["evidence"][0]
        saved["arguments"]["repo_path"] = "D:/forbidden-root"
        saved["result"]["reason"] = "private display prose"
        packet = visible_location_feedback({"evidence": review["evidence"]})
        encoded = json.dumps(packet)
        self.assertEqual(packet["references"], [])
        for value in ("synthetic source", "forbidden-root", "private display prose", "not authoritative"):
            self.assertNotIn(value, encoded)
        self.assertNotIn('"code"', encoded)
        self.assertNotIn('"desc"', encoded)
        self.assertEqual([row["evidence_ref"] for row in packet["ranges"]], ["E0008", "E0010"])

    def test_invalid_paths_and_receipt_shapes_are_omitted_not_echoed(self):
        for path in ("D:/outside.py", "../outside.py", "src\\outside.py", "src/\nname.py"):
            with self.subTest(path=path):
                packet = visible_location_feedback({"evidence": [receipt("E0008", 1, 2, path=path)]})
                self.assertEqual(packet["ranges"], [])
                self.assertEqual(packet["omitted"]["invalid_receipts"], 1)
        self.assertEqual(visible_location_feedback(None)["ranges"], [])
        self.assertEqual(visible_location_feedback({"evidence": [None]})["omitted"]["invalid_receipts"], 1)

    def test_budgets_omit_whole_rows_and_never_shorten_identities(self):
        review = fixture()
        review["evidence"].extend(receipt(f"E{number:04}", 1, 2, path="src/" + "中" * 120 + str(number) + ".py")
                                   for number in range(20, 60))
        original = deepcopy(review)
        for budget in (1_024, 4_000, 8_000, 16_000):
            with self.subTest(budget=budget):
                packet = visible_location_feedback(review, max_chars=budget)
                self.assertLessEqual(len(json.dumps(packet)), budget)
                self.assertEqual(packet["selected_commit"], SHA)
                self.assertTrue(packet["truncated"])
                for row in packet["ranges"]:
                    self.assertRegex(row["evidence_ref"], r"\AE[0-9]{4,8}\Z")
                    self.assertEqual(row["receipt_commit"], SHA)
                    source = next(item for item in review["evidence"] if item["id"] == row["evidence_ref"])
                    self.assertEqual(row["path"], source["result"]["path"])
                self.assertLessEqual(len(packet["ranges"]), 32)
                self.assertLessEqual(len(packet["references"]), 16)
        self.assertEqual(review, original)
        for budget in (True, False, None, "4000", 4_000.0, 0, 1_023, 16_001):
            with self.subTest(budget=budget), self.assertRaisesRegex(ValueError, "^visible_location_feedback_budget_invalid$"):
                visible_location_feedback(review, max_chars=budget)

    def test_oversized_inventory_is_not_prefix_scanned_past_possible_duplicate_ids(self):
        saved = receipt("E0008", 1, 2)
        packet = visible_location_feedback({"evidence": [saved] * 1_025}, max_chars=1_024)
        self.assertEqual(packet["ranges"], [])
        self.assertEqual(packet["references"], [])
        self.assertTrue(packet["truncated"])
        self.assertEqual(packet["omitted"]["range_limit"], 1_025)
        self.assertLessEqual(len(json.dumps(packet)), 1_024)


if __name__ == "__main__":
    unittest.main()
