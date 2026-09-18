"""Pure selected-claim previews: no repository, model, file or network calls."""
from copy import deepcopy
import json
import unittest
from unittest.mock import patch

from vulngym_t2.source_refs import review_locations


def location(line=1, **updates):
    return {"file": "src/example.py", "line": line, "code": "    retained_bytes()  ",
            "desc": "A model-supplied description, not a new observation.", **updates}


def fixture():
    return {"draft_fields": {"entry_point": location(), "critical_operation": location(7),
                              "trace": [location(3), location(5)]},
            "suggested_values": {}, "field_reviews": {
                name: {"status": "supported", "reason": "Existing assessment only."}
                for name in ("entry_point", "critical_operation", "trace")}}


class ClaimReviewTests(unittest.TestCase):
    def test_copies_selected_data_in_order_without_mutation_or_io(self):
        review = fixture()
        before = deepcopy(review)
        with patch("builtins.open", side_effect=AssertionError("Unexpected file read")):
            result = review_locations(review)
        self.assertEqual(review, before)
        self.assertEqual([row["field"] for row in result["locations"]],
                         ["entry_point", "critical_operation", "trace[0]", "trace[1]"])
        self.assertEqual([row["line"] for row in result["locations"]], [1, 7, 3, 5])
        self.assertTrue(all(row["code"] == location()["code"] for row in result["locations"]))
        self.assertTrue(all(row["from_suggestion"] is False for row in result["locations"]))
        self.assertFalse(result["truncated"])
        self.assertEqual(sum(result["omitted"].values()), 0)
        self.assertIn("不是新增独立证据", result["title"])
        self.assertIn("不表示源码不存在", result["notes"])

    def test_unknown_suggestion_identity_precedes_optional_trace(self):
        review = fixture()
        review["draft_fields"].update(entry_point=None, critical_operation=None,
                                       trace=[location(i + 1) for i in range(12)])
        review["suggested_values"] = {
            "entry_point": {"evidence_ref": "E0099", "start_line": 10, "end_line": 12, "desc": "Unresolved reference."},
            "critical_operation": location("20-22"), "trace": [location(30), location(40)]}
        for name in ("entry_point", "critical_operation"):
            review["field_reviews"][name]["status"] = "uncertain"
        result = review_locations(review)
        first, second = result["locations"][:2]
        self.assertEqual(first["reference"], {"evidence_ref": "E0099", "start_line": 10, "end_line": 12})
        self.assertNotIn("code", first)
        self.assertEqual(second["line"], "20-22")
        self.assertTrue(all(row["from_suggestion"] and row["status"] == "uncertain" for row in (first, second)))
        self.assertEqual([row["line"] for row in result["locations"][2:]], list(range(1, 9)))
        self.assertEqual(result["omitted"]["item_limit"], 6)
        self.assertEqual(len(result["locations"]), 10)
        self.assertTrue(result["truncated"])

    def test_individual_limits_are_inclusive_and_truncation_is_explicit(self):
        for extra in (0, 1):
            with self.subTest(extra=extra):
                review = fixture()
                review["draft_fields"] = {"entry_point": location("1-200", code="c" * (1600 + extra), desc="d" * (500 + extra))}
                review["field_reviews"]["entry_point"]["reason"] = "r" * (600 + extra)
                result = review_locations(review)
                item = result["locations"][0]
                self.assertEqual((len(item["code"]), len(item["desc"]), len(item["reason"])), (1600, 500, 600))
                self.assertEqual(item["line"], "1-200")
                self.assertEqual(item["truncated"], ["code", "desc", "reason"] if extra else [])
                self.assertEqual(result["truncated"], bool(extra))

    def test_json_budget_handles_escaped_and_unicode_text(self):
        for text in ("x", "\x00", "汉"):
            with self.subTest(text=repr(text)):
                review = fixture()
                review["draft_fields"]["trace"] = [location(i + 1, code=text * 1700, desc=text * 501) for i in range(10)]
                review["field_reviews"]["trace"]["reason"] = text * 601
                result = review_locations(review)
                self.assertLessEqual(len(json.dumps(result)), 12000)
                self.assertLessEqual(len(json.dumps(result, ensure_ascii=False)), 12000)
                self.assertGreater(result["omitted"]["budget"], 0)
                self.assertTrue(result["truncated"])
                self.assertEqual([row["field"] for row in result["locations"][:2]], ["entry_point", "critical_operation"])

    def test_abnormal_shapes_and_coordinates_are_skipped_without_throwing(self):
        bad_locations = [False, [], "not a location", location(True), location(0), location(-1),
                         location(100_000_001), location("2-1"), location("1-100000001"),
                         location("1-" + "9" * 5000), location(code=[]), location(desc=None),
                         location(file="../outside.py"), location(file="x" * 501),
                         {"evidence_ref": "E0001", "start_line": True, "end_line": 2}]
        for value in bad_locations:
            with self.subTest(value=type(value).__name__):
                review = fixture()
                review["draft_fields"] = {"entry_point": value}
                result = review_locations(review)
                self.assertEqual(result["locations"], [])
                self.assertEqual(result["omitted"]["invalid_shape"], 1)
                self.assertTrue(result["truncated"])
        for value in (None, [], "wrong", {"draft_fields": []}, {"field_reviews": []},
                      {"draft_fields": {"trace": {}}}, {"draft_fields": {"entry_point": location()}}):
            with self.subTest(review=value):
                result = review_locations(value)
                self.assertGreater(result["omitted"]["invalid_shape"], 0)
                self.assertLessEqual(len(json.dumps(result)), 12000)

    def test_does_not_invent_connections_correct_coordinates_or_promote_status(self):
        review = fixture()
        review["draft_fields"]["entry_point"] = location(900, code="unrelated()", desc="A claimed connection to a different handler.")
        review["field_reviews"]["entry_point"].update(status="uncertain", reason="The caller relationship is unestablished.")
        before = deepcopy(review)
        result = review_locations(review)
        item = result["locations"][0]
        self.assertEqual((item["line"], item["code"], item["status"]), (900, "unrelated()", "uncertain"))
        self.assertEqual(item["desc"], review["draft_fields"]["entry_point"]["desc"])
        self.assertEqual(item["reason"], review["field_reviews"]["entry_point"]["reason"])
        self.assertFalse({"connected", "valid", "verified", "correction"} & set(item))
        self.assertEqual(review, before)


if __name__ == "__main__":
    unittest.main()
