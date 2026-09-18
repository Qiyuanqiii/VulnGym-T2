"""Public encoding-budget records and explicit candidate-coverage presentation."""
from copy import deepcopy
import unittest

from tests.test_t2_v2_serial_output import serial_fixture
from tests.test_t2_v2_output import StubRepoReader
from vulngym_t2.multi_entry import allocate_entry_ids
from vulngym_t2.output import _saved_actions, finalize_job
from vulngym_t2.review_export import _candidate_selection_lines


class EncodingReserveOutputTests(unittest.TestCase):
    def test_pool_metadata_is_bounded_and_drops_unrelated_content(self):
        plan = {"action": "candidate_plan", "proposed_count": 3, "selected_count": 2,
                "omitted_count": 1, "encoding_reserve": 1, "budget_slots_without_reserve": 3,
                "encoding_reserve_reason": "reserved", "private_note": "NOT_PUBLIC"}
        saved = _saved_actions([plan])[0]
        self.assertEqual(saved["encoding_reserve"], 1)
        self.assertEqual(saved["budget_slots_without_reserve"], 3)
        self.assertEqual(saved["encoding_reserve_reason"], "reserved")
        self.assertNotIn("private_note", saved)
        for invalid in (True, -1, 2, "1"):
            plan["encoding_reserve"] = invalid
            self.assertNotIn("encoding_reserve", _saved_actions([plan])[0])

    def test_consumption_action_has_no_arbitrary_stage_or_payload(self):
        valid = {"action": "annotation_encoding_reserve", "stage": "self_review",
                 "summary": "consumed", "call": 8}
        self.assertEqual(_saved_actions([valid]), [valid])
        invalid = dict(valid, stage="arbitrary", summary="secret text", call=True, arguments={"secret": 1})
        self.assertEqual(_saved_actions([invalid]), [{"action": "annotation_encoding_reserve"}])

    def reviews(self):
        job, result = serial_fixture()
        result["actions"][0].update(encoding_reserve=1, budget_slots_without_reserve=3,
                                     encoding_reserve_reason="reserved")
        saved = finalize_job(job, result, StubRepoReader(), entry_ids=allocate_entry_ids([job])[0])
        return [item["review"] for item in saved["items"]]

    def test_serial_shared_plan_is_shown_once_and_distinct_from_completion(self):
        reviews = self.reviews()
        text = "\n".join(_candidate_selection_lines(reviews))
        self.assertEqual(text.count("| 3 | 2 | 1 | 1 |"), 1)
        self.assertIn("没有完成逐条处理", text)
        self.assertIn("不是准确率", text)
        self.assertNotIn("RAW_SCOPE_PRIVATE", text)

    def test_missing_pool_is_not_zero_and_malformed_counts_are_not_inferred(self):
        reviews = self.reviews()
        plan = reviews[0]["input_actions"][0]
        plan.pop("encoding_reserve")
        self.assertIn("| 3 | 2 | 1 | 未记录 |", "\n".join(_candidate_selection_lines(reviews)))
        for bad in (True, 99):
            with self.subTest(bad=bad):
                plan["selected_count"] = bad
                self.assertIn("记录不一致", "\n".join(_candidate_selection_lines(reviews)))

    def test_duplicate_plan_not_double_counted_and_old_missing_plan_not_invented(self):
        reviews = self.reviews()
        reviews[0]["input_actions"].append(deepcopy(reviews[0]["input_actions"][0]))
        self.assertIn("记录不一致", "\n".join(_candidate_selection_lines(reviews)))
        reviews[0]["input_actions"] = []
        self.assertEqual(_candidate_selection_lines(reviews), [])


if __name__ == "__main__":
    unittest.main()
