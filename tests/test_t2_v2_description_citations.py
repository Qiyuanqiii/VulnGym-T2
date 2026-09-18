"""Source bytes and narrative citations are separate correctness checks."""
import copy
import unittest

from tests.test_t2_v2_output import fixture, StubRepoReader
from vulngym_t2.output import finalize_result
from vulngym_t2.pipeline import _reason_citation_feedback


class DescriptionCitationTests(unittest.TestCase):
    def test_wrong_description_receipt_blocks_export_preserves_value_and_source(self):
        job, result = fixture()
        result["fields"]["entry_point"]["desc"] = "Registered route is shown at E0003 line 90."
        before = copy.deepcopy(result)
        output = finalize_result(job, result, StubRepoReader())
        self.assertIsNone(output["entry"])
        self.assertEqual(result, before)
        review = output["review"]
        self.assertIsNone(review["draft_fields"]["entry_point"])
        self.assertEqual(review["suggested_values"]["entry_point"], result["fields"]["entry_point"])
        feedback = _reason_citation_feedback(review)
        issue = next(item for item in feedback["issues"] if item["text_path"] == "entry_point.desc")
        self.assertEqual((issue["code"], issue["severity"]), ("reason_citation_out_of_bounds", "error"))

    def test_covered_description_is_not_downgraded(self):
        job, result = fixture()
        result["fields"]["critical_operation"]["desc"] = "E0003:4 shows the local call."
        output = finalize_result(job, result, StubRepoReader())
        self.assertIsNotNone(output["entry"])
        self.assertEqual(output["entry"]["verify"], 0)

    def test_negative_or_ambiguous_description_stays_a_warning_not_an_invented_verdict(self):
        job, result = fixture()
        result["fields"]["entry_point"]["desc"] = "E0003:90 was not read; only the selected input line is claimed."
        output = finalize_result(job, result, StubRepoReader())
        self.assertIsNotNone(output["entry"])
        rows = output["review"]["reason_citation_checks"]["entry_point"]["citations"]
        self.assertEqual(rows[0]["severity"], "warning")


if __name__ == "__main__":
    unittest.main()
