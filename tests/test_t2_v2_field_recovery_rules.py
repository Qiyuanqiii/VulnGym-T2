import unittest

from vulngym_t2.annotation_rules import for_phase


class FieldRecoveryRulesTests(unittest.TestCase):
    def test_only_targeted_fields_can_change_in_a_complete_snapshot(self):
        rules = for_phase("field_recovery")
        self.assertIn("only the non-commit fields named in targeted_field_review", rules)
        self.assertIn("ONE complete eight-field snapshot", rules)
        self.assertIn("same submit_annotation schema", rules)
        self.assertIn("Repeat non-target decisions", rules)
        self.assertIn("changes to them will not be applied", rules)

    def test_recovery_reassesses_support_without_erasing_uncertainty(self):
        rules = for_phase("field_recovery")
        self.assertIn("both their semantic support and schema validity", rules)
        self.assertIn("not a syntax-only repair", rules)
        self.assertIn("Unknown target premises must remain uncertain", rules)
        self.assertIn("useful suggestions retained", rules)
        self.assertIn("contradictions cannot be cleared merely by changing wording", rules)
        self.assertIn("not guaranteed", rules)

    def test_recovery_excludes_commit_new_evidence_and_unsupplied_details(self):
        rules = for_phase("field_recovery")
        self.assertIn("commit is excluded", rules)
        self.assertIn("cross-field revision review", rules)
        self.assertIn("current decision remains unchanged", rules)
        self.assertNotIn("remains pending", rules)
        self.assertIn("Do not guess unseen values or raw error properties", rules)
        self.assertIn("Do not request read tools or any new evidence", rules)
        self.assertIn("use submit_annotation only", rules)
        self.assertIn("once when the original call budget permits", rules)
        self.assertLess(len(rules), 1400)


if __name__ == "__main__":
    unittest.main()
