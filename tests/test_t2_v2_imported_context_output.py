"""Import navigation diagnostics never label a field semantically approved."""
import unittest

from vulngym_t2.output import _saved_actions


class ImportedContextOutputTests(unittest.TestCase):
    def test_unexecuted_search_budget_diagnostic_is_bounded(self):
        for allowance in (0, 4095, True, -1, "not a number"):
            shown = _saved_actions([{"action": "planning_read_skipped", "tool": "search_history",
                "reason": "reserve_source_window", "result_allowance_chars": allowance}])[0]
            self.assertEqual(shown["reason"], "reserve_source_window")
            self.assertNotIn("evidence_ref", shown)
            if type(allowance) is int and allowance >= 0:
                self.assertEqual(shown["result_allowance_chars"], allowance)
            else:
                self.assertNotIn("result_allowance_chars", shown)

    def test_new_and_original_import_reads_remain_navigation_only(self):
        for action in ("imported_context_header", "imported_context_search", "imported_context_skipped",
                       "imported_context_source", "imported_call_search", "imported_call_source"):
            with self.subTest(action=action):
                shown = _saved_actions([{"action": action, "success": True,
                    "semantic_approval": True, "evidence_ref": "E0004"}])[0]
                self.assertFalse(shown["semantic_approval"])
                self.assertTrue(shown["success"])
                self.assertEqual(shown["evidence_ref"], "E0004")


if __name__ == "__main__":
    unittest.main()
