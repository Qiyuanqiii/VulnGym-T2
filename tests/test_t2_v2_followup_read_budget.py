"""Sequential reads preserve the original cap and truthful visible intervals."""
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from tests.test_t2_v2_pipeline import job, VULNERABLE
from tests.test_t2_v2_staged_pipeline import MemoryRepo
from vulngym_t2 import annotation_rules, staged_protocol
from vulngym_t2.pipeline import _ProductionSession


class FollowupReadBudgetTests(unittest.TestCase):
    def state(self, size=64_743):
        client = SimpleNamespace(response_mode="staged_tool", annotation_format="assessed_tool",
                                 multi_entry=False, read_format="plan_tool", halted=None)
        state = _ProductionSession(job(False), client, MemoryRepo(), 12, 32)
        state.messages = [{"role": "system", "content": "x" * size}]
        return state

    def overhead(self, state):
        return (len(annotation_rules.for_phase("followup"))
                + len(staged_protocol.instruction("followup", read_format="plan_tool"))
                + 512 + 2 * 1024 + state.review_instruction_budget())

    def test_known_dense_context_fits_short_read_without_raising_cap(self):
        state = self.state()
        allowance = state.followup_read_allowance()
        self.assertTrue(state.followup_context_fits())
        self.assertGreaterEqual(allowance, 4096)
        self.assertLessEqual(allowance, 8000)
        self.assertLessEqual(64_743 + allowance + self.overhead(state), 100_000)

    def test_minimum_is_checked_at_exact_boundary_and_after_growth(self):
        state = self.state()
        limit = 100_000 - self.overhead(state) - 4096
        state.messages[0]["content"] = "x" * limit
        self.assertEqual(state.followup_read_allowance(), 4096)
        self.assertTrue(state.followup_context_fits())
        state.messages.append({"role": "user", "content": "x"})
        self.assertEqual(state.followup_read_allowance(), 4095)
        self.assertFalse(state.followup_context_fits())
        state.messages[0]["content"] = "x" * 100_000
        self.assertEqual(state.followup_read_allowance(), 0)

    def test_larger_future_review_reduces_allowance_instead_of_spending_reserve(self):
        state = self.state()
        with patch.object(state, "review_instruction_budget", return_value=30_000):
            self.assertFalse(state.followup_context_fits())
            self.assertLess(state.followup_read_allowance(), 4096)

    def test_short_allowance_retains_visible_source_and_truncation(self):
        state = self.state()
        lines = [{"line": n, "code": f"line_{n:04d} = 'synthetic source text only'"} for n in range(1, 401)]
        value = {"commit": VULNERABLE, "path": "fixture.py", "start_line": 1,
                 "end_line": 400, "total_lines": 400, "lines": lines,
                 "text": "\n".join(item["code"] for item in lines), "truncated": False}
        with patch.object(state.repo, "call", return_value=value):
            state.read_tool("read_file", {"commit": VULNERABLE, "path": "fixture.py",
                            "start_line": 1, "end_line": 400}, navigation_display_limit=4096)
        receipt = state.result["evidence"][-1]
        self.assertTrue(receipt["success"])
        self.assertTrue(receipt["result"]["truncated"])
        shown = receipt["result"]["lines"]
        self.assertGreater(len(shown), 0)
        self.assertLess(len(shown), 400)
        self.assertEqual(shown, lines[:len(shown)])
        self.assertEqual(receipt["result"]["end_line"], shown[-1]["line"])


if __name__ == "__main__":
    unittest.main()
