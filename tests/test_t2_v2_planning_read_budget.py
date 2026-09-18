"""Near-cap source reads use actual visible windows, not a larger context cap."""
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from tests.test_t2_v2_pipeline import job, VULNERABLE
from tests.test_t2_v2_staged_pipeline import MemoryRepo
from vulngym_t2.pipeline import _ProductionSession, _READ_CONTEXT_LIMIT, _json
from vulngym_t2.output import _saved_actions
from vulngym_t2.source_refs import resolve_location


class PlanningReadBudgetTests(unittest.TestCase):
    def state(self, size=60_000):
        client = SimpleNamespace(response_mode="staged_tool", annotation_format="assessed_tool",
                                 multi_entry=False, read_format="plan_tool", halted=None)
        state = _ProductionSession(job(False), client, MemoryRepo(), 12, 32)
        state.messages = [{"role": "system", "content": "x" * size}]
        return state

    def test_source_fits_below_the_original_maximum_reservation(self):
        state = self.state()
        allowance = state.planning_read_allowance([], "read_file")
        self.assertGreaterEqual(allowance, 4096)
        self.assertLess(allowance, 16000)
        self.assertEqual(60_000 + len(_json([])) + 1024 + allowance, _READ_CONTEXT_LIMIT)
        self.assertLess(state.planning_read_allowance([], "search_code"), 4096)
        state.staged_mode = False
        self.assertEqual(state.planning_read_allowance([], "read_file"), 0)

    def test_same_batch_results_reduce_space_and_cap_never_rises(self):
        state = self.state(10_000)
        self.assertEqual(state.planning_read_allowance([], "read_file"), 16000)
        state.messages[0]["content"] = "x" * (_READ_CONTEXT_LIMIT - 1024 - 2 - 4096)
        self.assertEqual(state.planning_read_allowance([], "read_file"), 4096)
        self.assertLess(state.planning_read_allowance([{"id": "E0004"}], "read_file"), 4096)
        state.messages[0]["content"] = "x" * _READ_CONTEXT_LIMIT
        self.assertEqual(state.planning_read_allowance([], "read_file"), 0)

    def run_read(self, state, *, lines=None, extra=None):
        if lines is None:
            lines = [{"line": n, "code": f"value_{n:04d} = 'synthetic fixture content'"} for n in range(1, 401)]
        value = {"commit": VULNERABLE, "path": "fixture.py", "start_line": 1,
                 "end_line": len(lines), "total_lines": len(lines), "lines": lines,
                 "text": "\n".join(row["code"] for row in lines), "truncated": False}
        value.update(extra or {})
        reply = {"action": "tools", "calls": [{"tool": "read_file", "arguments": {
            "commit": VULNERABLE, "path": "fixture.py", "start_line": 1, "end_line": 400}}]}
        with patch.object(state, "complete", side_effect=[reply, {"action": "draft"}]), \
                patch.object(state, "accept_snapshot", return_value=True), \
                patch.object(state.repo, "call", return_value=value) as called:
            state.read_and_draft()
        return lines, called

    def test_real_read_path_preserves_only_actual_visible_source(self):
        state = self.state()
        original, called = self.run_read(state)
        called.assert_called_once()
        saved = state.result["evidence"][-1]
        self.assertTrue(saved["success"])
        self.assertTrue(saved["result"]["context_truncated"])
        shown = saved["result"]["lines"]
        self.assertGreater(len(shown), 0)
        self.assertLess(len(shown), len(original))
        self.assertEqual(shown, original[:len(shown)])
        self.assertEqual(saved["result"]["end_line"], shown[-1]["line"])
        self.assertLessEqual(sum(len(row["content"]) for row in state.messages), _READ_CONTEXT_LIMIT)
        self.assertTrue(state.drafted)

    def test_insufficient_space_closes_without_call_or_fabricated_receipt(self):
        # 65k leaves roughly 1.7k after this request's envelope. That now
        # intentionally admits a small source window; use genuinely <1k here.
        state = self.state(66_000)
        count = len(state.result["evidence"])
        _, called = self.run_read(state)
        called.assert_not_called()
        self.assertTrue(state.read_context_closed)
        self.assertEqual(len(state.result["evidence"]), count)
        closed = next(row for row in state.result["actions"] if row["action"] == "read_context_closed")
        self.assertEqual(closed["tool"], "read_file")
        self.assertLess(closed["result_allowance_chars"], 1024)

    def test_one_to_four_k_source_window_keeps_whole_lines_without_expanding_scope(self):
        for size in (64_500, 65_000, 65_300):
            with self.subTest(context_size=size):
                state = self.state(size)
                original, called = self.run_read(state)
                called.assert_called_once()
                saved = state.result["evidence"][-1]
                self.assertTrue(saved["success"])
                data = saved["result"]
                shown = data["lines"]
                self.assertGreater(len(shown), 0)
                self.assertLess(len(shown), len(original))
                self.assertEqual(shown, original[:len(shown)])
                self.assertEqual(data["text"], "\n".join(row["code"] for row in shown))
                self.assertEqual(data["end_line"], shown[-1]["line"])
                self.assertTrue(data["context_truncated"])
                self.assertTrue(data["has_more"])
                resolved = resolve_location({"evidence_ref": saved["id"], "start_line": 1,
                                             "end_line": shown[-1]["line"], "desc": "visible only"},
                                            state.result["evidence"], VULNERABLE)
                self.assertEqual(resolved["code"], data["text"])
                with self.assertRaises(ValueError):
                    resolve_location({"evidence_ref": saved["id"], "start_line": shown[-1]["line"] + 1,
                                      "end_line": shown[-1]["line"] + 1, "desc": "unread"},
                                     state.result["evidence"], VULNERABLE)
                self.assertLessEqual(sum(len(row["content"]) for row in state.messages), _READ_CONTEXT_LIMIT)
                self.assertFalse(state.read_context_closed)

    def test_exact_one_k_boundary_accounts_for_the_actual_request_envelope(self):
        calls = [{"tool": "read_file", "arguments": {"commit": VULNERABLE, "path": "fixture.py",
                                                       "start_line": 1, "end_line": 400}}]
        request_size = len(_json({"action": "tools", "plan": "", "calls": calls}))
        for allowance in (1023, 1024):
            with self.subTest(allowance=allowance):
                size = _READ_CONTEXT_LIMIT - 1024 - len(_json([])) - request_size - allowance
                state = self.state(size)
                _, called = self.run_read(state)
                if allowance == 1023:
                    called.assert_not_called()
                    closed = next(row for row in state.result["actions"]
                                  if row["action"] == "read_context_closed")
                    self.assertEqual(closed["result_allowance_chars"], 1023)
                    self.assertEqual(state.result["evidence"], [])
                else:
                    called.assert_called_once()
                    self.assertTrue(state.result["evidence"][-1]["success"])
                    self.assertGreater(len(state.result["evidence"][-1]["result"]["lines"]), 0)
                self.assertLessEqual(sum(len(row["content"]) for row in state.messages), _READ_CONTEXT_LIMIT)

    def test_long_single_line_or_oversized_metadata_cannot_become_citable_source(self):
        for case in ("long_line", "large_metadata", "returned_error"):
            with self.subTest(case=case):
                state = self.state(65_000)
                lines = [{"line": 1, "code": "x" * 5000 if case == "long_line" else "value = 1"}]
                extra = ({"fixture_metadata": "x" * 5000} if case == "large_metadata" else
                         {"error": "source_unavailable", "success": False} if case == "returned_error" else {})
                _, called = self.run_read(state, lines=lines, extra=extra)
                called.assert_called_once()
                saved = state.result["evidence"][-1]
                self.assertFalse(saved["success"])
                self.assertTrue(saved["result"]["error"])
                if case != "returned_error":
                    self.assertEqual(saved["result"]["error_code"], "navigation_display_limit")
                    self.assertNotIn("lines", saved["result"])
                with self.assertRaises(ValueError):
                    resolve_location({"evidence_ref": saved["id"], "start_line": 1,
                                      "end_line": 1, "desc": "not available"},
                                     state.result["evidence"], VULNERABLE)

    def test_legacy_controller_does_not_gain_the_small_window_exception(self):
        state = self.state(65_000)
        state.staged_mode = False
        _, called = self.run_read(state)
        called.assert_not_called()
        self.assertEqual(state.result["evidence"], [])
        self.assertTrue(state.read_context_closed)

    def test_saved_closure_retains_only_bounded_numeric_allowance(self):
        for value in (0, 4095, 16000):
            saved = _saved_actions([{"action": "read_context_closed", "result_allowance_chars": value}])
            self.assertEqual(saved[0]["result_allowance_chars"], value)
        for value in (-1, 16001, True, "untrusted text"):
            saved = _saved_actions([{"action": "read_context_closed", "result_allowance_chars": value}])
            self.assertNotIn("result_allowance_chars", saved[0])


if __name__ == "__main__":
    unittest.main()
