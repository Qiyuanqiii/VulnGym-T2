"""A compared wrapper may reveal one helper to read, never a field verdict."""
import copy
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from vulngym_t2.pipeline import _ProductionSession
from vulngym_t2.revision_navigation import comparison_helper_seed, alternative_snapshot_read
from tests.test_t2_v2_entry_navigation import NavigationRepo
from tests.test_t2_v2_pipeline import VULNERABLE, FIXED, job


PATH = "src/handlers.py"
COMPARISON = {"commit": FIXED, "path": PATH, "symbol": "update_record"}


def receipt(body=None):
    lines = body or ["async def update_record(value, user):",
                     "    row = await lookup_record(value, owner=user)",
                     "    await notify(row)", "    return row", "",
                     "def sibling():", "    return None"]
    return {"id": "E0014", "tool": "read_file", "success": True, "result": {
        "commit": FIXED, "path": PATH, "start_line": 250,
        "end_line": 249 + len(lines), "text": "\n".join(lines)}}


class HelperRepo(NavigationRepo):
    def call(self, tool, arguments):
        if arguments.get("commit") != FIXED or tool not in ("read_file", "search_code"):
            return super().call(tool, arguments)
        self.calls.append((tool, copy.deepcopy(arguments)))
        if tool == "search_code":
            symbol = arguments["query"]
            line = {"update_record": 250, "lookup_record": 50}[symbol]
            return {"commit": FIXED, "query": symbol, "complete": True, "matches": [
                {"file": PATH, "line": line, "code": f"async def {symbol}(value, user=None):"}]}
        lines = [""] * 300
        lines[249:256] = receipt()["result"]["text"].splitlines()
        lines[49:54] = ["async def lookup_record(value, user=None):",
                        "    row = next_helper(value)", "    return row", "",
                        "def unrelated():"]
        first, last = arguments["start_line"], min(arguments["end_line"], len(lines))
        return {"commit": FIXED, "path": PATH, "start_line": first, "end_line": last,
                "text": "\n".join(lines[first - 1:last]), "total_lines": len(lines),
                "lines": [{"line": n, "code": lines[n - 1]} for n in range(first, last + 1)]}


class ComparisonHelperTests(unittest.TestCase):
    def test_real_assigned_name_and_same_sha_declaration_define_read_without_mutation(self):
        row = receipt()
        before = copy.deepcopy(row)
        seed = comparison_helper_seed(row, COMPARISON, [row])
        self.assertEqual(seed, {"commit": FIXED, "path": PATH, "symbol": "lookup_record",
                                "evidence_ref": "E0014"})
        found = {"tool": "search_code", "success": True, "result": {
            "commit": FIXED, "query": "lookup_record", "matches": [
                {"file": PATH, "line": 50, "code": "async def lookup_record(value, owner):"}]}}
        self.assertEqual(alternative_snapshot_read(found, seed), {
            "commit": FIXED, "path": PATH, "start_line": 1, "end_line": 82})
        found["result"]["matches"][0]["code"] = "    row = lookup_record(value, owner)"
        self.assertIsNone(alternative_snapshot_read(found, seed))
        self.assertEqual(row, before)

    def test_failed_mismatched_or_duplicate_receipts_do_not_supply_a_clue(self):
        for change in ("failed", "sha", "path", "id", "duplicate", "unrecorded"):
            row = receipt()
            saved = [row]
            if change == "failed":
                row["success"] = False
            elif change in ("sha", "path"):
                row["result"]["commit" if change == "sha" else "path"] = VULNERABLE if change == "sha" else "src/other.py"
            elif change == "id":
                row["id"] = "unknown"
            elif change == "duplicate":
                saved.append(copy.deepcopy(row))
            else:
                saved = []
            with self.subTest(change=change):
                self.assertIsNone(comparison_helper_seed(row, COMPARISON, saved))

    def test_ambiguous_shadowed_and_invalid_syntax_do_not_guess_a_helper(self):
        for body in (
            ["def update_record(value):", "    a = first(value)", "    b = second(value)", "    return b"],
            ["def update_record(lookup_record):", "    row = lookup_record()", "    return row"],
            ["def update_record(value):", "    row = lookup_record("],
            ["def update_record(value):", "    row = store.lookup_record(value)", "    return row"],
        ):
            row = receipt(body)
            with self.subTest(body=body):
                self.assertIsNone(comparison_helper_seed(row, COMPARISON, [row]))

    def test_already_read_same_sha_helper_is_not_read_again(self):
        row = receipt()
        helper = receipt(["def lookup_record(value):", "    return value"])
        helper["id"] = "E0015"
        self.assertIsNone(comparison_helper_seed(row, COMPARISON, [row, helper]))
        helper["result"]["commit"] = VULNERABLE
        self.assertIsNotNone(comparison_helper_seed(row, COMPARISON, [row, helper]))

    def session(self, limit):
        state = _ProductionSession(job(False), SimpleNamespace(response_mode="staged_tool", halted=None),
                                   HelperRepo(), 12, limit)
        state.prepare()
        return state

    def navigate(self, state):
        with patch("vulngym_t2.revision_navigation.alternative_snapshot_seed", return_value=COMPARISON), \
             patch("vulngym_t2.entry_navigation.entry_navigation_seed", return_value=None), \
             patch("vulngym_t2.entry_navigation.intermediate_assignment_seed", return_value=None):
            state.navigate_entry_context({})

    def test_production_adds_only_one_helper_pair_and_preserves_fields(self):
        state = self.session(16)
        fields = copy.deepcopy(state.result["fields"])
        reviews = copy.deepcopy(state.result["field_reviews"])
        self.navigate(state)
        calls = [(tool, args) for tool, args in state.repo.calls if args.get("commit") == FIXED]
        self.assertEqual([tool for tool, _ in calls], ["search_code", "read_file", "search_code", "read_file"])
        self.assertEqual([args["query"] for tool, args in calls if tool == "search_code"], ["update_record", "lookup_record"])
        self.assertEqual(state.result["fields"], fields)
        self.assertEqual(state.result["field_reviews"], reviews)
        self.assertEqual(state.result["model_calls"], 0)
        self.assertEqual(sum(row["action"] == "comparison_helper_read" for row in state.result["actions"]), 1)

    def test_original_tool_and_context_reserves_still_apply(self):
        state = self.session(4)
        self.navigate(state)
        self.assertEqual([tool for tool, args in state.repo.calls if args.get("commit") == FIXED], ["search_code", "read_file"])
        for kind in ("context", "provider"):
            state = self.session(16)
            if kind == "context":
                state.evidence("advisory", text="x" * 85000)
                state.messages.append({"role": "user", "content": "x" * 85000})
            else:
                state.client.halted = "stopped"
            self.navigate(state)
            self.assertFalse(any(args.get("commit") == FIXED for _, args in state.repo.calls))


if __name__ == "__main__":
    unittest.main()
