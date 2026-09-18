"""Pure saved-receipt navigation; no target execution or model calls."""
import copy
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from vulngym_t2.evidence_navigation import called_body_continuations
from vulngym_t2.entry_navigation import source_window_continuations
from vulngym_t2.output import _saved_actions
from vulngym_t2.pipeline import _ProductionSession
from tests.test_t2_v2_pipeline import VULNERABLE, job
from tests.test_t2_v2_source_continuation import ContinuationRepo
from tests.test_t2_v2_staged_pipeline import MemoryRepo


OLD, OTHER = "a" * 40, "b" * 40
PATH = "src/package/helpers.py"
CODE = ["result = build_values(value)", "", "def build_values(value):"] + ["    value += 1"] * 77


def source(identity, first, last, *, sha=OLD, code=CODE, total=140):
    rows = [{"line": line, "code": code[line - 1]} for line in range(first, last + 1)]
    return {"id": identity, "tool": "read_file", "success": True,
            "arguments": {"commit": sha, "path": PATH, "start_line": first, "end_line": 500},
            "result": {"commit": sha, "path": PATH, "start_line": first, "end_line": last,
                       "total_lines": total, "has_more": last < total, "truncated": True,
                       "lines": rows, "text": "\n".join(row["code"] for row in rows)}}


def review():
    return {"field_reviews": {"critical_operation": {"status": "uncertain", "evidence_refs": ["E0001", "E0002"]}},
            "evidence": [source("E0001", 1, 50), source("E0002", 50, 80)]}


class CalledBodyContinuationsTests(unittest.TestCase):
    def test_called_body_crosses_receipts_and_old_near_end_rule_misses_it(self):
        value = review()
        before = copy.deepcopy(value)
        self.assertEqual(source_window_continuations(value), [])
        requests = called_body_continuations(value)
        self.assertEqual(requests, [{"field": "critical_operation", "evidence_ref": "E0002",
                                    "evidence_refs": ["E0001", "E0002"], "symbol": "build_values",
                                    "boundary_line": 3, "arguments": {"commit": OLD, "path": PATH,
                                                                          "start_line": 81, "end_line": 120}}])
        self.assertEqual(value, before)

    def test_unknown_or_string_or_comment_only_call_is_not_a_seed(self):
        for first in ("result = other(value)", '# build_values(value)', '"build_values(value)"'):
            with self.subTest(first=first):
                code = [first, *CODE[1:]]
                value = review()
                value["evidence"] = [source("E0001", 1, 50, code=code), source("E0002", 50, 80, code=code)]
                self.assertEqual(called_body_continuations(value), [])

    def test_closed_called_body_does_not_continue_unrelated_sibling(self):
        code = CODE[:40] + ["def unrelated(value):"] + CODE[41:]
        value = review()
        value["evidence"] = [source("E0001", 1, 50, code=code), source("E0002", 50, 80, code=code)]
        self.assertEqual(called_body_continuations(value), [])

    def test_unseen_gap_and_other_revision_cannot_bridge_call_to_tail(self):
        for case in ("gap", "revision", "uncited"):
            with self.subTest(case=case):
                value = review()
                if case == "gap":
                    value["evidence"][0] = source("E0001", 1, 48)
                elif case == "revision":
                    value["evidence"][0] = source("E0001", 1, 50, sha=OTHER)
                else:
                    value["field_reviews"]["critical_operation"]["evidence_refs"] = ["E0002"]
                # The early receipt must not itself advertise an extendable boundary.
                value["evidence"][0]["result"]["has_more"] = False
                self.assertEqual(called_body_continuations(value), [])

    def test_conflicting_overlap_and_duplicate_receipt_ids_are_rejected(self):
        for case in ("overlap", "duplicate"):
            with self.subTest(case=case):
                value = review()
                if case == "overlap":
                    value["evidence"][1]["result"]["lines"][0]["code"] = "    value -= 1"
                    value["evidence"][1]["result"]["text"] = "\n".join(row["code"] for row in value["evidence"][1]["result"]["lines"])
                else:
                    value["evidence"].append(copy.deepcopy(value["evidence"][0]))
                self.assertEqual(called_body_continuations(value), [])

    def test_already_read_next_line_prevents_repeat_not_skip_ahead(self):
        value = review()
        value["evidence"].append(source("E0003", 81, 82, code=CODE + ["    value *= 2"] * 2))
        self.assertEqual(called_body_continuations(value), [])

    def test_selected_revision_conflict_is_not_repaired_by_navigation(self):
        for case in ("other", "conflicting", "malformed"):
            with self.subTest(case=case):
                value = review()
                value["draft_fields"] = {"commit": OTHER if case == "other" else OLD}
                if case == "conflicting":
                    value["suggested_values"] = {"commit": OTHER}
                elif case == "malformed":
                    value["suggested_values"] = {"commit": []}
                self.assertEqual(called_body_continuations(value), [])

    def test_visible_statement_cut_is_allowed_but_unclosed_string_is_unknown(self):
        for final, expected in (("    pending = {", 1), ('    text = """unfinished', 0),
                                ('    text = "unfinished', 0)):
            with self.subTest(final=final):
                code = [*CODE[:-1], final]
                value = review()
                value["evidence"] = [source("E0001", 1, 50, code=code), source("E0002", 50, 80, code=code)]
                self.assertEqual(len(called_body_continuations(value)), expected)

    def test_total_and_limit_are_bounded(self):
        value = review()
        value["evidence"][1]["result"]["total_lines"] = 85
        self.assertEqual(called_body_continuations(value, limit=1)[0]["arguments"]["end_line"], 85)
        for limit in (0, -1, True, "2"):
            self.assertEqual(called_body_continuations(value, limit=limit), [])
        for total in (True, "140", 80, 100_000_001):
            value["evidence"][1]["result"]["total_lines"] = total
            self.assertEqual(called_body_continuations(value), [])

    def test_ambiguous_nested_or_repeated_functions_are_not_selected(self):
        alternatives = [
            ["result = outer(value)", "", "def outer(value):", "    inner(value)",
             "    def inner(value):"] + ["        value += 1"] * 75,
            CODE[:40] + ["def build_values(value):"] + CODE[41:],
        ]
        for code in alternatives:
            with self.subTest(header=code[:5]):
                value = review()
                value["evidence"] = [source("E0001", 1, 50, code=code), source("E0002", 50, 80, code=code)]
                self.assertEqual(called_body_continuations(value), [])

    def test_invalid_header_or_method_reference_does_not_establish_a_local_body(self):
        for first, header in (("result = obj.build_values(value)", CODE[2]),
                              (CODE[0], "def build_values(:")):
            with self.subTest(first=first, header=header):
                code = [first, "", header, *CODE[3:]]
                value = review()
                value["evidence"] = [source("E0001", 1, 50, code=code), source("E0002", 50, 80, code=code)]
                self.assertEqual(called_body_continuations(value), [])

    def test_far_away_call_is_not_recovered_by_reading_the_entire_file(self):
        code = CODE + ["    value += 1"] * 240
        value = review()
        value["evidence"] = [source("E0001", 1, 200, code=code, total=500),
                             source("E0002", 200, 320, code=code, total=500)]
        self.assertEqual(called_body_continuations(value), [])

    def test_tab_indentation_does_not_mix_raw_and_expanded_columns(self):
        code = [*CODE[:3], *["\tvalue += 1"] * 77]
        value = review()
        value["evidence"] = [source("E0001", 1, 50, code=code), source("E0002", 50, 80, code=code)]
        self.assertEqual(called_body_continuations(value), [])


class CalledBodyIntegrationTests(unittest.TestCase):
    def session(self):
        client = SimpleNamespace(response_mode="staged_tool", annotation_format="assessed_tool", halted=None)
        session = _ProductionSession(job(False), client, MemoryRepo(), 16, 32)
        session.prepare()
        session.result["fields"]["commit"] = VULNERABLE
        session.repo = ContinuationRepo()
        return session

    def add_windows(self, session, *, path=PATH):
        refs = []
        for first, last in ((1, 50), (50, 80)):
            row = source("unused", first, last, sha=VULNERABLE)
            row["result"]["path"] = row["arguments"]["path"] = path
            saved = session.evidence("tool", **{key: value for key, value in row.items() if key != "id"})
            refs.append(saved["id"])
        session.result["field_reviews"]["critical_operation"].update(status="uncertain", evidence_refs=refs)
        return refs

    def test_one_local_read_preserves_fields_old_evidence_refs_and_model_budget(self):
        session = self.session()
        refs = self.add_windows(session)
        fields, judgments, evidence = (copy.deepcopy(session.result[key])
                                      for key in ("fields", "field_reviews", "evidence"))
        with patch("vulngym_t2.entry_navigation.navigate_entry", side_effect=AssertionError("No caller expansion")):
            session.navigate_entry_context({})
        self.assertEqual(session.repo.calls, [("read_file", {"commit": VULNERABLE, "path": PATH,
                                                           "start_line": 81, "end_line": 120})])
        self.assertEqual(session.result["model_calls"], 0)
        self.assertEqual(session.result["tool_calls"], 1)
        self.assertEqual(session.result["fields"], fields)
        self.assertEqual(session.result["field_reviews"], judgments)
        self.assertEqual(session.result["evidence"][:-1], evidence)
        action = next(row for row in _saved_actions(session.result["actions"])
                      if row["action"] == "source_window_continuation")
        self.assertEqual(action["evidence_refs"], refs)
        self.assertEqual(action["arguments"]["start_line"], 81)
        self.assertTrue(action["success"])
        self.assertTrue(session.followup_context_fits())
        self.assertLessEqual(sum(len(row["content"]) for row in session.messages), session.navigation_context_limit())

    def test_existing_input_wide_two_attempt_limit_survives_new_candidates(self):
        session = self.session()
        for index in range(3):
            self.add_windows(session, path=f"src/package/helper_{index}.py")
            session.navigate_entry_context({})
        self.assertEqual(len(session.source_continuation_attempts), 2)
        self.assertEqual(len(session.repo.calls), 2)
        self.assertEqual(session.result["model_calls"], 0)

    def test_failed_first_boundary_does_not_hide_the_second_untried_body(self):
        session = self.session()
        refs = self.add_windows(session, path="src/package/first.py")
        refs += self.add_windows(session, path="src/package/second.py")
        session.result["field_reviews"]["critical_operation"]["evidence_refs"] = refs
        before = copy.deepcopy((session.result["fields"], session.result["field_reviews"]))
        with patch.object(session.repo, "call", side_effect=OSError("synthetic unavailable")) as failed:
            session.navigate_entry_context({})
        self.assertEqual(failed.call_count, 1)
        self.assertEqual(failed.call_args.args[1]["path"], "src/package/first.py")
        self.assertFalse(session.result["evidence"][-1]["success"])
        # A failed read supplies no successful next-line receipt, so the pure
        # helper still proposes it first. The hook must skip it before choosing
        # the next unused seed, without retrying or widening this pass.
        session.navigate_entry_context({})
        self.assertEqual(session.repo.calls, [("read_file", {"commit": VULNERABLE,
            "path": "src/package/second.py", "start_line": 81, "end_line": 120})])
        self.assertEqual((session.result["tool_calls"], len(session.source_continuation_attempts)), (2, 2))
        self.assertEqual(session.result["model_calls"], 0)
        self.assertEqual((session.result["fields"], session.result["field_reviews"]), before)
        session.navigate_entry_context({})
        self.assertEqual(len(session.repo.calls), 1)
        self.assertEqual(session.result["tool_calls"], 2)

    def test_existing_provider_and_tool_gates_prevent_the_small_read(self):
        for reason in ("provider", "tools"):
            with self.subTest(reason=reason):
                session = self.session()
                self.add_windows(session)
                if reason == "provider":
                    session.client.halted = "stopped"
                else:
                    session.max_tool_calls = 2
                session.navigate_entry_context({})
                self.assertEqual(session.repo.calls, [])
                self.assertEqual(session.result["model_calls"], 0)
                self.assertEqual(session.source_continuation_attempts, set())


if __name__ == "__main__":
    unittest.main()
