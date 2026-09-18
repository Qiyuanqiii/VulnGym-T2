"""Bounded helper-window continuation uses synthetic receipts only, no HTTP."""
import copy
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from vulngym_t2 import annotation_rules
from vulngym_t2.entry_navigation import source_window_continuations
from vulngym_t2.output import _saved_actions
from vulngym_t2.pipeline import _ProductionSession, _json
from tests.test_t2_v2_pipeline import FIXED, VULNERABLE, job
from tests.test_t2_v2_staged_pipeline import MemoryRepo


def receipt(identity="E0010", path="service/worker.py", commit=VULNERABLE):
    lines = ["def wrapper(value):", "    return make_record(value)"] + [""] * 15
    lines += ["def make_record(value):", "    # Remaining statements have not been read.", "    original = value"]
    return {"id": identity, "tool": "read_file", "success": True,
        "result": {"commit": commit, "path": path, "start_line": 121, "end_line": 140,
            "total_lines": 500, "has_more": True, "truncated": False,
            "lines": [{"line": 121 + i, "code": line} for i, line in enumerate(lines)],
            "text": "\n".join(lines)}}


def review():
    return {"evidence": [receipt()], "draft_fields": {"commit": VULNERABLE},
        "field_reviews": {"critical_operation": {"status": "uncertain", "evidence_refs": ["E0010"]}}}


class SourceContinuationTests(unittest.TestCase):
    def test_cited_boundary_helper_gets_only_next_eighty_lines_at_same_sha(self):
        value = review()
        original = copy.deepcopy(value)
        requests = source_window_continuations(value)
        self.assertEqual(requests, [{"field": "critical_operation", "evidence_ref": "E0010",
            "boundary_line": 138, "arguments": {"commit": VULNERABLE, "path": "service/worker.py",
                "start_line": 141, "end_line": 220}}])
        self.assertEqual(value, original)

    def test_unknown_selected_revision_does_not_invent_or_copy_one(self):
        value = review()
        value["draft_fields"] = {}
        self.assertEqual(source_window_continuations(value)[0]["arguments"]["commit"], VULNERABLE)
        value["draft_fields"]["commit"] = FIXED
        self.assertEqual(source_window_continuations(value), [])
        value["suggested_values"] = {"commit": VULNERABLE}
        self.assertEqual(source_window_continuations(value), [])

    def test_declaration_exactly_twelve_lines_from_end_is_included(self):
        value = review()
        data = value["evidence"][0]["result"]
        for index in range(7, 20):
            data["lines"][index]["code"] = "def make_record(value):" if index == 7 else "    # visible helper context"
        request = source_window_continuations(value)[0]
        self.assertEqual(request["boundary_line"], 128)
        self.assertEqual(request["arguments"]["start_line"], 141)
        data["lines"][6]["code"] = "def make_record(value):"
        data["lines"][7]["code"] = "    # declaration is now outside the boundary allowance"
        self.assertEqual(source_window_continuations(value), [])

    def test_absent_more_flag_eof_bad_coordinates_or_failed_read_never_seed(self):
        variants = [("has_more", False), ("has_more", 1), ("total_lines", 140),
                    ("total_lines", "500"), ("commit", "HEAD"), ("end_line", 200),
                    ("path", "../outside.py")]
        for key, item in variants:
            with self.subTest(key=key, item=item):
                value = review()
                value["evidence"][0]["result"][key] = item
                self.assertEqual(source_window_continuations(value), [])
        value = review()
        value["evidence"][0]["success"] = False
        self.assertEqual(source_window_continuations(value), [])
        value = review()
        del value["evidence"][0]["result"]["has_more"]
        self.assertEqual(source_window_continuations(value), [])

    def test_uncited_tests_unreferenced_sibling_or_closed_declaration_are_not_directions(self):
        value = review()
        value["evidence"].append(receipt("E0011", "tests/other.py"))
        self.assertEqual(len(source_window_continuations(value)), 1)
        for index, code in ((1, "    return something_else(value)"), (19, "AFTER_HELPER = True")):
            value = review()
            value["evidence"][0]["result"]["lines"][index]["code"] = code
            self.assertEqual(source_window_continuations(value), [])

    def test_existing_same_sha_visible_continuation_prevents_a_repeat(self):
        value = review()
        following = {"id": "E0011", "tool": "read_file", "success": True,
            "result": {"commit": VULNERABLE, "path": "service/worker.py", "start_line": 141,
                "end_line": 141, "lines": [{"line": 141, "code": "    return original"}]}}
        value["evidence"].append(following)
        self.assertEqual(source_window_continuations(value), [])
        following["result"]["commit"] = FIXED
        self.assertEqual(len(source_window_continuations(value)), 1)

    def test_at_most_two_related_windows_clipped_to_real_file_end(self):
        value = review()
        value["evidence"].extend([receipt("E0011", "service/second.py"), receipt("E0012", "service/third.py")])
        value["field_reviews"]["critical_operation"]["evidence_refs"] = ["E0010", "E0011", "E0012"]
        value["evidence"][0]["result"]["total_lines"] = 150
        requests = source_window_continuations(value, limit=20)
        self.assertEqual(len(requests), 2)
        self.assertEqual(requests[0]["arguments"]["end_line"], 150)
        self.assertEqual(len(source_window_continuations(value, limit=1)), 1)
        value["evidence"].append(copy.deepcopy(value["evidence"][0]))
        self.assertEqual(source_window_continuations(value), [])


class ContinuationRepo(MemoryRepo):
    def call(self, tool, arguments):
        self.calls.append((tool, copy.deepcopy(arguments)))
        if tool != "read_file":
            raise AssertionError("The continuation must replace caller/comparison expansion")
        first, last = arguments["start_line"], arguments["end_line"]
        return {"commit": arguments["commit"], "path": arguments["path"],
            "start_line": first, "end_line": last, "total_lines": 500, "has_more": True,
            "lines": [{"line": line, "code": "    saved = original"} for line in range(first, last + 1)]}


class ContinuationIntegrationTests(unittest.TestCase):
    def session(self):
        client = SimpleNamespace(response_mode="staged_tool", annotation_format="assessed_tool", halted=None)
        session = _ProductionSession(job(False), client, MemoryRepo(), 16, 32)
        session.prepare()
        source = receipt()
        source = session.evidence("tool", **{key: val for key, val in source.items() if key != "id"})
        session.result["fields"]["commit"] = VULNERABLE
        session.result["field_reviews"]["critical_operation"].update(status="uncertain", evidence_refs=[source["id"]])
        session.repo = ContinuationRepo()
        return session

    def test_one_continuation_replaces_expansion_and_keeps_fields_evidence_and_review_reserve(self):
        session = self.session()
        fields, judgments, evidence = (copy.deepcopy(session.result[key]) for key in ("fields", "field_reviews", "evidence"))
        with patch("vulngym_t2.entry_navigation.navigate_entry", side_effect=AssertionError("No caller expansion")):
            session.navigate_entry_context({})
        self.assertEqual(len(session.repo.calls), 1)
        self.assertEqual(session.result["model_calls"], 0)
        self.assertEqual(session.result["tool_calls"], 1)
        self.assertEqual(session.result["fields"], fields)
        self.assertEqual(session.result["field_reviews"], judgments)
        self.assertEqual(session.result["evidence"][:-1], evidence)
        self.assertTrue(session.followup_context_fits())
        self.assertLessEqual(sum(len(row["content"]) for row in session.messages), session.navigation_context_limit())
        action = next(row for row in _saved_actions(session.result["actions"]) if row["action"] == "source_window_continuation")
        self.assertIn("next-read-v1", action["summary"])
        self.assertEqual(action["arguments"]["start_line"], 141)

    def test_no_space_or_stopped_provider_keeps_original_reserves_and_does_not_read(self):
        for reason in ("context", "tools", "provider"):
            with self.subTest(reason=reason):
                session = self.session()
                if reason == "context":
                    session.evidence("advisory", text="x" * 85000)
                    session.messages.append({"role": "user", "content": _json(session.result["evidence"])})
                elif reason == "tools":
                    session.max_tool_calls = 2
                else:
                    session.client.halted = "stopped"
                session.navigate_entry_context({})
                self.assertEqual(session.repo.calls, [])
                self.assertEqual(session.result["tool_calls"], 0)
                self.assertEqual(session.source_continuation_attempts, set())
                self.assertTrue(any(row["action"] == "source_window_continuation_skipped" for row in session.result["actions"]))

    def test_input_wide_two_read_limit_cannot_reset_between_candidates(self):
        session = self.session()
        for i in range(3):
            source = receipt(path=f"service/worker_{i}.py")
            source = session.evidence("tool", **{key: val for key, val in source.items() if key != "id"})
            session.result["field_reviews"]["critical_operation"]["evidence_refs"] = [source["id"]]
            # No selected EP/CO location, so the old navigator has no alternative seed.
            session.navigate_entry_context({})
        self.assertEqual(len(session.source_continuation_attempts), 2)
        self.assertEqual(len(session.repo.calls), 2)

    def test_revision_guidance_uses_exact_sha_and_existing_local_scope_rule(self):
        self.assertIn("copy a revision's full SHA exactly from its receipt", annotation_rules.TASK_RULES)
        self.assertIn('does not establish "no guards" globally', " ".join(annotation_rules.TASK_RULES.split()))


if __name__ == "__main__":
    unittest.main()
