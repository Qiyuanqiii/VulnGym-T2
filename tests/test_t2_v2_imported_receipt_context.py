"""Receipt-only import context uses synthetic source, never annotation fields."""
import copy
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from tests.test_t2_v2_imported_call_navigation import SHA, OTHER, SOURCE, TARGET, source
from tests import test_t2_v2_sequential_followup as sequential
from tests.test_t2_v2_pipeline import job
from vulngym_t2.imported_call_navigation import imported_receipt_context
from vulngym_t2.pipeline import _ProductionSession, _READ_CONTEXT_LIMIT, _json


BODY = ["@bound.capture", "def entry(args):", "    return Record.from_json(args)"]
ORIGIN = {"commit": SHA, "path": SOURCE, "start_line": 200, "end_line": 202}
HEAD = ["# module header"] * 120
HEAD[7] = "from sample.helpers import audit as bound"


def body(lines=None):
    row = source("E0002", BODY if lines is None else lines, first=200)
    row["arguments"] = {**ORIGIN, "end_line": row["result"]["end_line"]}
    return row


class ImportedReceiptSelectorTests(unittest.TestCase):
    def partial_window(self):
        lines = ["# observed module context"] * 287
        lines[7] = "from sample.helpers import audit as bound"
        lines[204:207] = ["@bound.capture", "def entry(args):", "    return args"]
        lines[279] = "last_complete = 1"
        lines[280:282] = ["unfinished = build(", "    value,"]
        head = source("E0001", lines[:112])
        window = source("E0002", lines[111:], first=112)
        return head, window

    def test_contiguous_saved_prefix_preserves_decorator_before_unclosed_window_tail(self):
        head, window = self.partial_window()
        original = copy.deepcopy((head, window))
        context = imported_receipt_context(window, [head, window])
        self.assertEqual(context["seed"]["arguments"], {"commit": SHA, "query": "def capture"})
        self.assertEqual(context["seed"]["source_line"], 205)
        self.assertEqual(context["seed"]["evidence_refs"], ["E0001", "E0002"])
        self.assertIsNone(context["header"])
        self.assertIs(context["seed"]["semantic_approval"], False)
        self.assertEqual((head, window), original)

    def test_partial_tail_is_not_recovered_across_unknown_or_other_sha_prefix_gap(self):
        head, window = self.partial_window()
        self.assertIsNone(imported_receipt_context(window, [window]))
        head["result"]["commit"] = OTHER
        self.assertIsNone(imported_receipt_context(window, [head, window]))
        head = source("E0001", ["from sample.helpers import audit as bound"] * 110)
        self.assertIsNone(imported_receipt_context(window, [head, window]))

    def test_visible_string_start_before_new_window_does_not_become_a_decorator(self):
        lines = ["from sample.helpers import audit as bound", 'example = """',
                 "@bound.capture", "def example(): pass", '"""', "unfinished = build("]
        head = source("E0001", lines[:2])
        window = source("E0002", lines[2:], first=3)
        self.assertIsNone(imported_receipt_context(window, [head, window]))

    def test_incomplete_call_and_any_uses_after_first_lexical_error_are_not_anchors(self):
        head = source("E0001", ["from sample.helpers import audit as bound"])
        for lines in (["@bound.capture("], ["bound.capture("],
                      ["broken = '\\", "@bound.capture", "def entry(): pass"]):
            window = source("E0002", lines, first=2)
            self.assertIsNone(imported_receipt_context(window, [head, window]))
        window = source("E0002", ["@bound.capture", "def entry(): pass", "broken = '",
                                  "@other.different", "def unseen(): pass"], first=2)
        context = imported_receipt_context(window, [head, window])
        self.assertEqual(context["seed"]["qualified_name"], "bound.capture")

    def test_missing_header_and_real_import_seed_require_no_fields_or_proposals(self):
        row = body()
        original = copy.deepcopy(row)
        request = imported_receipt_context(row, [row])
        self.assertEqual(request["header"], {"commit": SHA, "path": SOURCE, "start_line": 1, "end_line": 120})
        self.assertIsNone(request["seed"])
        self.assertEqual(request["evidence_refs"], [row["id"]])
        head = source("E0003", HEAD)
        resolved = imported_receipt_context(row, [row, head])
        self.assertIsNone(resolved["header"])
        self.assertEqual(resolved["seed"]["arguments"], {"commit": SHA, "query": "def capture"})
        self.assertEqual(resolved["seed"]["module_candidate"], "sample.helpers.audit")
        self.assertEqual(resolved["seed"]["evidence_refs"], ["E0002", "E0003"])
        self.assertNotIn("field", resolved["seed"])
        self.assertIs(resolved["seed"]["semantic_approval"], False)
        self.assertIs(resolved["seed"]["shadowing_proof"], False)
        self.assertEqual(row, original)

    def test_unique_decorator_precedes_other_calls_but_ambiguous_decorators_are_rejected(self):
        row = body(BODY + ["    warnings.warn('notice')"])
        self.assertEqual(imported_receipt_context(row, [row])["qualified_name"], "bound.capture")
        for lines in (["@bound.capture", "@other.second", "def entry(args): pass"],
                      ["first.run(value)", "second.run(value)"]):
            row = body(lines)
            self.assertIsNone(imported_receipt_context(row, [row]))
        row = body(["bound.capture(value)"])
        self.assertEqual(imported_receipt_context(row, [row])["qualified_name"], "bound.capture")

    def test_strings_comments_incomplete_tokens_and_visible_local_objects_do_not_spend_header_read(self):
        for lines in (["# @bound.capture"], ['text = "bound.capture(value)"'],
                      ['text = """', "@bound.capture", "def entry(): pass", '"""'],
                      ["@bound.capture", 'text = """'],
                      ["self.capture(value)"], ["cls.capture(value)"],
                      ["def entry(bound):", "    bound.capture(value)"],
                      ["bound = build()", "bound.capture(value)"]):
            with self.subTest(lines=lines):
                row = body(lines)
                self.assertIsNone(imported_receipt_context(row, [row]))

    def test_existing_binding_rebinding_conflict_or_missing_same_sha_header_is_not_guessed(self):
        row = body()
        for lines in (["from other import audit as bound", "from sample.helpers import audit as bound"],
                      ["from sample.helpers import audit as bound", "bound = replacement"]):
            head = source("E0003", lines)
            self.assertIsNone(imported_receipt_context(row, [row, head]))
        head = source("E0003", HEAD, commit=OTHER)
        self.assertIsNone(imported_receipt_context(row, [row, head])["seed"])
        self.assertIsNone(imported_receipt_context(row, [row, source("E0003", ["different"], first=200)]))

    def test_header_gap_is_bounded_and_previously_attempted_interval_is_not_retried(self):
        row = body()
        partial = source("E0003", ["# prefix"] * 5)
        self.assertEqual(imported_receipt_context(row, [row, partial])["header"]["start_line"], 6)
        failed = {"id": "E0004", "tool": "read_file", "success": False,
                  "arguments": {"commit": SHA, "path": SOURCE, "start_line": 1, "end_line": 120},
                  "result": {"error": "failed"}}
        self.assertIsNone(imported_receipt_context(row, [row, failed]))
        full = source("E0003", ["# no binding"] * 120)
        self.assertIsNone(imported_receipt_context(row, [row, full]))

    def test_only_unchanged_real_python_receipt_and_valid_evidence_identity_are_accepted(self):
        row = body()
        for changed in ({**row, "success": False}, {**row, "id": "missing"},
                        {**row, "result": {**row["result"], "commit": "HEAD"}},
                        {**row, "result": {**row["result"], "path": "../source.py"}},
                        {**row, "result": {**row["result"], "path": "source.js"}}):
            self.assertIsNone(imported_receipt_context(changed, [changed]))
        self.assertIsNone(imported_receipt_context(row, [row, copy.deepcopy(row)]))
        self.assertIsNone(imported_receipt_context({**row, "success": False}, [row]))


class ContextRepo(sequential.ChainRepo):
    def __init__(self):
        super().__init__()
        self.fail_header = False
        self.complete_search = True

    def call(self, tool, arguments):
        if tool == "read_file" and arguments.get("path") in (SOURCE, TARGET):
            self.calls.append((tool, copy.deepcopy(arguments)))
            first, last = arguments["start_line"], arguments["end_line"]
            if arguments["path"] == SOURCE:
                if first == 1 and self.fail_header:
                    return {"error": "source_file_unavailable"}
                lines = HEAD[first - 1:last] if first < 200 else BODY[first - 200:last - 199]
            else:
                lines = ["def capture(fn):" if line == 50 else "    return fn" if line == 51 else ""
                         for line in range(first, last + 1)]
            return source("E0000", lines, path=arguments["path"], first=first)["result"]
        if tool == "search_code" and arguments.get("query") == "def capture":
            self.calls.append((tool, copy.deepcopy(arguments)))
            return {**arguments, "paths": None, "complete": self.complete_search,
                    "truncated": not self.complete_search, "skipped_count": 0,
                    "matches": [{"file": TARGET, "line": 50, "code": "def capture(fn):"}]}
        return super().call(tool, arguments)


class ImportedReceiptControllerTests(unittest.TestCase):
    def session(self, *, drafted=True):
        client = SimpleNamespace(response_mode="staged_tool", annotation_format="assessed_tool",
                                 remaining_requests=16, halted=None, multi_entry=False)
        session = _ProductionSession(job(False), client, ContextRepo(), 12, 24)
        session.prepare()
        session.drafted = drafted
        receipt = session.read_tool("read_file", ORIGIN)
        session.messages.append({"role": "user", "content": _json({"tool_results": [receipt]})})
        return session, receipt

    def test_header_search_source_once_shared_with_existing_flag_and_no_field_changes(self):
        session, receipt = self.session()
        original = copy.deepcopy((session.result["fields"], session.result["field_reviews"]))
        with patch.object(session, "read_tool", wraps=session.read_tool) as reads:
            session.navigate_imported_context([receipt])
        self.assertEqual([call.kwargs["navigation_display_limit"] for call in reads.call_args_list], [4000, 4000, 8000])
        self.assertEqual([row["action"] for row in session.result["actions"] if row["action"].startswith("imported_context")],
                         ["imported_context_header", "imported_context_search", "imported_context_source"])
        self.assertTrue(session.imported_call_attempted)
        self.assertEqual(session.result["tool_calls"], 4)  # Origin plus at most three navigation reads.
        self.assertEqual(session.result["model_calls"], 0)
        self.assertEqual((session.result["fields"], session.result["field_reviews"]), original)
        session.navigate_imported_context([receipt])
        self.assertEqual(session.result["tool_calls"], 4)

    def test_known_header_needs_only_search_and_source(self):
        session, receipt = self.session()
        session.evidence("tool", tool="read_file", success=True, result=source("E0000", HEAD)["result"])
        session.navigate_imported_context([receipt])
        self.assertEqual(session.result["tool_calls"], 3)
        self.assertFalse(any(row["action"] == "imported_context_header" for row in session.result["actions"]))

    def test_failure_or_truncated_search_stops_without_retry_or_invented_binding(self):
        for failure, tools in (("fail_header", 2), ("complete_search", 3)):
            session, receipt = self.session()
            setattr(session.repo, failure, failure == "fail_header")
            session.navigate_imported_context([receipt])
            session.navigate_imported_context([receipt])
            self.assertEqual(session.result["tool_calls"], tools)
            self.assertTrue(session.imported_call_attempted)
            self.assertFalse(any(row["action"] == "imported_context_source" for row in session.result["actions"]))

    def test_provider_local_global_tool_context_and_later_reserves_are_never_bypassed(self):
        for reason in ("provider", "local", "global", "tool", "context", "reserved", "initial_context"):
            with self.subTest(reason=reason):
                session, receipt = self.session(drafted=reason != "initial_context")
                reserved = 0
                if reason == "provider":
                    session.client.halted = "stopped"
                elif reason == "local":
                    session.result["model_calls"] = session.max_calls - 2
                elif reason == "global":
                    session.client.remaining_requests = 2
                elif reason == "tool":
                    session.max_tool_calls = 5  # Origin leaves fewer than 3 + 2 calls.
                elif reason == "reserved":
                    reserved = 10
                else:
                    session.messages.append({"role": "user", "content": "x" * _READ_CONTEXT_LIMIT})
                with patch.object(session, "compact_candidate_context"):
                    session.navigate_imported_context([receipt], reserved_calls=reserved)
                self.assertEqual(session.result["tool_calls"], 1)
                self.assertTrue(any(row["action"] == "imported_context_skipped" for row in session.result["actions"]))

    def test_legacy_multi_prior_attempt_and_reused_receipts_do_not_enter_new_navigation(self):
        for reason in ("legacy", "multi", "attempted", "reused"):
            session, receipt = self.session()
            if reason == "legacy":
                session.staged_mode = False
            elif reason == "multi":
                session.multi_mode = True
            elif reason == "attempted":
                session.imported_call_attempted = True
            else:
                receipt = {"reused_evidence_ref": receipt["id"]}
            session.navigate_imported_context([receipt])
            self.assertEqual(session.result["tool_calls"], 1)

    def test_last_third_model_followup_can_resolve_import_without_fourth_decision_or_old_navigation(self):
        requests = [sequential.read_request(("search_code", {"commit": SHA, "query": "first"})),
                    sequential.read_request(("search_code", {"commit": SHA, "query": "second"})),
                    sequential.read_request(("read_file", ORIGIN))]
        session, calls, navigation, pending = sequential.FollowupLoopTests().run_session(requests, repo=ContextRepo())
        self.assertEqual([stage for stage, _ in calls], ["evidence_followup"] * 3 + ["self_review"])
        self.assertEqual(len(navigation), 1)  # Only the existing initial navigation, never a late replay.
        self.assertEqual(pending, [])
        self.assertTrue(any(row["action"] == "imported_context_source" for row in session.result["actions"]))
        self.assertEqual(session.result["self_review_status"], "completed")

    def test_initial_read_batch_runs_receipt_navigation_before_next_model_decision(self):
        session, _ = self.session(drafted=False)
        # Use a fresh initial session: the origin must be a new actual receipt.
        session = _ProductionSession(job(False), session.client, ContextRepo(), 12, 24)
        session.prepare()
        sequence = []
        def complete(stage):
            sequence.append(stage)
            session.result["model_calls"] += 1
            if len(sequence) == 1:
                return sequential.read_request(("read_file", ORIGIN))
            self.assertTrue(any(row["action"] == "imported_context_source" for row in session.result["actions"]))
            return None
        with patch.object(session, "complete", side_effect=complete):
            session.read_and_draft()
        self.assertEqual(sequence, ["plan_and_read", "plan_and_read"])


if __name__ == "__main__":
    unittest.main()
