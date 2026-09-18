"""Regression checks for v7's real-history integration failures, without HTTP."""
import copy
import json
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from vulngym_t2 import staged_protocol
from vulngym_t2.pipeline import _ProductionSession, _json
from vulngym_t2.entry_navigation import entry_navigation_seed, public_navigation_report, VERSION
from vulngym_t2.output import _saved_actions
from vulngym_t2.prompt_evidence import bounded_navigation_result, display_record
from tests import test_t2_v2_staged_pipeline as fixture
from tests.test_t2_v2_entry_navigation import NavigationRepo, SOURCES, review_fixture
from tests.test_t2_v2_pipeline import VULNERABLE, job, evidence_from


def long_read():
    lines = [{"line": n, "code": f'  value_{n} = "\t字符 {n}";'} for n in range(100, 200)]
    return {"id": "E0040", "tool": "read_file", "success": True,
            "result": {"commit": VULNERABLE, "path": "src/source.ts", "start_line": 100, "end_line": 199,
                       "lines": lines, "text": "\n".join(row["code"] for row in lines), "total_lines": 250}}


class NavigationDisplayTests(unittest.TestCase):
    def test_numbered_text_preserves_every_source_byte_coordinate_and_receipt(self):
        receipt = long_read()
        original = copy.deepcopy(receipt)
        shown = display_record(receipt, compact=True)
        self.assertNotIn("lines", shown["result"])
        self.assertNotIn("text", shown["result"])
        decoded = [[int(number), code] for number, code in
                   (line.split(": ", 1) for line in shown["result"]["numbered_source"].split("\n"))]
        self.assertEqual(decoded, [[row["line"], row["code"]] for row in receipt["result"]["lines"]])
        self.assertEqual(shown["id"], receipt["id"])
        self.assertEqual(shown["result"]["commit"], VULNERABLE)
        self.assertEqual(receipt, original)

    def test_bounded_display_keeps_only_contiguous_visible_source_in_storage(self):
        value = long_read()["result"]
        bounded = bounded_navigation_result(value, 1500)
        shown = display_record({"result": bounded}, compact=True)["result"]
        self.assertLessEqual(len(json.dumps(shown, ensure_ascii=False, sort_keys=True, separators=(",", ":"))), 1500)
        self.assertTrue(bounded["truncated"])
        self.assertLess(bounded["end_line"], value["end_line"])
        self.assertEqual(bounded["end_line"], bounded["start_line"] + len(bounded["lines"]) - 1)
        self.assertEqual(bounded["text"], "\n".join(row["code"] for row in bounded["lines"]))
        self.assertEqual(bounded["lines"], value["lines"][:len(bounded["lines"])])

    def test_clipped_search_is_not_reported_complete_and_does_not_mutate_input(self):
        value = {"commit": VULNERABLE, "query": "gate", "complete": True,
                 "matches": [{"file": f"src/file{i}.ts", "line": 2, "code": "gate(ctx);"} for i in range(100)]}
        original = copy.deepcopy(value)
        bounded = bounded_navigation_result(value, 900)
        self.assertFalse(bounded["complete"])
        self.assertTrue(bounded["truncated"])
        self.assertLess(len(bounded["matches"]), 100)
        self.assertEqual(value, original)

    def test_oversized_metadata_is_failure_not_invisible_success(self):
        value = {"commit": VULNERABLE, "query": "gate", "other": "x" * 9000, "matches": []}
        self.assertEqual(bounded_navigation_result(value, 4000)["error_code"], "navigation_display_limit")

    def test_failure_flags_and_malformed_source_are_not_repaired_by_display(self):
        receipt = long_read()
        receipt.update(success=False)
        receipt["result"]["lines"][1]["line"] += 1
        shown = display_record(receipt, compact=True)
        self.assertFalse(shown["success"])
        self.assertIn("lines", shown["result"])
        self.assertNotIn("numbered_source", shown["result"])

    def test_only_duplicate_successful_request_coordinates_are_omitted(self):
        receipt = long_read()
        receipt["arguments"] = {"commit": VULNERABLE, "path": "src/source.ts", "start_line": 100, "end_line": 299}
        self.assertEqual(display_record(receipt, compact=True)["arguments"], {"end_line": 299})
        receipt["success"] = False
        self.assertEqual(display_record(receipt, compact=True)["arguments"], receipt["arguments"])


class NavigationSeedWhitespaceTests(unittest.TestCase):
    def make_review(self, lines, end):
        review = review_fixture()
        review["evidence"][0]["result"].update(start_line=255, end_line=254 + len(lines),
            lines=[{"line": 255 + index, "code": code} for index, code in enumerate(lines)], text="\n".join(lines))
        review["suggested_values"]["entry_point"].update(start_line=255, end_line=end)
        return review

    def test_leading_blank_inside_selected_span_finds_following_declaration(self):
        review = self.make_review(["", "export async function gate(params) {", "  return params.ok;"], 257)
        original = copy.deepcopy(review)
        self.assertEqual(entry_navigation_seed(review)["line"], 256)
        self.assertEqual(entry_navigation_seed(review)["symbol"], "gate")
        self.assertEqual(review, original)

    def test_no_scan_beyond_selected_visible_span(self):
        review = self.make_review(["", "function gate(ctx) {"], 255)
        self.assertIsNone(entry_navigation_seed(review))
        review["suggested_values"]["entry_point"]["end_line"] = 260
        review["evidence"][0]["result"].update(end_line=255, lines=[{"line": 255, "code": ""}], text="")
        self.assertIsNone(entry_navigation_seed(review))

    def test_no_forward_scan_across_comment_executable_line_or_more_than_eight_blanks(self):
        for lines in (["// not a declaration", "function gate(ctx) {"],
                      ["perform(ctx);", "function gate(ctx) {"],
                      [""] * 9 + ["function gate(ctx) {"]):
            with self.subTest(lines=lines):
                self.assertIsNone(entry_navigation_seed(self.make_review(lines, 254 + len(lines))))


class NavigationActionExportTests(unittest.TestCase):
    def report(self):
        return {"action": "entry_navigation", "version": VERSION, "stop_reason": "budget_reserved",
                "semantic_approval": False, "seed": {"commit": VULNERABLE, "path": "src/helper.ts", "line": 2,
                    "field": "critical_operation", "symbol": "gate", "evidence_ref": "E0009"},
                "steps": [{"tool": "search_code", "arguments": {"commit": VULNERABLE, "query": "gate"},
                           "success": True, "evidence_ref": "E0010"}],
                "budget": {"context_chars": 71000, "context_limit": 76000, "remaining_tool_calls": 24,
                           "reason": "context_budget"}}

    def test_saved_action_keeps_stop_reason_steps_seed_and_measured_budget(self):
        report = self.report()
        self.assertEqual(_saved_actions([report]), [report])

    def test_public_report_drops_arbitrary_payloads_and_cannot_claim_approval(self):
        report = self.report()
        report.update(secret="credential-value", semantic_approval=True)
        report["seed"].update(path="C:/Users/private/source.ts", code="hidden source", unexpected="payload")
        report["steps"][0]["arguments"].update(query="gate(); arbitrary payload", raw="secret")
        report["budget"].update(reason="untrusted arbitrary text", raw="payload")
        saved = json.dumps(public_navigation_report(report))
        self.assertNotIn("private", saved)
        self.assertNotIn("payload", saved)
        self.assertNotIn("hidden source", saved)
        self.assertNotIn("credential", saved)
        self.assertIs(public_navigation_report(report)["semantic_approval"], False)

    def test_context_compaction_measurements_survive_export(self):
        action = {"action": "evidence_context_compacted", "before_chars": 80000, "after_chars": 41000,
                  "evidence_count": 11, "scope_retained": True}
        self.assertEqual(_saved_actions([action]), [action])


class BulkyNavigationRepo(NavigationRepo):
    def call(self, tool, arguments):
        if tool == "read_diff":
            self.calls.append((tool, copy.deepcopy(arguments)))
            return {"before": arguments["before"], "after": arguments["after"], "diff": "d" * 14000}
        result = super().call(tool, arguments)
        if tool == "read_file" and arguments.get("end_line", 0) >= 16:
            # Exercise compact display and stored-receipt navigation together;
            # a three-line fixture alone cannot expose that integration error.
            while result["end_line"] < min(arguments["end_line"], 30):
                result["end_line"] += 1
                result["lines"].append({"line": result["end_line"], "code": "// additional visible context"})
            result["total_lines"] = result["end_line"]
            result["text"] = "\n".join(row["code"] for row in result["lines"])
        return result


class ContextCompactionTests(unittest.TestCase):
    def session(self):
        client = SimpleNamespace(response_mode="staged_tool", multi_entry=True, halted=None)
        session = _ProductionSession(job(False), client, fixture.MemoryRepo(), 16, 32)
        session.prepare()
        return session

    def test_scope_source_current_decisions_and_uncertainty_survive_compaction(self):
        session = self.session()
        receipt = long_read()
        session.evidence("tool", **{key: val for key, val in receipt.items() if key != "id"})
        session.active_candidate_scope = {"slot": 2, "scope": "Only this selected candidate", "evidence_refs": ["E0001"]}
        session.result["field_reviews"]["entry_point"].update(
            status="uncertain", reason="Evidence does not establish the external entry.")
        session.messages.append({"role": "assistant", "content": "Obsolete planning notes. " * 4000})
        original = copy.deepcopy(session.result)
        snapshot = copy.deepcopy(session.prompt_draft())
        checks = {"entry_point": {"issues": [{"code": "supported_reason_conflict"}]}}
        session.compact_candidate_context(checks)
        self.assertEqual(session.result["evidence"], original["evidence"])
        self.assertEqual(session.result["fields"], original["fields"])
        self.assertEqual(session.result["field_reviews"], original["field_reviews"])
        body = json.loads(session.messages[1]["content"])
        self.assertEqual(body["candidate_scope"], session.active_candidate_scope)
        self.assertEqual(body["support_consistency_checks"], checks)
        self.assertEqual([row["id"] for row in body["evidence"]], [row["id"] for row in original["evidence"]])
        self.assertEqual(body["evidence"][-1]["result"]["numbered_source"],
                         "\n".join(f"{row['line']}: {row['code']}" for row in receipt["result"]["lines"]))
        self.assertEqual(json.loads(session.messages[2]["content"]), snapshot)

    def test_evidence_that_cannot_fit_stops_with_measured_reason_and_no_read(self):
        session = self.session()
        fixture_review = review_fixture()
        receipt = session.evidence("tool", **{key: val for key, val in fixture_review["evidence"][0].items() if key != "id"})
        session.result["fields"]["commit"] = VULNERABLE
        session.result["field_reviews"]["entry_point"].update(status="uncertain", evidence_refs=[receipt["id"]],
            suggested_value={"evidence_ref": receipt["id"], "start_line": 1, "end_line": 1})
        session.evidence("advisory", text="x" * 85000)
        session.messages.append({"role": "user", "content": _json(session.result["evidence"])})
        session.navigate_entry_context({})
        report = next(row for row in session.result["actions"] if row["action"] == "entry_navigation")
        self.assertEqual(report["stop_reason"], "budget_reserved")
        self.assertEqual(report["budget"]["reason"], "context_budget")
        self.assertGreater(report["budget"]["context_chars"], 80928)
        self.assertEqual(report["steps"], [])
        self.assertEqual(session.result["tool_calls"], 0)

    def test_navigation_reclaims_duplicate_messages_between_hops_without_losing_evidence(self):
        session = self.session()
        session.repo = NavigationRepo()
        source = review_fixture()["evidence"][0]
        receipt = session.evidence("tool", **{key: val for key, val in source.items() if key != "id"})
        session.result["fields"]["commit"] = VULNERABLE
        session.result["field_reviews"]["entry_point"].update(status="uncertain", evidence_refs=[receipt["id"]],
            suggested_value={"evidence_ref": receipt["id"], "start_line": 1, "end_line": 1})
        session.active_candidate_scope = {"slot": 1, "scope": "Original candidate only", "evidence_refs": [receipt["id"]]}
        fields, judgments = copy.deepcopy(session.result["fields"]), copy.deepcopy(session.result["field_reviews"])
        execute = session.read_tool
        contexts = []
        def repeated_display(*args, **kwargs):
            contexts.append(sum(len(row["content"]) for row in session.messages))
            result = execute(*args, **kwargs)
            # Duplicate display of real synthetic receipts, never extra facts.
            # Each hop must reclaim it before checking the next read's budget.
            rendered = _json(result)
            session.messages.append({"role": "user", "content": rendered * (85000 // len(rendered) + 1)})
            return result
        with patch.object(session, "read_tool", side_effect=repeated_display):
            session.navigate_entry_context({})
        self.assertTrue(any(args.get("path") == "src/provider.ts" for _, args in session.repo.calls))
        self.assertTrue(all(count <= 84000 - 3072 for count in contexts))
        self.assertLessEqual(len(contexts), 8)
        self.assertGreater(len(contexts), 2)
        self.assertEqual(session.result["model_calls"], 0)
        self.assertEqual(session.result["fields"], fields)
        self.assertEqual(session.result["field_reviews"], judgments)
        self.assertEqual(session.result["evidence"][3], receipt)
        compactions = [row for row in session.result["actions"] if row["action"] == "evidence_context_compacted"]
        self.assertGreater(len(compactions), 1)
        self.assertTrue(all(row["scope_retained"] for row in compactions))


class RealisticHistoryNavigationTests(unittest.TestCase):
    setUp = fixture.StagedPipelineTests.setUp
    run_script = fixture.StagedPipelineTests.run_script

    def test_large_original_evidence_still_navigates_and_reaches_review_in_same_call_budget(self):
        def uncertain(payload):
            tool, snapshot = fixture.full_annotation(payload)
            snapshot["entry_point"].update(status="uncertain", reason="Only the helper has been read; needs caller evidence.")
            return tool, snapshot

        def final_review(payload):
            reads = [row for row in evidence_from(payload["messages"]) if row.get("tool") == "read_file"]
            self.assertTrue(any(row["result"]["path"] == "src/provider.ts" for row in reads))
            original_diff = next(row for row in evidence_from(payload["messages"]) if row.get("tool") == "read_diff")
            self.assertEqual(original_diff["result"]["diff"], "d" * 14000)
            return uncertain(payload)  # Reads never automatically approve the annotation.

        supplied = job(False)
        supplied["documents"] = [{"name": "advisory", "text": supplied["documents"][0]["text"] + "a" * 11000},
                                 {"name": "support", "text": "b" * 11000}]
        read = ("read_file", {"commit": VULNERABLE, "path": "src/helper.ts", "start_line": 1, "end_line": 3})
        diff = ("read_diff", {"before": VULNERABLE, "after": "b" * 40, "path": ""})
        with patch.object(fixture, "MemoryRepo", BulkyNavigationRepo):
            result, final, client, repo, payloads = self.run_script(
                [read, diff, fixture.FINISH, uncertain, fixture.FINISH, final_review],
                max_calls=6, supplied=supplied)
        self.assertIsNone(client.halted)
        report = next(row for row in result["actions"] if row["action"] == "entry_navigation")
        self.assertGreater(len(report["steps"]), 0)
        self.assertTrue(any(args.get("path") == "src/provider.ts" for _, args in repo.calls))
        self.assertEqual(result["model_calls"], 6)
        self.assertEqual(result["self_review_status"], "completed")
        compaction = next(row for row in result["actions"] if row["action"] == "evidence_context_compacted")
        self.assertGreater(compaction["before_chars"], 42928)
        self.assertLess(compaction["after_chars"], compaction["before_chars"])
        self.assertTrue(any("numbered_source" in row.get("result", {})
                            for row in evidence_from(payloads[-1]["messages"])))
        self.assertIsNone(final["entry"])
        saved = next(row for row in final["review"]["actions"] if row["action"] == "entry_navigation")
        self.assertIn("budget", saved)
        self.assertIn("stop_reason", saved)
        for payload in payloads:
            self.assertLessEqual(sum(len(message["content"]) for message in payload["messages"]), 100000)


if __name__ == "__main__":
    unittest.main()
