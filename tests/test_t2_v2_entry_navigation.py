"""Source navigation and annotation stay separate, using only fixture bytes."""
import copy
import unittest
from unittest.mock import patch

from vulngym_t2.entry_navigation import entry_navigation_seed, navigate_entry
from tests import test_t2_v2_staged_pipeline as fixture
from tests.test_t2_v2_pipeline import VULNERABLE, FIXED, evidence_from


SOURCES = {
    "src/helper.ts": ["export function gate(ctx) {", "  return ctx.allowed;", "}"],
    "src/widgets.ts": ["class Widget extends Component {", "  async run(ctx) {", "    gate(ctx);", "  }", "}",
                       "export function makeWidget(ctx) {", "  return new Widget(ctx);", "}"],
    "src/provider.ts": ["const components = [makeWidget(ctx)];", "new Client({components});"],
}


def source_record(identity, path, first=1, last=None, commit=VULNERABLE):
    last = min(last or len(SOURCES[path]), len(SOURCES[path]))
    lines = [{"line": index, "code": SOURCES[path][index - 1]} for index in range(first, last + 1)]
    return {"id": identity, "tool": "read_file", "success": True,
            "result": {"commit": commit, "path": path, "start_line": first, "end_line": last,
                       "total_lines": len(SOURCES[path]), "lines": lines,
                       "text": "\n".join(item["code"] for item in lines)}}


def review_fixture():
    return {"draft_fields": {"commit": VULNERABLE}, "suggested_values": {
                "entry_point": {"evidence_ref": "E0001", "start_line": 1, "end_line": 1}},
            "field_reviews": {"entry_point": {"status": "uncertain", "evidence_refs": ["E0001"]}},
            "evidence": [source_record("E0001", "src/helper.ts")]}


class NavigationRepo(fixture.MemoryRepo):
    sources = SOURCES

    def call(self, tool, arguments):
        self.calls.append((tool, copy.deepcopy(arguments)))
        if tool == "read_file":
            return source_record("unused", arguments["path"], arguments.get("start_line", 1),
                                 arguments.get("end_line"), arguments["commit"])["result"]
        if tool == "search_code":
            return {"commit": arguments["commit"], "query": arguments["query"],
                    "matches": [{"file": path, "line": index, "code": code}
                                for path, lines in SOURCES.items() for index, code in enumerate(lines, 1)
                                if arguments["query"] in code]}
        raise AssertionError("Unexpected fixture tool: " + tool)


class EntryNavigationTests(unittest.TestCase):
    def test_observed_nearby_factory_declaration_reduces_the_window_not_the_evidence_checks(self):
        lines = ["// filler"] * 120 + ["export function makeWidget(ctx): Widget {", "  return new Widget(ctx);", "}"]
        with patch.dict(SOURCES, {"src/widgets.ts": lines}):
            data = review_fixture()
            data["suggested_values"]["entry_point"] = {"evidence_ref": "E0001", "start_line": 1, "end_line": 1}
            source = data["evidence"][0]["result"]
            source.update(path="src/widget.ts", lines=[{"line": 1, "code": "class Widget {"}],
                          text="class Widget {", start_line=1, end_line=1, total_lines=1)
            calls = []
            def execute(tool, arguments):
                calls.append((tool, copy.deepcopy(arguments)))
                if tool == "search_code":
                    return {"id": "E0002", "tool": tool, "success": True, "result": {
                        "commit": VULNERABLE, "query": "Widget", "matches": [
                            {"file": "src/widgets.ts", "line": 121, "code": lines[120]},
                            {"file": "src/widgets.ts", "line": 122, "code": lines[121]}]}}
                return source_record("E0003", "src/widgets.ts", arguments["start_line"], arguments["end_line"])
            before = copy.deepcopy(data)
            navigate_entry(data, execute, lambda: len(calls) < 2)
            self.assertEqual(calls[1][1]["start_line"], 113)
            self.assertEqual(calls[1][1]["end_line"], 153)
            self.assertEqual(data, before)

    def test_closed_inner_callback_is_not_the_owner_of_a_later_operation(self):
        lines = ["export async function gate(ctx) {", "  const reply = async () => {",
                 "    respond(ctx);", "  };", "  if (ctx.denied) {", "    await reply();", "  }", "}"]
        review = review_fixture()
        review["evidence"][0]["result"].update(end_line=8, total_lines=8, text="\n".join(lines),
            lines=[{"line": n, "code": code} for n, code in enumerate(lines, 1)])
        for line, owner in ((3, "reply"), (5, "gate"), (6, "gate")):
            with self.subTest(line=line):
                review["suggested_values"]["entry_point"].update(start_line=line, end_line=line)
                self.assertEqual(entry_navigation_seed(review)["symbol"], owner)

    def test_python_nested_function_after_dedent_does_not_own_later_block(self):
        lines = ["def gate(ctx):", "    def reply():", "        respond(ctx)",
                 "    if ctx.denied:", "        reply()"]
        review = review_fixture()
        review["evidence"][0]["result"].update(path="src/helper.py", end_line=5, total_lines=5, text="\n".join(lines),
            lines=[{"line": n, "code": code} for n, code in enumerate(lines, 1)])
        review["suggested_values"]["entry_point"].update(start_line=5, end_line=5)
        self.assertEqual(entry_navigation_seed(review)["symbol"], "gate")

    def run_navigation(self, review, limit=8, transform=None):
        repo = NavigationRepo()

        def execute(tool, arguments):
            data = repo.call(tool, arguments)
            row = {"id": f"E{len(review['evidence']) + 1:04}", "tool": tool,
                   "arguments": copy.deepcopy(arguments), "success": True, "result": data}
            if transform:
                transform(row)
            review["evidence"].append(row)
            return row

        report = navigate_entry(review, execute, lambda: len(repo.calls) < limit)
        return report, repo

    def test_walks_helper_callback_factory_registration_without_changing_annotation(self):
        review = review_fixture()
        fields, assessments = copy.deepcopy(review["draft_fields"]), copy.deepcopy(review["field_reviews"])
        report, repo = self.run_navigation(review)
        self.assertEqual([args["query"] for tool, args in repo.calls if tool == "search_code"],
                         ["gate", "Widget", "makeWidget"])
        self.assertEqual([args["path"] for tool, args in repo.calls if tool == "read_file"],
                         ["src/widgets.ts", "src/widgets.ts", "src/provider.ts"])
        self.assertFalse(report["semantic_approval"])
        self.assertEqual(report["stop_reason"], "enclosing_symbol_not_visible")
        self.assertEqual(review["draft_fields"], fields)
        self.assertEqual(review["field_reviews"], assessments)
        for _, args in repo.calls:
            self.assertEqual(args["commit"], VULNERABLE)

    def test_budget_checked_before_every_call_including_between_search_and_read(self):
        for limit in range(6):
            with self.subTest(limit=limit):
                report, repo = self.run_navigation(review_fixture(), limit)
                self.assertEqual(len(repo.calls), limit)
                self.assertEqual(report["stop_reason"], "budget_reserved")

    def test_failed_read_stops_without_retry(self):
        def fail(row):
            row.update(success=False, result={"error": "fixture_unavailable"})
        report, repo = self.run_navigation(review_fixture(), transform=fail)
        self.assertEqual(len(repo.calls), 1)
        self.assertEqual(report["stop_reason"], "read_failed")

    def test_other_sha_search_is_never_followed(self):
        report, repo = self.run_navigation(review_fixture(), transform=lambda row: row["result"].update(commit=FIXED))
        self.assertEqual(len(repo.calls), 1)
        self.assertEqual(report["stop_reason"], "no_usable_reference_hit")

    def test_actual_read_must_cover_the_hit_not_just_requested_coordinates(self):
        def truncate(row):
            if row["tool"] == "read_file":
                row["result"] = source_record("unused", "src/widgets.ts", last=1)["result"]
        report, repo = self.run_navigation(review_fixture(), transform=truncate)
        self.assertEqual(len(repo.calls), 2)
        self.assertEqual(report["stop_reason"], "enclosing_symbol_not_visible")

    def test_unavailable_or_ambiguous_seed_makes_no_tool_call(self):
        for change in (lambda row: row["evidence"].append(copy.deepcopy(row["evidence"][0])),
                       lambda row: row["draft_fields"].update(commit="HEAD"),
                       lambda row: row["suggested_values"].update(commit=FIXED),
                       lambda row: row["evidence"][0].update(success=False),
                       lambda row: row["evidence"][0]["result"].update(path="../outside.ts"),
                       lambda row: row["field_reviews"]["entry_point"].update(status="supported")):
            review = review_fixture()
            change(review)
            report, repo = self.run_navigation(review)
            self.assertEqual(repo.calls, [])
            self.assertEqual(report["stop_reason"], "no_source_seed")

    def test_explicit_support_conflict_triggers_navigation_without_semantic_promotion(self):
        review = review_fixture()
        review["field_reviews"]["entry_point"].update(status="supported", validation_errors=["supported_reason_conflict"])
        self.assertEqual(entry_navigation_seed(review)["symbol"], "gate")

    def test_wrong_revision_entry_uses_independent_selected_revision_operation_not_transplant(self):
        review = review_fixture()
        review["evidence"][0]["result"]["commit"] = FIXED
        review["evidence"].append(source_record("E0002", "src/widgets.ts"))
        review["draft_fields"]["critical_operation"] = {"evidence_ref": "E0002", "start_line": 3, "end_line": 3}
        seed = entry_navigation_seed(review)
        self.assertEqual(seed["symbol"], "Widget")
        self.assertEqual(seed["field"], "critical_operation")
        self.assertEqual(seed["commit"], VULNERABLE)
        self.assertEqual(review["suggested_values"]["entry_point"]["evidence_ref"], "E0001")

    def test_public_text_can_supply_navigation_but_does_not_become_an_annotation(self):
        review = review_fixture()
        del review["evidence"][0]["result"]["lines"]
        self.assertEqual(entry_navigation_seed(review)["symbol"], "gate")
        self.assertNotIn("entry_point", review["draft_fields"])

    def test_malformed_reviews_are_ignored(self):
        for review in (None, [], {}, {"field_reviews": []}, {"field_reviews": {"entry_point": None}},
                       {"field_reviews": {"entry_point": {"status": [], "validation_errors": 7}}}):
            with self.subTest(review=review):
                self.assertIsNone(entry_navigation_seed(review))

    def test_protocol_invalid_entry_does_not_spend_reads_via_operation_fallback(self):
        review = review_fixture()
        review["draft_fields"]["critical_operation"] = copy.deepcopy(review["suggested_values"]["entry_point"])
        review["annotation_errors"] = [{"field": "entry_point", "code": "invalid_type"}]
        self.assertIsNone(entry_navigation_seed(review))
        del review["annotation_errors"]
        review["suggested_values"]["entry_point"] = []
        self.assertIsNone(entry_navigation_seed(review))

    def test_cycle_stops_and_hit_comments_imports_do_not_claim_a_caller(self):
        def recurse(row):
            if row["tool"] == "search_code":
                row["result"]["matches"] = [{"file": "src/helper.ts", "line": 2, "code": "return gate(ctx);"},
                    {"file": "src/comments.ts", "line": 1, "code": "// gate(ctx);"},
                    {"file": "src/imports.ts", "line": 1, "code": "gate,"}]
        report, repo = self.run_navigation(review_fixture(), transform=recurse)
        self.assertEqual(len(repo.calls), 2)
        self.assertEqual(report["stop_reason"], "symbol_cycle")

    def test_chain_cannot_exceed_four_search_read_pairs(self):
        review = review_fixture()
        def chain(row):
            if row["tool"] == "search_code":
                row["result"]["matches"] = [{"file": "src/next.ts", "line": 2,
                    "code": "return " + row["arguments"]["query"] + "(ctx);"}]
            else:
                symbol = "next_" + str(len(review["evidence"]))
                row["result"] = {"commit": VULNERABLE, "path": "src/next.ts", "start_line": 1, "end_line": 2,
                    "lines": [{"line": 1, "code": "function " + symbol + "(ctx) {"}, {"line": 2, "code": "  gate(ctx);"}]}
        calls = []
        def execute(tool, arguments):
            calls.append(tool)
            row = {"id": f"E{len(review['evidence']) + 1:04}", "success": True, "tool": tool,
                   "arguments": arguments, "result": {"commit": VULNERABLE, "query": arguments.get("query")}}
            chain(row)
            review["evidence"].append(row)
            return row
        report = navigate_entry(review, execute, lambda: True)
        self.assertEqual(len(calls), 8)
        self.assertEqual(report["stop_reason"], "hop_limit")


class EntryNavigationIntegrationTests(unittest.TestCase):
    setUp = fixture.StagedPipelineTests.setUp
    run_script = fixture.StagedPipelineTests.run_script

    @staticmethod
    def uncertain(payload):
        tool, snapshot = fixture.full_annotation(payload)
        snapshot["entry_point"].update(status="uncertain", reason="Only the internal helper has been read.")
        return tool, snapshot

    def test_existing_review_sees_new_registration_but_navigation_cannot_promote_entry(self):
        def final_review(payload):
            reads = [row for row in evidence_from(payload["messages"]) if row.get("tool") == "read_file"]
            self.assertTrue(any(row["result"]["path"] == "src/provider.ts" for row in reads))
            return self.uncertain(payload)
        read = ("read_file", {"commit": VULNERABLE, "path": "src/helper.ts", "start_line": 1, "end_line": 3})
        with patch.object(fixture, "MemoryRepo", NavigationRepo):
            result, final, client, repo, _ = self.run_script(
                [read, fixture.FINISH, self.uncertain, fixture.FINISH, final_review])
        self.assertIsNone(client.halted)
        self.assertEqual(result["model_calls"], 5)
        self.assertIsNone(final["entry"])
        self.assertEqual(final["review"]["field_reviews"]["entry_point"]["status"], "uncertain")
        self.assertEqual(result["tool_calls"], len(repo.calls))
        self.assertEqual(result["self_review_status"], "completed")
        self.assertTrue(any(row["action"] == "entry_navigation" for row in result["actions"]))

    def test_navigation_reserves_original_followup_tool_budget(self):
        read = ("read_file", {"commit": VULNERABLE, "path": "src/helper.ts", "start_line": 1, "end_line": 3})
        with patch.object(fixture, "MemoryRepo", NavigationRepo):
            result, _, _, repo, _ = self.run_script(
                [read, fixture.FINISH, self.uncertain, fixture.FINISH, self.uncertain], max_tool_calls=4)
        self.assertEqual(result["tool_calls"], 2)  # initial read + search; two tools remain reserved
        self.assertEqual(len(repo.calls), 2)
        report = next(row for row in result["actions"] if row["action"] == "entry_navigation")
        self.assertEqual(report["stop_reason"], "budget_reserved")

    def test_reviewer_can_select_new_callback_from_actual_reads_in_original_call_budget(self):
        def reassess(payload):
            tool, snapshot = self.uncertain(payload)
            reads = [row for row in evidence_from(payload["messages"]) if row.get("tool") == "read_file"]
            callback = next(row for row in reads if row["result"]["path"] == "src/widgets.ts")
            registration = next(row for row in reads if row["result"]["path"] == "src/provider.ts")
            snapshot["entry_point"].update(status="supported", evidence_refs=[callback["id"], registration["id"]],
                reason="The fixture callback and its registration are explicitly selected from the new reads.",
                value={"evidence_ref": callback["id"], "start_line": 2, "end_line": 2, "desc": "Fixture callback."})
            return tool, snapshot
        read = ("read_file", {"commit": VULNERABLE, "path": "src/helper.ts", "start_line": 1, "end_line": 3})
        with patch.object(fixture, "MemoryRepo", NavigationRepo):
            result, final, _, _, _ = self.run_script(
                [read, fixture.FINISH, self.uncertain, fixture.FINISH, reassess])
        self.assertEqual(result["model_calls"], 5)
        self.assertIsNotNone(final["entry"])
        self.assertEqual(final["entry"]["entry_point"]["file"], "src/widgets.ts")
        self.assertEqual(final["entry"]["entry_point"]["code"], "  async run(ctx) {")
        self.assertEqual(final["entry"]["verify"], 0)


if __name__ == "__main__":
    unittest.main()
