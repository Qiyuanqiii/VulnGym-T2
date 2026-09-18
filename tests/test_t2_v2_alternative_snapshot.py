"""Read another observed snapshot, without choosing a vulnerable revision."""
import copy
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from vulngym_t2.pipeline import _ProductionSession
from vulngym_t2.revision_navigation import alternative_snapshot_seed, alternative_snapshot_read
from tests.test_t2_v2_entry_navigation import NavigationRepo, review_fixture, source_record
from tests.test_t2_v2_pipeline import job, VULNERABLE, FIXED


def review():
    data = review_fixture()
    data["field_reviews"]["commit"] = {"status": "uncertain", "revision_basis": "inspected_only"}
    data["evidence"].extend([
        {"id": "E0002", "tool": "inspect_commit", "success": True,
         "result": {"commit": VULNERABLE, "parents": ["c" * 40], "message": "CI change"}},
        {"id": "E0003", "tool": "inspect_commit", "success": True,
         "result": {"commit": FIXED, "message": "docs change"}},
    ])
    return data


def search(seed):
    return {"id": "E0040", "tool": "search_code", "success": True,
            "result": {"commit": seed["commit"], "query": seed["symbol"],
                "matches": [{"file": seed["path"], "line": 250, "code": "export function gate(ctx) {"}]}}


class AlternativeSnapshotTests(unittest.TestCase):
    def location_direction_review(self):
        data = review()
        def source(identity, first, lines):
            return {"id": identity, "tool": "read_file", "success": True, "result": {
                "commit": VULNERABLE, "path": "src/handlers.py", "start_line": first,
                "end_line": first + len(lines) - 1, "text": "\n".join(lines)}}
        data["evidence"] = [*data["evidence"][1:],
            source("E0010", 1, ["async def create_record(value):", "    return value"]),
            source("E0020", 100, ["async def update_record(value, user):", "    row = await lookup_record(",
                                   "        value, owner=user.id", "    )", "    return row"])]
        data["draft_fields"] = {}
        data["suggested_values"] = {"critical_operation": {
            "evidence_ref": "E0020", "start_line": 101, "end_line": 103}}
        data["field_reviews"] = {
            "commit": {"status": "uncertain", "revision_basis": "unknown", "evidence_refs": ["E0010", "E0020"]},
            "entry_point": {"status": "uncertain", "evidence_refs": ["E0010"]},
            "critical_operation": {"status": "uncertain", "evidence_refs": ["E0020"]}}
        return data

    def test_unselected_revision_prefers_actual_operation_call_over_unrelated_first_declaration(self):
        data = self.location_direction_review()
        before = copy.deepcopy(data)
        seed = alternative_snapshot_seed(data)
        self.assertEqual((seed["symbol"], seed["source_evidence_ref"], seed["source_revision"], seed["commit"]),
                         ("lookup_record", "E0020", VULNERABLE, FIXED))
        self.assertEqual(data, before)
        self.assertNotIn("commit", data["draft_fields"])
        self.assertEqual(data["field_reviews"]["commit"]["status"], "uncertain")
        # Only an actual matching declaration at the other SHA supplies lines.
        found = {"id": "E0040", "tool": "search_code", "success": True, "result": {
            "commit": FIXED, "query": "lookup_record", "matches": [
                {"file": "src/handlers.py", "line": 250, "code": "async def lookup_record(value, owner):"}]}}
        self.assertEqual(alternative_snapshot_read(found, seed), {
            "commit": FIXED, "path": "src/handlers.py", "start_line": 170, "end_line": 282})
        found["result"]["matches"][0]["code"] = "    row = await lookup_record(value, owner)"
        self.assertIsNone(alternative_snapshot_read(found, seed))

    def test_no_location_prioritizes_operation_citations_before_broad_commit_citations(self):
        data = self.location_direction_review()
        data["suggested_values"] = {}
        seed = alternative_snapshot_seed(data)
        self.assertEqual((seed["symbol"], seed["source_evidence_ref"]), ("update_record", "E0020"))

    def test_whole_function_selection_compares_owner_not_nested_assigned_call(self):
        for nested_name in ("build_statement", "select", "make_result"):
            data = self.location_direction_review()
            source = data["evidence"][-1]["result"]
            source["text"] = ("async def update_record(value, user):\n"
                f"    statement = {nested_name}(value)\n"
                "    return statement")
            source["end_line"] = 102
            data["suggested_values"]["critical_operation"].update(start_line=100, end_line=102)
            before = copy.deepcopy(data)
            with self.subTest(nested_name=nested_name):
                seed = alternative_snapshot_seed(data)
                self.assertEqual(seed["symbol"], "update_record")
                found = {"tool": "search_code", "success": True, "result": {
                    "commit": FIXED, "query": "update_record", "matches": [
                        {"file": "src/handlers.py", "line": 250,
                         "code": "async def update_record(value, user):"}]}}
                self.assertEqual(alternative_snapshot_read(found, seed), {
                    "commit": FIXED, "path": "src/handlers.py", "start_line": 170, "end_line": 282})
                self.assertEqual(data, before)

    def test_selected_decorated_function_keeps_its_owner_as_comparison_direction(self):
        data = self.location_direction_review()
        source = data["evidence"][-1]["result"]
        source["text"] = ('\n@route("/record")\nasync def update_record(value, user):\n'
                          '    result = build_statement(value)\n    return result')
        source["end_line"] = 104
        data["suggested_values"]["critical_operation"].update(start_line=100, end_line=104)
        self.assertEqual(alternative_snapshot_seed(data)["symbol"], "update_record")

    def test_invalid_or_unread_location_cannot_supply_a_called_symbol(self):
        for change in ("outside", "wrong_sha", "failed", "unknown_id", "expanded_wrong_bytes"):
            data = self.location_direction_review()
            value = data["suggested_values"]["critical_operation"]
            if change == "outside":
                value.update(start_line=105, end_line=106)
            elif change == "wrong_sha":
                data["evidence"][-1]["result"]["commit"] = FIXED
            elif change == "failed":
                data["evidence"][-1]["success"] = False
            elif change == "unknown_id":
                value["evidence_ref"] = "E9999"
            else:
                data["suggested_values"]["critical_operation"] = {
                    "file": "src/handlers.py", "line": "101-103", "code": "not actual source bytes"}
            with self.subTest(change=change):
                seed = alternative_snapshot_seed(data)
                self.assertTrue(seed is None or seed["symbol"] != "lookup_record")

    def test_multiple_selected_calls_do_not_choose_an_arbitrary_helper(self):
        data = self.location_direction_review()
        data["evidence"][-1]["result"]["text"] += "\n    other = another_lookup(value)"
        data["evidence"][-1]["result"]["end_line"] = 105
        data["suggested_values"]["critical_operation"]["end_line"] = 105
        seed = alternative_snapshot_seed(data)
        self.assertEqual(seed["symbol"], "update_record")

    def unselected_review(self):
        data = review()
        data["draft_fields"] = {"commit": None, "entry_point": None, "critical_operation": None}
        data["suggested_values"] = {}
        data["field_reviews"]["entry_point"]["evidence_refs"] = ["E0001"]
        return data

    def test_no_model_revision_or_location_still_allows_cited_source_comparison(self):
        data = self.unselected_review()
        before = copy.deepcopy(data)
        seed = alternative_snapshot_seed(data)
        self.assertEqual((seed["commit"], seed["source_revision"], seed["symbol"]),
                         (FIXED, VULNERABLE, "gate"))
        self.assertEqual(seed["source_evidence_ref"], "E0001")
        self.assertEqual(data, before)

    def test_new_focused_source_does_not_need_an_impossible_earlier_citation(self):
        data = self.unselected_review()
        data["field_reviews"]["entry_point"]["evidence_refs"] = []
        self.assertIsNone(alternative_snapshot_seed(data))
        data["navigation_evidence_refs"] = ["E0001"]
        before = copy.deepcopy(data)
        seed = alternative_snapshot_seed(data)
        self.assertEqual((seed["commit"], seed["source_revision"], seed["source_evidence_ref"]),
                         (FIXED, VULNERABLE, "E0001"))
        self.assertEqual(data, before)

    def focused_python_review(self, body, *, signature="async def update_record(value, user):"):
        data = self.location_direction_review()
        data["suggested_values"] = {}
        data["navigation_evidence_refs"] = ["E0020"]
        source = data["evidence"][-1]["result"]
        source["text"] = "\n".join([signature, *body])
        source["end_line"] = source["start_line"] + len(body)
        return data

    def test_focused_python_call_guides_same_budget_comparison_not_sibling_or_nested_calls(self):
        data = self.focused_python_review([
            "    row = await lookup_record(value, owner=user.id)",
            "    def nested():", "        other = unrelated_lookup(value)",
            "    return row", "", "@router.post('/other')",
            "async def other_record(value):", "    row = other_lookup(value)", "    return row"])
        before = copy.deepcopy(data)
        seed = alternative_snapshot_seed(data)
        self.assertEqual((seed["symbol"], seed["source_evidence_ref"], seed["source_revision"], seed["commit"]),
                         ("lookup_record", "E0020", VULNERABLE, FIXED))
        self.assertEqual(data, before)
        self.assertEqual(data["field_reviews"]["commit"]["status"], "uncertain")
        found = {"id": "E0040", "tool": "search_code", "success": True, "result": {
            "commit": FIXED, "query": "lookup_record", "matches": [
                {"file": seed["path"], "line": 250, "code": "async def lookup_record(value, owner):"}]}}
        self.assertEqual(alternative_snapshot_read(found, seed)["start_line"], 170)
        found["result"]["matches"][0]["code"] = "    row = lookup_record(value, owner)"
        self.assertIsNone(alternative_snapshot_read(found, seed))

    def test_focused_python_ambiguous_partial_dynamic_or_shadowed_calls_keep_wrapper_direction(self):
        bodies = [
            ["    row = lookup_record(value)", "    other = another_lookup(value)", "    return row"],
            ["    row = await lookup_record(", "        value,"],
            ["    row = service.lookup_record(value)", "    return row"],
            ['    text = "row = lookup_record(value)"', "    # row = another_lookup(value)", "    return text"],
            ["    lookup_record = value", "    row = lookup_record(user)", "    return row"],
            ["    from other import lookup_record", "    row = lookup_record(user)", "    return row"],
            ["    def lookup_record(x):", "        return x", "    row = lookup_record(value)", "    return row"],
            ["    row = dict(value)", "    return row"],
        ]
        for body in bodies:
            with self.subTest(body=body):
                data = self.focused_python_review(body)
                self.assertEqual(alternative_snapshot_seed(data)["symbol"], "update_record")
        data = self.focused_python_review(["    row = lookup_record(value)", "    return row"],
                                         signature="async def update_record(value, lookup_record):")
        self.assertEqual(alternative_snapshot_seed(data)["symbol"], "update_record")

    def test_focused_python_unknown_or_oversized_syntax_retains_the_original_direction(self):
        data = self.focused_python_review(["    row = lookup_record(value)", "    return row"])
        data["evidence"][-1]["result"]["path"] = "src/handlers.ts"
        self.assertEqual(alternative_snapshot_seed(data)["symbol"], "update_record")
        data = self.focused_python_review(['    text = "' + 'x' * 16_000 + '"', "    row = lookup_record(value)", "    return row"])
        self.assertEqual(alternative_snapshot_seed(data)["symbol"], "update_record")

    def test_focused_python_helper_does_not_repeat_an_already_read_alternative(self):
        data = self.focused_python_review(["    row = lookup_record(value)", "    return row"])
        data["evidence"].append({"id": "E0045", "tool": "read_file", "success": True, "result": {
            "commit": FIXED, "path": "src/handlers.py", "start_line": 20, "end_line": 21,
            "text": "async def lookup_record(value):\n    return value"}})
        before = copy.deepcopy(data)
        self.assertIsNone(alternative_snapshot_seed(data))
        self.assertEqual(data, before)

    def test_focused_comparison_rejects_missing_failed_ambiguous_or_incompatible_reads(self):
        for change in ("empty", "missing", "not_ids", "too_many", "failed", "not_source",
                       "two_paths", "uninspected_selected_sha", "uninspected_suggested_sha", "already_read"):
            data = self.unselected_review()
            # Earlier cited source must not restart the late navigation pass.
            data["navigation_evidence_refs"] = ["E0001"]
            if change == "empty":
                data["navigation_evidence_refs"] = []
            elif change == "missing":
                data["navigation_evidence_refs"] = ["E9999"]
            elif change == "not_ids":
                data["navigation_evidence_refs"] = [True]
            elif change == "too_many":
                data["navigation_evidence_refs"] = ["E0001"] * 3
            elif change == "failed":
                data["evidence"][0]["success"] = False
            elif change == "not_source":
                data["navigation_evidence_refs"] = ["E0002"]
            elif change == "two_paths":
                data["evidence"].append(source_record("E0020", "src/widgets.ts"))
                data["navigation_evidence_refs"].append("E0020")
            elif change == "uninspected_selected_sha":
                data["draft_fields"]["commit"] = "c" * 40
            elif change == "uninspected_suggested_sha":
                data["suggested_values"]["commit"] = "c" * 40
            else:
                data["evidence"].append(source_record("E0020", "src/helper.ts", commit=FIXED))
            with self.subTest(change=change):
                self.assertIsNone(alternative_snapshot_seed(data))

    def test_focused_other_source_compares_only_the_explicit_inspected_target(self):
        for key in ("draft_fields", "suggested_values"):
            data = self.unselected_review()
            data["navigation_evidence_refs"] = ["E0001"]
            data[key]["commit"] = FIXED
            data["evidence"].insert(1, {"id": "E0070", "tool": "inspect_commit", "success": True,
                                      "result": {"commit": "c" * 40}})
            before = copy.deepcopy(data)
            with self.subTest(key=key):
                seed = alternative_snapshot_seed(data)
                self.assertEqual((seed["commit"], seed["source_revision"]), (FIXED, VULNERABLE))
                self.assertEqual(data, before)
                self.assertEqual(data["field_reviews"]["commit"]["status"], "uncertain")

    def test_focused_conflicting_invalid_or_already_read_target_never_retargets(self):
        for change in ("conflict", "invalid", "already_read", "failed_inspection"):
            data = self.unselected_review()
            data["navigation_evidence_refs"] = ["E0001"]
            data["suggested_values"]["commit"] = FIXED
            if change == "conflict":
                data["draft_fields"]["commit"] = VULNERABLE
            elif change == "invalid":
                data["suggested_values"]["commit"] = "HEAD"
            elif change == "already_read":
                data["evidence"].append(source_record("E0020", "src/helper.ts", commit=FIXED))
            else:
                data["evidence"][-1]["success"] = False
            with self.subTest(change=change):
                self.assertIsNone(alternative_snapshot_seed(data))

    def test_focused_production_pass_cannot_repeat_old_navigation_after_non_source_results(self):
        for focused in ([], [{"id": "E0002", "tool": "inspect_commit", "success": True}],
                        [{"id": "E0002", "tool": "read_file", "success": False}]):
            session = self.session(24)
            session.navigate_entry_context({}, focused_reads=focused)
            self.assertEqual(session.repo.calls, [])

    def test_focused_comparison_keeps_tool_context_and_provider_limits(self):
        for limit in ("tools", "context", "provider"):
            session = self.session(3 if limit == "tools" else 24)
            source = next(row for row in session.result["evidence"] if row.get("tool") == "read_file")
            if limit == "context":
                session.evidence("advisory", text="x" * 85000)
                session.messages.append({"role": "user", "content": "x" * 85000})
            elif limit == "provider":
                session.client.halted = "stop"
            before = copy.deepcopy(session.result["field_reviews"])
            session.navigate_entry_context({}, focused_reads=[source])
            self.assertEqual([tool for tool, _ in session.repo.calls], ["search_code"] if limit == "tools" else [])
            self.assertEqual(session.result["field_reviews"], before)
            self.assertEqual(session.result["model_calls"], 0)

    def test_multi_finish_draft_keeps_focused_comparison_before_tools_closed_review(self):
        # Single-entry follow-up now uses bounded sequential model decisions.
        # Multi-candidate slots retain this original one-decision comparison.
        session = _ProductionSession(job(False), SimpleNamespace(response_mode="staged_tool", multi_entry=True, halted=None),
                                     NavigationRepo(), 6, 24)
        session.prepare()
        for sha in (VULNERABLE, FIXED):
            session.evidence("tool", tool="inspect_commit", success=True, result={"commit": sha})
        session.drafted = session.accept_snapshot({"action": "draft",
            "fields": {"commit": None, "entry_point": None, "critical_operation": None},
            "field_reviews": {
                "commit": {"status": "uncertain", "revision_basis": "unknown", "reason": "No source read.", "evidence_refs": []},
                "entry_point": {"status": "uncertain", "reason": "No source read.", "evidence_refs": []},
                "critical_operation": {"status": "uncertain", "reason": "No source read.", "evidence_refs": []}}})
        before = copy.deepcopy(session.result["field_reviews"])
        phases = []

        def complete(stage, **kwargs):
            phases.append(stage)
            if stage == "evidence_followup":
                self.assertEqual(session.repo.calls, [])
                return {"action": "tools", "calls": [{"tool": "read_file", "arguments": {
                    "commit": VULNERABLE, "path": "src/helper.ts", "start_line": 1, "end_line": 3}}]}
            self.assertEqual(stage, "self_review")
            comparisons = [row for row in session.result["actions"] if row["action"] == "alternative_snapshot_read"]
            self.assertEqual(len(comparisons), 1)
            self.assertTrue(comparisons[0]["success"])
            self.assertEqual(session.result["field_reviews"], before)
            self.assertNotIn("commit", session.result["fields"])
            return {"action": "draft", "fields": {}, "field_reviews": {}}

        with patch.object(session, "complete", side_effect=complete):
            session.finish_draft()
        self.assertEqual(phases, ["evidence_followup", "self_review"])
        self.assertEqual([tool for tool, _ in session.repo.calls], ["read_file", "search_code", "read_file"])
        self.assertEqual(session.result["evidence_followup_status"], "completed")
        self.assertEqual(session.result["self_review_status"], "completed")
        self.assertEqual(session.result["model_calls"], 0)

    def test_unselected_direction_rejects_uncited_ambiguous_or_unread_source(self):
        for change in ("uncited", "failed", "duplicate", "two_revisions", "two_paths",
                       "invalid_selection", "no_declaration"):
            data = self.unselected_review()
            if change == "uncited":
                data["field_reviews"]["entry_point"]["evidence_refs"] = []
            elif change == "failed":
                data["evidence"][0]["success"] = False
            elif change == "duplicate":
                data["evidence"].append(copy.deepcopy(data["evidence"][0]))
            elif change in ("two_revisions", "two_paths"):
                extra = source_record("E0020", "src/helper.ts", commit=FIXED if change == "two_revisions" else VULNERABLE)
                if change == "two_paths":
                    extra["result"]["path"] = "src/other.ts"
                data["evidence"].append(extra)
                data["field_reviews"]["entry_point"]["evidence_refs"].append("E0020")
            elif change == "invalid_selection":
                data["draft_fields"]["commit"] = "HEAD"
            else:
                data["evidence"][0]["result"].update(start_line=2, end_line=2,
                    lines=[{"line": 2, "code": "return context;"}], text="return context;")
            with self.subTest(change=change):
                self.assertIsNone(alternative_snapshot_seed(data))

    def test_unselected_production_merge_reads_other_snapshot_without_selecting_it(self):
        session = self.session(24)
        source = next(row for row in session.result["evidence"] if row.get("tool") == "read_file")
        session.merge_draft({"fields": {"commit": None, "entry_point": None, "critical_operation": None},
            "field_reviews": {
                "commit": {"status": "uncertain", "revision_basis": "unknown", "reason": "No revision chosen.", "evidence_refs": []},
                "entry_point": {"status": "uncertain", "reason": "Only a different behavior was read.", "evidence_refs": [source["id"]]},
                "critical_operation": {"status": "uncertain", "reason": "No location selected.", "evidence_refs": []}}})
        before = copy.deepcopy(session.result["field_reviews"])
        session.navigate_entry_context({})
        self.assertTrue(any(row["action"] == "alternative_snapshot_read" for row in session.result["actions"]))
        self.assertEqual(session.result["field_reviews"], before)
        self.assertNotIn("commit", session.result["fields"])
        self.assertEqual(session.result["model_calls"], 0)
        self.assertEqual([tool for tool, args in session.repo.calls if args.get("commit") == FIXED],
                         ["search_code", "read_file"])

    def without_locations(self):
        data = review()
        data["suggested_values"] = {}
        data["field_reviews"]["commit"]["evidence_refs"] = ["E0001"]
        data["evidence"].append({"id": "E0004", "tool": "search_code", "success": True,
            "result": {"commit": VULNERABLE, "query": "function gate", "matches": [
                {"file": "src/helper.ts", "line": 1, "code": "export function gate(ctx) {"}]}})
        return data

    def test_cited_declaration_search_can_compare_without_selected_entry_or_operation(self):
        data = self.without_locations()
        before = copy.deepcopy(data)
        seed = alternative_snapshot_seed(data)
        self.assertEqual((seed["commit"], seed["symbol"], seed["path"], seed["source_evidence_ref"]),
                         (FIXED, "gate", "src/helper.ts", "E0001"))
        self.assertEqual(data, before)

    def test_declaration_search_requires_cited_exact_visible_source_and_unambiguous_revision(self):
        for change in ("uncited", "wrong_code", "wrong_line", "wrong_sha", "plain_query", "truncated",
                       "incomplete", "duplicate_id", "conflicting_selection", "failed"):
            data = self.without_locations()
            found = data["evidence"][-1]
            if change == "uncited":
                data["field_reviews"]["commit"]["evidence_refs"] = []
                data["field_reviews"]["entry_point"]["evidence_refs"] = []
            elif change == "wrong_code":
                found["result"]["matches"][0]["code"] = "function gate(unseen) {"
            elif change == "wrong_line":
                found["result"]["matches"][0]["line"] = True
            elif change == "wrong_sha":
                found["result"]["commit"] = FIXED
            elif change == "plain_query":
                found["result"]["query"] = "gate"
            elif change == "truncated":
                found["result"]["truncated"] = True
            elif change == "incomplete":
                found["result"]["complete"] = False
            elif change == "duplicate_id":
                found["id"] = "E0001"
            elif change == "conflicting_selection":
                data["suggested_values"]["commit"] = FIXED
            else:
                found["success"] = False
            with self.subTest(change=change):
                self.assertIsNone(alternative_snapshot_seed(data))

    def test_locationless_production_merge_retains_search_direction_not_field_approval(self):
        session = self.session(24)
        source = next(row for row in session.result["evidence"] if row.get("tool") == "read_file")
        search_record = self.without_locations()["evidence"][-1]
        session.evidence("tool", **{key: value for key, value in search_record.items() if key != "id"})
        session.merge_draft({"fields": {"commit": None, "entry_point": None, "critical_operation": None},
            "field_reviews": {
                "commit": {"status": "uncertain", "suggested_value": VULNERABLE, "revision_basis": "inspected_only",
                           "reason": "Only this inspected behavior is known.", "evidence_refs": [source["id"]]},
                "entry_point": {"status": "uncertain", "suggested_value": None, "reason": "No selected position.", "evidence_refs": []},
                "critical_operation": {"status": "uncertain", "suggested_value": None, "reason": "No selected position.", "evidence_refs": []}}})
        before = copy.deepcopy(session.result["field_reviews"])
        session.navigate_entry_context({})
        self.assertTrue(any(row["action"] == "alternative_snapshot_read" for row in session.result["actions"]))
        self.assertEqual(session.result["field_reviews"], before)
        self.assertEqual(session.result["model_calls"], 0)
        self.assertEqual([tool for tool, args in session.repo.calls if args.get("commit") == FIXED],
                         ["search_code", "read_file"])

    def decorated_review(self, lines):
        data = review()
        data["evidence"][0]["result"].update(path="src/handler.py", start_line=430,
            end_line=429 + len(lines), text="\n".join(lines), total_lines=500,
            lines=[{"line": 430 + n, "code": code} for n, code in enumerate(lines)])
        data["suggested_values"]["entry_point"].update(start_line=430, end_line=429 + len(lines))
        return data

    def test_python_decorated_location_finds_its_visible_handler_not_previous_function(self):
        data = self.decorated_review(['@router.get("/{key}", status_code=200)', '@cached',
                                      'async def receive_value(', '    value: str,', '):', '    return value'])
        original = copy.deepcopy(data)
        seed = alternative_snapshot_seed(data)
        self.assertEqual((seed["symbol"], seed["path"], seed["commit"]), ("receive_value", "src/handler.py", FIXED))
        self.assertEqual(data, original)

    def test_decorator_does_not_cross_incomplete_selected_or_executable_boundaries(self):
        for lines in (['@router.get("/x")'], ['@router.get(', 'def receive_value():'],
                      ['@cached', 'run_other()', 'def receive_value():'],
                      ['    @cached', 'def receive_value():'],
                      ['@cached'] * 9 + ['def receive_value():']):
            with self.subTest(lines=lines):
                self.assertIsNone(alternative_snapshot_seed(self.decorated_review(lines)))
        data = self.decorated_review(['@cached', 'def receive_value():'])
        data["suggested_values"]["entry_point"]["end_line"] = 430
        self.assertIsNone(alternative_snapshot_seed(data))

    def test_only_successfully_inspected_alternative_and_observed_name_are_used(self):
        data = review()
        before = copy.deepcopy(data)
        seed = alternative_snapshot_seed(data)
        self.assertEqual((seed["commit"], seed["source_revision"], seed["symbol"], seed["path"]),
                         (FIXED, VULNERABLE, "gate", "src/helper.ts"))
        self.assertEqual(seed["inspection_ref"], "E0003")
        self.assertEqual(data, before)
        for change in ("failed", "alias", "duplicate"):
            invalid = copy.deepcopy(data)
            if change == "failed":
                invalid["evidence"][-1]["success"] = False
            elif change == "alias":
                invalid["evidence"][-1]["result"]["commit"] = "HEAD"
            else:
                invalid["evidence"][-1]["id"] = "E0002"
            self.assertIsNone(alternative_snapshot_seed(invalid))

    def test_read_origin_does_not_need_a_redundant_commit_inspection(self):
        data = review()
        data["evidence"] = [row for row in data["evidence"] if row["id"] != "E0002"]
        before = copy.deepcopy(data)
        seed = alternative_snapshot_seed(data)
        self.assertEqual((seed["source_revision"], seed["commit"], seed["inspection_ref"]),
                         (VULNERABLE, FIXED, "E0003"))
        self.assertEqual(data, before)
        # Reading the source is essential; an inspect receipt alone is not it.
        data["evidence"][0]["success"] = False
        self.assertIsNone(alternative_snapshot_seed(data))

    def test_single_alternative_inspection_drives_the_production_comparison(self):
        session = self.session(24, inspect_current=False)
        before = copy.deepcopy((session.result["fields"], session.result["field_reviews"]))
        session.navigate_entry_context({})
        alternate = [(tool, args) for tool, args in session.repo.calls if args.get("commit") == FIXED]
        self.assertEqual([tool for tool, _ in alternate], ["search_code", "read_file"])
        self.assertEqual(before, (session.result["fields"], session.result["field_reviews"]))
        self.assertEqual(session.result["model_calls"], 0)

    def test_supported_or_already_read_snapshot_does_not_spend_more_tools(self):
        for decision in ({"status": "supported", "revision_basis": "behavior_at_revision"},
                         {"status": "conflicting", "revision_basis": "inspected_only"}):
            data = review()
            data["field_reviews"]["commit"] = decision
            self.assertIsNone(alternative_snapshot_seed(data))
        data = review()
        data["evidence"].append(source_record("E0004", "src/helper.ts", commit=FIXED))
        self.assertIsNone(alternative_snapshot_seed(data))

    def test_reading_only_an_alternative_header_does_not_cover_the_declaration(self):
        data = self.unselected_review()
        header = source_record("E0004", "src/helper.ts", commit=FIXED)
        header["result"].update(start_line=1, end_line=2, text="// module header\n// no declaration",
            lines=[{"line": 1, "code": "// module header"}, {"line": 2, "code": "// no declaration"}])
        data["evidence"].append(header)
        before = copy.deepcopy(data)
        self.assertEqual(alternative_snapshot_seed(data)["commit"], FIXED)
        self.assertEqual(data, before)
        # A real read of the relevant declaration closes this navigation gap.
        data["evidence"].append(source_record("E0005", "src/helper.ts", commit=FIXED))
        self.assertIsNone(alternative_snapshot_seed(data))

    def test_revision_comparison_is_independent_of_supported_entry_and_proposed_basis(self):
        for basis in ("inspected_only", "unknown", "behavior_at_revision", "affected_range_and_source"):
            data = review()
            data["field_reviews"]["entry_point"]["status"] = "supported"
            data["field_reviews"]["commit"]["revision_basis"] = basis
            before = copy.deepcopy(data)
            with self.subTest(basis=basis):
                self.assertEqual(alternative_snapshot_seed(data)["commit"], FIXED)
                self.assertEqual(data, before)

    def test_controller_can_compare_even_without_unresolved_entry_navigation(self):
        session = self.session(24)
        session.result["field_reviews"]["entry_point"]["status"] = "supported"
        session.navigate_entry_context({})
        self.assertTrue(any(row["action"] == "alternative_snapshot_read" for row in session.result["actions"]))
        self.assertEqual(session.result["field_reviews"]["commit"]["status"], "uncertain")

    def test_coordinates_come_from_new_declaration_not_old_source_or_call_hit(self):
        seed = alternative_snapshot_seed(review())
        receipt = search(seed)
        before = copy.deepcopy(receipt)
        request = alternative_snapshot_read(receipt, seed)
        self.assertEqual(request, {"commit": FIXED, "path": "src/helper.ts", "start_line": 170, "end_line": 282})
        self.assertEqual(receipt, before)
        for change in ("failed", "wrong_sha", "other_path", "call_only", "bool_line"):
            invalid = copy.deepcopy(receipt)
            if change == "failed":
                invalid["success"] = False
            elif change == "wrong_sha":
                invalid["result"]["commit"] = VULNERABLE
            elif change == "other_path":
                invalid["result"]["matches"][0]["file"] = "other.ts"
            elif change == "call_only":
                invalid["result"]["matches"][0]["code"] = "gate(ctx);"
            else:
                invalid["result"]["matches"][0]["line"] = True
            self.assertIsNone(alternative_snapshot_read(invalid, seed))

    def session(self, tool_limit, *, inspect_current=True):
        session = _ProductionSession(job(False), SimpleNamespace(response_mode="staged_tool", halted=None),
                                     NavigationRepo(), 6, tool_limit)
        session.prepare()
        source = source_record("unused", "src/helper.ts")
        receipt = session.evidence("tool", **{key: value for key, value in source.items() if key != "id"})
        for sha in ((VULNERABLE, FIXED) if inspect_current else (FIXED,)):
            session.evidence("tool", tool="inspect_commit", success=True, result={"commit": sha})
        session.result["fields"]["commit"] = VULNERABLE
        session.result["field_reviews"]["commit"].update(status="uncertain", revision_basis="inspected_only")
        session.result["field_reviews"]["entry_point"].update(status="uncertain", evidence_refs=[receipt["id"]],
            suggested_value={"evidence_ref": receipt["id"], "start_line": 1, "end_line": 1})
        return session

    def test_controller_adds_at_most_one_comparison_pair_without_decision_or_model_changes(self):
        session = self.session(24)
        fields = copy.deepcopy(session.result["fields"])
        judgments = copy.deepcopy(session.result["field_reviews"])
        original = copy.deepcopy(session.result["evidence"])
        session.navigate_entry_context({})
        alternate_calls = [(tool, args) for tool, args in session.repo.calls if args.get("commit") == FIXED]
        self.assertEqual([tool for tool, _ in alternate_calls], ["search_code", "read_file"])
        self.assertEqual(alternate_calls[0][1]["paths"], ["src/helper.ts"])
        self.assertEqual(session.result["fields"], fields)
        self.assertEqual(session.result["field_reviews"], judgments)
        self.assertEqual(session.result["evidence"][:len(original)], original)
        self.assertEqual(session.result["model_calls"], 0)
        self.assertTrue(any(row["action"] == "alternative_snapshot_read" for row in session.result["actions"]))

    def test_existing_tool_and_context_reserves_stop_comparison(self):
        session = self.session(3)
        session.navigate_entry_context({})
        self.assertEqual([tool for tool, _ in session.repo.calls], ["search_code"])
        session = self.session(24)
        session.evidence("advisory", text="x" * 85000)
        session.messages.append({"role": "user", "content": "x" * 85000})
        session.navigate_entry_context({})
        self.assertEqual(session.repo.calls, [])


if __name__ == "__main__":
    unittest.main()
