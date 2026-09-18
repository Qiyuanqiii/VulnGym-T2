"""An observed assignment can select a read, never approve an input relation."""
import copy
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from vulngym_t2.entry_navigation import intermediate_assignment_seed, assignment_definition_read
from vulngym_t2.pipeline import _ProductionSession
from vulngym_t2.source_refs import resolve_location
from tests.test_t2_v2_entry_navigation import SOURCES, NavigationRepo, source_record
from tests.test_t2_v2_pipeline import job, VULNERABLE, FIXED


PATH = "service/pipeline.py"
HELPER = "service/normalization.py"
LINES = ["async def consume_stream(response):", "    data = await response.read()",
         "    # an intervening transformation", "    data, _ = await normalize_value(",
         "        body=data,", "    )", "    if data:", "        emit(data['event'])"]


def review():
    with patch.dict(SOURCES, {PATH: LINES}):
        receipt = source_record("E0001", PATH)
    return {"draft_fields": {"commit": VULNERABLE,
                "entry_point": {"evidence_ref": "E0001", "start_line": 2, "end_line": 2},
                "critical_operation": {"evidence_ref": "E0001", "start_line": 8, "end_line": 8}},
            "field_reviews": {"entry_point": {"status": "supported", "evidence_refs": ["E0001"]},
                              "critical_operation": {"status": "supported", "evidence_refs": ["E0001"]},
                              "trace": {"status": "uncertain"}},
            "evidence": [receipt]}


def search():
    return {"tool": "search_code", "success": True, "result": {
        "commit": VULNERABLE, "query": "normalize_value", "complete": True,
        "matches": [{"file": HELPER, "line": 20, "code": "async def normalize_value(body):"},
                    {"file": PATH, "line": 4, "code": LINES[3]}]}}


class IntermediateReadTests(unittest.TestCase):
    def test_expanded_locations_used_by_the_real_controller_are_supported(self):
        data = review()
        for field in ("entry_point", "critical_operation"):
            data["draft_fields"][field] = resolve_location(data["draft_fields"][field], data["evidence"], VULNERABLE)
        before = copy.deepcopy(data)
        self.assertEqual(intermediate_assignment_seed(data)["symbol"], "normalize_value")
        self.assertEqual(data, before)
        data["suggested_values"] = {"entry_point": data["draft_fields"].pop("entry_point")}
        data["field_reviews"]["entry_point"]["status"] = "uncertain"
        self.assertEqual(intermediate_assignment_seed(data)["symbol"], "normalize_value")

    def test_expanded_locations_need_exact_code_and_a_real_same_revision_citation(self):
        for change in ("code", "range", "path", "uncited", "other_revision"):
            data = review()
            for field in ("entry_point", "critical_operation"):
                data["draft_fields"][field] = resolve_location(data["draft_fields"][field], data["evidence"], VULNERABLE)
            value = data["draft_fields"]["entry_point"]
            if change == "code":
                value["code"] += " fabricated"
            elif change == "range":
                value["line"] = "2-7"
            elif change == "path":
                value["file"] = HELPER
            elif change == "uncited":
                data["field_reviews"]["entry_point"]["evidence_refs"] = []
            else:
                data["evidence"][0]["result"]["commit"] = FIXED
            with self.subTest(change=change):
                self.assertIsNone(intermediate_assignment_seed(data))

    def test_visible_assigned_call_selects_only_a_navigation_query(self):
        data = review()
        original = copy.deepcopy(data)
        self.assertEqual(intermediate_assignment_seed(data), {"commit": VULNERABLE,
            "path": PATH, "symbol": "normalize_value", "line": 4, "evidence_ref": "E0001"})
        self.assertEqual(data, original)
        data["field_reviews"]["trace"]["status"] = "supported"
        # An overconfident initial label does not close the tool investigation.
        self.assertEqual(intermediate_assignment_seed(data)["symbol"], "normalize_value")
        self.assertEqual(data["field_reviews"]["trace"]["status"], "supported")

    def test_missing_rows_other_revision_and_conflicting_identity_do_not_seed(self):
        for change in ("gap", "wrong_sha", "duplicate", "other_path", "unseen_location"):
            data = review()
            source = data["evidence"][0]["result"]
            if change == "gap":
                source["lines"].pop(3)
                source["text"] = "\n".join(row["code"] for row in source["lines"])
            elif change == "wrong_sha":
                source["commit"] = FIXED
            elif change == "duplicate":
                data["evidence"].append(copy.deepcopy(data["evidence"][0]))
            elif change == "other_path":
                other = copy.deepcopy(data["evidence"][0])
                other["id"], other["result"]["path"] = "E0002", HELPER
                data["evidence"].append(other)
                data["draft_fields"]["critical_operation"]["evidence_ref"] = "E0002"
            else:
                data["draft_fields"]["entry_point"]["start_line"] = 0
            with self.subTest(change=change):
                self.assertIsNone(intermediate_assignment_seed(data))

    def test_unrelated_assignment_and_other_function_are_not_a_seed(self):
        for replacement in ("    unrelated = await normalize_value()",
                            "    # data = await normalize_value()", "    data = helper.normalize_value()"):
            data = review()
            source = data["evidence"][0]["result"]
            source["lines"][3]["code"] = replacement
            source["text"] = "\n".join(row["code"] for row in source["lines"])
            self.assertIsNone(intermediate_assignment_seed(data))
        data = review()
        source = data["evidence"][0]["result"]
        source["lines"][6]["code"] = "def other_callback(data):"
        source["text"] = "\n".join(row["code"] for row in source["lines"])
        self.assertIsNone(intermediate_assignment_seed(data))

    def test_search_must_identify_one_complete_same_revision_declaration(self):
        seed = intermediate_assignment_seed(review())
        self.assertEqual(assignment_definition_read(search(), seed),
            {"commit": VULNERABLE, "path": HELPER, "start_line": 16, "end_line": 116})
        for change in ("wrong_sha", "query", "truncated", "ambiguous", "call_only", "failed", "boolean_line"):
            found = search()
            if change == "wrong_sha":
                found["result"]["commit"] = FIXED
            elif change == "query":
                found["result"]["query"] = "other"
            elif change == "truncated":
                found["result"]["truncated"] = True
            elif change == "ambiguous":
                found["result"]["matches"].append({"file": "other.py", "line": 1,
                                                   "code": "def normalize_value(body):"})
            elif change == "call_only":
                found["result"]["matches"].pop(0)
            elif change == "failed":
                found["success"] = False
            else:
                found["result"]["matches"][0]["line"] = True
            with self.subTest(change=change):
                self.assertIsNone(assignment_definition_read(found, seed))

    def test_already_read_definition_is_not_requested_again(self):
        data = review()
        with patch.dict(SOURCES, {HELPER: ["def normalize_value(body):", "    return body, None"]}):
            data["evidence"].append(source_record("E0002", HELPER))
        self.assertIsNone(intermediate_assignment_seed(data))

    def session(self, budget, *, assessed=False):
        session = _ProductionSession(job(False), SimpleNamespace(response_mode="staged_tool", halted=None,
                                     annotation_format="assessed_tool" if assessed else "native_tool"),
                                     NavigationRepo(), 12, budget)
        session.prepare()
        supplied = review()
        record = session.evidence("tool", **{key: value for key, value in supplied["evidence"][0].items() if key != "id"})
        for field in ("entry_point", "critical_operation"):
            supplied["draft_fields"][field]["evidence_ref"] = record["id"]
        # Exercise the production boundary: real merge_draft expands references
        # to file/line/code before navigate_entry_context ever sees the values.
        session.result["fields"]["commit"] = VULNERABLE
        session.result["field_reviews"]["commit"].update(status="supported", revision_basis="behavior_at_revision",
                                                       reason="Synthetic selected source revision.", evidence_refs=[record["id"]])
        for field in ("entry_point", "critical_operation"):
            supplied["field_reviews"][field].update(reason="Synthetic local source statement.", evidence_refs=[record["id"]])
        session.merge_draft({"fields": {field: supplied["draft_fields"][field]
                                        for field in ("entry_point", "critical_operation")},
                             "field_reviews": supplied["field_reviews"]})
        self.assertNotIn("evidence_ref", session.result["fields"]["entry_point"])
        self.assertEqual(session.result["fields"]["entry_point"]["file"], PATH)
        return session

    def test_rejected_operation_is_recovered_before_relationship_navigation_closes(self):
        with patch.dict(SOURCES, {PATH: LINES, HELPER: ["def normalize_value(body):", "    return body, None"]}, clear=True):
            session = self.session(24, assessed=True)
            old_value = copy.deepcopy(session.result["fields"]["critical_operation"])
            old_review = copy.deepcopy(session.result["field_reviews"]["critical_operation"])
            session.merge_draft({"fields": {}, "field_reviews": {}, "annotation_errors": [
                {"field": "critical_operation", "code": "unexpected_properties",
                 "path": "$[0].arguments.critical_operation.value"}]})
            session.drafted, session.initial_valid_updates = True, 7
            stages = []

            def complete(stage, **kwargs):
                stages.append(stage)
                if stage == "field_recovery":
                    self.assertEqual(session.repo.calls, [])
                    return {"action": "draft", "fields": {"critical_operation": old_value},
                            "field_reviews": {"critical_operation": old_review}}
                if stage == "evidence_followup":
                    self.assertTrue(any(row["action"] == "intermediate_assignment_read" for row in session.result["actions"]))
                    return {"action": "finish_reading", "reason": "enough_evidence"}
                return {"action": "draft", "fields": {}, "field_reviews": {}}

            with patch.object(session, "complete", side_effect=complete):
                session.finish_draft()
            self.assertEqual(stages, ["field_recovery", "evidence_followup", "self_review"])
            self.assertEqual(session.result["fields"]["critical_operation"], old_value)
            self.assertFalse(session.result["annotation_errors"])
            self.assertEqual([tool for tool, _ in session.repo.calls], ["search_code", "read_file"])

    def test_controller_spends_existing_tools_not_model_calls_or_field_approval(self):
        with patch.dict(SOURCES, {PATH: LINES, HELPER: ["def normalize_value(body):", "    return body, None"]}, clear=True):
            session = self.session(24)
            before = copy.deepcopy(session.result["field_reviews"])
            session.navigate_entry_context({})
            self.assertEqual([tool for tool, _ in session.repo.calls], ["search_code", "read_file"])
            self.assertEqual(session.repo.calls[1][1]["path"], HELPER)
            self.assertEqual(session.result["model_calls"], 0)
            self.assertEqual(session.result["field_reviews"], before)
            self.assertTrue(any(row["action"] == "intermediate_assignment_read" for row in session.result["actions"]))
            session = self.session(3)
            session.navigate_entry_context({})
            self.assertEqual([tool for tool, _ in session.repo.calls], ["search_code"])

    def test_comparison_citation_and_new_prefix_do_not_hide_the_intermediate_read(self):
        with patch.dict(SOURCES, {PATH: LINES, HELPER: ["def normalize_value(body):", "    return body, None"]}, clear=True):
            session = self.session(24, assessed=True)
            record = next(row for row in session.result["evidence"] if row.get("tool") == "read_file")
            record["result"].update(start_line=2, text="\n".join(LINES[1:]),
                lines=[{"line": n, "code": LINES[n - 1]} for n in range(2, 9)])
            contrast = source_record("E0900", PATH, commit=FIXED)
            contrast = session.evidence("tool", **{key: value for key, value in contrast.items() if key != "id"})
            session.result["field_reviews"]["entry_point"]["evidence_refs"].append(contrast["id"])
            before = copy.deepcopy((session.result["fields"], session.result["field_reviews"]))
            session.navigate_entry_context({})
            self.assertEqual([tool for tool, _ in session.repo.calls], ["read_file", "search_code", "read_file"])
            self.assertEqual(session.repo.calls[0][1], {"commit": VULNERABLE, "path": PATH, "start_line": 1, "end_line": 1})
            self.assertEqual(session.repo.calls[-1][1]["path"], HELPER)
            self.assertEqual((session.result["fields"], session.result["field_reviews"]), before)
            self.assertEqual(session.result["model_calls"], 0)


if __name__ == "__main__":
    unittest.main()
