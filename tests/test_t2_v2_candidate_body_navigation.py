"""Candidate navigation inspects an observed file, never promotes a field."""
import copy
import json
from types import SimpleNamespace
import unittest

from vulngym_t2.candidate_navigation import candidate_body_request
from vulngym_t2.pipeline import ENTRY_FIELDS, _ProductionSession


OLD, NEW = "a" * 40, "b" * 40
LEFT = "src/components/Left/actions/store.operation.ts"
RIGHT = "src/components/Right/actions/store.operation.ts"
HELPER = "src/components/Right/helpers/value.ts"


def source(eid, path, sha=OLD):
    return {"id": eid, "tool": "read_file", "success": True,
            "result": {"commit": sha, "path": path, "start_line": 1, "end_line": 2,
                       "lines": [{"line": 1, "code": "export function value(x) {"},
                                 {"line": 2, "code": "  return x; }"}],
                       "text": "export function value(x) {\n  return x; }", "truncated": False}}


def inputs():
    scope = {"scope": "Right store branch takes the configured value", "evidence_refs": ["E0001", "E0002"]}
    evidence = [{"id": "E0001", "tool": "inspect_commit", "success": True,
                 "result": {"commit": NEW, "parents": [OLD], "changed_paths_against": OLD,
                            "changed_paths": [LEFT, RIGHT]}}, source("E0002", HELPER)]
    return scope, evidence


class MemoryRepo:
    def __init__(self, *, fail=False):
        self.calls, self.fail = [], fail

    def call(self, tool, arguments):
        self.calls.append((tool, copy.deepcopy(arguments)))
        if self.fail:
            return {"error": "source_file_unavailable"}
        if tool != "read_file":
            raise AssertionError(tool)
        result = source("unused", arguments["path"], arguments["commit"])["result"]
        result["total_lines"] = 2
        return result


class CandidateBodyNavigationTests(unittest.TestCase):
    def test_scope_filename_and_nearest_cited_directory_select_real_changed_path(self):
        scope, evidence = inputs()
        before = copy.deepcopy((scope, evidence))
        request = candidate_body_request(scope, evidence)
        self.assertEqual(request["arguments"], {"commit": OLD, "path": RIGHT, "start_line": 1, "end_line": 180})
        self.assertEqual(set(request["evidence_refs"]), {"E0001", "E0002"})
        self.assertEqual((scope, evidence), before)

    def test_unknown_name_or_unrelated_revision_or_existing_body_has_no_preference(self):
        for case in ("unknown_name", "unrelated_revision", "already_read", "invalid_path", "no_cited_source"):
            with self.subTest(case=case):
                scope, evidence = inputs()
                if case == "unknown_name":
                    scope["scope"] = "An operation with no known filename"
                elif case == "unrelated_revision":
                    evidence[0]["result"]["changed_paths_against"] = "c" * 40
                elif case == "already_read":
                    evidence.append(source("E0003", RIGHT))
                elif case == "invalid_path":
                    evidence[0]["result"]["changed_paths"] = ["../../store.operation.ts"]
                else:
                    scope["evidence_refs"] = ["E0001"]
                self.assertIsNone(candidate_body_request(scope, evidence))

    def test_ambiguous_components_or_revisions_preserve_model_reading(self):
        for variant in ("components", "revisions"):
            with self.subTest(variant=variant):
                scope, evidence = inputs()
                evidence.append(source("E0003", "src/components/Left/helpers/value.ts"
                                       if variant == "components" else HELPER,
                                       OLD if variant == "components" else NEW))
                scope["evidence_refs"].append("E0003")
                self.assertIsNone(candidate_body_request(scope, evidence))

    def test_cited_existing_body_does_not_redirect_to_unread_sibling(self):
        scope, evidence = inputs()
        evidence.append(source("E0003", LEFT))
        scope.update(scope="Left store branch", evidence_refs=["E0001", "E0003"])
        self.assertIsNone(candidate_body_request(scope, evidence))

    def test_read_helper_does_not_hide_a_different_named_unread_body(self):
        scope, evidence = inputs()
        helper = "src/components/Right/helpers/utils.ts"
        scope["scope"] = "Right store branch uses helpers/utils.ts"
        evidence[0]["result"]["changed_paths"].append(helper)
        evidence[1] = source("E0002", helper)
        before = copy.deepcopy((scope, evidence))
        request = candidate_body_request(scope, evidence)
        self.assertEqual(request["arguments"],
                         {"commit": OLD, "path": RIGHT, "start_line": 1, "end_line": 180})
        self.assertEqual(set(request["evidence_refs"]), {"E0001", "E0002"})
        self.assertEqual((scope, evidence), before)

    def test_multiple_unread_named_groups_preserve_model_reading(self):
        scope, evidence = inputs()
        scope["scope"] = "Right store branch uses helpers/utils.ts"
        evidence[0]["result"]["changed_paths"].append("src/components/Right/helpers/utils.ts")
        self.assertIsNone(candidate_body_request(scope, evidence))

    def test_ambiguous_group_blocks_another_unique_named_group(self):
        scope, evidence = inputs()
        scope["scope"] = "Store branch uses helpers/utils.ts"
        evidence[0]["result"]["changed_paths"].append("src/components/Right/helpers/utils.ts")
        evidence.append(source("E0003", "src/components/Left/helpers/value.ts"))
        scope["evidence_refs"].append("E0003")
        self.assertIsNone(candidate_body_request(scope, evidence))

    def test_read_group_winner_still_blocks_its_sibling_in_multiple_named_groups(self):
        scope, evidence = inputs()
        helper = "src/components/Right/helpers/utils.ts"
        scope["scope"] = "Store branch uses helpers/utils.ts"
        evidence[0]["result"]["changed_paths"].append(helper)
        evidence.append(source("E0003", LEFT))
        scope["evidence_refs"].append("E0003")
        request = candidate_body_request(scope, evidence)
        self.assertEqual(request["arguments"]["path"], helper)
        self.assertNotEqual(request["arguments"]["path"], RIGHT)

    def test_diff_paths_are_observed_leads_and_malformed_metadata_is_inert(self):
        scope, evidence = inputs()
        evidence[0].update(tool="read_diff", result={"before": OLD, "after": NEW, "paths": [LEFT, RIGHT]})
        self.assertEqual(candidate_body_request(scope, evidence)["arguments"]["path"], RIGHT)
        evidence[0]["result"].update(before=[], after={})
        self.assertIsNone(candidate_body_request(scope, evidence))
        evidence[0]["id"] = []
        self.assertIsNone(candidate_body_request(scope, evidence))

    def state(self, *, fail=False):
        scope, evidence = inputs()
        client = SimpleNamespace(response_mode="staged_tool", annotation_format="assessed_tool",
                                 multi_entry=True, halted=None, remaining_requests=12)
        state = _ProductionSession({"report_id": "GHSA-2222-3333-4444"}, client, MemoryRepo(fail=fail), 16, 24)
        state.result["evidence"] = evidence
        state.result["field_reviews"] = {name: {"status": "missing", "reason": "Not established.",
                                              "evidence_refs": []} for name in ENTRY_FIELDS}
        state.evidence_by_id = {row["id"]: row for row in evidence}
        state.active_candidate_scope = scope
        state.messages = [{"role": "system", "content": "Use saved evidence only."},
                          {"role": "user", "content": json.dumps({"evidence": evidence})}]
        return state

    def test_controller_reads_once_without_model_call_or_field_approval(self):
        state = self.state()
        fields, reviews = copy.deepcopy((state.result["fields"], state.result["field_reviews"]))
        state.read_candidate_body()
        state.read_candidate_body()
        self.assertEqual(len(state.repo.calls), 1)
        self.assertEqual(state.result["model_calls"], 0)
        self.assertEqual(state.result["tool_calls"], 1)
        self.assertEqual((state.result["fields"], state.result["field_reviews"]), (fields, reviews))
        self.assertTrue(any(item.get("action") == "candidate_source_probe" and item["success"]
                            for item in state.result["actions"]))
        self.assertIn(RIGHT, json.dumps(state.messages))

    def test_failed_body_is_saved_and_not_retried(self):
        state = self.state(fail=True)
        state.read_candidate_body()
        state.read_candidate_body()
        self.assertEqual(len(state.repo.calls), 1)
        action = next(item for item in state.result["actions"] if item["action"] == "candidate_source_probe")
        self.assertFalse(action["success"])
        self.assertEqual(state.result["fields"], {})

    def test_closed_provider_low_tool_budget_and_single_mode_do_not_probe(self):
        for case in ("halted", "tool_budget", "single", "context"):
            with self.subTest(case=case):
                state = self.state()
                if case == "halted":
                    state.client.halted = "stopped"
                elif case == "tool_budget":
                    state.max_tool_calls = 2
                elif case == "single":
                    state.multi_mode = False
                else:
                    state.navigation_context_limit = lambda: 100
                state.read_candidate_body()
                self.assertEqual(state.repo.calls, [])
                self.assertEqual(state.result["model_calls"], 0)


if __name__ == "__main__":
    unittest.main()
