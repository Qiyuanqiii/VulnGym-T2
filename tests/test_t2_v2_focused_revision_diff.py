"""Deferred per-file comparisons use only synthetic saved evidence, no HTTP."""
import copy
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from vulngym_t2.output import _saved_actions
from vulngym_t2.pipeline import _ProductionSession, _json
from vulngym_t2.revision_navigation import comparison_reads, focused_diff_seed, uncovered_comparison_reads
from tests import test_t2_v2_staged_pipeline as fixture
from tests.test_t2_v2_pipeline import FIXED, VULNERABLE, evidence_from, job
from tests.test_t2_v2_source_continuation import receipt as continuation_receipt


PATH = "service/handler.py"


def full_diff():
    return {"id": "E0010", "tool": "read_diff", "success": False,
        "arguments": {"before": VULNERABLE, "after": FIXED},
        "result": {"error": "Repository read failed: ValueError", "error_code": "git_output_limit"}}


def source(identity="E0011", *, path=PATH, commit=FIXED, first=40, last=44):
    lines = ["def serve(request):", "    return process(request.value)"] + [""] * (last - first - 1)
    return {"id": identity, "tool": "read_file", "success": True,
        "result": {"commit": commit, "path": path, "start_line": first, "end_line": last,
            "text": "\n".join(lines),
            "lines": [{"line": first + index, "code": code} for index, code in enumerate(lines)]}}


def scoped_diff():
    return {"id": "E0012", "tool": "read_diff", "success": True,
        "arguments": {"before": VULNERABLE, "after": FIXED, "path": PATH},
        "result": {"before": VULNERABLE, "after": FIXED, "paths": [PATH], "truncated": False,
            "diff": f"diff --git a/{PATH} b/{PATH}\n--- a/{PATH}\n+++ b/{PATH}\n"
                    "@@ -1,2 +1,2 @@\n-old header\n+new header\n"
                    "@@ -37,2 +40,2 @@\n def serve(request):\n-old\n+new\n"}}


def review():
    return {"evidence": [full_diff(), source()], "draft_fields": {}, "suggested_values": {},
        "field_reviews": {"critical_operation": {"status": "uncertain", "evidence_refs": ["E0011"]}}}


def priority_review():
    """Broad cited head plus split later source, with no selected location."""
    lines = [""] * 250
    lines[9] = "from updated import Setting"
    lines[49:52] = ["def helper(value):", '    """Example only: run(value) if permitted."""', "    return value"]
    lines[179:187] = ["    enabled: bool = False", "", "    def build(self):",
                      "        self.item = make_item()", "        return self.item", "",
                      "    @property", "    def item_keys(self):"]
    value = review()
    value["evidence"] = [full_diff()]
    for identity, first, last in (("E0011", 1, 90), ("E0013", 160, 184), ("E0014", 185, 230)):
        row = source(identity, first=first, last=last)
        row["result"].update(text="\n".join(lines[first - 1:last]),
            lines=[{"line": n, "code": lines[n - 1]} for n in range(first, last + 1)])
        value["evidence"].append(row)
    value["field_reviews"].update(commit={"status": "uncertain", "evidence_refs": ["E0013"]},
                                  entry_point={"status": "uncertain", "evidence_refs": ["E0014"]})
    return value


def priority_diff():
    row = scoped_diff()
    row["result"]["diff"] = (f"diff --git a/{PATH} b/{PATH}\n--- a/{PATH}\n+++ b/{PATH}\n"
        "@@ -10,1 +10,1 @@\n-from previous import Setting\n+from updated import Setting\n"
        "@@ -50,3 +50,3 @@\n def helper(value):\n-    \"\"\"Older example.\"\"\"\n"
        "+    \"\"\"Example only: run(value) if permitted.\"\"\"\n     return value\n"
        "@@ -180,4 +180,8 @@ class Worker:\n     enabled: bool = False\n \n"
        "+    def build(self):\n+        self.item = make_item()\n+        return self.item\n+\n"
        "     @property\n     def item_keys(self):\n")
    return row


class FocusedDiffSeedTests(unittest.TestCase):
    def test_saved_failed_whole_diff_and_cited_source_supply_exact_pair_and_path_without_mutation(self):
        value = review()
        original = copy.deepcopy(value)
        self.assertEqual(focused_diff_seed(value), {"arguments": {
            "before": VULNERABLE, "after": FIXED, "path": PATH},
            "evidence_refs": ["E0010", "E0011"], "source_revision": FIXED, "source_line": None,
            "source_windows": [{"commit": FIXED, "start_line": 40, "end_line": 44}], "selected_windows": []})
        self.assertEqual(value, original)

    def test_successful_but_truncated_full_diff_is_eligible_not_a_complete_diff(self):
        value = review()
        value["evidence"][0] = scoped_diff()
        value["evidence"][0]["id"] = "E0010"
        del value["evidence"][0]["arguments"]["path"]
        self.assertIsNone(focused_diff_seed(value))
        for flag in ("truncated", "context_truncated", "complete"):
            with self.subTest(flag=flag):
                copy_value = copy.deepcopy(value)
                copy_value["evidence"][0]["result"][flag] = flag != "complete"
                self.assertIsNotNone(focused_diff_seed(copy_value))

    def test_no_successful_cited_source_no_full_sha_no_matching_result_or_invalid_receipts_do_not_seed(self):
        mutations = {
            "uncited": lambda value: value["field_reviews"]["critical_operation"].update(evidence_refs=[]),
            "failed source": lambda value: value["evidence"][1].update(success=False),
            "source no bytes": lambda value: value["evidence"][1]["result"].update(lines=[], text=""),
            "source other sha": lambda value: value["evidence"][1]["result"].update(commit="c" * 40),
            "alias before": lambda value: value["evidence"][0]["arguments"].update(before="HEAD^"),
            "alias source": lambda value: value["evidence"][1]["result"].update(commit="HEAD"),
            "equal pair": lambda value: value["evidence"][0]["arguments"].update(before=FIXED),
            "mismatched result": lambda value: value["evidence"][0]["result"].update(before="c" * 40),
            "missing arguments": lambda value: value["evidence"][0].pop("arguments"),
            "duplicate id": lambda value: value["evidence"].append(copy.deepcopy(value["evidence"][1])),
            "bad id": lambda value: value["evidence"][1].update(id="not_evidence"),
            "too many receipts": lambda value: value["evidence"].extend([{}] * 256),
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name):
                value = review()
                mutate(value)
                self.assertIsNone(focused_diff_seed(value))

    def test_unsafe_and_noncanonical_source_paths_cannot_become_pathspecs(self):
        for path in ("../outside.py", "/outside.py", "C:/outside.py", "src\\worker.py", "./worker.py",
                     "src//worker.py", "src/./worker.py", "--output=elsewhere", ":(glob)**", "src/\nworker.py"):
            with self.subTest(path=path):
                value = review()
                value["evidence"][1]["result"]["path"] = path
                self.assertIsNone(focused_diff_seed(value))

    def test_existing_scoped_attempt_in_either_direction_prevents_an_automatic_repeat(self):
        for success in (False, True):
            for reverse in (False, True):
                with self.subTest(success=success, reverse=reverse):
                    value = review()
                    attempted = scoped_diff()
                    attempted["success"] = success
                    if reverse:
                        attempted["arguments"].update(before=FIXED, after=VULNERABLE)
                    value["evidence"].append(attempted)
                    self.assertIsNone(focused_diff_seed(value))
        value = review()
        attempted = scoped_diff()
        attempted["arguments"]["path"] = "service/other.py"
        value["evidence"].append(attempted)
        self.assertIsNotNone(focused_diff_seed(value))

    def test_ambiguous_citations_need_a_real_selected_location_not_a_guessed_path(self):
        value = review()
        value["evidence"].append(source("E0013", path="service/other.py"))
        decision = value["field_reviews"]["critical_operation"]
        decision["evidence_refs"].append("E0013")
        self.assertIsNone(focused_diff_seed(value))
        value["suggested_values"]["critical_operation"] = {
            "file": PATH, "line": 41, "code": "    return process(request.value)"}
        self.assertEqual(focused_diff_seed(value)["source_line"], 41)
        value["suggested_values"]["critical_operation"]["code"] = "not the shown code"
        self.assertIsNone(focused_diff_seed(value))

    def test_actual_nearest_hunk_supplies_both_snapshots_and_never_transplants_source_coordinates(self):
        seed, result = focused_diff_seed(review()), scoped_diff()
        original = copy.deepcopy(result)
        self.assertEqual(comparison_reads(result, focus=seed), [
            {"commit": VULNERABLE, "path": PATH, "start_line": 25, "end_line": 50},
            {"commit": FIXED, "path": PATH, "start_line": 28, "end_line": 53}])
        self.assertEqual(result, original)
        result["result"]["truncated"] = True
        self.assertEqual(len(comparison_reads(result, focus=seed)), 2)
        # The cited source may be either side, without reversing/deriving SHAs.
        value = review()
        value["evidence"][1]["result"]["commit"] = VULNERABLE
        before_seed = focused_diff_seed(value)
        self.assertEqual(before_seed["arguments"], seed["arguments"])
        self.assertEqual(comparison_reads(result, focus=before_seed), comparison_reads(result, focus=seed))

    def test_failed_empty_unrelated_renamed_or_mismatched_scoped_diff_never_guesses_source(self):
        mutations = {
            "failed": lambda row: row.update(success=False),
            "empty": lambda row: row["result"].update(diff=""),
            "other pair": lambda row: row["result"].update(before="c" * 40),
            "other file": lambda row: row["result"].update(diff=row["result"]["diff"].replace(PATH, "service/other.py")),
            "renamed": lambda row: row["result"].update(diff=row["result"]["diff"].replace("+++ b/" + PATH, "+++ b/renamed.py")),
            "zero side": lambda row: row["result"].update(diff=row["result"]["diff"].replace("-1,2", "-0,0")),
        }
        seed = focused_diff_seed(review())
        for name, mutate in mutations.items():
            with self.subTest(name=name):
                row = scoped_diff()
                mutate(row)
                self.assertEqual(comparison_reads(row, focus=seed), [])
        for focus in (None, [], {}, {"arguments": []}):
            if focus is not None:
                self.assertEqual(comparison_reads(scoped_diff(), focus=focus), [])


class FocusedDiffPriorityTests(unittest.TestCase):
    def test_all_essential_field_ranges_outrank_broad_head_imports_and_docstring_code_examples(self):
        value = priority_review()
        original = copy.deepcopy(value)
        seed = focused_diff_seed(value)
        self.assertIsNone(seed["source_line"])
        self.assertEqual(seed["evidence_refs"], ["E0010", "E0011", "E0014", "E0013"])
        requests = comparison_reads(priority_diff(), focus=seed)
        self.assertEqual(requests, [
            {"commit": VULNERABLE, "path": PATH, "start_line": 168, "end_line": 195},
            {"commit": FIXED, "path": PATH, "start_line": 168, "end_line": 199}])
        self.assertEqual(value, original)
        self.assertEqual(uncovered_comparison_reads(requests, value["evidence"]), [requests[0]])

    def test_precisely_selected_actual_changed_import_is_still_eligible(self):
        value = priority_review()
        value["suggested_values"]["critical_operation"] = {
            "evidence_ref": "E0011", "start_line": 10, "end_line": 10}
        seed = focused_diff_seed(value)
        self.assertEqual(seed["source_line"], 10)
        self.assertEqual(comparison_reads(priority_diff(), focus=seed)[0]["start_line"], 1)

    def test_uncited_or_failed_later_source_does_not_supply_behavior_priority(self):
        for kind in ("uncited", "failed"):
            with self.subTest(kind=kind):
                value = priority_review()
                if kind == "uncited":
                    value["field_reviews"]["commit"]["evidence_refs"] = []
                    value["field_reviews"]["entry_point"]["evidence_refs"] = []
                else:
                    for row in value["evidence"][2:]:
                        row["success"] = False
                seed = focused_diff_seed(value)
                self.assertEqual(seed["source_windows"], [{"commit": FIXED, "start_line": 1, "end_line": 90}])
                self.assertNotEqual(comparison_reads(priority_diff(), focus=seed)[0]["start_line"], 168)

    def test_union_coverage_requires_every_actual_line_same_sha_and_agreeing_bytes(self):
        value = priority_review()
        request = comparison_reads(priority_diff(), focus=focused_diff_seed(value))[1]
        for kind in ("gap", "failed", "different_sha", "conflict"):
            with self.subTest(kind=kind):
                evidence = copy.deepcopy(value["evidence"])
                if kind == "gap":
                    evidence[-1]["result"]["lines"].pop(0)
                    evidence[-1]["result"]["start_line"] += 1
                elif kind == "failed":
                    evidence[-1]["success"] = False
                elif kind == "different_sha":
                    evidence[-1]["result"]["commit"] = VULNERABLE
                else:
                    other = copy.deepcopy(evidence[-1])
                    other["id"] = "E0018"
                    other["result"]["lines"][0]["code"] = "different bytes"
                    evidence.append(other)
                self.assertEqual(uncovered_comparison_reads([request], evidence), [request])

    def test_bad_window_coordinates_do_not_create_unbounded_or_cross_revision_priority(self):
        for window in ({"commit": "HEAD", "start_line": 1, "end_line": 9},
                       {"commit": FIXED, "start_line": 1, "end_line": True},
                       {"commit": FIXED, "start_line": 5, "end_line": 1}):
            seed = focused_diff_seed(priority_review())
            seed["source_windows"] = [window]
            self.assertEqual(comparison_reads(priority_diff(), focus=seed), [])


class ScopedDiffRepo(fixture.MemoryRepo):
    def __init__(self, outcome="success"):
        super().__init__()
        self.outcome = outcome

    def call(self, tool, arguments):
        if tool == "read_diff":
            self.calls.append((tool, copy.deepcopy(arguments)))
            if arguments.get("path") is None or self.outcome == "failed":
                return {"error": "No complete diff was returned", "error_code": "git_output_limit"}
            result = scoped_diff()["result"]
            if self.outcome == "oversized":
                result["diff"] += "x" * 20000
            elif self.outcome == "empty":
                result["diff"] = ""
            return result
        if tool == "read_file":
            self.calls.append((tool, copy.deepcopy(arguments)))
            if self.outcome == "before_source_failed" and arguments["commit"] == VULNERABLE:
                return {"error": "Source unavailable in this snapshot", "error_code": "source_file_unavailable"}
            first, last = arguments["start_line"], arguments["end_line"]
            result = source(commit=arguments["commit"], path=arguments["path"], first=first, last=last)["result"]
            # Actual independently returned bytes, not the current side's text.
            for row in result["lines"]:
                row["code"] = f"# {arguments['commit'][0]} snapshot line {row['line']}"
            result["text"] = "\n".join(row["code"] for row in result["lines"])
            return result
        return super().call(tool, arguments)


class FocusedDiffIntegrationTests(unittest.TestCase):
    def session(self, outcome="success", *, assessed=False):
        client = SimpleNamespace(response_mode="staged_tool", halted=None,
                                 annotation_format="assessed_tool" if assessed else "snapshot_tool")
        session = _ProductionSession(job(False), client, ScopedDiffRepo(outcome), 16, 32)
        session.prepare()
        for row in (full_diff(), source()):
            saved = session.evidence("tool", **{key: value for key, value in row.items() if key != "id"})
        session.result["field_reviews"]["critical_operation"].update(status="uncertain", evidence_refs=[saved["id"]])
        return session

    def test_one_scoped_diff_and_actual_current_parent_reads_replace_other_navigation_without_semantic_changes(self):
        session = self.session(assessed=True)
        original = {key: copy.deepcopy(session.result[key]) for key in ("fields", "field_reviews", "evidence")}
        with patch("vulngym_t2.entry_navigation.navigate_entry", side_effect=AssertionError("No appended caller chain")):
            session.navigate_entry_context({})
        self.assertEqual([tool for tool, _ in session.repo.calls], ["read_diff", "read_file", "read_file"])
        self.assertEqual(session.repo.calls[0][1], {"before": VULNERABLE, "after": FIXED, "path": PATH})
        self.assertEqual({args["commit"] for tool, args in session.repo.calls if tool == "read_file"}, {VULNERABLE, FIXED})
        for key in ("fields", "field_reviews"):
            self.assertEqual(session.result[key], original[key])
        self.assertEqual(session.result["evidence"][:-3], original["evidence"])
        self.assertEqual(session.result["model_calls"], 0)
        self.assertTrue(session.focused_diff_attempted)
        self.assertTrue(session.followup_context_fits())
        self.assertLessEqual(sum(len(row["content"]) for row in session.messages), session.navigation_context_limit())
        actions = _saved_actions(session.result["actions"])
        self.assertEqual(len([row for row in actions if row["action"] == "focused_revision_source"]), 2)
        self.assertTrue(all("approved" in row["summary"] or "automatically" in row["summary"]
                            for row in actions if row["action"].startswith("focused_revision")))

    def test_failed_empty_and_oversized_diff_never_trigger_source_reads_or_loop(self):
        for outcome in ("failed", "empty", "oversized"):
            with self.subTest(outcome=outcome):
                session = self.session(outcome)
                session.navigate_entry_context({})
                session.navigate_entry_context({})
                self.assertEqual([tool for tool, _ in session.repo.calls], ["read_diff"])
                self.assertTrue(session.focused_diff_attempted)
                if outcome == "oversized":
                    self.assertEqual(session.result["evidence"][-1]["result"]["error_code"], "navigation_display_limit")

    def test_no_tool_context_or_provider_budget_does_not_spend_or_claim_an_attempt(self):
        for reason in ("tools", "context", "provider"):
            with self.subTest(reason=reason):
                session = self.session()
                if reason == "tools":
                    session.max_tool_calls = 4  # Three new reads plus the existing two-tool reserve do not fit.
                elif reason == "context":
                    session.evidence("advisory", text="x" * 85000)
                    session.messages.append({"role": "user", "content": _json(session.result["evidence"])})
                else:
                    session.client.halted = "stopped"
                session.navigate_entry_context({})
                self.assertEqual(session.repo.calls, [])
                self.assertFalse(session.focused_diff_attempted)
                self.assertTrue(any(row["action"] == "focused_revision_diff_skipped" for row in session.result["actions"]))

    def test_failed_parent_source_is_retained_as_failure_and_current_side_remains_independent(self):
        session = self.session("before_source_failed")
        session.navigate_entry_context({})
        session.navigate_entry_context({})
        self.assertEqual([tool for tool, _ in session.repo.calls], ["read_diff", "read_file", "read_file"])
        compared = session.result["evidence"][-2:]
        self.assertFalse(compared[0]["success"])
        self.assertEqual(compared[0]["arguments"]["commit"], VULNERABLE)
        self.assertTrue(compared[1]["success"])
        self.assertEqual(compared[1]["result"]["commit"], FIXED)
        self.assertEqual(session.result["field_reviews"]["critical_operation"]["status"], "uncertain")

    def test_already_visible_exact_source_windows_reuse_receipts_not_extra_reads(self):
        session = self.session()
        for request in comparison_reads(scoped_diff(), focus=focused_diff_seed(review())):
            row = source(commit=request["commit"], first=request["start_line"], last=request["end_line"])
            if request["commit"] == FIXED:
                original = source()["result"]["lines"]
                known = {line["line"]: line["code"] for line in original}
                for line in row["result"]["lines"]:
                    if line["line"] in known:
                        line["code"] = known[line["line"]]
                row["result"]["text"] = "\n".join(line["code"] for line in row["result"]["lines"])
            session.evidence("tool", **{key: value for key, value in row.items() if key != "id"})
        session.navigate_entry_context({})
        self.assertEqual([tool for tool, _ in session.repo.calls], ["read_diff"])
        self.assertFalse(any(row["action"] == "focused_revision_source" for row in session.result["actions"]))

    def test_attempt_is_shared_across_later_candidates_and_focused_read_passes(self):
        session = self.session()
        session.navigate_entry_context({})
        row = source(path="service/second.py")
        saved = session.evidence("tool", **{key: value for key, value in row.items() if key != "id"})
        session.result["field_reviews"]["critical_operation"]["evidence_refs"] = [saved["id"]]
        session.navigate_entry_context({})
        session.navigate_entry_context({}, focused_reads=[saved])
        self.assertEqual(len([tool for tool, _ in session.repo.calls if tool == "read_diff"]), 1)

    def test_boundary_cut_source_continuation_has_priority_over_deferred_diff(self):
        session = self.session()
        row = continuation_receipt(commit=FIXED, path=PATH)
        saved = session.evidence("tool", **{key: value for key, value in row.items() if key != "id"})
        session.result["field_reviews"]["critical_operation"]["evidence_refs"] = [saved["id"]]
        session.navigate_entry_context({})
        self.assertEqual([tool for tool, _ in session.repo.calls], ["read_file"])
        self.assertEqual(session.repo.calls[0][1]["start_line"], 141)
        self.assertFalse(session.focused_diff_attempted)


class FocusedDiffStagedPipelineTests(unittest.TestCase):
    setUp = fixture.StagedPipelineTests.setUp
    run_script = fixture.StagedPipelineTests.run_script

    def test_deferred_reads_reach_original_final_review_without_extra_model_calls_or_status_promotion(self):
        def initial(payload):
            row = next(row for row in evidence_from(payload["messages"]) if row.get("tool") == "read_file")
            response = fixture.annotation()
            response[1]["commit"].update(status="uncertain", reason="The source needs comparison.",
                evidence_refs=[row["id"]], value=FIXED, revision_basis="inspected_only")
            return response

        def final(payload):
            rows = evidence_from(payload["messages"])
            self.assertEqual({row["result"]["commit"] for row in rows if row.get("tool") == "read_file"},
                             {VULNERABLE, FIXED})
            self.assertEqual(len([row for row in rows if row.get("tool") == "read_diff"
                                  and row.get("success") is True]), 1)
            return fixture.annotation()

        with patch.object(fixture, "MemoryRepo", ScopedDiffRepo):
            result, finalized, client, repo, _ = self.run_script([
                ("read_file", {"commit": FIXED, "path": PATH, "start_line": 40, "end_line": 44}),
                fixture.FINISH, initial, fixture.FINISH, final], supplied=job(True), max_calls=5)
        self.assertEqual(result["model_calls"], 5)
        self.assertEqual(result["self_review_status"], "completed")
        self.assertIsNone(client.halted)
        self.assertIsNone(result["fields"].get("commit"))
        self.assertIsNone(finalized["entry"])
        diffs = [args for tool, args in repo.calls if tool == "read_diff"]
        self.assertEqual(len(diffs), 2)
        self.assertNotIn("path", diffs[0])
        self.assertEqual(diffs[1]["path"], PATH)


if __name__ == "__main__":
    unittest.main()
