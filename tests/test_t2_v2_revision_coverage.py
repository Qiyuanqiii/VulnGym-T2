"""Revision discovery uses observed tree coverage, not a commit-title verdict."""
import copy
import json
import unittest

from vulngym_t2 import annotation_rules
from vulngym_t2.pipeline import _ProductionSession
from vulngym_t2.revision_navigation import revision_read_coverage
from tests.test_t2_v2_pipeline import job, VULNERABLE, FIXED
from tests.test_t2_v2_staged_pipeline import MemoryRepo


def receipts():
    return [
        {"id": "E0011", "tool": "inspect_commit", "success": True,
         "result": {"commit": FIXED, "message": "docs update", "parents": ["c" * 40]}},
        {"id": "E0012", "tool": "inspect_commit", "success": True,
         "result": {"commit": VULNERABLE, "message": "CI update"}},
        {"id": "E0013", "tool": "read_file", "success": True,
         "result": {"commit": FIXED, "path": "service/handler.py", "start_line": 10,
                    "end_line": 10, "text": "return lookup(current_user)", "truncated": True}},
    ]


class RevisionCoverageTests(unittest.TestCase):
    def test_single_inspected_snapshot_without_source_still_has_coverage_hint(self):
        data = receipts()[:1]
        original = copy.deepcopy(data)
        result = revision_read_coverage(data)
        self.assertEqual(result["inspected_snapshots"], [{
            "commit": FIXED, "inspection_ref": "E0011",
            "paths_with_visible_source": [], "omitted_path_count": 0}])
        self.assertEqual(result["omitted_snapshot_count"], 0)
        self.assertIn("even when a diff failed", result["note"])
        self.assertNotIn("c" * 40, json.dumps(result))
        self.assertEqual(data, original)
        self.assertEqual(revision_read_coverage([]), {})

    def test_inventory_retains_unread_snapshot_without_selecting_or_inventing_source(self):
        data = receipts()
        original = copy.deepcopy(data)
        result = revision_read_coverage(data)
        first, second = result["inspected_snapshots"]
        self.assertEqual(first["paths_with_visible_source"], ["service/handler.py"])
        self.assertEqual(second["paths_with_visible_source"], [])
        self.assertEqual(second["commit"], VULNERABLE)
        self.assertEqual(second["inspection_ref"], "E0012")
        self.assertNotIn("c" * 40, json.dumps(result))  # No guessed parent.
        self.assertNotIn("CI update", json.dumps(result))
        self.assertEqual(data, original)
        self.assertEqual(revision_read_coverage(data, max_chars=20), {})

    def test_failed_source_and_unresolved_refs_are_not_coverage(self):
        data = receipts()
        data[2]["success"] = False
        self.assertTrue(all(not row["paths_with_visible_source"]
                            for row in revision_read_coverage(data)["inspected_snapshots"]))
        data[1]["result"]["commit"] = "HEAD"
        rows = revision_read_coverage(data)["inspected_snapshots"]
        self.assertEqual([row["commit"] for row in rows], [FIXED])
        self.assertEqual(rows[0]["paths_with_visible_source"], [])
        self.assertIn("do not reuse line numbers", annotation_rules.TASK_RULES)

    def test_failed_diff_metadata_repeats_only_saved_errors_for_inspected_sha(self):
        data = receipts()[:1] + [{
            "id": "E0020", "tool": "read_diff", "success": False,
            "arguments": {"before": "c" * 40, "after": FIXED},
            "result": {"error": "Repository read failed: ValueError",
                       "error_code": "commit_unavailable"}}]
        original = copy.deepcopy(data)
        result = revision_read_coverage(data)
        row, = result["inspected_snapshots"]
        self.assertEqual(row["failed_diff_reads"], [{
            "evidence_ref": "E0020", "error": data[-1]["result"]["error"],
            "error_code": "commit_unavailable"}])
        self.assertEqual(row["omitted_failed_diff_count"], 0)
        self.assertEqual(row["paths_with_visible_source"], [])
        self.assertNotIn("c" * 40, json.dumps(result))
        self.assertEqual(data, original)

    def test_successful_unrelated_and_unresolved_diffs_do_not_become_failures(self):
        data = receipts()[:1]
        for identity, before, after, success in (
                ("E0020", FIXED, VULNERABLE, True),
                ("E0021", VULNERABLE, "c" * 40, False),
                ("E0022", "HEAD", "main", False)):
            data.append({"id": identity, "tool": "read_diff", "success": success,
                         "arguments": {"before": before, "after": after},
                         "result": {} if success else {"error": "commit_unavailable"}})
        row, = revision_read_coverage(data)["inspected_snapshots"]
        self.assertNotIn("failed_diff_reads", row)
        self.assertEqual(row["commit"], FIXED)
        data[0]["success"] = False
        self.assertEqual(revision_read_coverage(data), {})

    def test_failed_diff_metadata_and_serialized_inventory_remain_bounded(self):
        data = receipts()[:1]
        for number in range(20, 25):
            data.append({"id": f"E{number:04}", "tool": "read_diff", "success": False,
                         "arguments": {"before": FIXED, "after": VULNERABLE},
                         "result": {"error": "failure " * 100, "error_code": "x" * 500}})
        result = revision_read_coverage(data)
        row, = result["inspected_snapshots"]
        self.assertEqual(len(row["failed_diff_reads"]), 2)
        self.assertEqual(row["omitted_failed_diff_count"], 3)
        for failure in row["failed_diff_reads"]:
            self.assertEqual(failure["error"], data[-1]["result"]["error"][:160])
            self.assertEqual(failure["error_code"], "x" * 160)
            self.assertIs(failure["metadata_truncated"], True)
        encoded_length = len(json.dumps(result, ensure_ascii=False))
        self.assertLessEqual(encoded_length, 2400)
        self.assertEqual(revision_read_coverage(data, max_chars=encoded_length), result)
        self.assertEqual(revision_read_coverage(data, max_chars=encoded_length - 1), {})

    def test_failed_diff_without_error_text_does_not_invent_a_cause(self):
        data = receipts()[:1] + [{
            "id": "E0020", "tool": "read_diff", "success": False,
            "arguments": {"before": FIXED, "after": VULNERABLE}, "result": {}}]
        row, = revision_read_coverage(data)["inspected_snapshots"]
        self.assertEqual(row["failed_diff_reads"], [{"evidence_ref": "E0020"}])

    def test_read_phase_receives_fresh_inventory_without_an_extra_tool_call(self):
        class Client:
            response_mode = "staged_tool"
            def complete(self, messages, stage):
                self.messages = messages
                return {"action": "finish_reading", "reason": "evidence_ready"}
        client, repo = Client(), MemoryRepo()
        session = _ProductionSession(job(False), client, repo, 3, 24)
        session.prepare()
        session.result["evidence"].extend(receipts())
        before = copy.deepcopy(session.result)
        tools_before = list(repo.calls)
        session.complete("plan_and_read")
        inventory = [json.loads(message["content"])["revision_read_coverage"]
                     for message in client.messages
                     if message["content"].startswith('{"revision_read_coverage":')]
        self.assertEqual(len(inventory), 1)
        self.assertEqual(repo.calls, tools_before)
        self.assertEqual(session.result["fields"], before["fields"])
        self.assertEqual(session.result["evidence"], before["evidence"])
        self.assertEqual(session.result["model_calls"], 1)


if __name__ == "__main__":
    unittest.main()
