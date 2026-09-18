"""Diff-directed source reads do not establish a revision's semantic status."""
import copy
import unittest
from unittest.mock import patch

from vulngym_t2.revision_navigation import comparison_reads
from tests import test_t2_v2_staged_pipeline as fixture
from tests.test_t2_v2_pipeline import VULNERABLE, FIXED, evidence_from, job


def diff_record():
    return {"id": "E0005", "tool": "read_diff", "success": True, "result": {
        "before": VULNERABLE, "after": FIXED,
        "diff": "diff --git a/service/handler.py b/service/handler.py\n"
                "--- a/service/handler.py\n+++ b/service/handler.py\n@@ -40,5 +42,6 @@\n-old\n+new\n"}}


class ComparisonReadTests(unittest.TestCase):
    def test_actual_two_revisions_and_hunk_coordinates_without_selection_or_mutation(self):
        record = diff_record()
        original = copy.deepcopy(record)
        self.assertEqual(comparison_reads(record), [
            {"commit": VULNERABLE, "path": "service/handler.py", "start_line": 28, "end_line": 56},
            {"commit": FIXED, "path": "service/handler.py", "start_line": 30, "end_line": 59}])
        self.assertEqual(record, original)

    def test_unknown_paths_missing_sides_failed_reads_and_ambiguous_sha_are_not_guessed(self):
        for mutate in (
            lambda row: row.update(success=False),
            lambda row: row["result"].update(before="HEAD"),
            lambda row: row["result"].update(after=VULNERABLE),
            lambda row: row["result"].update(diff=row["result"]["diff"].replace("a/service/handler.py", "/dev/null")),
            lambda row: row["result"].update(diff=row["result"]["diff"].replace("b/service/handler.py", "b/../outside.py")),
            lambda row: row["result"].update(diff=row["result"]["diff"].replace("-40,5", "-0,0")),
        ):
            record = diff_record()
            mutate(record)
            with self.subTest(mutate=mutate):
                self.assertEqual(comparison_reads(record), [])

    def test_large_hunk_is_only_a_bounded_read_and_not_full_coverage(self):
        record = diff_record()
        record["result"]["diff"] = record["result"]["diff"].replace("-40,5 +42,6", "-1,500 +1,600")
        requests = comparison_reads(record)
        self.assertEqual(len(requests), 2)
        self.assertTrue(all(row["start_line"] == 1 and row["end_line"] == 72 for row in requests))


class ComparisonRepo(fixture.MemoryRepo):
    def call(self, tool, arguments):
        if tool == "read_diff":
            self.calls.append((tool, copy.deepcopy(arguments)))
            result = diff_record()["result"]
            result["diff"] = result["diff"].replace("-40,5 +42,6", "-1,2 +1,2")
            return result
        return super().call(tool, arguments)


class ComparisonIntegrationTests(unittest.TestCase):
    setUp = fixture.StagedPipelineTests.setUp
    run_script = fixture.StagedPipelineTests.run_script

    def test_source_comparison_precedes_model_and_never_auto_selects_parent(self):
        def finish(payload):
            records = evidence_from(payload["messages"])
            self.assertEqual({row["result"]["commit"] for row in records if row.get("tool") == "read_file"},
                             {VULNERABLE, FIXED})
            return fixture.FINISH

        with patch.object(fixture, "MemoryRepo", ComparisonRepo):
            result, final, client, _, _ = self.run_script(
                [finish, fixture.annotation(), fixture.annotation()], max_calls=3, supplied=job(True))
        self.assertIsNone(client.halted)
        self.assertIsNone(final["entry"])
        self.assertIsNone(result["fields"].get("commit"))
        self.assertEqual(result["model_calls"], 3)
        self.assertTrue(any(row["action"] == "revision_comparison_reads" for row in result["actions"]))


if __name__ == "__main__":
    unittest.main()
