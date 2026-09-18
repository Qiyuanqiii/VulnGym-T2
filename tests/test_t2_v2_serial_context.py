"""Exercise a complete serial batch after the first candidate adds source reads.

All provider replies and repository contents are synthetic. Success here is
control-flow/evidence preservation, never a real-model accuracy score.
"""
import copy
import json
import unittest
from unittest.mock import patch

from tests import test_t2_v2_staged_pipeline as fixture
from tests.test_t2_v2_navigation_context import BulkyNavigationRepo
from tests.test_t2_v2_pipeline import VULNERABLE, evidence_from, job
from tests.test_t2_v2_staged_multi import proposals


def current_scope(payload):
    for message in payload["messages"]:
        if message["content"].startswith("{"):
            scope = json.loads(message["content"]).get("candidate_scope")
            if scope:
                return scope["scope"]
    raise AssertionError("Current candidate scope was lost")


def annotation_for_scope(payload, *, uncertain=False):
    tool, snapshot = fixture.full_annotation(payload)
    snapshot["vuln_title"]["value"] = current_scope(payload)
    if uncertain:
        snapshot["entry_point"].update(status="uncertain", reason="Only the helper is established; inspect caller evidence.")
    return tool, snapshot


class SerialContextTests(unittest.TestCase):
    setUp = fixture.StagedPipelineTests.setUp
    run_script = fixture.StagedPipelineTests.run_script

    def test_three_candidates_share_new_reads_without_losing_self_review_or_evidence(self):
        supplied = job(False)
        supplied["documents"] = [{"name": "advisory", "text": supplied["documents"][0]["text"] + "a" * 11000},
                                 {"name": "support", "text": "b" * 11000}]
        read = ("read_file", {"commit": VULNERABLE, "path": "src/helper.ts", "start_line": 1, "end_line": 3})
        diff = ("read_diff", {"before": VULNERABLE, "after": "b" * 40, "path": ""})

        def after_navigation(payload):
            receipts = evidence_from(payload["messages"])
            self.assertTrue(any(row.get("result", {}).get("path") == "src/provider.ts" for row in receipts))
            self.assertEqual(next(row["result"]["diff"] for row in receipts if row.get("tool") == "read_diff"), "d" * 14000)
            bookmarks = [json.loads(message["content"])["saved_source_bookmarks"]
                         for message in payload["messages"] if message["content"].startswith("{")
                         and "saved_source_bookmarks" in json.loads(message["content"])]
            self.assertTrue(bookmarks)
            self.assertTrue(bookmarks[-1]["bookmarks"])
            return annotation_for_scope(payload)

        with patch.object(fixture, "MemoryRepo", BulkyNavigationRepo):
            result, _, client, repo, payloads = self.run_script(
                [read, diff, fixture.FINISH, lambda p: proposals(p, 3),
                 lambda p: annotation_for_scope(p, uncertain=True), fixture.FINISH, after_navigation,
                 after_navigation, after_navigation, after_navigation, after_navigation],
                supplied=supplied, multi_entry=True, max_calls=11, max_tool_calls=32)
        self.assertIsNone(client.halted)
        self.assertEqual([entry["self_review_status"] for entry in result["entry_results"]], ["completed"] * 3)
        self.assertEqual(result["errors"], [])
        self.assertEqual(result["model_calls"], 11)
        self.assertTrue(any(arguments.get("path") == "src/provider.ts" for _, arguments in repo.calls))
        for index, entry in enumerate(result["entry_results"]):
            self.assertEqual(entry["errors"], [])
            self.assertEqual(entry["fields"]["vuln_title"], f"Independent synthetic scope {index}")
        for payload in payloads[5:]:
            self.assertLessEqual(sum(len(message["content"]) for message in payload["messages"]), 100000)
            scope = current_scope(payload)
            self.assertTrue(scope)
            for other in range(3):
                # Earlier original proposals now remain bounded scope context;
                # later unassessed proposals still do not leak into this slot.
                if other > int(scope[-1]):
                    self.assertNotIn(f"Independent synthetic scope {other}", json.dumps(payload["messages"]))


if __name__ == "__main__":
    unittest.main()
