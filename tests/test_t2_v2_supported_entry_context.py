"""Initial model confidence cannot replace the source needed by self-review."""
import copy
import unittest
from unittest.mock import patch

from vulngym_t2.source_refs import entry_context_request
from tests import test_t2_v2_entry_context as context_fixture
from tests import test_t2_v2_staged_pipeline as fixture
from tests.test_t2_v2_pipeline import VULNERABLE, evidence_from


class SupportedContextRequestTests(unittest.TestCase):
    def test_explicit_review_context_keeps_status_coverage_and_revision_rules(self):
        review = context_fixture.fixture()
        review["field_reviews"]["entry_point"]["status"] = "supported"
        before = copy.deepcopy(review)
        self.assertIsNone(entry_context_request(review))
        request = entry_context_request(review, include_supported=True)
        self.assertEqual(request["start_line"], 400)
        self.assertEqual(request["end_line"], 519)
        self.assertEqual(review, before)
        review["evidence"].append(context_fixture.receipt("E0010", 400, 519))
        self.assertIsNone(entry_context_request(review, include_supported=True))
        review = before
        review["draft_fields"]["commit"] = context_fixture.OTHER_SHA
        self.assertIsNone(entry_context_request(review, include_supported=True))


class PartialRepo(fixture.MemoryRepo):
    sources = {"service/handler.py": [""] * 58 + [
        "def handle_input(request):", "    item = request.body", "    consume(item)"]}

    def call(self, tool, arguments):
        if tool != "read_file":
            return super().call(tool, arguments)
        self.calls.append((tool, copy.deepcopy(arguments)))
        rows = self.sources[arguments["path"]]
        first, last = arguments["start_line"], min(arguments["end_line"], len(rows))
        return {"commit": arguments["commit"], "path": arguments["path"], "start_line": first,
            "end_line": last, "total_lines": len(rows), "text": "\n".join(rows[first - 1:last]),
            "lines": [{"line": n, "code": rows[n - 1]} for n in range(first, last + 1)]}


class SupportedContextIntegrationTests(unittest.TestCase):
    setUp = fixture.StagedPipelineTests.setUp
    run_script = fixture.StagedPipelineTests.run_script

    def test_original_review_sees_adjacent_source_without_extra_model_call_or_promotion(self):
        def annotation(payload, uncertain=False):
            tool, snapshot = fixture.full_annotation(payload)
            for field, line in (("entry_point", 60), ("critical_operation", 61)):
                snapshot[field]["value"].update(start_line=line, end_line=line)
            if uncertain:
                snapshot["entry_point"].update(status="uncertain", reason="Synthetic reviewer still needs external registration.")
            return tool, snapshot

        for tool_budget, expected_prefixes in ((4, 1), (3, 0)):
            with self.subTest(tool_budget=tool_budget):
                def final_review(payload):
                    reads = [row for row in evidence_from(payload["messages"]) if row.get("tool") == "read_file"]
                    self.assertEqual(sum(row["result"].get("start_line") == 1 for row in reads), expected_prefixes)
                    return annotation(payload, uncertain=True)

                read = ("read_file", {"commit": VULNERABLE, "path": "service/handler.py", "start_line": 60, "end_line": 61})
                with patch.object(fixture, "MemoryRepo", PartialRepo):
                    result, final, client, repo, _ = self.run_script(
                        [read, fixture.FINISH, annotation, fixture.FINISH, final_review], max_tool_calls=tool_budget)
                self.assertIsNone(client.halted)
                self.assertEqual(result["model_calls"], 5)
                self.assertEqual(result["tool_calls"], 1 + expected_prefixes)
                self.assertEqual(len(repo.calls), 1 + expected_prefixes)
                self.assertEqual(result["self_review_status"], "completed")
                self.assertIsNone(final["entry"])
                self.assertEqual(final["review"]["field_reviews"]["entry_point"]["status"], "uncertain")


if __name__ == "__main__":
    unittest.main()
