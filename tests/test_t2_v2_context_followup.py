"""One bounded adjacent read must resolve source context, never fabricate it."""
import copy
import unittest
from unittest.mock import patch

from tests import test_t2_v2_staged_pipeline as fixture
from tests.test_t2_v2_staged_pipeline import FINISH, MemoryRepo, full_annotation
from tests.test_t2_v2_pipeline import VULNERABLE, evidence_from


class WindowRepo(MemoryRepo):
    sources = {"service/handler.py": [f"fixture line {index}" for index in range(1, 151)]}

    def call(self, tool, arguments):
        if tool != "read_file":
            return super().call(tool, arguments)
        self.calls.append((tool, copy.deepcopy(arguments)))
        first, last = arguments["start_line"], min(150, arguments["end_line"])
        rows = [{"line": line, "code": self.sources[arguments["path"]][line - 1]}
                for line in range(first, last + 1)]
        return {"commit": arguments["commit"], "path": arguments["path"], "start_line": first,
                "end_line": last, "total_lines": 150, "lines": rows,
                "text": "\n".join(row["code"] for row in rows), "truncated": last < 150}


READ_WINDOW = ("read_file", {"commit": VULNERABLE, "path": "service/handler.py",
                            "start_line": 100, "end_line": 110})


def uncertain_fragment(payload):
    tool, snapshot = full_annotation(payload)
    snapshot["entry_point"]["value"].update(start_line=100, end_line=100)
    snapshot["entry_point"].update(status="uncertain", reason="Enclosing declaration is not shown.")
    snapshot["critical_operation"]["value"].update(start_line=101, end_line=101)
    return tool, snapshot


class EntryContextIntegrationTests(unittest.TestCase):
    setUp = fixture.StagedPipelineTests.setUp
    run_script = fixture.StagedPipelineTests.run_script

    def test_existing_review_receives_actual_adjacent_read_without_extra_model_request(self):
        def review(payload):
            tool, snapshot = uncertain_fragment(payload)
            reads = [row for row in evidence_from(payload["messages"]) if row.get("tool") == "read_file"]
            context = next(row for row in reads if row["result"]["end_line"] == 99)
            snapshot["entry_point"]["value"].update(evidence_ref=context["id"], start_line=99, end_line=99)
            snapshot["entry_point"].update(status="supported", evidence_refs=[context["id"]],
                                            reason="Explicit fixture selection from the new read.")
            return tool, snapshot

        with patch.object(fixture, "MemoryRepo", WindowRepo):
            result, finalized, client, repo, _ = self.run_script(
                [READ_WINDOW, FINISH, uncertain_fragment, FINISH, review], max_calls=5)
        self.assertIsNone(client.halted)
        self.assertEqual(result["model_calls"], 5)
        self.assertEqual(result["tool_calls"], 2)
        self.assertEqual(len(repo.calls), 2)
        actions = [row for row in result["actions"] if row["action"] == "entry_context_read"]
        self.assertEqual(len(actions), 1)
        self.assertEqual(actions[0]["arguments"],
                         {"commit": VULNERABLE, "path": "service/handler.py", "start_line": 1, "end_line": 99})
        self.assertTrue(actions[0]["success"])
        self.assertIsNotNone(finalized["entry"])
        self.assertEqual(finalized["entry"]["entry_point"]["line"], 99)

    def test_no_adjacent_read_when_only_final_review_budget_remains(self):
        with patch.object(fixture, "MemoryRepo", WindowRepo):
            result, finalized, _, _, _ = self.run_script(
                [READ_WINDOW, FINISH, uncertain_fragment, uncertain_fragment], max_calls=4)
        self.assertEqual(result["model_calls"], 4)
        self.assertEqual(result["tool_calls"], 1)
        self.assertFalse(any(row["action"] == "entry_context_read" for row in result["actions"]))
        self.assertIsNone(finalized["entry"])


if __name__ == "__main__":
    unittest.main()
