"""Keep the original self-review under bounded, entirely synthetic read history."""
import copy
import unittest

from vulngym_t2 import staged_protocol
from vulngym_t2.output import finalize_result
from vulngym_t2.pipeline import produce
from tests.test_t2_v2_pipeline import SOURCE, VULNERABLE, evidence_from, job
from tests.test_t2_v2_staged_pipeline import FINISH, READ, MemoryRepo, full_annotation


class BulkyHistoryRepo(MemoryRepo):
    """Fixture data only: four legal navigation reads, not target source."""

    def call(self, tool, arguments):
        if tool == "read_diff":
            self.calls.append((tool, copy.deepcopy(arguments)))
            return {"before": arguments["before"], "after": arguments["after"],
                    "path": arguments["path"], "diff": "x" * 15_000}
        return super().call(tool, arguments)


class ContextBudgetClient:
    """Pure protocol-normalized replies; no HTTP client, ledger or files."""

    response_mode = "staged_tool"
    multi_entry = False
    halted = None

    def __init__(self):
        self.calls = []

    def complete(self, messages, *, stage):
        self.calls.append({"stage": stage, "messages": copy.deepcopy(messages)})
        if len(self.calls) > 6:
            raise AssertionError("The controller exceeded the original six-call budget")
        if len(self.calls) == 1:
            replies = [READ]
        elif len(self.calls) == 2:
            replies = [("read_diff", {"before": VULNERABLE, "after": "b" * 40,
                                     "path": f"change-{index}.py"}) for index in range(4)]
        elif stage == "annotation":
            tool, snapshot = full_annotation({"messages": messages})
            for decision in snapshot.values():
                tail = " Synthetic caveat end"
                decision["reason"] = "r" * (2_000 - len(tail)) + tail
            replies = [(tool, snapshot)]
        else:
            replies = [FINISH]
        return staged_protocol.normalize_calls(
            [{"tool": tool, "arguments": arguments} for tool, arguments in replies], stage)


class ContextBudgetTests(unittest.TestCase):
    def test_read_history_and_full_snapshot_do_not_displace_the_original_self_review(self):
        supplied = job(False)
        original_advisory = supplied["documents"][0]["text"]
        supplied["documents"] = [
            {"name": "advisory", "text": (original_advisory + " " + "a" * 12_000)[:12_000]},
            {"name": "supporting", "text": "b" * 12_000},
        ]
        client, repo = ContextBudgetClient(), BulkyHistoryRepo()
        result = produce(supplied, client, repo, max_calls=6)
        finalized = finalize_result(supplied, result, repo)

        self.assertEqual(result["self_review_status"], "completed")
        self.assertEqual(result["initial_draft_status"], "accepted")
        self.assertEqual(result["annotation_errors"], [])
        self.assertEqual(len(result["field_reviews"]["commit"]["reason"]), 2_000)
        self.assertFalse(result["field_reviews"]["commit"].get("reason_truncated", False))
        self.assertTrue(result["field_reviews"]["commit"]["reason"].endswith(" Synthetic caveat end"))
        model_actions = [row for row in result["actions"] if row["action"] == "model_call"]
        self.assertEqual(sum(row["stage"] == "self_review" for row in model_actions), 1)
        self.assertEqual(result["model_calls"], len(client.calls))
        self.assertLessEqual(len(client.calls), 6)
        self.assertEqual(sum(row["stage"] == "annotation" for row in client.calls), 2)
        self.assertFalse(any("context limit" in error.lower() for error in result["errors"]))
        self.assertTrue(all(sum(len(message["content"]) for message in call["messages"]) <= 100_000
                            for call in client.calls))
        self.assertTrue(all(sum(len(message["content"]) for message in call["messages"])
                            + len(staged_protocol.instruction(call["stage"])) <= 100_000
                            for call in client.calls))

        # A compacted review must still see the successful original receipt,
        # including both exact source lines and its selected SHA, not a summary.
        review_messages = [call["messages"] for call in client.calls if call["stage"] == "annotation"][-1]
        shown_reads = [row for row in evidence_from(review_messages)
                       if row.get("tool") == "read_file" and row.get("success") is True]
        self.assertEqual(len(shown_reads), 1)
        self.assertEqual(shown_reads[0]["result"]["commit"], VULNERABLE)
        self.assertEqual([row["code"] for row in shown_reads[0]["result"]["lines"]], SOURCE)
        self.assertEqual(sum(tool == "read_file" for tool, _ in repo.calls), 1)
        self.assertIsNotNone(finalized["entry"])
        self.assertEqual(finalized["entry"]["verify"], 0)
        self.assertEqual(finalized["entry"]["commit"], VULNERABLE)
        self.assertEqual(finalized["entry"]["entry_point"]["code"], SOURCE[0])
        self.assertEqual(finalized["entry"]["critical_operation"]["code"], SOURCE[1])


if __name__ == "__main__":
    unittest.main()
