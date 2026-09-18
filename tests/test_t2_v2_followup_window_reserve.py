"""Chain-shaped staged single-input runs keep a follow-up decision window.

The v79 chain receipt finished at 11/12 calls with evidence_followup_status
still not_requested: exploration spent calls 1-7 and the accepted draft pair
calls 8-9, leaving three calls, while the unchanged finish_draft admission
gate needs 1 + annotation_call_cost + encoding_reserve = 4. On a sufficiently
funded staged single-input run the planning cap now holds one call back for
that decision; small budgets keep the previous path unchanged.
"""
import copy
import json
from pathlib import Path
import tempfile
import unittest

from vulngym_t2.llm import DeepSeekClient, RequestLedger
from vulngym_t2.output import finalize_result
from vulngym_t2.pipeline import produce
from tests import test_t2_v2_staged_pipeline as fixture
from tests.test_t2_v2_pipeline import job, VULNERABLE
from tests.test_t2_v2_assessed_tool import envelope, NOTE
from tests.test_t2_v2_sequential_followup import SEARCH, ChainRepo


class FollowupWindowReserveTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="t2-followup-window-")
        self.addCleanup(self.temp.cleanup)
        self.run_number = 0

    def run_script(self, replies, *, max_calls):
        """Scripted assessed single-input run; every request stays budgeted."""
        self.run_number += 1
        ledger = RequestLedger(Path(self.temp.name).resolve() / f"ledger-{self.run_number}.jsonl", limit=32)
        self.addCleanup(ledger.close)
        pending, payloads = list(replies), []

        def send(body, _key, _timeout):
            payload = json.loads(body)
            payloads.append(payload)
            self.assertTrue(pending, "Controller exceeded the explicitly scripted request budget")
            response = pending.pop(0)
            response = response(payload) if callable(response) else response
            if "tools" not in payload:
                # The assessed reasoning step returns one bounded plain text.
                return envelope(content=response)
            return envelope(call=response)

        client = DeepSeekClient("dummy-not-a-real-key", ledger, run_id="synthetic", send=send,
            max_requests=max_calls, response_mode="staged_tool", thinking="enabled",
            annotation_format="assessed_tool")
        self.addCleanup(client.close)
        supplied = copy.deepcopy(job(False))
        client.start_next_case(supplied["report_id"])
        repo = ChainRepo()
        result = produce(supplied, client, repo, max_calls=max_calls)
        final = finalize_result(supplied, result, repo)
        self.assertEqual(pending, [])
        self.assertEqual(result["model_calls"], len(payloads))
        self.assertEqual(client.calls, len(payloads))
        self.assertEqual(ledger.started, len(payloads))
        self.assertLessEqual(client.calls, max_calls)
        self.assertEqual(client.summary()["automatic_retries"], 0)
        self.assertIsNone(client.halted)
        self.assertNotIn("synthetic private reasoning", json.dumps(result))
        return result, final, client, repo, payloads

    def call_stages(self, result):
        return [row["stage"] for row in
                (row for row in result["actions"] if row.get("action") == "model_call")]

    def test_funded_run_spends_the_reserved_decision_between_draft_and_review(self):
        # max_calls=12 with the same shape as the chain receipt: repeated
        # exploration turns, then the draft pair. Exploration is capped one
        # call earlier (6, not 7), so the draft ends with four remaining calls
        # and the follow-up decision really runs before the final review.
        result, final, _, repo, _ = self.run_script(
            [fixture.READ, fixture.CALLER, fixture.READ, fixture.CALLER, fixture.READ, fixture.CALLER,
             NOTE, fixture.full_annotation,
             SEARCH,
             NOTE, fixture.full_annotation],
            max_calls=12)
        self.assertEqual(self.call_stages(result),
            ["plan_and_read"] * 6 + ["draft_assessment", "draft", "evidence_followup",
                                     "self_review_assessment", "self_review"])
        self.assertEqual(result["evidence_followup_status"], "completed")
        self.assertEqual(result["self_review_status"], "completed")
        self.assertEqual(result["model_calls"], 11)
        # The decision read was actually executed and saved, not simulated.
        searches = [row for row in result["evidence"]
                    if row.get("tool") == "search_code" and row.get("success") is True]
        self.assertEqual(len(searches), 1)
        self.assertEqual(searches[0]["arguments"]["query"], "def emit")
        self.assertIsNotNone(final["entry"])
        self.assertEqual(final["entry"]["verify"], 0)
        self.assertFalse(any(row.get("summary") == "budget_unavailable" for row in result["actions"]))

    def test_small_budget_keeps_the_previous_planning_path(self):
        # max_calls=8 stays below 2 * annotation_call_cost + 5: the planning
        # cap is exactly the pre-change value (5), the draft ends with three
        # remaining calls (the receipt's arithmetic in miniature: three left,
        # four needed), and no decision window is reserved or started.
        result, final, _, repo, _ = self.run_script(
            [fixture.READ, fixture.CALLER, fixture.READ,
             NOTE, fixture.full_annotation,
             NOTE, fixture.full_annotation],
            max_calls=8)
        self.assertEqual(self.call_stages(result),
            ["plan_and_read"] * 3 + ["draft_assessment", "draft",
                                     "self_review_assessment", "self_review"])
        self.assertEqual(result["evidence_followup_status"], "not_requested")
        self.assertEqual(result["self_review_status"], "completed")
        self.assertEqual(result["model_calls"], 7)
        self.assertFalse(any(row.get("tool") == "search_code" for row in result["evidence"]))
        self.assertIsNotNone(final["entry"])

    def test_threshold_is_pinned_between_eight_and_nine_calls(self):
        # Both budgets yield the same planning cap (5) and the same three
        # exploration turns; only the reserved decision window differs. Each
        # run also leaves its unused tail unspent instead of consuming the
        # reserve with a forced extra request.
        for max_calls, followups, stages, replies in (
                (8, 0, ["plan_and_read"] * 3 + ["draft_assessment", "draft",
                                                "self_review_assessment", "self_review"],
                 [fixture.READ, fixture.CALLER, fixture.READ,
                  NOTE, fixture.full_annotation, NOTE, fixture.full_annotation]),
                (9, 1, ["plan_and_read"] * 3 + ["draft_assessment", "draft", "evidence_followup",
                                                "self_review_assessment", "self_review"],
                 [fixture.READ, fixture.CALLER, fixture.READ,
                  NOTE, fixture.full_annotation, ("finish_reading", {"reason": "enough_evidence"}),
                  NOTE, fixture.full_annotation])):
            with self.subTest(max_calls=max_calls):
                result, final, _, _, _ = self.run_script(replies, max_calls=max_calls)
                self.assertEqual(self.call_stages(result), stages)
                self.assertEqual(result["evidence_followup_status"],
                                 "completed" if followups else "not_requested")
                self.assertEqual(sum(row.get("stage") == "evidence_followup"
                                     for row in result["actions"] if row.get("action") == "model_call"),
                                 followups)
                self.assertEqual(result["self_review_status"], "completed")
                self.assertEqual(result["model_calls"], max_calls - 1)
                self.assertIsNotNone(final["entry"])


if __name__ == "__main__":
    unittest.main()
