"""Shared-pool admission preserves review; unreserved direct calls keep legacy boundaries."""
import copy
import json
from pathlib import Path
import tempfile
import unittest

from vulngym_t2 import staged_protocol
from vulngym_t2.llm import DeepSeekClient, RequestLedger
from vulngym_t2.output import finalize_job
from vulngym_t2.pipeline import _ProductionSession, produce
from tests import test_t2_v2_staged_pipeline as fixture
from tests.test_t2_v2_pipeline import job
from tests.test_t2_v2_snapshot_json import envelope
from tests.test_t2_v2_assessed_tool import NOTE
from tests.test_t2_v2_staged_multi import full_for_scope, proposals

REJECTED_MARKER = "rejected-encoding-never-applied"


def rejected_root(payload):
    """One lone decision: a whole-answer missing-root rejection like the receipt."""
    return "submit_annotation", {"vuln_title": {"value": REJECTED_MARKER,
        "status": "supported", "reason": "Rejected encoding; no value is reusable.",
        "evidence_refs": ["E0001"]}}


def scoped_valid(payload):
    """Wire-ready recovered snapshot carrying this candidate's own scope decision."""
    tool, snapshot = full_for_scope(payload)
    return tool, staged_protocol.source_id_snapshot(snapshot)


def plain_valid(payload):
    """Scope-free valid snapshot for direct complete() calls without candidates."""
    return "submit_annotation", staged_protocol.source_id_snapshot(fixture.annotation()[1])


class MultiDraftReencodeBudgetTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="t2-multi-reencode-")
        self.addCleanup(self.temp.cleanup)
        self.run_number = 0

    def run_script(self, replies, *, max_calls):
        """Scripted assessed multi-candidate run; every request stays budgeted."""
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
            annotation_format="assessed_tool", multi_entry=True)
        self.addCleanup(client.close)
        supplied = copy.deepcopy(job(False))
        client.start_next_case(supplied["report_id"])
        repo = fixture.MemoryRepo()
        result = produce(supplied, client, repo, max_calls=max_calls)
        self.assertEqual(pending, [])
        self.assertEqual(result["model_calls"], len(payloads))
        self.assertEqual(client.calls, len(payloads))
        self.assertEqual(ledger.started, len(payloads))
        self.assertLessEqual(client.calls, max_calls)
        self.assertEqual(client.summary()["automatic_retries"], 0)
        self.assertIsNone(client.halted)
        self.assertNotIn("synthetic private reasoning", json.dumps(result))
        return result, client, repo, payloads

    def call_stages(self, result):
        """Ordered model-call stages across the shared actions and every slot."""
        rows = list(result["actions"])
        for entry in result.get("entry_results", []):
            rows.extend(entry["actions"])
        return [row["stage"] for row in sorted(
            (row for row in rows if row.get("action") == "model_call"), key=lambda row: row["call"])]

    def test_admission_omits_one_scope_to_recover_draft_without_sacrificing_review(self):
        # The old 15-call schedule admitted three scopes at their bare 4-call
        # cost, then sacrificed slot 2's review after a draft rejection. The
        # same fixed ceiling now admits two and explicitly omits the third.
        # Both selected scopes retain independent, complete self-reviews.
        result, client, repo, payloads = self.run_script(
            [fixture.READ, fixture.FINISH, lambda p: proposals(p, 3),
             NOTE, scoped_valid, fixture.FINISH, NOTE, scoped_valid,
             NOTE, rejected_root, scoped_valid, fixture.FINISH, NOTE, scoped_valid],
            max_calls=15)
        self.assertEqual(len(result["entry_results"]), 2)
        plan = next(row for row in result["actions"] if row["action"] == "candidate_plan")
        self.assertEqual((plan["proposed_count"], plan["selected_count"], plan["omitted_count"]), (3, 2, 1))
        self.assertEqual((plan["budget_slots_without_reserve"], plan["budget_slots"], plan["encoding_reserve"]), (3, 2, 1))
        self.assertEqual(self.call_stages(result),
            ["plan_and_read", "plan_and_read", "candidate_selection",
             "draft_assessment", "draft", "evidence_followup", "self_review_assessment", "self_review",
             "draft_assessment", "draft", "encoding_shape_review",
             "evidence_followup", "self_review_assessment", "self_review"])
        self.assertEqual(result["model_calls"], 14)
        second = result["entry_results"][1]
        self.assertTrue(any(row.get("code") == "missing_root_fields"
                            for row in second["actions"] if row["action"] == "annotation_snapshot_rejected"))
        self.assertEqual([row for row in second["actions"] if row["action"] == "annotation_snapshot_reencoding"],
                         [{"action": "annotation_snapshot_reencoding", "stage": "draft", "summary": "recovered"}])
        self.assertFalse(any(row.get("summary") == "budget_unavailable"
                             for row in result["actions"] + [row for e in result["entry_results"] for row in e["actions"]]))
        self.assertEqual(second["initial_draft_status"], "accepted")
        self.assertEqual(second["self_review_status"], "completed")
        self.assertEqual(result["entry_results"][0]["self_review_status"], "completed")
        # The rejected object stays dead data; the merged decision comes from
        # the accepted re-encoding, never from the rejected answer.
        self.assertNotIn(REJECTED_MARKER, json.dumps(result))
        self.assertEqual(second["fields"]["vuln_title"], "Independent synthetic scope 1")
        group = finalize_job(job(False), result, repo,
                             entry_ids={1: job(False)["entry_id"], 2: "entry-00002", 3: "entry-00003"})
        self.assertEqual(group["status"], "complete")  # Selected snapshots only, not coverage of all proposals.
        self.assertEqual(len(group["items"]), 2)
        self.assertIsNotNone(group["items"][0]["entry"])
        self.assertIsNotNone(group["items"][1]["entry"])
        self.assertFalse(any(row["code"] == "self_review_required"
                             for item in group["items"] for row in item["review"]["errors"]))

    def test_last_selected_slot_rejection_uses_pool_and_keeps_full_review(self):
        # Five calls remain after read/selection: one selected candidate gets
        # its draft, sole encoding correction and full review, with no extra
        # authorization. The other proposed scope remains explicitly omitted.
        result, client, repo, payloads = self.run_script(
            [fixture.READ, fixture.FINISH, lambda p: proposals(p, 2),
             NOTE, rejected_root, scoped_valid, NOTE, scoped_valid],
            max_calls=8)
        self.assertEqual(self.call_stages(result),
            ["plan_and_read", "plan_and_read", "candidate_selection",
             "draft_assessment", "draft", "encoding_shape_review", "self_review_assessment", "self_review"])
        self.assertEqual(result["model_calls"], 8)
        plan = next(row for row in result["actions"] if row["action"] == "candidate_plan")
        self.assertEqual((plan["selected_count"], plan["omitted_count"], plan["encoding_reserve"]), (1, 1, 1))
        selected = result["entry_results"][0]
        self.assertEqual([row for row in selected["actions"] if row["action"] == "annotation_snapshot_reencoding"],
                         [{"action": "annotation_snapshot_reencoding", "stage": "draft", "summary": "recovered"}])
        self.assertEqual(selected["initial_draft_status"], "accepted")
        self.assertEqual(selected["self_review_status"], "completed")
        self.assertNotIn(REJECTED_MARKER, json.dumps(result))

    def scripted_multi_session(self, *, max_calls, reserved):
        """Direct complete("draft") with the later slots' four-call reserve."""
        ledger = RequestLedger(Path(self.temp.name).resolve()
                               / f"ledger-session-{self.run_number}.jsonl", limit=32)
        self.run_number += 1
        self.addCleanup(ledger.close)
        payloads = []

        def send(body, *_):
            payload = json.loads(body)
            payloads.append(payload)
            if "tools" not in payload:
                return envelope(content=NOTE)
            names = [row["function"]["name"] for row in payload["tools"]]
            if names == ["submit_annotation"]:
                # The first encoding rejects whole; the sole correction recovers.
                return envelope(call=rejected_root(payload) if len(payloads) == 2
                                else plain_valid(payload))
            return envelope(call=fixture.READ if len(payloads) == 1 else fixture.FINISH)

        client = DeepSeekClient("dummy-not-a-real-key", ledger, run_id="synthetic", send=send,
            max_requests=max_calls, response_mode="staged_tool", thinking="enabled",
            annotation_format="assessed_tool", multi_entry=True)
        self.addCleanup(client.close)
        session = _ProductionSession(job(False), client, fixture.MemoryRepo(), max_calls, 24)
        session.prepare()
        reply = session.complete("draft", reserved_calls=reserved)
        return session, client, payloads, reply

    def test_later_candidate_reserve_still_caps_the_correction(self):
        # With the later slots' four-call reserve outstanding, five remaining
        # calls fund exactly the correction (1 + 4) and four do not. The removed
        # term is only the rejected candidate's own never-runnable review
        # reserve; the later-candidate reserve keeps vetoing the correction.
        for max_calls, expected in ((6, "budget_unavailable"), (7, "recovered")):
            with self.subTest(max_calls=max_calls, expected=expected):
                session, client, payloads, reply = self.scripted_multi_session(
                    max_calls=max_calls, reserved=4)
                self.assertEqual(len(payloads), 3 if expected == "recovered" else 2)
                self.assertEqual(session.result["actions"][-1]["summary"], expected)
                self.assertEqual(session.result["model_calls"], 3 if expected == "recovered" else 2)
                if expected == "recovered":
                    self.assertEqual(reply["action"], "draft")
                else:
                    self.assertIsNone(reply)
                self.assertEqual(client.summary()["automatic_retries"], 0)

    def test_single_input_draft_keeps_its_own_review_reserve(self):
        # Single-input drafts keep the pre-existing reserve: their review
        # follows the recovered draft directly, so the correction still needs
        # 1 + annotation_call_cost beyond the passed-in reserve. The boundary
        # (blocked at two remaining calls, started at three) is unchanged.
        for max_calls, expected in ((4, "budget_unavailable"), (5, "recovered")):
            with self.subTest(max_calls=max_calls, expected=expected):
                ledger = RequestLedger(Path(self.temp.name).resolve()
                                       / f"ledger-single-{self.run_number}.jsonl", limit=32)
                self.run_number += 1
                self.addCleanup(ledger.close)
                payloads = []

                def send(body, *_):
                    payload = json.loads(body)
                    payloads.append(payload)
                    if "tools" not in payload:
                        return envelope(content=NOTE)
                    names = [row["function"]["name"] for row in payload["tools"]]
                    if names == ["submit_annotation"]:
                        return envelope(call=rejected_root(payload) if len(payloads) == 2
                                        else plain_valid(payload))
                    return envelope(call=fixture.READ if len(payloads) == 1 else fixture.FINISH)

                client = DeepSeekClient("dummy-not-a-real-key", ledger, run_id="synthetic", send=send,
                    max_requests=max_calls, response_mode="staged_tool", thinking="enabled",
                    annotation_format="assessed_tool")
                self.addCleanup(client.close)
                session = _ProductionSession(job(False), client, fixture.MemoryRepo(), max_calls, 24)
                session.prepare()
                reply = session.complete("draft")
                self.assertEqual(len(payloads), 3 if expected == "recovered" else 2)
                self.assertEqual(session.result["actions"][-1]["summary"], expected)
                self.assertEqual(session.result["model_calls"], 3 if expected == "recovered" else 2)
                if expected == "recovered":
                    self.assertEqual(reply["action"], "draft")
                else:
                    self.assertIsNone(reply)
                self.assertEqual(client.summary()["automatic_retries"], 0)


if __name__ == "__main__":
    unittest.main()
