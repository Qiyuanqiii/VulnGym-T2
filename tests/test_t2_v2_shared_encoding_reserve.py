"""Fixed-budget assessed multi recovery; synthetic envelopes and in-memory source only."""
import copy
import json
from unittest.mock import patch
import unittest

from vulngym_t2 import staged_protocol
from vulngym_t2.llm import DeepSeekClient, RequestLedger
from vulngym_t2.output import finalize_job
from vulngym_t2.pipeline import _ProductionSession
from tests import test_t2_v2_staged_pipeline as fixture
from tests.test_t2_v2_assessed_tool import NOTE, envelope
from tests import test_t2_v2_multi_draft_reencode_budget as budget_fixture
from tests.test_t2_v2_multi_draft_reencode_budget import scoped_valid
from tests.test_t2_v2_pipeline import job
from tests.test_t2_v2_staged_multi import proposals


REJECTED = "rejected-commit-must-never-be-merged"


def commit_only(_payload):
    return "submit_annotation", {"commit": {"value": "a" * 40, "status": "supported",
        "revision_basis": "behavior_at_revision", "reason": REJECTED, "evidence_refs": ["E0001"]}}


class SharedEncodingReserveTests(unittest.TestCase):
    setUp = budget_fixture.MultiDraftReencodeBudgetTests.setUp
    run_script = budget_fixture.MultiDraftReencodeBudgetTests.run_script
    call_stages = budget_fixture.MultiDraftReencodeBudgetTests.call_stages

    def actions(self, result, name):
        rows = result["actions"] + [row for entry in result.get("entry_results", [])
                                    for row in entry["actions"]]
        return [row for row in rows if row["action"] == name]

    def test_sixteen_call_two_review_rejections_recover_without_increasing_authorization(self):
        # Same 4-call read/selection prefix and commit-only final encodings as
        # the public failure shape. Source, scopes and responses are synthetic.
        result, client, repo, payloads = self.run_script([
            fixture.READ, fixture.CALLER, fixture.FINISH, lambda p: proposals(p, 4),
            NOTE, scoped_valid, fixture.FINISH, NOTE, commit_only, scoped_valid,
            NOTE, scoped_valid, fixture.FINISH, NOTE, commit_only, scoped_valid,
        ], max_calls=16)
        plan = self.actions(result, "candidate_plan")[0]
        self.assertEqual((plan["proposed_count"], plan["selected_count"], plan["omitted_count"]), (4, 2, 2))
        self.assertEqual((plan["budget_slots_without_reserve"], plan["budget_slots"], plan["encoding_reserve"]), (3, 2, 1))
        self.assertEqual(plan["encoding_reserve_reason"], "reserved")
        self.assertEqual((result["model_calls"], client.calls, len(payloads)), (16, 16, 16))
        self.assertEqual(self.actions(result, "annotation_snapshot_reencoding"), [
            {"action": "annotation_snapshot_reencoding", "stage": "self_review", "summary": "recovered"},
            {"action": "annotation_snapshot_reencoding", "stage": "self_review", "summary": "recovered"}])
        self.assertEqual(len(self.actions(result, "annotation_encoding_reserve")), 1)
        self.assertEqual(self.actions(result, "annotation_encoding_reserve")[0]["call"], 10)
        self.assertTrue(all(entry["self_review_status"] == "completed" for entry in result["entry_results"]))
        self.assertNotIn(REJECTED, json.dumps(result))
        for index in (9, 15):
            correction = payloads[index]
            self.assertEqual(correction["tools"][0]["function"]["parameters"]["required"],
                             list(staged_protocol.ANNOTATION_FIELDS))
            self.assertEqual(correction["messages"][:-2], payloads[index - 1]["messages"][:-1])
            self.assertNotIn(REJECTED, json.dumps(correction))
        group = finalize_job(job(False), result, repo, entry_ids={1: job(False)["entry_id"], 2: "entry-00002"})
        self.assertEqual(len(group["items"]), 2)  # Omitted proposals never become completed entries.
        self.assertTrue(all(item["entry"]["verify"] == 0 for item in group["items"]))

    def test_exact_pool_tail_cannot_be_spent_on_followup(self):
        result, client, _, _ = self.run_script([
            fixture.READ, fixture.FINISH, lambda p: proposals(p, 2),
            NOTE, scoped_valid, NOTE, commit_only, scoped_valid,
        ], max_calls=8)
        self.assertEqual(result["model_calls"], 8)
        self.assertEqual(self.actions(result, "candidate_plan")[0]["selected_count"], 1)
        self.assertNotIn("evidence_followup", self.call_stages(result))
        self.assertEqual(self.actions(result, "annotation_encoding_reserve")[0]["call"], 8)
        self.assertEqual(result["entry_results"][0]["self_review_status"], "completed")
        self.assertEqual(client.summary()["automatic_retries"], 0)

    def test_four_call_tail_keeps_the_only_candidate_with_explicit_no_reserve(self):
        result, _, _, _ = self.run_script([
            fixture.READ, fixture.FINISH, lambda p: proposals(p, 2),
            NOTE, scoped_valid, NOTE, scoped_valid,
        ], max_calls=7)
        plan = self.actions(result, "candidate_plan")[0]
        self.assertEqual((plan["selected_count"], plan["omitted_count"], plan["encoding_reserve"]), (1, 1, 0))
        self.assertEqual(plan["encoding_reserve_reason"], "insufficient_budget")
        self.assertEqual(result["entry_results"][0]["self_review_status"], "completed")

    def test_repeated_commit_only_encoding_is_not_retried_or_merged(self):
        result, _, repo, _ = self.run_script([
            fixture.READ, fixture.FINISH, lambda p: proposals(p, 1),
            NOTE, scoped_valid, NOTE, commit_only, commit_only,
        ], max_calls=8)
        self.assertEqual(self.call_stages(result).count("encoding_shape_review"), 1)
        entry = result["entry_results"][0]
        self.assertEqual(entry["initial_draft_status"], "accepted")
        self.assertEqual(entry["self_review_status"], "failed")
        self.assertNotIn(REJECTED, json.dumps(result))
        group = finalize_job(job(False), result, repo, entry_ids={1: job(False)["entry_id"]})
        self.assertIsNone(group["items"][0]["entry"])
        self.assertEqual(len(self.actions(result, "annotation_encoding_reserve")), 1)

    def test_initial_encoding_correction_keeps_its_own_full_review(self):
        result, _, _, _ = self.run_script([
            fixture.READ, fixture.FINISH, lambda p: proposals(p, 1),
            NOTE, commit_only, scoped_valid, NOTE, scoped_valid,
        ], max_calls=8)
        self.assertEqual(self.call_stages(result)[-3:],
                         ["encoding_shape_review", "self_review_assessment", "self_review"])
        self.assertEqual(result["entry_results"][0]["self_review_status"], "completed")
        self.assertEqual(self.actions(result, "annotation_encoding_reserve")[0]["stage"], "draft")

    def test_valid_snapshots_do_not_consume_the_pool(self):
        result, client, _, _ = self.run_script([
            fixture.READ, fixture.FINISH, lambda p: proposals(p, 1),
            NOTE, scoped_valid, NOTE, scoped_valid,
        ], max_calls=8)
        self.assertEqual(client.calls, 7)
        self.assertFalse(self.actions(result, "annotation_encoding_reserve"))

    def session(self, send=None, *, max_calls=8, provider_limit=None):
        self.run_number += 1
        from pathlib import Path
        ledger = RequestLedger(Path(self.temp.name) / f"reserve-{self.run_number}.jsonl", limit=32)
        self.addCleanup(ledger.close)
        payloads = []

        def dispatch(body, *_):
            payload = json.loads(body)
            payloads.append(payload)
            if send is not None:
                return send(payload)
            return envelope(content=NOTE) if "tools" not in payload else envelope(call=fixture.annotation())

        client = DeepSeekClient("synthetic-not-a-key", ledger, run_id="synthetic", send=dispatch,
            max_requests=provider_limit or max_calls, response_mode="staged_tool", thinking="enabled",
            annotation_format="assessed_tool", multi_entry=True)
        self.addCleanup(client.close)
        state = _ProductionSession(job(False), client, fixture.MemoryRepo(), max_calls, 24)
        state.prepare()
        state.shared_encoding_reserve = 1
        state.shared_encoding_reserve_enabled = True
        return state, client, ledger, payloads

    def rejection(self):
        return {"action": "annotation_snapshot_rejected", "code": "missing_root_fields",
                "path": "$[0].arguments", "missing_fields": sorted(set(staged_protocol.ANNOTATION_FIELDS) - {"commit"})}

    def test_normal_requests_and_field_recovery_cannot_consume_the_pool(self):
        for stage in ("plan_and_read", "evidence_followup", "draft", "self_review", "field_recovery"):
            with self.subTest(stage=stage):
                state, client, _, _ = self.session()
                state.result["model_calls"] = state.max_calls - (2 if stage in {"draft", "self_review", "field_recovery"} else 1)
                self.assertIsNone(state.complete(stage))
                self.assertEqual((client.calls, state.shared_encoding_reserve), (0, 1))
        state, client, _, _ = self.session()
        state.result["model_calls"] = state.max_calls - 2
        state.result["annotation_errors"] = [{"field": "entry_point", "code": "missing_property",
                                              "path": "$[0].arguments.entry_point.status"}]
        state.recover_annotation_fields(0)
        self.assertEqual((client.calls, state.shared_encoding_reserve), (0, 1))
        self.assertFalse(state.annotation_recovery_attempted)

    def test_read_plan_repair_cannot_consume_the_snapshot_pool(self):
        state, client, _, _ = self.session()
        state.result["model_calls"] = state.max_calls - 1
        rejection = {"action": "read_plan_rejected", "code": "invalid_plan_json",
                     "path": "$[0].arguments", "answer_characters": 8}
        self.assertIsNone(state.reencode_rejected_read_plan(state.messages, "evidence_followup", "followup", rejection, 0))
        self.assertEqual((client.calls, state.shared_encoding_reserve, state.read_plan_encoding_reviews), (0, 1, 0))
        self.assertEqual(state.result["actions"][-1]["summary"], "budget_unavailable")

    def test_provider_stop_context_and_budget_guards_do_not_consume_the_pool(self):
        for guard in ("provider", "context", "budget"):
            with self.subTest(guard=guard):
                state, client, _, _ = self.session()
                outgoing, reserved = state.messages, 0
                if guard == "provider":
                    client.halted = "synthetic_stop"
                elif guard == "context":
                    outgoing = [{"role": "system", "content": "x" * 100_001}]
                else:
                    reserved = state.max_calls
                self.assertIsNone(state.reencode_rejected_snapshot(outgoing, "self_review", self.rejection(), reserved))
                self.assertEqual((client.calls, state.shared_encoding_reserve), (0, 1))
                self.assertFalse(self.actions(state.result, "annotation_encoding_reserve"))

    def test_pre_send_failure_does_not_consume_but_started_failure_does(self):
        state, client, ledger, _ = self.session()
        with patch.object(client, "complete", side_effect=RuntimeError("synthetic pre-send refusal")):
            self.assertIsNone(state.reencode_rejected_snapshot(state.messages, "self_review", self.rejection(), 0))
        self.assertEqual((client.calls, ledger.started, state.shared_encoding_reserve), (0, 0, 1))
        self.assertFalse(self.actions(state.result, "annotation_encoding_reserve"))

        def failed_send(_payload):
            raise OSError("synthetic started transport failure")

        state, client, ledger, _ = self.session(failed_send)
        self.assertIsNone(state.reencode_rejected_snapshot(state.messages, "self_review", self.rejection(), 0))
        self.assertEqual((client.calls, ledger.started, state.shared_encoding_reserve), (1, 1, 0))
        self.assertEqual(len(self.actions(state.result, "annotation_encoding_reserve")), 1)

    def test_effective_provider_budget_keeps_later_slots_reserved(self):
        state, client, _, _ = self.session(provider_limit=4)
        before = copy.deepcopy(state.result["fields"])
        self.assertIsNone(state.reencode_rejected_snapshot(state.messages, "self_review", self.rejection(), 4))
        self.assertEqual((client.calls, state.shared_encoding_reserve), (0, 1))
        self.assertEqual(state.result["fields"], before)

    def test_candidate_admission_uses_actual_provider_remainder(self):
        state, client, ledger, _ = self.session(max_calls=16, provider_limit=7)
        # Three genuine synthetic requests, not a fabricated counter, leave
        # four provider-authorized calls even though the input ceiling is 16.
        for _ in range(3):
            state.request_completion(state.messages, "synthetic_setup", "assessment")
        state.candidate_proposals = [
            {"scope": f"Synthetic candidate {index}", "evidence_refs": [state.input_id]}
            for index in range(3)]
        state.run_candidates()
        plan = self.actions(state.result, "candidate_plan")[0]
        self.assertEqual((plan["selected_count"], plan["omitted_count"], plan["encoding_reserve"]), (1, 2, 0))
        self.assertEqual(plan["encoding_reserve_reason"], "insufficient_budget")
        self.assertEqual((client.calls, ledger.started, state.result["model_calls"]), (7, 7, 7))
        self.assertEqual(state.result["entry_results"][0]["self_review_status"], "completed")

    def test_empty_candidate_set_does_not_reserve_or_spend_a_request(self):
        state, client, _, _ = self.session()
        state.candidate_proposals = []
        state.run_candidates()
        plan = self.actions(state.result, "candidate_plan")[0]
        self.assertEqual((plan["selected_count"], plan["encoding_reserve"]), (0, 0))
        self.assertEqual(plan["encoding_reserve_reason"], "no_candidates")
        self.assertEqual((client.calls, state.shared_encoding_reserve), (0, 0))


if __name__ == "__main__":
    unittest.main()
