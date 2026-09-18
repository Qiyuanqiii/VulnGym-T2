"""Offline review/read cycles: synthetic transport, fixture bytes, shared limits."""
import copy
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from tests import test_t2_v2_staged_pipeline as fixture
from tests import test_t2_v2_multi_draft_reencode_budget as multi_fixture
from tests.test_t2_v2_assessed_tool import NOTE, envelope
from tests.test_t2_v2_pipeline import evidence_from, job, source_draft
from tests.test_t2_v2_sequential_followup import ChainRepo, CONSUMER, read_request
from tests.test_t2_v2_staged_multi import proposals
from tests.test_t2_v2_support_consistency import OPENCLAW_EP_REASON
from vulngym_t2.output import finalize_result
from vulngym_t2.pipeline import _ProductionSession, produce
from vulngym_t2.llm import DeepSeekClient, RequestLedger


FINISH = {"action": "finish_reading", "reason": "enough_evidence"}
RETAIN = {"action": "draft", "fields": {}, "field_reviews": {}}


def uncertain_entry(session):
    return {"action": "draft", "fields": {}, "field_reviews": {"entry_point": {
        "status": "uncertain", "reason": "Read the route registration to check this external callback.",
        "evidence_refs": copy.deepcopy(session.result["field_reviews"]["entry_point"]["evidence_refs"]),
        "suggested_value": copy.deepcopy(session.result["fields"].get("entry_point")),
    }}}


class ReviewGapNativeIntegrationTests(unittest.TestCase):
    # Real DeepSeekClient protocol and ledger; transport is the synthetic send
    # fixture, never a provider request or target repository.
    setUp = fixture.StagedPipelineTests.setUp
    run_script = fixture.StagedPipelineTests.run_script

    def run_cycles(self, replies, *, cycles=1, max_calls=9):
        def configured_produce(*args, **kwargs):
            return produce(*args, **kwargs, review_read_cycles=cycles)

        with patch.object(fixture, "produce", side_effect=configured_produce):
            return self.run_script(replies, max_calls=max_calls)

    def test_new_self_review_gap_causes_actual_read_then_corrected_snapshot(self):
        def first_review(payload):
            draft = fixture.full_annotation(payload)
            draft[1]["entry_point"].update(status="uncertain",
                reason="Read the route registration to check this external callback.")
            return draft

        def corrected_review(payload):
            reads = [row for row in evidence_from(payload["messages"])
                     if row.get("tool") == "read_file" and row.get("success")]
            self.assertEqual([row["result"]["path"] for row in reads],
                             ["service/handler.py", "service/routes.py"])
            draft = fixture.full_annotation(payload)
            draft[1]["entry_point"].update(
                evidence_refs=[row["id"] for row in reads],
                reason="The read registration calls the shown handler at the selected revision.")
            return draft

        result, exported, client, repo, payloads = self.run_cycles([
            fixture.READ, fixture.FINISH, fixture.full_annotation,
            fixture.FINISH, first_review, fixture.CALLER, corrected_review,
        ])
        self.assertEqual(result["model_calls"], 7)
        self.assertEqual(client.calls, 7)
        self.assertEqual(repo.calls, [fixture.READ, fixture.CALLER])
        self.assertEqual(result["self_review_status"], "completed")
        self.assertEqual(exported["review"]["status"], "complete")
        self.assertEqual(exported["entry"]["verify"], 0)
        gaps = [row for row in result["actions"] if row["action"] == "review_cycle_gap"]
        self.assertEqual([row["field"] for row in gaps], ["entry_point"])
        self.assertIn("registration", gaps[0]["reason"])
        queue = next(json.loads(message["content"])["review_gap_queue"]
                     for message in payloads[5]["messages"]
                     if message["content"].startswith('{"review_gap_queue":'))
        self.assertEqual(queue["cycle"], 1)
        self.assertEqual(queue["open_questions"][0]["field"], "entry_point")
        cycle = next(row for row in result["actions"] if row["action"] == "review_cycle_result")
        self.assertEqual(cycle["evidence_refs"], [result["evidence"][-1]["id"]])
        stages = [row["stage"] for row in result["actions"] if row["action"] == "model_call"]
        self.assertEqual(stages[-4:], ["evidence_followup", "self_review", "evidence_followup", "self_review"])
        reserve = next(row for row in result["actions"] if row["action"] == "review_cycle_planning_reserve")
        self.assertEqual(reserve["requested_calls"], 2)

    def test_complete_or_only_optional_trace_unknown_does_not_buy_another_call(self):
        def trace_unknown(payload):
            value = fixture.full_annotation(payload)
            value[1]["trace"] = {"value": [], "status": "uncertain",
                "reason": "Optional intermediate steps were not reconstructed.", "evidence_refs": []}
            return value

        for review in (fixture.full_annotation, trace_unknown):
            with self.subTest(review=review.__name__):
                result, exported, client, _, _ = self.run_cycles([
                    fixture.READ, fixture.FINISH, fixture.full_annotation, fixture.FINISH, review,
                ], cycles=2)
                self.assertEqual(client.calls, 5)
                self.assertEqual(exported["review"]["status"], "complete")
                self.assertEqual([row["reason"] for row in result["actions"]
                                  if row["action"] == "review_cycle_stopped"], ["no_required_gaps"])
                self.assertFalse(any(row["action"] == "review_cycle_started" for row in result["actions"]))

    def test_default_zero_preserves_original_request_sequence(self):
        result, exported, client, _, _ = self.run_cycles([
            fixture.READ, fixture.FINISH, fixture.full_annotation, fixture.FINISH, fixture.full_annotation,
        ], cycles=0, max_calls=5)
        self.assertEqual(client.calls, 5)
        self.assertEqual(exported["review"]["status"], "complete")
        self.assertFalse(any(row["action"].startswith("review_cycle_") for row in result["actions"]))


class ReviewGapControllerTests(unittest.TestCase):
    def session(self, *, max_calls=12, global_calls=16, max_tools=24,
                assessed=False, multi=False, cycles=2, repo=None):
        client = SimpleNamespace(response_mode="staged_tool",
            annotation_format="assessed_tool" if assessed else "snapshot_tool",
            multi_entry=multi, remaining_requests=global_calls, halted=None)
        session = _ProductionSession(job(False), client, repo or ChainRepo(), max_calls, max_tools,
                                     review_read_cycles=cycles)
        session.prepare()
        receipt = session.read_tool(*fixture.READ)
        session.messages.append({"role": "user", "content": json.dumps({"tool_results": [receipt]})})
        session.merge_draft(source_draft(session.messages))
        session.drafted, session.initial_valid_updates = True, 1
        session.result["initial_draft_status"] = "accepted"
        return session

    def finish(self, session, script, *, reserved=0, context=None, allow_followup=True):
        pending, calls = list(script), []

        def complete(stage, *, reserved_calls=0):
            self.assertTrue(pending, "Unexpected model-stage call")
            expected, reply = pending.pop(0)
            self.assertEqual(stage, expected)
            cost = session.annotation_call_cost if stage == "self_review" else 1
            self.assertGreaterEqual(session.client.remaining_requests, cost + reserved_calls)
            self.assertGreaterEqual(session.max_calls - session.result["model_calls"], cost + reserved_calls)
            session.client.remaining_requests -= cost
            session.result["model_calls"] += cost
            calls.append((stage, reserved_calls))
            # Match complete()'s pessimistic phase state until a valid reply is
            # merged; no stale successful review can certify new evidence.
            status = "self_review_status" if stage == "self_review" else "evidence_followup_status"
            session.result[status] = "failed"
            return reply(session) if callable(reply) else copy.deepcopy(reply)

        with patch.object(session, "complete", side_effect=complete), \
                patch.object(session, "navigate_entry_context"), \
                patch.object(session, "navigate_imported_context"):
            if context is None:
                session.finish_draft(reserved_calls=reserved, allow_followup=allow_followup)
            else:
                with patch.object(session, "followup_context_fits", side_effect=context):
                    session.finish_draft(reserved_calls=reserved, allow_followup=allow_followup)
        self.assertEqual(pending, [])
        return calls

    @staticmethod
    def first_pass():
        return [("evidence_followup", FINISH), ("self_review", uncertain_entry)]

    @staticmethod
    def stop_reasons(session):
        return [row["reason"] for row in session.result["actions"] if row["action"] == "review_cycle_stopped"]

    def test_finish_reading_does_not_repeat_review_or_start_second_cycle(self):
        session = self.session()
        calls = self.finish(session, self.first_pass() + [("evidence_followup", FINISH)])
        self.assertEqual([stage for stage, _ in calls], ["evidence_followup", "self_review", "evidence_followup"])
        self.assertEqual(self.stop_reasons(session), ["no_new_evidence"])
        self.assertEqual(session.result["self_review_status"], "completed")
        self.assertEqual(session.result["tool_calls"], 1)
        self.assertIsNone(finalize_result(session.job, session.result, session.repo)["entry"])

    def test_duplicate_and_already_covered_reads_do_not_repeat_self_review(self):
        covered = (fixture.READ[0], {**fixture.READ[1], "end_line": 1})
        for request in (fixture.READ, covered):
            with self.subTest(request=request):
                session = self.session()
                evidence_count = len(session.result["evidence"])
                calls = self.finish(session, self.first_pass() + [("evidence_followup", read_request(request))])
                self.assertEqual(sum(stage == "self_review" for stage, _ in calls), 1)
                self.assertEqual(len(session.result["evidence"]), evidence_count)
                self.assertEqual(self.stop_reasons(session), ["no_new_evidence"])
                self.assertEqual(session.repo.calls, [fixture.READ])

    def test_failed_local_read_is_not_new_successful_evidence(self):
        session = self.session()
        original = session.repo.call

        def fail_route(tool, arguments):
            if arguments.get("path") == "service/routes.py":
                raise ValueError("synthetic fixture unavailable")
            return original(tool, arguments)

        with patch.object(session.repo, "call", side_effect=fail_route):
            calls = self.finish(session, self.first_pass() + [("evidence_followup", read_request(fixture.CALLER))])
        self.assertEqual(sum(stage == "self_review" for stage, _ in calls), 1)
        self.assertFalse(session.result["evidence"][-1]["success"])
        self.assertEqual(self.stop_reasons(session), ["no_new_evidence"])

    def test_first_review_failure_never_starts_a_cycle(self):
        session = self.session()
        calls = self.finish(session, [("evidence_followup", FINISH), ("self_review", None)])
        self.assertEqual(len(calls), 2)
        self.assertEqual(session.result["self_review_status"], "failed")
        self.assertFalse(any(row["action"] == "review_cycle_started" for row in session.result["actions"]))
        self.assertIsNone(finalize_result(session.job, session.result, session.repo)["entry"])

    def test_review_failure_after_successful_gap_read_does_not_reuse_prior_completion(self):
        session = self.session(cycles=1)
        calls = self.finish(session, self.first_pass() + [
            ("evidence_followup", read_request(fixture.CALLER)), ("self_review", None),
        ])
        self.assertEqual(sum(stage == "self_review" for stage, _ in calls), 2)
        self.assertEqual(session.result["evidence"][-1]["result"]["path"], "service/routes.py")
        self.assertTrue(session.result["evidence"][-1]["success"])
        self.assertEqual(session.result["self_review_status"], "failed")
        self.assertEqual(next(row["summary"] for row in session.result["actions"]
                              if row["action"] == "review_cycle_result"), "failed")
        self.assertIsNone(finalize_result(session.job, session.result, session.repo)["entry"])

    def test_cycle_count_is_hard_bounded_when_gaps_remain(self):
        session = self.session(max_calls=16)
        calls = self.finish(session, self.first_pass() + [
            ("evidence_followup", read_request(fixture.CALLER)), ("self_review", RETAIN),
            ("evidence_followup", read_request(CONSUMER)), ("self_review", RETAIN),
        ])
        self.assertEqual(len(calls), 6)
        self.assertEqual([row["slot"] for row in session.result["actions"]
                          if row["action"] == "review_cycle_result"], [1, 2])
        self.assertEqual(session.repo.calls, [fixture.READ, fixture.CALLER, CONSUMER])
        self.assertIsNone(finalize_result(session.job, session.result, session.repo)["entry"])

    def test_local_and_global_request_limits_stop_before_extra_read(self):
        for local, available in ((2, 16), (16, 2)):
            with self.subTest(local=local, available=available):
                session = self.session(max_calls=local, global_calls=available)
                calls = self.finish(session, self.first_pass())
                self.assertEqual(len(calls), 2)
                self.assertEqual(self.stop_reasons(session), ["model_budget"])
                self.assertEqual(session.repo.calls, [fixture.READ])
                self.assertEqual(session.result["model_calls"], 2)

    def test_assessed_multi_cycle_preserves_shared_pool_and_sibling_reserve(self):
        session = self.session(max_calls=7, assessed=True, multi=True)
        session.shared_encoding_reserve_enabled = True
        session.shared_encoding_reserve = 1
        calls = self.finish(session, self.first_pass(), reserved=2)
        self.assertEqual(calls, [("evidence_followup", 2), ("self_review", 2)])
        self.assertEqual(session.shared_encoding_reserve, 1)
        self.assertEqual(self.stop_reasons(session), ["model_budget"])
        self.assertGreaterEqual(session.max_calls - session.result["model_calls"], 2 + 1)
        self.assertEqual(session.repo.calls, [fixture.READ])

    def test_unrelated_receipt_and_smoother_reason_cannot_erase_prior_support_hold(self):
        session = self.session(cycles=1)
        session.result["field_reviews"]["entry_point"]["reason"] = OPENCLAW_EP_REASON
        original_refs = copy.deepcopy(session.result["field_reviews"]["entry_point"]["evidence_refs"])

        def smooth_reason(current):
            draft = source_draft(current.messages)
            draft["field_reviews"]["entry_point"].update(
                reason="The selected fixture location is supported by the original saved source.",
                evidence_refs=copy.deepcopy(original_refs))
            return draft

        self.finish(session, [
            ("evidence_followup", FINISH), ("self_review", smooth_reason),
            ("evidence_followup", read_request(CONSUMER)), ("self_review", smooth_reason),
        ])
        holds = [row for row in session.result["actions"] if row["action"] == "support_consistency_hold"]
        self.assertEqual(len(holds), 2)
        self.assertEqual(session.result["field_reviews"]["entry_point"]["evidence_refs"], original_refs)
        self.assertIn("pending_support_conflict", session.result["field_reviews"]["entry_point"])
        self.assertEqual(session.result["evidence"][-1]["result"]["path"], "service/audit.py")
        exported = finalize_result(session.job, session.result, session.repo)
        self.assertIsNone(exported["entry"])
        self.assertEqual(exported["review"]["field_reviews"]["entry_point"]["status"], "uncertain")

    def test_new_cited_same_revision_source_allows_hold_to_be_reassessed_not_human_approved(self):
        session = self.session(cycles=1)
        session.result["field_reviews"]["entry_point"]["reason"] = OPENCLAW_EP_REASON

        def first_review(current):
            draft = source_draft(current.messages)
            draft["field_reviews"]["entry_point"]["reason"] = "The selected synthetic location was read."
            return draft

        def changed_basis(current):
            draft = first_review(current)
            new_source = next(row for row in current.result["evidence"]
                              if row.get("result", {}).get("path") == "service/routes.py")
            draft["field_reviews"]["entry_point"]["evidence_refs"].append(new_source["id"])
            draft["field_reviews"]["entry_point"]["reason"] = "The newly read registration calls this handler at the selected revision."
            return draft

        self.finish(session, [
            ("evidence_followup", FINISH), ("self_review", first_review),
            ("evidence_followup", read_request(fixture.CALLER)), ("self_review", changed_basis),
        ])
        self.assertNotIn("pending_support_conflict", session.result["field_reviews"]["entry_point"])
        exported = finalize_result(session.job, session.result, session.repo)
        self.assertIsNotNone(exported["entry"])
        self.assertEqual(exported["entry"]["verify"], 0)
        self.assertIn("not independent human proof", exported["review"]["verification"])

    def test_temporary_uncertainty_cannot_reset_original_held_basis_across_three_reviews(self):
        session = self.session(cycles=2)
        session.result["field_reviews"]["entry_point"]["reason"] = OPENCLAW_EP_REASON
        held_value = copy.deepcopy(session.result["fields"]["entry_point"])
        held_refs = copy.deepcopy(session.result["field_reviews"]["entry_point"]["evidence_refs"])

        def smooth_original_claim(current):
            draft = source_draft(current.messages)
            draft["field_reviews"]["entry_point"].update(
                reason="The original selected fixture location was read.",
                evidence_refs=copy.deepcopy(held_refs))
            return draft

        def temporarily_uncertain(current):
            self.assertIn("pending_support_conflict", current.result["field_reviews"]["entry_point"])
            draft = uncertain_entry(current)
            draft["field_reviews"]["entry_point"]["reason"] = "The role is currently uncertain."
            return draft

        def next_unrelated_read(current):
            # merge_draft really removed the value. That absence must not become
            # a fabricated new baseline before the original claim is restored.
            self.assertNotIn("entry_point", current.result["fields"])
            self.assertEqual(current.result["field_reviews"]["entry_point"]["status"], "uncertain")
            self.assertEqual(current.review_hold_baselines["entry_point"]["value"], held_value)
            self.assertEqual(current.review_hold_baselines["entry_point"]["assessment"]["evidence_refs"], held_refs)
            return read_request(fixture.CALLER)

        calls = self.finish(session, [
            ("evidence_followup", FINISH), ("self_review", smooth_original_claim),
            ("evidence_followup", read_request(CONSUMER)), ("self_review", temporarily_uncertain),
            ("evidence_followup", next_unrelated_read), ("self_review", smooth_original_claim),
        ])
        self.assertEqual(sum(stage == "self_review" for stage, _ in calls), 3)
        self.assertEqual(session.result["fields"]["entry_point"], held_value)
        self.assertEqual(session.result["field_reviews"]["entry_point"]["evidence_refs"], held_refs)
        self.assertIn("pending_support_conflict", session.result["field_reviews"]["entry_point"])
        self.assertEqual(session.review_hold_baselines["entry_point"]["value"], held_value)
        self.assertEqual(len([row for row in session.result["actions"]
                              if row["action"] == "support_consistency_hold"]), 3)
        self.assertEqual(session.repo.calls, [fixture.READ, CONSUMER, fixture.CALLER])
        exported = finalize_result(session.job, session.result, session.repo)
        self.assertIsNone(exported["entry"])
        self.assertEqual(exported["review"]["field_reviews"]["entry_point"]["status"], "uncertain")

    def test_entry_state_isolates_held_basis_between_candidates_and_restores_outer_state(self):
        session = self.session(multi=True, cycles=1)
        keys = ("fields", "field_reviews", "annotation_errors", "errors", "actions",
                "initial_draft_status", "self_review_status", "evidence_followup_status")
        first = {"slot": 1, **{key: copy.deepcopy(session.result[key]) for key in keys}}
        second = {"slot": 2, **{key: copy.deepcopy(session.result[key]) for key in keys}}
        outer_baselines = {"outer_scope": {"untouched": True}}
        session.review_hold_baselines = outer_baselines

        with session.entry_state(first):
            self.assertEqual(session.review_hold_baselines, {})
            session.result["field_reviews"]["entry_point"]["reason"] = OPENCLAW_EP_REASON
            self.finish(session, [("self_review", lambda current: source_draft(current.messages))],
                        allow_followup=False)
            self.assertIn("entry_point", session.review_hold_baselines)
            self.assertIsNone(finalize_result(session.job, session.result, session.repo)["entry"])
        self.assertIs(session.review_hold_baselines, outer_baselines)
        self.assertIn("pending_support_conflict", first["field_reviews"]["entry_point"])

        with session.entry_state(second):
            self.assertEqual(session.review_hold_baselines, {})
            self.assertNotIn("pending_support_conflict", session.result["field_reviews"]["entry_point"])
            self.finish(session, [("self_review", RETAIN)], allow_followup=False)
            self.assertEqual(session.review_hold_baselines, {})
            self.assertIsNotNone(finalize_result(session.job, session.result, session.repo)["entry"])
        self.assertIs(session.review_hold_baselines, outer_baselines)
        self.assertEqual(outer_baselines, {"outer_scope": {"untouched": True}})
        self.assertEqual(session.result["model_calls"], 2)  # Usage remains shared.

    def test_provider_stop_after_first_review_prevents_a_cycle(self):
        session = self.session()

        def stop_provider(current):
            current.client.halted = "synthetic_cumulative_limit"
            return uncertain_entry(current)

        self.finish(session, [("evidence_followup", FINISH), ("self_review", stop_provider)])
        self.assertEqual(self.stop_reasons(session), ["provider_stopped"])
        self.assertEqual(session.repo.calls, [fixture.READ])

    def test_tool_limit_and_context_limit_are_rechecked_after_review(self):
        session = self.session(max_tools=1)
        self.finish(session, [("self_review", uncertain_entry)])
        self.assertEqual(self.stop_reasons(session), ["tool_budget"])
        self.assertEqual(session.repo.calls, [fixture.READ])

        session = self.session()
        self.finish(session, self.first_pass(), context=[True, False])
        self.assertEqual(self.stop_reasons(session), ["context_budget"])
        self.assertEqual(session.repo.calls, [fixture.READ])

    def test_explicit_closed_followup_does_not_override_parent_decision(self):
        session = self.session()
        calls = self.finish(session, [("self_review", uncertain_entry)], allow_followup=False)
        self.assertEqual([stage for stage, _ in calls], ["self_review"])
        self.assertFalse(any(row["action"] == "review_cycle_started" for row in session.result["actions"]))

    def test_configuration_rejects_invalid_cycles_before_preparation(self):
        for value in (-1, 3, True, False, 1.0, "1", None):
            with self.subTest(value=value):
                with self.assertRaisesRegex(ValueError, "review_read_cycles_invalid"):
                    self.session(cycles=value)
        with self.assertRaisesRegex(ValueError, "review_read_cycles_requires_staged_tool"):
            _ProductionSession(job(False), SimpleNamespace(response_mode="strict_tool"), ChainRepo(), 8, 24,
                               review_read_cycles=1)


class ReviewGapMultiNativeIntegrationTests(unittest.TestCase):
    setUp = multi_fixture.MultiDraftReencodeBudgetTests.setUp
    run_script = multi_fixture.MultiDraftReencodeBudgetTests.run_script

    def test_provider_twelve_caps_planning_even_when_per_report_limit_is_sixteen(self):
        observed = []
        for local_limit in (16, 12):
            with self.subTest(local_limit=local_limit):
                ledger = RequestLedger(Path(self.temp.name) / f"planning-{local_limit}.jsonl", limit=32)
                self.addCleanup(ledger.close)
                payloads = []

                def send(body, _synthetic_key, _timeout):
                    payload = json.loads(body)
                    payloads.append(payload)
                    names = [tool["function"]["name"] for tool in payload["tools"]]
                    if names == ["propose_candidates"]:
                        return envelope(call=proposals(payload, 3))
                    # Deliberately do not finish early: the controller's real
                    # planning boundary, not the fake model, must close reads.
                    self.assertIn("read_file", names)
                    return envelope(call=fixture.READ)

                client = DeepSeekClient("synthetic-not-a-key", ledger, run_id="synthetic-planning",
                    send=send, max_requests=12, response_mode="staged_tool", thinking="enabled",
                    annotation_format="assessed_tool", multi_entry=True)
                self.addCleanup(client.close)
                supplied = job(False)
                client.start_next_case(supplied["report_id"])
                session = _ProductionSession(supplied, client, fixture.MemoryRepo(), local_limit, 24,
                                             review_read_cycles=1)
                session.prepare()
                session.read_and_draft()
                stages = [row["stage"] for row in session.result["actions"] if row["action"] == "model_call"]
                self.assertEqual(stages, ["plan_and_read"] * 3 + ["candidate_selection"])
                self.assertEqual((client.calls, ledger.started, len(payloads)), (4, 4, 4))
                self.assertEqual(client.remaining_requests, 8)
                self.assertEqual(session.max_calls, local_limit)
                self.assertEqual(len(session.candidate_proposals), 3)
                self.assertEqual(client.summary()["automatic_retries"], 0)
                observed.append((stages, session.candidate_proposals,
                                 [row for row in session.result["actions"]
                                  if row["action"] == "review_cycle_planning_reserve"]))
        self.assertEqual(observed[0], observed[1])

    def test_assessed_multi_cycle_is_reachable_and_coverage_cost_is_explicit(self):
        def uncertain_review(payload):
            value = multi_fixture.scoped_valid(payload)
            value[1]["entry_point"].update(status="uncertain",
                reason="Read the route registration to check this external callback.")
            return value

        def changed_basis(payload):
            value = multi_fixture.scoped_valid(payload)
            new_source = next(row for row in evidence_from(payload["messages"])
                              if row.get("result", {}).get("path") == "service/routes.py")
            value[1]["entry_point"]["evidence_refs"].append(new_source["id"])
            value[1]["entry_point"]["reason"] = "The newly read registration calls the selected handler."
            return value

        def configured_produce(*args, **kwargs):
            return produce(*args, **kwargs, review_read_cycles=1)

        with patch.object(multi_fixture, "produce", side_effect=configured_produce):
            result, client, repo, payloads = self.run_script([
                fixture.READ, fixture.FINISH, lambda p: proposals(p, 3),
                NOTE, multi_fixture.scoped_valid, fixture.FINISH, NOTE, uncertain_review,
                fixture.CALLER, NOTE, changed_basis,
                NOTE, multi_fixture.scoped_valid, NOTE, multi_fixture.scoped_valid,
            ], max_calls=16)
        plan = next(row for row in result["actions"] if row["action"] == "candidate_plan")
        self.assertEqual((plan["proposed_count"], plan["selected_count"], plan["omitted_count"]), (3, 2, 1))
        self.assertEqual(plan["encoding_reserve"], 1)
        self.assertEqual(len(result["entry_results"]), 2)
        first, second = result["entry_results"]
        self.assertEqual([row["slot"] for row in first["actions"]
                          if row["action"] == "review_cycle_started"], [1])
        self.assertEqual(first["self_review_status"], "completed")
        self.assertEqual(second["self_review_status"], "completed")
        self.assertEqual(first["field_reviews"]["entry_point"]["status"], "supported")
        self.assertFalse(any(row["action"] == "review_cycle_started" for row in second["actions"]))
        self.assertEqual(repo.calls, [fixture.READ, fixture.CALLER])
        self.assertEqual((result["model_calls"], client.calls, len(payloads)), (15, 15, 15))
        self.assertTrue(all(sum(len(row["content"]) for row in payload["messages"]) <= 100_000
                            for payload in payloads))
        self.assertFalse(any(row["action"] == "annotation_encoding_reserve"
                             for entry in result["entry_results"] for row in entry["actions"]))
        # Same original total cap with feature off admits three ordinary pairs.
        baseline, baseline_client, _, _ = self.run_script([
            fixture.READ, fixture.FINISH, lambda p: proposals(p, 3),
            NOTE, multi_fixture.scoped_valid, NOTE, multi_fixture.scoped_valid,
            NOTE, multi_fixture.scoped_valid, NOTE, multi_fixture.scoped_valid,
            NOTE, multi_fixture.scoped_valid, NOTE, multi_fixture.scoped_valid,
        ], max_calls=16)
        baseline_plan = next(row for row in baseline["actions"] if row["action"] == "candidate_plan")
        self.assertEqual((baseline_plan["selected_count"], baseline_plan["omitted_count"]), (3, 0))
        self.assertEqual(baseline_client.calls, 15)


if __name__ == "__main__":
    unittest.main()
