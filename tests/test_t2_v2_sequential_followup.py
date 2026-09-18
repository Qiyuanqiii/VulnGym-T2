"""Bounded dependent follow-up decisions; synthetic providers/source only."""
import copy
import json
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from tests import test_t2_v2_staged_pipeline as fixture
from tests import test_t2_v2_assessed_tool as assessed_fixture
from tests.test_t2_v2_assessed_tool import envelope, NOTE
from tests.test_t2_v2_pipeline import evidence_from, job, VULNERABLE
from tests.test_t2_v2_read_plan import response
from tests.test_t2_v2_read_plan_encoding import encoded
from tests.test_t2_v2_snapshot_json import envelope as raw_envelope
from vulngym_t2 import staged_protocol
from vulngym_t2.pipeline import _ProductionSession, produce


def read_request(call):
    return {"action": "tools", "calls": [{"tool": call[0], "arguments": copy.deepcopy(call[1])}]}


FINISH = {"action": "finish_reading", "reason": "enough_evidence"}
SEARCH = ("search_code", {"commit": VULNERABLE, "query": "def emit", "paths": []})
CONSUMER = ("read_file", {"commit": VULNERABLE, "path": "service/audit.py", "start_line": 1, "end_line": 2})


class ChainRepo(fixture.MemoryRepo):
    sources = {**fixture.MemoryRepo.sources, "service/audit.py": ["def emit(value):", "    persist(value)"]}

    def call(self, tool, arguments):
        if tool == "search_code" and arguments["query"] == "def emit":
            self.calls.append((tool, copy.deepcopy(arguments)))
            return {"commit": arguments["commit"], "query": arguments["query"], "paths": None,
                    "complete": True, "truncated": False,
                    "matches": [{"file": "service/audit.py", "line": 1, "code": self.sources["service/audit.py"][0]}]}
        if tool == "read_file" and arguments["path"] == "service/audit.py":
            self.calls.append((tool, copy.deepcopy(arguments)))
            lines = self.sources[arguments["path"]]
            return {"commit": arguments["commit"], "path": arguments["path"], "start_line": 1, "end_line": 2,
                    "total_lines": 2, "text": "\n".join(lines), "truncated": False,
                    "lines": [{"line": index + 1, "code": code} for index, code in enumerate(lines)]}
        return super().call(tool, arguments)


class FollowupLoopTests(unittest.TestCase):
    def run_session(self, replies, *, assessed=True, staged=True, multi=False, max_calls=12,
                    global_calls=16, max_tools=24, reserved=0, context=None, repo=None):
        client = SimpleNamespace(response_mode="staged_tool" if staged else "strict_tool",
                                 annotation_format="assessed_tool" if assessed else "snapshot_tool",
                                 multi_entry=multi, remaining_requests=global_calls, halted=None)
        session = _ProductionSession(job(False), client, repo or ChainRepo(), max_calls, max_tools)
        session.prepare()
        session.drafted, session.initial_valid_updates = True, 1
        session.result["initial_draft_status"] = "accepted"
        calls, pending, hints = [], list(replies), []

        def complete(stage, *, reserved_calls=0):
            cost = session.annotation_call_cost if stage == "self_review" else 1
            self.assertGreaterEqual(client.remaining_requests, cost)
            self.assertGreaterEqual(session.max_calls - session.result["model_calls"], cost)
            session.result["model_calls"] += cost
            client.remaining_requests -= cost
            calls.append((stage, reserved_calls))
            if stage == "evidence_followup":
                hints.append(session.messages[-1]["content"])
                session.result["evidence_followup_status"] = "failed"
                self.assertTrue(pending, "Unexpected extra business decision")
                reply = pending.pop(0)
                return reply(session) if callable(reply) else copy.deepcopy(reply)
            self.assertEqual(stage, "self_review")
            return {"action": "draft", "fields": {}, "field_reviews": {}}

        with patch.object(session, "complete", side_effect=complete), patch.object(session, "navigate_entry_context") as navigation:
            if context is None:
                session.finish_draft(reserved_calls=reserved)
            else:
                with patch.object(session, "followup_context_fits", side_effect=context):
                    session.finish_draft(reserved_calls=reserved)
        if staged:
            self.assertTrue(all(len(hint) <= 512 for hint in hints))
            self.assertTrue(all(hint.startswith("Focused read decision") for hint in hints))
        return session, calls, navigation.call_args_list, pending

    def test_three_reads_stop_without_a_fourth_decision_and_keep_review_reserve(self):
        replies = [read_request(fixture.READ), read_request(SEARCH), read_request(CONSUMER), FINISH]
        session, calls, navigation, pending = self.run_session(replies, max_calls=6, global_calls=6)
        self.assertEqual(calls, [("evidence_followup", 1)] * 3 + [("self_review", 0)])
        self.assertEqual(session.result["model_calls"], 5)
        self.assertEqual(session.client.remaining_requests, 1)
        self.assertEqual(session.result["tool_calls"], 3)
        self.assertEqual(session.result["self_review_status"], "completed")
        self.assertEqual(pending, [FINISH])
        self.assertEqual(len(navigation), 1)  # Original initial navigation only.
        self.assertNotIn("focused_reads", navigation[0].kwargs)

    def test_finish_reading_stops_at_first_or_second_decision(self):
        for replies, expected in (([FINISH, read_request(fixture.READ)], 1),
                                  ([read_request(fixture.READ), FINISH, read_request(SEARCH)], 2)):
            with self.subTest(expected=expected):
                session, calls, _, pending = self.run_session(replies)
                self.assertEqual(sum(stage == "evidence_followup" for stage, _ in calls), expected)
                self.assertEqual(len(pending), 1)
                self.assertEqual(session.result["self_review_status"], "completed")

    def test_local_global_and_later_slot_reserves_are_rechecked(self):
        for local, available, reserved, expected in ((4, 16, 0, 1), (12, 4, 0, 1),
                (12, 3, 0, 0), (6, 16, 2, 1), (12, 6, 2, 1)):
            with self.subTest(local=local, available=available, reserved=reserved):
                session, calls, _, _ = self.run_session([read_request(fixture.READ), read_request(SEARCH)],
                    max_calls=local, global_calls=available, reserved=reserved)
                self.assertEqual(sum(stage == "evidence_followup" for stage, _ in calls), expected)
                self.assertTrue(all(value == reserved + 1 for stage, value in calls if stage == "evidence_followup"))
                self.assertGreaterEqual(min(local - session.result["model_calls"], session.client.remaining_requests), 1 + reserved)

    def test_context_and_tool_limits_stop_normally_after_real_receipt(self):
        for settings in ({"context": [True, False]}, {"max_tools": 1}):
            with self.subTest(settings=settings):
                session, calls, _, pending = self.run_session(
                    [read_request(fixture.READ), read_request(SEARCH)], **settings)
                self.assertEqual([stage for stage, _ in calls], ["evidence_followup", "self_review"])
                self.assertEqual(session.result["evidence_followup_status"], "completed")
                self.assertEqual(session.result["tool_calls"], 1)
                self.assertEqual(len(pending), 1)

    def test_duplicate_or_covered_read_does_not_keep_loop_alive(self):
        covered = ("read_file", {**fixture.READ[1], "end_line": 1})
        for second in (fixture.READ, covered):
            with self.subTest(second=second):
                session, calls, _, pending = self.run_session(
                    [read_request(fixture.READ), read_request(second), read_request(SEARCH)])
                self.assertEqual(sum(stage == "evidence_followup" for stage, _ in calls), 2)
                self.assertEqual(session.result["tool_calls"], 1)
                self.assertEqual(len(pending), 1)
                self.assertTrue(any(row.get("reason") == "no_new_evidence" for row in session.result["actions"]))

    def test_failed_response_is_not_overwritten_by_a_later_success(self):
        session, calls, _, pending = self.run_session([read_request(fixture.READ), None, FINISH])
        self.assertEqual([stage for stage, _ in calls], ["evidence_followup"] * 2)
        self.assertEqual(session.result["evidence_followup_status"], "failed")
        self.assertEqual(session.result["self_review_status"], "not_requested")
        self.assertEqual(pending, [FINISH])

    def test_failed_repository_receipt_is_retained_but_not_new_successful_evidence(self):
        repo = ChainRepo()
        with patch.object(repo, "call", return_value={"error": "source_file_unavailable"}):
            session, calls, _, pending = self.run_session([read_request(fixture.READ), FINISH], repo=repo)
        self.assertEqual([stage for stage, _ in calls], ["evidence_followup", "self_review"])
        self.assertIs(session.result["evidence"][-1]["success"], False)
        self.assertTrue(session.result["errors"])
        self.assertEqual(pending, [FINISH])

    def test_multi_and_legacy_still_have_one_business_decision(self):
        for settings in ({"multi": True}, {"staged": False, "assessed": False}):
            with self.subTest(settings=settings):
                session, calls, navigation, pending = self.run_session(
                    [read_request(fixture.READ), FINISH], **settings)
                self.assertEqual([stage for stage, _ in calls], ["evidence_followup", "self_review"])
                self.assertEqual(pending, [FINISH])
                self.assertEqual(sum("focused_reads" in row.kwargs for row in navigation), int(settings.get("multi", False)))


class FollowupNativeIntegrationTests(unittest.TestCase):
    setUp = fixture.StagedPipelineTests.setUp
    run_script = fixture.StagedPipelineTests.run_script

    def test_dependent_read_search_read_sees_each_previous_actual_result(self):
        def search(payload):
            self.assertTrue(any(row.get("result", {}).get("path") == fixture.CALLER[1]["path"]
                                for row in evidence_from(payload["messages"])))
            return SEARCH

        def read_hit(payload):
            saved = next(row for row in evidence_from(payload["messages"]) if row.get("tool") == "search_code")
            hit = saved["result"]["matches"][0]
            return "read_file", {"commit": saved["result"]["commit"], "path": hit["file"],
                                 "start_line": hit["line"], "end_line": hit["line"] + 1}

        def review(payload):
            self.assertTrue(any(row.get("result", {}).get("path") == CONSUMER[1]["path"]
                                and row.get("tool") == "read_file" for row in evidence_from(payload["messages"])))
            return fixture.full_annotation(payload)

        with patch.object(fixture, "MemoryRepo", ChainRepo):
            result, _, client, _, payloads = self.run_script(
                [fixture.READ, fixture.FINISH, fixture.full_annotation, fixture.CALLER, search, read_hit, review], max_calls=7)
        self.assertEqual(result["model_calls"], 7)
        self.assertEqual(result["tool_calls"], 4)
        self.assertEqual(sum(row.get("stage") == "evidence_followup" and row["action"] == "model_call"
                             for row in result["actions"]), 3)
        self.assertEqual(result["self_review_status"], "completed")
        self.assertEqual(client.summary()["automatic_retries"], 0)
        self.assertTrue(all(sum(len(row["content"]) for row in item["messages"]) <= 100_000 for item in payloads))


class FollowupEncodingIntegrationTests(unittest.TestCase):
    setUp = assessed_fixture.AssessedToolTests.setUp
    client = assessed_fixture.AssessedToolTests.client

    def test_plan_correction_leaves_final_assessment_encoding_and_its_correction(self):
        payloads = []

        def send(body, *_):
            payload = json.loads(body)
            payloads.append(payload)
            index = len(payloads)
            if index in (1, 2, 6, 7):
                return response([{1: fixture.READ, 2: fixture.FINISH, 6: fixture.CALLER, 7: fixture.FINISH}[index]])
            if index in (3, 8):
                return envelope(content=NOTE)
            if index == 5:
                return encoded()  # Existing single whole-input encoding correction.
            if index == 9:
                value = staged_protocol.source_id_snapshot(fixture.full_annotation(payload)[1])
                return raw_envelope(call=("submit_annotation", {"commit": value["commit"]}))
            self.assertIn(index, (4, 10))
            return envelope(call=fixture.full_annotation(payload))

        client = self.client(send, read_format="plan_tool", max_requests=10)
        result = produce(job(False), client, ChainRepo(), max_calls=10)
        stages = [row["stage"] for row in result["actions"] if row["action"] == "model_call"]
        self.assertEqual(stages[-6:], ["evidence_followup", "read_plan_encoding_review", "evidence_followup",
                                      "self_review_assessment", "self_review", "encoding_shape_review"])
        self.assertEqual((len(payloads), result["model_calls"], self.ledger.started), (10, 10, 10))
        self.assertEqual(client.summary()["automatic_retries"], 0)
        self.assertEqual(result["self_review_status"], "completed")
        self.assertEqual(sum(row["action"] == "read_plan_reencoding" for row in result["actions"]), 1)


if __name__ == "__main__":
    unittest.main()
