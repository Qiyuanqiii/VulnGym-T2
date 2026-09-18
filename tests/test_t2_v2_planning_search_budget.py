"""Small initial searches reserve source space without changing wire budgets."""
import copy
from contextlib import closing
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from tests import test_t2_v2_planning_read_budget as planning
from tests import test_t2_v2_staged_pipeline as fixture
from tests import test_t2_v2_assessed_tool as assessed_fixture
from tests.test_t2_v2_pipeline import VULNERABLE, job
from tests.test_t2_v2_read_plan import response as plan_response
from tests.test_t2_v2_staged_read_batch import native_envelope
from vulngym_t2.llm import DeepSeekClient, RequestLedger
from vulngym_t2.pipeline import _ProductionSession, _READ_CONTEXT_LIMIT, _json
from vulngym_t2.prompt_evidence import bounded_navigation_result


HISTORY = ("search_history", {"commit": VULNERABLE, "query": "release clue", "path": "", "limit": 20})
SEARCH = ("search_code", {"commit": VULNERABLE, "query": "RecordProcessor", "paths": []})


def history_result():
    return {**HISTORY[1], "matches": [{"commit": f"{n:040x}", "parents": [VULNERABLE],
            "subject": "release clue " + "x" * 350, "subject_truncated": False} for n in range(20)],
            "has_more": False, "negative_result_conclusive": False, "shallow": False, "truncated": False}


class MetadataRepo(fixture.MemoryRepo):
    def call(self, tool, arguments):
        if tool == "search_history":
            self.calls.append((tool, copy.deepcopy(arguments)))
            return history_result()
        if tool == "search_code":
            self.calls.append((tool, copy.deepcopy(arguments)))
            matches = [{"file": f"docs/example{n}.txt", "line": 1, "code": '"RecordProcessor"' + "x" * 100}
                       for n in range(59)]
            matches.append({"file": "src/worker.py", "line": 20, "code": "class RecordProcessor(Base):"})
            return {**arguments, "matches": matches, "complete": True, "truncated": False, "skipped_count": 0}
        return super().call(tool, arguments)


class PlanningSearchAllowanceTests(unittest.TestCase):
    state = planning.PlanningReadBudgetTests.state

    def test_searches_fit_below_sixteen_k_and_leave_source_plus_envelope(self):
        state = self.state(55_000)
        for tool in ("search_code", "search_history"):
            allowance = state.planning_read_allowance([], tool)
            self.assertEqual(allowance, 4096)
            self.assertLess(68000 - 55000, 16000)
            self.assertLessEqual(55_000 + len(_json([])) + 1024 + allowance + 4096 + 1024, _READ_CONTEXT_LIMIT)
        state.messages[0]["content"] = "x" * 60_000
        self.assertLess(state.planning_read_allowance([], "search_code"), 4096)
        self.assertGreaterEqual(state.planning_read_allowance([], "read_file"), 4096)

    def test_other_tools_and_legacy_keep_existing_reservation_rules(self):
        state = self.state(55_000)
        for tool in ("inspect_commit", "list_refs", "list_files", "read_diff"):
            self.assertEqual(state.planning_read_allowance([], tool), 0)
        state.staged_mode = False
        for tool in ("search_code", "search_history", "read_file"):
            self.assertEqual(state.planning_read_allowance([], tool), 0)
        state.messages[0]["content"] = "x" * 10_000
        self.assertEqual(state.planning_read_allowance([], "search_history"), 16000)

    def test_clipped_history_never_claims_exhaustiveness_and_preserves_failure(self):
        value = history_result()
        original = copy.deepcopy(value)
        shown = bounded_navigation_result(value, 4096)
        self.assertLessEqual(len(_json(shown)), 4096)
        self.assertEqual(shown["matches"], value["matches"][:len(shown["matches"])])
        self.assertTrue(shown["has_more"])
        self.assertTrue(shown["truncated"])
        self.assertTrue(shown["context_truncated"])
        self.assertFalse(shown["complete"])
        self.assertFalse(shown["negative_result_conclusive"])
        self.assertEqual(value, original)
        value.update(error="real_failure", success=False, negative_result_conclusive=True)
        shown = bounded_navigation_result(value, 4096)
        self.assertEqual(shown["error"], "real_failure")
        self.assertIs(shown["success"], False)
        self.assertIs(shown["negative_result_conclusive"], False)

    def test_insufficient_remaining_space_produces_no_tool_or_fake_receipt(self):
        # A 65k context can now carry an independently requested small source
        # read. Keep this no-read assertion at a genuinely sub-1k remainder.
        state = self.state(66_000)
        reply = {"action": "tools", "calls": [{"tool": tool, "arguments": args} for tool, args in (HISTORY, fixture.READ)]}
        with patch.object(state, "complete", side_effect=[reply, {"action": "draft"}]), \
             patch.object(state, "accept_snapshot", return_value=True), patch.object(state.repo, "call") as called:
            state.read_and_draft()
        called.assert_not_called()
        self.assertEqual(state.result["evidence"], [])
        self.assertEqual(state.result["tool_calls"], 0)
        self.assertTrue(state.read_context_closed)

    def test_search_minimum_stays_four_k_while_small_independent_source_can_proceed(self):
        state = self.state(65_000)
        reply = {"action": "tools", "calls": [{"tool": tool, "arguments": args}
                                                 for tool, args in (HISTORY, fixture.READ)]}
        with patch.object(state, "complete", side_effect=[reply, {"action": "draft"}]), \
             patch.object(state, "accept_snapshot", return_value=True):
            state.read_and_draft()
        self.assertEqual([tool for tool, _ in state.repo.calls], ["read_file"])
        skipped = [row for row in state.result["actions"] if row["action"] == "planning_read_skipped"]
        self.assertEqual([row["tool"] for row in skipped], ["search_history"])
        self.assertTrue(all(row["result_allowance_chars"] < 4096 for row in skipped))
        self.assertEqual([row["tool"] for row in state.result["evidence"]], ["read_file"])
        self.assertFalse(state.read_context_closed)


class PlanningSearchWireTests(unittest.TestCase):
    def run_wire(self, read_format, context_size):
        temp = tempfile.TemporaryDirectory(prefix="t2-planning-search-")
        self.addCleanup(temp.cleanup)
        ledger = RequestLedger(Path(temp.name) / "ledger.jsonl", limit=6)
        self.addCleanup(ledger.close)
        payloads = []
        def send(body, _key, _timeout):
            payload = json.loads(body)
            payloads.append(payload)
            names = [tool["function"]["name"] for tool in payload["tools"]]
            if "submit_annotation" in names:
                return json.dumps(native_envelope([fixture.annotation()])).encode()
            calls = [HISTORY, SEARCH, fixture.READ] if len(payloads) == 1 else [fixture.FINISH]
            return (plan_response(calls) if read_format == "plan_tool"
                    else json.dumps(native_envelope(calls)).encode())
        client = DeepSeekClient("synthetic-no-api-key", ledger, run_id="budget-fixture", send=send,
            max_requests=6, response_mode="staged_tool", read_format=read_format, thinking="disabled")
        self.addCleanup(client.close)
        supplied = job(False)
        client.start_next_case(supplied["report_id"])
        repo = MetadataRepo()
        state = _ProductionSession(supplied, client, repo, 6, 24)
        state.prepare()
        state.messages = [{"role": "user", "content": "x" * context_size}]
        state.read_and_draft()
        self.assertEqual(client.calls, len(payloads))
        self.assertEqual(ledger.started, len(payloads))
        self.assertEqual(client.summary()["automatic_retries"], 0)
        self.assertLessEqual(len(payloads), 3)
        self.assertLessEqual(state.result["tool_calls"], 3)
        self.assertIsNone(client.halted)
        return state, repo

    def test_wire_client_controller_metadata_then_same_batch_source_at_original_caps(self):
        for read_format in ("native_tool", "plan_tool"):
            with self.subTest(read_format=read_format):
                state, repo = self.run_wire(read_format, 45_000)
                self.assertEqual([tool for tool, _ in repo.calls], ["search_history", "search_code", "read_file"])
                tools = [row for row in state.result["evidence"] if row.get("tool")]
                for row in tools[:2]:
                    self.assertLessEqual(len(_json(row["result"])), 4096)
                    self.assertTrue(row["result"]["truncated"])
                self.assertTrue(tools[0]["result"]["has_more"])
                self.assertFalse(tools[0]["result"]["negative_result_conclusive"])
                self.assertEqual(tools[1]["result"]["matches"][0]["code"], "class RecordProcessor(Base):")
                self.assertEqual(tools[-1]["tool"], "read_file")
                self.assertTrue(tools[-1]["success"])

    def test_wire_skipped_searches_do_not_discard_later_independent_source_or_make_receipts(self):
        for read_format in ("native_tool", "plan_tool"):
            with self.subTest(read_format=read_format):
                state, repo = self.run_wire(read_format, 59_000)
                self.assertEqual([tool for tool, _ in repo.calls], ["read_file"])
                skipped = [row for row in state.result["actions"] if row["action"] == "planning_read_skipped"]
                self.assertEqual([row["tool"] for row in skipped], ["search_history", "search_code"])
                self.assertTrue(all(row["reason"] == "reserve_source_window" for row in skipped))
                self.assertTrue(all("evidence_ref" not in row and "success" not in row for row in skipped))
                self.assertEqual([row["tool"] for row in state.result["evidence"] if row.get("tool")], ["read_file"])
                self.assertFalse(state.read_context_closed)

    def test_assessed_wire_small_source_reaches_self_review_without_extra_requests(self):
        for read_format in ("native_tool", "plan_tool"):
            with self.subTest(read_format=read_format):
                with tempfile.TemporaryDirectory(prefix="t2-planning-small-wire-") as temp:
                    with closing(RequestLedger(Path(temp) / "ledger.jsonl", limit=6)) as ledger:
                        payloads = []

                        def send(body, *_):
                            payload = json.loads(body)
                            payloads.append(payload)
                            if "tools" not in payload:
                                return assessed_fixture.envelope(content="Uncertain; use only the actual saved source window.")
                            if [row["function"]["name"] for row in payload["tools"]] == ["submit_annotation"]:
                                return assessed_fixture.envelope(call=fixture.annotation())
                            calls = [fixture.READ] if len(payloads) == 1 else [fixture.FINISH]
                            return (plan_response(calls) if read_format == "plan_tool"
                                    else json.dumps(native_envelope(calls)).encode())

                        client = DeepSeekClient("synthetic-not-a-key", ledger, run_id="small-window",
                            send=send, max_requests=6, response_mode="staged_tool", read_format=read_format,
                            annotation_format="assessed_tool", thinking="enabled", reasoning_effort="low")
                        try:
                            supplied, repo = job(False), fixture.MemoryRepo()
                            client.start_next_case(supplied["report_id"])
                            state = _ProductionSession(supplied, client, repo, 6, 24)
                            state.prepare()
                            state.messages = [{"role": "user", "content": "x" * 65_000}]
                            state.read_and_draft()
                            state.finish_draft(allow_followup=False)
                            self.assertEqual([tool for tool, _ in repo.calls], ["read_file"])
                            self.assertEqual((state.result["model_calls"], client.calls, ledger.started), (6, 6, 6))
                            self.assertEqual(state.result["self_review_status"], "completed")
                            self.assertIsNone(client.halted)
                            self.assertEqual(client.summary()["automatic_retries"], 0)
                            calls = [row for row in state.result["actions"] if row["action"] == "model_call"]
                            self.assertEqual([row["stage"] for row in calls],
                                ["plan_and_read", "plan_and_read", "draft_assessment", "draft",
                                 "self_review_assessment", "self_review"])
                            for payload in payloads:
                                self.assertLessEqual(sum(len(row["content"]) for row in payload["messages"]), 100_000)
                            saved = [row for row in state.result["evidence"] if row.get("tool") == "read_file"]
                            self.assertEqual(len(saved), 1)
                            self.assertTrue(saved[0]["success"])
                            self.assertEqual(saved[0]["result"]["lines"],
                                             [{"line": index + 1, "code": code}
                                              for index, code in enumerate(fixture.SOURCE)])
                            self.assertIn("def serve(request):", json.dumps(payloads[-2]))
                        finally:
                            client.close()


if __name__ == "__main__":
    unittest.main()
