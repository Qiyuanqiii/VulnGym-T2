"""Explicit read-plan wire; synthetic transport only, no paid or target calls."""
import copy
from contextlib import redirect_stdout
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from vulngym_t2 import annotation_rules, cli, protocol, read_plan_protocol as plan
from vulngym_t2 import staged_protocol as staged, transport
from vulngym_t2.llm import DeepSeekClient, ProviderError, RequestLedger
from vulngym_t2.output import finalize_result
from vulngym_t2.pipeline import _ProductionSession, produce
from tests import test_t2_v2_assessed_tool as assessed
from tests import test_t2_v2_staged_pipeline as fixture
from tests.test_t2_v2_pipeline import VULNERABLE, job
from tests.test_t2_v2_staged_read_batch import native_envelope, parsed_calls


def response(calls):
    return json.dumps(native_envelope([(plan.TOOL_NAME, {"calls": parsed_calls(calls)})])).encode()


class ReadPlanProtocolTests(unittest.TestCase):
    def test_followup_can_investigate_observed_history_without_broadening_call_count(self):
        history = {"tool": "search_history", "arguments": {
            "commit": VULNERABLE, "query": "release clue", "path": "", "limit": 10}}
        result = plan.normalize({"calls": [history]}, "followup")
        self.assertEqual(result["action"], "tools")
        self.assertEqual(result["calls"][0]["tool"], "search_history")
        with self.assertRaises(staged.ProtocolError):
            plan.normalize({"calls": [history, history]}, "followup")
        invalid = copy.deepcopy(history)
        invalid["arguments"]["limit"] = 100_001
        with self.assertRaises(staged.ProtocolError):
            plan.normalize({"calls": [invalid]}, "followup")

    def test_closed_union_is_derived_from_each_stages_original_operation_schemas(self):
        for stage in ("read", "followup"):
            with self.subTest(stage=stage):
                definition = plan.definition(stage)
                function = definition["function"]
                self.assertEqual(function["name"], plan.TOOL_NAME)
                self.assertIs(function["strict"], True)
                root = function["parameters"]
                self.assertEqual(root["required"], ["calls"])
                self.assertFalse(root["additionalProperties"])
                choices = root["properties"]["calls"]["items"]["anyOf"]
                actual = {item["properties"]["tool"]["enum"][0]: item["properties"]["arguments"] for item in choices}
                self.assertEqual(actual, staged._schemas(stage))
                self.assertNotIn("submit_annotation", actual)
                self.assertEqual([definition], staged.tool_definitions(stage, read_format="plan_tool"))
                root["properties"].clear()
                self.assertIn("calls", plan.definition(stage)["function"]["parameters"]["properties"])
                text = staged.instruction(stage, read_format="plan_tool")
                self.assertIn("ONLY native function is " + plan.TOOL_NAME, text)
                self.assertEqual(json.loads(text.split("Current operation names (JSON array): ")[1]), list(actual))
                if stage == "followup":
                    self.assertNotIn("list_files", text)
                    self.assertIn("preserve uncertainty", text)

    def test_all_read_operations_and_finish_preserve_the_original_normalization(self):
        calls = [("list_refs", {"prefix": "", "limit": 8}),
                 ("inspect_commit", {"commit": VULNERABLE}),
                 ("search_history", {"query": "fix", "commit": VULNERABLE, "path": "", "limit": 10}),
                 ("list_files", {"commit": VULNERABLE, "prefix": "", "offset": 0, "limit": 10}),
                 fixture.READ,
                 ("search_code", {"commit": VULNERABLE, "query": "serve", "paths": ["service"]}),
                 ("read_diff", {"before": VULNERABLE, "after": "b" * 40, "path": ""}), fixture.FINISH]
        for call in calls:
            for stage in ("read", "followup"):
                if call[0] not in staged._schemas(stage):
                    continue
                with self.subTest(tool=call[0], stage=stage):
                    arguments = {"calls": parsed_calls([call])}
                    before = copy.deepcopy(arguments)
                    expected = staged.normalize_calls(arguments["calls"], stage)
                    self.assertEqual(plan.normalize(arguments, stage), expected)
                    self.assertEqual(transport.parse_chat_response(response([call]), response_mode="staged_tool",
                        stage=stage, read_format="plan_tool"), expected)
                    self.assertEqual(arguments, before)

    def test_exact_container_resource_limits_and_unknown_operations_are_not_repaired(self):
        valid = parsed_calls([fixture.READ])
        invalid = [None, [], {"calls": []}, {"calls": "bad"},
                   {"calls": valid * 5}, {"calls": [*valid, {"tool": "not-an-operation", "arguments": {}}]},
                   {"calls": [*valid, {"tool": "read_file", "arguments": {**fixture.READ[1], "path": " "}}]}]
        for value in invalid:
            with self.subTest(value=value), self.assertRaises(staged.ProtocolError):
                plan.normalize(value, "read")
        for value in ({}, {"calls": valid, "fields": {}}):
            before = copy.deepcopy(value)
            rejected = plan.normalize(value, "read")
            self.assertEqual(rejected["action"], "read_plan_rejected")
            self.assertEqual(rejected["code"], "invalid_plan_shape")
            self.assertNotIn("calls", rejected)
            self.assertEqual(value, before)
        with self.assertRaises(staged.ProtocolError):
            plan.normalize({"calls": valid * 2}, "followup")
        for stage in ("annotation", "candidate_selection", None):
            with self.subTest(stage=stage), self.assertRaisesRegex(ValueError, "read_plan_stage_invalid"):
                plan.definition(stage)

    def test_known_argument_and_finish_feedback_rejects_the_whole_plan(self):
        missing = ("read_file", {"commit": VULNERABLE})
        for calls in ([fixture.READ, fixture.FINISH], [fixture.READ, missing],
                      [("read_file", {**fixture.READ[1], "start_line": 0})]):
            with self.subTest(calls=calls):
                expected = staged.normalize_calls(parsed_calls(calls), "read")
                self.assertEqual(expected["action"], "read_request_rejected")
                actual = transport.parse_chat_response(response(calls), response_mode="staged_tool",
                                                      stage="read", read_format="plan_tool")
                self.assertEqual(actual, expected)
                self.assertNotIn("calls", actual)

    def test_native_envelope_and_json_remain_strict_and_never_alias_a_function(self):
        good = native_envelope([(plan.TOOL_NAME, {"calls": parsed_calls([fixture.READ])})])
        mutations = [lambda m: m["tool_calls"][0]["function"].update(name="read_file"),
                     lambda m: m["tool_calls"].append(copy.deepcopy(m["tool_calls"][0])),
                     lambda m: m["tool_calls"][0].update(id=""),
                     lambda m: m.update(refusal="synthetic refusal"),
                     lambda m: m["tool_calls"][0]["function"].update(arguments='{"calls":[],"calls":[]}')]
        for mutate in mutations:
            body = copy.deepcopy(good)
            mutate(body["choices"][0]["message"])
            with self.subTest(mutation=mutations.index(mutate)), self.assertRaises(transport.TransportError):
                transport.parse_chat_response(json.dumps(body).encode(), response_mode="staged_tool",
                                              stage="read", read_format="plan_tool")
        with self.assertRaises(transport.TransportError):
            transport.parse_chat_response(response([fixture.READ]), response_mode="staged_tool", stage="read")


class ReadPlanIntegrationTests(unittest.TestCase):
    def test_history_followup_passes_wire_and_execution_gate_then_finishes_review(self):
        history = ("search_history", {"commit": VULNERABLE, "query": "release clue", "path": "", "limit": 10})

        class HistoryRepo(fixture.MemoryRepo):
            def call(self, tool, arguments):
                if tool == "search_history":
                    self.calls.append((tool, copy.deepcopy(arguments)))
                    return {"commit": arguments["commit"], "query": arguments["query"],
                            "commits": [{"commit": "b" * 40, "subject": "synthetic release clue"}],
                            "has_more": False}
                return super().call(tool, arguments)

        plans = []
        def send(body, *_):
            payload = json.loads(body)
            if "tools" not in payload:
                return assessed.envelope(content=assessed.NOTE)
            if payload["tools"][0]["function"]["name"] == plan.TOOL_NAME:
                plans.append(payload)
                calls = ([fixture.READ, fixture.CALLER] if len(plans) == 1 else
                         [history] if len(plans) == 3 else [fixture.FINISH])
                return response(calls)
            return assessed.envelope(call=fixture.full_annotation(payload))

        client, repo = self.client(send), HistoryRepo()
        result = produce(job(False), client, repo, max_calls=10)
        self.assertIsNone(client.halted)
        self.assertEqual(result["evidence_followup_status"], "completed")
        self.assertEqual(result["self_review_status"], "completed")
        history_reads = [row for row in repo.calls if row[0] == "search_history"]
        self.assertEqual(len(history_reads), 1)
        self.assertEqual(history_reads[0][1]["query"], "release clue")
        receipt = next(row for row in result["evidence"] if row.get("tool") == "search_history")
        self.assertTrue(receipt["success"])
        self.assertEqual((client.calls, self.ledger.started, result["model_calls"]), (8, 8, 8))

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="t2-read-plan-")
        self.addCleanup(self.temp.cleanup)
        self.ledger = RequestLedger(Path(self.temp.name).resolve() / "requests.jsonl", limit=16)
        self.addCleanup(self.ledger.close)

    def client(self, send, **overrides):
        options = {"response_mode": "staged_tool", "thinking": "enabled", "annotation_format": "assessed_tool",
                   "read_format": "plan_tool", "max_requests": 12, "send": send}
        options.update(overrides)
        client = DeepSeekClient("synthetic-not-a-key", self.ledger, run_id="synthetic", **options)
        self.addCleanup(client.close)
        return client

    def test_real_client_and_controller_keep_assessment_self_review_and_source_fields(self):
        payloads, plans = [], []

        def send(body, *_):
            payload = json.loads(body)
            payloads.append(payload)
            if "tools" not in payload:
                return assessed.envelope(content=assessed.NOTE)
            if payload["tools"][0]["function"]["name"] == plan.TOOL_NAME:
                plans.append(payload)
                return response([fixture.READ, fixture.CALLER] if len(plans) == 1 else [fixture.FINISH])
            return assessed.envelope(call=fixture.full_annotation(payload))

        client, repo = self.client(send), fixture.MemoryRepo()
        supplied = job(False)
        result = produce(supplied, client, repo, max_calls=6)
        final = finalize_result(supplied, result, repo)
        self.assertIsNotNone(final["entry"])
        self.assertEqual(final["entry"]["verify"], 0)
        self.assertEqual(result["self_review_status"], "completed")
        self.assertEqual(repo.calls[:2], [fixture.READ, fixture.CALLER])
        self.assertEqual((client.calls, self.ledger.started, result["model_calls"]), (6, 6, 6))
        self.assertEqual(len([p for p in payloads if "tools" not in p]), 2)
        for payload in plans:
            self.assertEqual(len(payload["tools"]), 1)
            self.assertEqual(payload["tool_choice"], {"type": "function", "function": {"name": plan.TOOL_NAME}})
            self.assertEqual(payload["thinking"], {"type": "disabled"})
            self.assertNotIn("reasoning_effort", payload)
        for payload in payloads:
            if payload not in plans:
                # Both current assessment and its encoder see actual receipt
                # identity rules, not just the initial source-planning prompt.
                rendered = "\n".join(message["content"] for message in payload["messages"])
                self.assertIn(annotation_rules.RECEIPT_IDENTITY_GUIDANCE, rendered)
                self.assertIn("Different files/purposes are not different SHAs", rendered)
                self.assertIn("Read helpers != unread consumers", rendered)
                self.assertIn("inspected SHAs from all successful receipts", rendered)
                self.assertIn("source-read SHAs from read_file result.commit/line only", rendered)
        summary = client.summary()
        self.assertEqual(summary["read_format"], "plan_tool")
        self.assertEqual(summary["read_wire_version"], plan.VERSION)
        self.assertEqual(summary["stage_settings"]["read"]["tool_choice"], plans[0]["tool_choice"])
        self.assertEqual(summary["automatic_retries"], 0)
        self.assertEqual(client.events[0]["diagnostics"]["response_wire"], "read_plan")
        self.assertEqual(client.events[-1]["diagnostics"]["response_wire"], "native_tool")

    def test_bad_later_operation_executes_nothing_and_stops_without_retry_or_leak(self):
        sent = []
        client = self.client(lambda *_: sent.append(True) or response([
            fixture.READ, ("synthetic_unknown_operation", {})]))
        repo = fixture.MemoryRepo()
        result = produce(job(False), client, repo, max_calls=8)
        self.assertEqual((len(sent), client.calls, self.ledger.started, result["tool_calls"]), (1, 1, 1, 0))
        self.assertEqual(repo.calls, [])
        self.assertEqual(client.halted, "deepseek_staged_protocol_invalid")
        self.assertFalse(client.can_continue_after_format_error)
        with self.assertRaises(ProviderError):
            client.complete([{"role": "user", "content": "again"}], stage="read")
        self.assertEqual(len(sent), 1)
        self.assertNotIn("commit", result["fields"])
        self.assertNotIn("synthetic_unknown_operation", json.dumps(result))
        self.assertNotIn("synthetic_unknown_operation", self.ledger.path.read_text())

    def test_focused_followup_uses_the_named_plan_and_only_its_original_operations(self):
        for annotation_format in ("native_tool", "snapshot_json", "snapshot_tool", "assessed_tool"):
            payloads = []
            client = self.client(lambda body, *_: payloads.append(json.loads(body)) or response([fixture.READ]),
                                 annotation_format=annotation_format)
            with self.subTest(annotation_format=annotation_format):
                actual = client.complete([{"role": "user", "content": "Focused fixture read."}], stage="followup")
                self.assertEqual(actual, staged.normalize_calls(parsed_calls([fixture.READ]), "followup"))
                self.assertEqual(len(payloads), 1)
                payload = payloads[0]
                self.assertEqual(payload["tools"], [plan.definition("followup")])
                self.assertEqual(payload["tool_choice"], {"type": "function", "function": {"name": plan.TOOL_NAME}})
                self.assertEqual(payload["thinking"], {"type": "disabled"})
                self.assertNotIn("reasoning_effort", payload)
                self.assertEqual(payload["messages"][-1]["content"], plan.instruction("followup"))
                self.assertEqual(client.events[0]["diagnostics"]["response_wire"], "read_plan")
                self.assertEqual(client.summary()["stage_settings"]["read"]["tool_choice"], payload["tool_choice"])
        self.assertEqual(self.ledger.started, 4)

    def test_request_and_tool_budgets_are_not_expanded_by_the_wrapper(self):
        sent = []
        client = self.client(lambda *_: sent.append(True) or response([fixture.READ, fixture.CALLER]), max_requests=1)
        repo = fixture.MemoryRepo()
        result = produce(job(False), client, repo, max_calls=6, max_tool_calls=1)
        self.assertEqual((len(sent), self.ledger.started, result["tool_calls"]), (1, 1, 1))
        self.assertEqual(repo.calls, [fixture.READ])
        self.assertIsNone(finalize_result(job(False), result, repo)["entry"])

    def test_actual_plan_instruction_counts_before_any_request(self):
        for extra in (0, 1):
            calls = []
            class Client:
                response_mode = "staged_tool"
                read_format = "plan_tool"
                def complete(self, messages, *, stage):
                    calls.append(messages)
                    return {"action": "finish_reading", "reason": "enough_evidence"}
            session = _ProductionSession(job(False), Client(), fixture.MemoryRepo(), 2, 0)
            session.prepare()
            system_size = len(annotation_rules.TASK_RULES + "\n" + annotation_rules.for_phase("read"))
            wire_size = len(plan.instruction("read"))
            session.messages = [{"role": "system", "content": "replaced"},
                                {"role": "user", "content": "x" * (100_000 - system_size - wire_size + extra)}]
            session.complete("plan_and_read")
            self.assertEqual(len(calls), 1 - extra)

    def test_cli_prepare_reports_choice_without_key_or_provider_access(self):
        with patch.object(cli, "load_jobs", return_value=[{}]), patch.object(cli, "prepare", return_value=({}, [])), \
             patch.object(cli, "DeepSeekClient") as provider, patch.object(cli.getpass, "getpass") as key:
            output = io.StringIO()
            with redirect_stdout(output):
                code = cli.main(["--input", "synthetic.jsonl", "--response-mode", "staged_tool",
                                 "--read-format", "plan_tool", "--prepare-only"])
            self.assertEqual(code, 0)
            self.assertEqual(json.loads(output.getvalue())["configuration"]["read_format"], "plan_tool")
            provider.assert_not_called()
            key.assert_not_called()

    def test_invalid_modes_stop_before_intake_or_secret_or_budget(self):
        with self.assertRaisesRegex(ValueError, "plan_tool_requires_staged_tool"):
            self.client(lambda *_: self.fail("not sent"), response_mode="json", annotation_format="native_tool")
        with patch.object(cli, "load_jobs") as intake, patch.object(cli.getpass, "getpass") as key:
            with redirect_stdout(io.StringIO()):
                self.assertEqual(cli.main(["--input", "synthetic.jsonl", "--read-format", "plan_tool"]), 2)
            intake.assert_not_called()
            key.assert_not_called()
        self.assertEqual(self.ledger.started, 0)


if __name__ == "__main__":
    unittest.main()
