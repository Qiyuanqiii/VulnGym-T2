"""Offline native read batching: reject an invalid batch before any fixture read."""
import copy
import json
import unittest

from vulngym_t2 import annotation_rules, staged_protocol as staged, transport
from tests.test_t2_v2_protocol import tool_envelope
from tests import test_t2_v2_staged_pipeline as fixture


INSPECTS = [("inspect_commit", {"commit": "a" * 40}), ("inspect_commit", {"commit": "b" * 40})]


def parsed_calls(calls):
    return [{"tool": name, "arguments": arguments} for name, arguments in calls]


def native_envelope(calls):
    body = json.loads(tool_envelope())
    body["choices"][0]["message"]["tool_calls"] = [
        {"id": f"synthetic_{index}", "type": "function", "function": {
            "name": name, "arguments": json.dumps(arguments)}} for index, (name, arguments) in enumerate(calls)]
    return body


class ReadBatchProtocolTests(unittest.TestCase):
    def test_current_read_function_names_are_generated_from_the_same_stage_schema(self):
        for stage in ("read", "followup"):
            with self.subTest(stage=stage):
                text = staged.instruction(stage)
                names = json.loads(text.split("Current function names (JSON array): ", 1)[1])
                self.assertEqual(names, [row["function"]["name"] for row in staged.tool_definitions(stage)])
                self.assertEqual(len(names), len(set(names)))
                self.assertIn("finish_reading", names)
                self.assertNotIn("submit_annotation", names)
                self.assertIn("do not abbreviate, translate, prefix or invent an alias", text)

    def test_two_inspect_calls_normalize_together_and_keep_order(self):
        calls = parsed_calls(INSPECTS)
        original = copy.deepcopy(calls)
        expected = {"action": "tools", "plan": "", "calls": calls}
        self.assertEqual(staged.normalize_calls(calls, "read"), expected)
        self.assertEqual(transport.parse_chat_response(json.dumps(native_envelope(INSPECTS)).encode(),
            response_mode="staged_tool", stage="read"), expected)
        self.assertEqual(calls, original)
        self.assertEqual(len(staged.normalize_calls(parsed_calls(INSPECTS * 2), "read")["calls"]), 4)
        self.assertIn("one to four", staged.instruction("read"))
        self.assertIn("one to four", annotation_rules.for_phase("read"))
        self.assertIn("exactly one", staged.instruction("followup"))

    def test_resource_limits_and_other_stage_batches_remain_hard_failures(self):
        for calls in (INSPECTS * 2 + INSPECTS[:1],):
            with self.subTest(calls=len(calls)), self.assertRaises(staged.ProtocolError):
                staged.normalize_calls(parsed_calls(calls), "read")
            with self.assertRaises(transport.TransportError):
                transport.parse_chat_response(json.dumps(native_envelope(calls)).encode(), response_mode="staged_tool", stage="read")
        for calls in ([*INSPECTS, fixture.FINISH], [fixture.FINISH, *INSPECTS]):
            normalized = staged.normalize_calls(parsed_calls(calls), "read")
            self.assertEqual(normalized["action"], "read_request_rejected")
            self.assertEqual(normalized["errors"][0]["code"], "finish_must_be_alone")
            self.assertNotIn("calls", normalized)
            self.assertEqual(transport.parse_chat_response(json.dumps(native_envelope(calls)).encode(),
                response_mode="staged_tool", stage="read"), normalized)
        for stage in ("followup", "annotation", "candidate_selection"):
            with self.subTest(stage=stage), self.assertRaises(transport.TransportError):
                transport.parse_chat_response(json.dumps(native_envelope(INSPECTS)).encode(), response_mode="staged_tool", stage=stage)
        strict = json.loads(tool_envelope())
        strict["choices"][0]["message"]["tool_calls"] *= 2
        with self.assertRaisesRegex(transport.TransportError, "deepseek_strict_tool_call_invalid"):
            transport.parse_chat_response(json.dumps(strict).encode(), response_mode="strict_tool")

    def test_second_envelope_and_argument_shape_are_fully_checked(self):
        mutations = [lambda call: call.update(type="shell"),
                     lambda call: call.update(id=""),
                     lambda call: call.update(id=False),
                     lambda call: call["function"].update(name="not-a-read-tool"),
                     lambda call: call["function"].update(arguments={}),
                     lambda call: call["function"].update(arguments='{"commit":'),
                     lambda call: call["function"].update(arguments='{"commit":42}')]
        for mutate in mutations:
            body = native_envelope(INSPECTS)
            mutate(body["choices"][0]["message"]["tool_calls"][1])
            with self.subTest(mutation=mutations.index(mutate)), self.assertRaises(transport.TransportError):
                transport.parse_chat_response(json.dumps(body).encode(), response_mode="staged_tool", stage="read")
        body = native_envelope(INSPECTS)
        body["choices"][0]["message"]["tool_calls"][1]["function"]["arguments"] = '{}'
        rejected = transport.parse_chat_response(json.dumps(body).encode(), response_mode="staged_tool", stage="read")
        self.assertEqual(rejected["action"], "read_request_rejected")
        self.assertEqual(rejected["requested_calls"], 2)
        self.assertEqual(rejected["errors"][0]["path"], "$[1].arguments.commit")
        for second, path in ((('inspect_commit', {"commit": " "}), "$[1].arguments.commit"),
                             (('read_file', {"commit": "a" * 40, "path": "", "start_line": 1, "end_line": 2}), "$[1].arguments.path")):
            with self.subTest(path=path), self.assertRaises(staged.ProtocolError) as caught:
                staged.normalize_calls(parsed_calls([INSPECTS[0], second]), "read")
            self.assertEqual(caught.exception.diagnostic["protocol_reason"], "blank_argument")
            self.assertEqual(caught.exception.diagnostic["protocol_path"], path)


class ReadBatchPipelineTests(unittest.TestCase):
    setUp = fixture.StagedPipelineTests.setUp
    run_script = fixture.StagedPipelineTests.run_script

    def test_two_reads_cost_one_model_call_and_existing_tool_budget(self):
        reads = [fixture.READ, fixture.CALLER]
        result, finalized, _, repo, _ = self.run_script([reads, fixture.full_annotation, fixture.full_annotation], max_calls=3)
        self.assertEqual((result["model_calls"], result["tool_calls"]), (3, 2))
        self.assertEqual(repo.calls, reads)
        self.assertIsNotNone(finalized["entry"])
        result, finalized, _, repo, _ = self.run_script([reads, fixture.full_annotation, fixture.full_annotation], max_calls=3, max_tool_calls=1)
        self.assertEqual((result["model_calls"], result["tool_calls"]), (3, 1))
        self.assertEqual(repo.calls, reads[:1])
        self.assertIsNotNone(finalized["entry"])

    def test_bad_second_call_executes_none_of_the_batch(self):
        batches = [[INSPECTS[0], ("inspect_commit", {"commit": 42})],
                   [INSPECTS[0], ("inspect_commit", {"commit": " "})],
                   INSPECTS * 2 + INSPECTS[:1]]
        for batch in batches:
            with self.subTest(batch=len(batch)):
                result, _, client, repo, _ = self.run_script([batch], max_calls=3)
                self.assertEqual((result["model_calls"], result["tool_calls"]), (1, 0))
                self.assertEqual(repo.calls, [])
                self.assertTrue(client.halted)
                self.assertNotIn("commit", result["fields"])

    def test_known_read_plus_unknown_function_stops_without_any_execution_or_retry(self):
        result, _, client, repo, _ = self.run_script(
            [[fixture.READ, ("synthetic_unknown_function", {})]], max_calls=8)
        self.assertEqual((result["model_calls"], result["tool_calls"]), (1, 0))
        self.assertEqual(repo.calls, [])
        self.assertEqual(client.halted, "deepseek_strict_tool_call_invalid")
        self.assertEqual(client.summary()["automatic_retries"], 0)
        self.assertNotIn("commit", result["fields"])
        self.assertNotIn("synthetic_unknown_function", json.dumps(result))
        failure = next(row for row in result["actions"] if row["action"] == "model_failure")
        self.assertEqual(failure["diagnostics"]["tool_call_count"], 2)
        self.assertEqual(failure["diagnostics"]["unknown_tool_count"], 1)
        self.assertEqual(failure["diagnostics"]["tool_names"], ["read_file"])


if __name__ == "__main__":
    unittest.main()
