"""Reject invalid numeric read inputs without executing or clamping them."""
import copy
import json
import unittest

from tests import test_t2_v2_staged_pipeline as fixture
from vulngym_t2 import staged_protocol


BAD = ("read_file", {**fixture.READ[1], "start_line": 0})


class ReadCoordinateFeedbackTests(unittest.TestCase):
    setUp = fixture.StagedPipelineTests.setUp
    run_script = fixture.StagedPipelineTests.run_script

    def test_batch_is_not_executed_and_next_valid_plan_uses_original_budget(self):
        def corrected(payload):
            feedback = next(json.loads(row["content"])["read_request_rejected"]
                            for row in payload["messages"] if row["content"].startswith("{")
                            and "read_request_rejected" in json.loads(row["content"]))
            self.assertEqual(feedback["requested_calls"], 2)
            self.assertEqual(feedback["errors"][0]["code"], "numeric_range")
            self.assertEqual(feedback["errors"][0]["minimum"], 1)
            return fixture.READ
        result, final, client, repo, _ = self.run_script(
            [[BAD, fixture.CALLER], corrected, fixture.FINISH, fixture.full_annotation,
             fixture.FINISH, fixture.full_annotation], max_calls=6)
        self.assertIsNone(client.halted)
        self.assertIsNotNone(final["entry"])
        self.assertEqual(result["model_calls"], 6)
        self.assertEqual([arguments["path"] for tool, arguments in repo.calls if tool == "read_file"],
                         [fixture.READ[1]["path"]])
        self.assertEqual(sum(row["action"] == "read_request_rejected" for row in final["review"]["actions"]), 1)
        self.assertEqual(client.events[0]["diagnostics"]["read_request_rejections"][0]["minimum"], 1)

    def test_unknown_sibling_tool_is_still_a_hard_failure(self):
        bad = {"tool": BAD[0], "arguments": copy.deepcopy(BAD[1])}
        with self.assertRaises(staged_protocol.ProtocolError):
            staged_protocol.normalize_calls([bad, {"tool": "unavailable_tool", "arguments": {}}], "read")

    def test_missing_read_argument_rejects_whole_batch_then_accepts_a_valid_next_plan(self):
        bad = ("read_diff", {"before": "a" * 40, "after": "b" * 40})
        def corrected(payload):
            feedback = next(json.loads(row["content"])["read_request_rejected"]
                            for row in payload["messages"] if row["content"].startswith("{")
                            and "read_request_rejected" in json.loads(row["content"]))
            error = feedback["errors"][0]
            self.assertEqual(error["code"], "missing_property")
            self.assertEqual(error["path"], "$[0].arguments.path")
            self.assertIn("path", error["required_keys"])
            self.assertEqual(error["property_schema"], {"type": "string"})
            return fixture.READ
        result, final, client, repo, _ = self.run_script(
            [[bad, fixture.CALLER], corrected, fixture.FINISH, fixture.full_annotation,
             fixture.FINISH, fixture.full_annotation], max_calls=6)
        self.assertIsNone(client.halted)
        self.assertIsNotNone(final["entry"])
        self.assertEqual([tool for tool, _ in repo.calls], ["read_file"])
        self.assertEqual(result["model_calls"], 6)

    def test_missing_read_file_path_is_feedback_without_filling_input_or_raising_key_error(self):
        calls = [{"tool": "read_file", "arguments": {"commit": "a" * 40, "start_line": 1, "end_line": 2}}]
        original = copy.deepcopy(calls)
        self.assertEqual(staged_protocol.normalize_calls(calls, "read")["action"], "read_request_rejected")
        self.assertEqual(calls, original)
        for stage in ("read", "followup"):
            with self.assertRaises(staged_protocol.ProtocolError):
                staged_protocol.normalize_calls([{"tool": "finish_reading", "arguments": {}}], stage)

    def test_repeated_bad_coordinates_do_not_expand_call_budget_or_make_source(self):
        unknown = fixture.annotation()
        result, final, client, repo, _ = self.run_script([BAD, BAD, unknown, unknown], max_calls=4)
        self.assertIsNone(client.halted)
        self.assertIsNone(final["entry"])
        self.assertEqual(result["model_calls"], 4)
        self.assertEqual(result["tool_calls"], 0)
        self.assertEqual(repo.calls, [])

    def test_conflicting_finish_rejects_every_read_and_next_plan_keeps_original_budget(self):
        for batch in ([fixture.READ, fixture.FINISH], [fixture.FINISH, fixture.READ]):
            with self.subTest(batch=batch):
                def corrected(payload):
                    feedback = next(json.loads(row["content"])["read_request_rejected"]
                                    for row in payload["messages"] if row["content"].startswith("{")
                                    and "read_request_rejected" in json.loads(row["content"]))
                    self.assertEqual(feedback["errors"][0]["code"], "finish_must_be_alone")
                    self.assertEqual(feedback["requested_calls"], 2)
                    return fixture.READ
                result, final, client, repo, _ = self.run_script(
                    [batch, corrected, fixture.FINISH, fixture.full_annotation,
                     fixture.FINISH, fixture.full_annotation], max_calls=6)
                self.assertIsNone(client.halted)
                self.assertIsNotNone(final["entry"])
                self.assertEqual(result["model_calls"], 6)
                self.assertEqual([tool for tool, _ in repo.calls], ["read_file"])
                self.assertEqual(client.events[0]["diagnostics"]["read_request_rejections"][0]["code"],
                                 "finish_must_be_alone")

    def test_repeated_finish_conflict_never_closes_reading_executes_tools_or_adds_budget(self):
        conflict = [fixture.READ, fixture.FINISH]
        result, final, client, repo, _ = self.run_script(
            [conflict, conflict, fixture.annotation(), fixture.annotation()], max_calls=4)
        self.assertIsNone(client.halted)
        self.assertIsNone(final["entry"])
        self.assertEqual(result["model_calls"], 4)
        self.assertEqual(repo.calls, [])
        self.assertNotIn("finish_reading", [row["action"] for row in result["actions"]])

    def test_finish_conflict_does_not_hide_unknown_siblings_or_invalid_control_arguments(self):
        finish = {"tool": fixture.FINISH[0], "arguments": copy.deepcopy(fixture.FINISH[1])}
        read = {"tool": fixture.READ[0], "arguments": copy.deepcopy(fixture.READ[1])}
        for batch in ([finish, read, {"tool": "unavailable_tool", "arguments": {}}],
                      [read, {"tool": finish["tool"], "arguments": {"reason": "free form"}}]):
            with self.subTest(batch=batch), self.assertRaises(staged_protocol.ProtocolError):
                staged_protocol.normalize_calls(batch, "read")
        original = copy.deepcopy([finish, read])
        self.assertEqual(staged_protocol.normalize_calls(original, "read")["action"], "read_request_rejected")
        self.assertEqual(original, [finish, read])
        with self.assertRaises(staged_protocol.ProtocolError):
            staged_protocol.normalize_calls(original, "followup")


if __name__ == "__main__":
    unittest.main()
