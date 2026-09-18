"""One whole-plan encoding correction, without executing rejected arguments."""
import copy
import json
from pathlib import Path
import tempfile
import unittest

from vulngym_t2 import annotation_rules, read_plan_protocol as plan, transport
from vulngym_t2.llm import DeepSeekClient, RequestLedger
from vulngym_t2.output import _saved_actions, finalize_result
from vulngym_t2.pipeline import _ProductionSession, produce
from tests import test_t2_v2_staged_pipeline as fixture
from tests.test_t2_v2_assessed_tool import envelope, NOTE
from tests.test_t2_v2_pipeline import job
from tests.test_t2_v2_read_plan import response


BAD = '{"calls":[{"tool":"synthetic-discarded",arguments:{}}]}'


def encoded(arguments=BAD):
    raw = json.loads(response([fixture.READ]))
    raw["choices"][0]["message"]["tool_calls"][0]["function"]["arguments"] = arguments
    return json.dumps(raw).encode()


def parse(raw, stage="read"):
    return transport.parse_chat_response(raw, response_mode="staged_tool", stage=stage, read_format="plan_tool")


class ReadPlanEncodingProtocolTests(unittest.TestCase):
    def test_root_shape_rejection_exposes_only_bounded_counts(self):
        for value in ({}, {"fields": {"private_operation": "private-payload"}}, {"calls": [], "execute": True},
                      {"calls": [{"tool": "read_file", "arguments": fixture.READ[1]}], "private_extra": "private-payload"}):
            original = copy.deepcopy(value)
            detail = parse(encoded(json.dumps(value)))
            self.assertEqual(detail["code"], "invalid_plan_shape")
            self.assertEqual(detail["missing_calls"], "calls" not in value)
            self.assertEqual(detail["extra_key_count"], len(set(value) - {"calls"}))
            self.assertEqual(_saved_actions([{**detail, "raw": "private-payload"}]), [detail])
            self.assertNotIn("private", json.dumps(detail))
            self.assertEqual(value, original)
            self.assertEqual(plan.public_rejection({**detail, "extra_key_count": True}), {})
            self.assertEqual(plan.public_rejection({**detail, "missing_calls": 1}), {})

    def test_only_bounded_syntax_is_rejected_and_no_plan_values_escape(self):
        for bad in (BAD, '{"calls":', '{"calls":[]', '{"calls":[{"arguments":{} "tool":"read_file"}]}'):
            for stage in ("read", "followup"):
                with self.subTest(length=len(bad), stage=stage):
                    detail = parse(encoded(bad), stage)
                    self.assertEqual(detail, {"action": "read_plan_rejected", "code": "invalid_plan_json",
                        "path": "$[0].arguments", "answer_characters": len(bad)})
                    self.assertEqual(_saved_actions([{**detail, "raw": bad}]), [detail])
                    self.assertNotIn("synthetic-discarded", json.dumps(detail))
                    with self.assertRaises(transport._CompletionJSONBlocked):
                        transport._parse_completion_json(bad, unwrap_fence=False)

    def test_invalid_envelopes_other_wires_and_refusals_remain_hard_stops(self):
        for change in ("function", "multiple", "refusal", "length", "model", "envelope", "id", "filter"):
            raw = json.loads(encoded())
            choice, message = raw["choices"][0], raw["choices"][0]["message"]
            if change == "function":
                message["tool_calls"][0]["function"]["name"] = "read_file"
            elif change == "multiple":
                message["tool_calls"].append(copy.deepcopy(message["tool_calls"][0]))
            elif change == "refusal":
                message["refusal"] = "synthetic refusal"
            elif change in ("length", "filter"):
                choice["finish_reason"] = "length" if change == "length" else "content_filter"
            elif change == "model":
                raw["model"] = "different-model"
            elif change == "id":
                message["tool_calls"][0]["id"] = ""
            else:
                raw["choices"] = []
            with self.subTest(change=change), self.assertRaises(transport.TransportError):
                parse(json.dumps(raw).encode())
        with self.assertRaises(transport.TransportError):
            transport.parse_chat_response(encoded(), response_mode="staged_tool", stage="read")
        with self.assertRaises(ValueError):
            parse(encoded(), "annotation")

    def test_resources_duplicate_keys_unknown_operations_and_inner_schema_are_not_reencoded(self):
        for bad in ('{"calls":' + '[' * 17, '{"calls":"' + 'x' * 262_144,
                    '{"calls":[' + '1,' * 10_000, '{"calls":NaN}', '{"calls":[],"calls":[]}',
                    '{"calls":[{"tool":"unknown_operation","arguments":{}}]}',
                    '{"calls":[]}', '[]', '```json\n{}\n```'):
            with self.subTest(prefix=bad[:40]), self.assertRaises(transport.TransportError):
                parse(encoded(bad))

    def test_public_metadata_never_retains_raw_content_or_unbounded_counts(self):
        detail = parse(encoded())
        self.assertEqual(plan.public_rejection({**detail, "raw": BAD}), detail)
        for change in ({"answer_characters": True}, {"answer_characters": 0},
                       {"answer_characters": 262_145}, {"code": "arbitrary"}, {"path": "raw/path"}):
            self.assertEqual(plan.public_rejection({**detail, **change}), {})
        saved = _saved_actions([{**detail, "stage": "read_plan_encoding_review", "raw": BAD},
                                {"action": "read_plan_reencoding", "summary": "recovered", "stage": "plan_and_read", "raw": BAD}])
        self.assertNotIn("synthetic-discarded", json.dumps(saved))
        self.assertEqual(saved[0]["stage"], "read_plan_encoding_review")


class ReadPlanEncodingIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="t2-plan-encoding-")
        self.addCleanup(self.temp.cleanup)
        self.ledger = RequestLedger(Path(self.temp.name).resolve() / "requests.jsonl", limit=64)
        self.addCleanup(self.ledger.close)

    def client(self, send, max_requests=12):
        client = DeepSeekClient("synthetic-not-a-key", self.ledger, run_id="synthetic",
            max_requests=max_requests, response_mode="staged_tool", thinking="enabled",
            annotation_format="assessed_tool", read_format="plan_tool", send=send)
        self.addCleanup(client.close)
        return client

    def test_correction_uses_original_context_and_never_applies_failed_operations_or_fields(self):
        payloads = []
        def send(body, *_):
            payloads.append(json.loads(body))
            return encoded() if len(payloads) == 1 else response([fixture.READ])
        client, repo = self.client(send), fixture.MemoryRepo()
        session = _ProductionSession(job(False), client, repo, 8, 24)
        session.prepare()
        before = copy.deepcopy({key: session.result[key] for key in ("fields", "field_reviews", "evidence")})
        reply = session.complete("plan_and_read")
        self.assertEqual(reply["action"], "tools")
        self.assertEqual((client.calls, session.result["model_calls"], self.ledger.started), (2, 2, 2))
        self.assertEqual(repo.calls, [])
        self.assertEqual({key: session.result[key] for key in before}, before)
        self.assertEqual(payloads[1]["messages"][:-2], payloads[0]["messages"][:-1])
        self.assertIn("read_plan_encoding_correction", payloads[1]["messages"][-2]["content"])
        self.assertNotIn("synthetic-discarded", json.dumps(payloads))
        self.assertNotIn("synthetic-discarded", self.ledger.path.read_text())
        self.assertEqual(client.summary()["read_plan_rejection_count"], 1)
        self.assertEqual(client.summary()["automatic_retries"], 0)
        self.assertEqual(client.summary()["max_read_plan_encoding_reviews_per_input"], 1)
        self.assertIsNone(client.halted)

    def test_root_correction_is_one_new_plan_without_executing_wrong_container(self):
        payloads = []
        bad = json.dumps({"calls": [{"tool": "read_file", "arguments": fixture.READ[1]}],
                          "private_extra": "private-payload"})

        def send(body, *_):
            payloads.append(json.loads(body))
            return encoded(bad) if len(payloads) == 1 else response([fixture.READ])

        repo, client = fixture.MemoryRepo(), self.client(send)
        session = _ProductionSession(job(False), client, repo, 8, 24)
        session.prepare()
        result = session.complete("plan_and_read")
        self.assertEqual(result["action"], "tools")
        self.assertEqual(repo.calls, [])
        self.assertEqual(len(payloads), 2)
        self.assertEqual(session.read_plan_encoding_reviews, 1)
        self.assertTrue(all(row["temperature"] == 0 for row in payloads))
        self.assertEqual(client.summary()["stage_settings"]["read"]["temperature"], 0)
        self.assertNotIn("private-payload", json.dumps(payloads))
        self.assertNotIn("private_extra", json.dumps(payloads))

    def test_repeated_root_rejection_stops_without_running_valid_sibling(self):
        calls = []
        bad = json.dumps({"calls": [{"tool": "read_file", "arguments": fixture.READ[1]}], "fields": {}})
        client = self.client(lambda *_: calls.append(True) or encoded(bad))
        repo = fixture.MemoryRepo()
        session = _ProductionSession(job(False), client, repo, 8, 24)
        session.prepare()
        self.assertIsNone(session.complete("plan_and_read"))
        self.assertEqual((len(calls), repo.calls), (2, []))
        self.assertEqual(session.result["actions"][-1]["summary"], "failed")
        self.assertEqual(client.summary()["automatic_retries"], 0)

    def test_correction_allowance_is_shared_across_read_and_followup(self):
        calls = []
        client = self.client(lambda *_: calls.append(True) or (response([fixture.FINISH]) if len(calls) == 2 else encoded()))
        session = _ProductionSession(job(False), client, fixture.MemoryRepo(), 12, 24)
        session.prepare()
        self.assertEqual(session.complete("plan_and_read")["action"], "finish_reading")
        self.assertIsNone(session.complete("evidence_followup"))
        self.assertEqual(len(calls), 3)
        self.assertEqual(session.read_plan_encoding_reviews, 1)
        self.assertEqual(session.result["actions"][-1]["summary"], "correction_limit")

    def test_repeated_syntax_transport_and_unknown_operation_stop_without_further_corrections(self):
        for kind in ("syntax", "transport", "operation"):
            calls = []
            def send(*_):
                calls.append(True)
                if len(calls) == 1 or kind == "syntax":
                    return encoded()
                if kind == "transport":
                    raise transport.TransportError("deepseek_network_unavailable")
                return response([( "unknown_operation", {})])
            with self.subTest(kind=kind):
                client, repo = self.client(send), fixture.MemoryRepo()
                result = produce(job(False), client, repo, max_calls=8)
                self.assertEqual((len(calls), result["tool_calls"]), (2, 0))
                self.assertEqual(repo.calls, [])
                self.assertIsNone(finalize_result(job(False), result, repo)["entry"])
                self.assertIn("failed", [a.get("summary") for a in result["actions"] if a["action"] == "read_plan_reencoding"])
                self.assertEqual(client.summary()["read_plan_rejection_count"], 2 if kind == "syntax" else 1)

    def test_model_http_review_and_later_candidate_reserves_are_preserved(self):
        for stage, max_calls, max_requests, reserved in (("plan_and_read", 5, 12, 0),
                ("plan_and_read", 8, 5, 0), ("plan_and_read", 8, 12, 3),
                ("evidence_followup", 3, 12, 0), ("evidence_followup", 8, 3, 0),
                ("evidence_followup", 8, 12, 5)):
            calls = []
            with self.subTest(stage=stage, calls=max_calls, http=max_requests, reserved=reserved):
                session = _ProductionSession(job(False), self.client(lambda *_: calls.append(True) or encoded(), max_requests),
                                             fixture.MemoryRepo(), max_calls, 24)
                session.prepare()
                self.assertIsNone(session.complete(stage, reserved_calls=reserved))
                self.assertEqual(len(calls), 1)
                self.assertEqual(session.read_plan_encoding_reviews, 0)
                self.assertEqual(session.result["actions"][-1]["summary"], "budget_unavailable")

    def test_feedback_and_actual_plan_instruction_share_the_context_limit(self):
        calls = []
        session = _ProductionSession(job(False), self.client(lambda *_: calls.append(True) or encoded()),
                                     fixture.MemoryRepo(), 8, 24)
        session.prepare()
        system = len(annotation_rules.TASK_RULES + "\n" + annotation_rules.for_phase("read"))
        session.messages = [{"role": "system", "content": "replaced"},
            {"role": "user", "content": "x" * (100_000 - system - len(plan.instruction("read")) - 5)}]
        self.assertIsNone(session.complete("plan_and_read"))
        self.assertEqual(len(calls), 1)
        self.assertEqual(session.result["actions"][-1]["summary"], "context_unavailable")

    def test_actual_controller_completes_with_one_correction_and_unchanged_source_review(self):
        payloads, plans = [], []
        def send(body, *_):
            payload = json.loads(body)
            payloads.append(payload)
            if "tools" not in payload:
                return envelope(content=NOTE)
            if payload["tools"][0]["function"]["name"] == plan.TOOL_NAME:
                plans.append(payload)
                return encoded() if len(plans) == 1 else response([
                    fixture.READ, fixture.CALLER] if len(plans) == 2 else [fixture.FINISH])
            return envelope(call=fixture.full_annotation(payload))
        client, repo, supplied = self.client(send), fixture.MemoryRepo(), job(False)
        result = produce(supplied, client, repo, max_calls=7)
        final = finalize_result(supplied, result, repo)
        self.assertIsNotNone(final["entry"], json.dumps(result["errors"]))
        self.assertEqual(final["entry"]["verify"], 0)
        self.assertEqual(result["self_review_status"], "completed")
        self.assertEqual((len(payloads), len(plans), result["model_calls"]), (7, 3, 7))
        self.assertEqual(sum("tools" not in p for p in payloads), 2)
        self.assertEqual(repo.calls, [fixture.READ, fixture.CALLER])
        self.assertEqual(client.summary()["read_plan_rejection_count"], 1)
        self.assertFalse(result["errors"])
        self.assertFalse(result["annotation_errors"])
        self.assertEqual(len([a for a in final["review"]["actions"] if a["action"] == "read_plan_rejected"]), 1)


if __name__ == "__main__":
    unittest.main()
