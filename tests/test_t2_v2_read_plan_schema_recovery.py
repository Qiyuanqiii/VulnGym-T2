"""Synthetic schema rejection/re-encoding; no provider or target calls.

The saved Airflow diagnostic does not identify a failed argument. Null and
finite-float examples below are reproductions of the validator failure class,
not reconstructions of the unavailable real response.
"""
import copy
import json
from pathlib import Path
import tempfile
import unittest

from vulngym_t2 import annotation_rules, protocol, read_plan_protocol as plan
from vulngym_t2 import staged_protocol, transport
from vulngym_t2.llm import DeepSeekClient, RequestLedger
from vulngym_t2.output import _saved_actions, finalize_result
from vulngym_t2.pipeline import _ProductionSession, produce
from tests import test_t2_v2_staged_pipeline as fixture
from tests.test_t2_v2_assessed_tool import envelope, NOTE
from tests.test_t2_v2_pipeline import job
from tests.test_t2_v2_read_plan import response
from tests.test_t2_v2_read_plan_encoding import encoded, parse


def typed_plan(**updates):
    return {"calls": [{"tool": "read_file", "arguments": {**fixture.READ[1], **updates}}]}


def bad_response():
    return encoded(json.dumps(typed_plan(path=None)))


class ReadPlanSchemaRejectionTests(unittest.TestCase):
    def test_null_and_float_reproduce_same_legacy_diagnostic_not_unique_real_value(self):
        for value in (typed_plan(path=None), typed_plan(end_line=2.0), {"calls": None}):
            with self.subTest(value=value):
                with self.assertRaises(protocol.ProtocolError) as caught:
                    protocol._bounded(value)
                error = staged_protocol._legacy_error(caught.exception)
                self.assertEqual(error.diagnostic, {"phase": "validate_staged_step",
                    "protocol_reason": "unsupported_value_type", "protocol_path": "$"})
        # A non-object JSON root fails earlier, not with validate_staged_step.
        with self.assertRaises(transport._CompletionJSONBlocked) as caught:
            parse(encoded("null"))
        self.assertEqual(caught.exception.diagnostic["phase"], "parse_completion_json")

    def test_exact_known_read_type_errors_reject_whole_plan_without_values(self):
        variants = [(typed_plan(path=None), "expected_string", "$[0].arguments.path"),
                    (typed_plan(end_line=2.0), "expected_integer", "$[0].arguments.end_line"),
                    (typed_plan(start_line=True), "expected_integer", "$[0].arguments.start_line"),
                    ({"calls": [{"tool": "read_file", "arguments": None}]},
                     "expected_object", "$[0].arguments"),
                    ({"calls": [{"tool": "search_code", "arguments": {
                        "commit": fixture.READ[1]["commit"], "query": "discarded-private-query", "paths": None}}]},
                     "expected_array", "$[0].arguments.paths"),
                    ({"calls": [{"tool": "search_code", "arguments": {
                        "commit": fixture.READ[1]["commit"], "query": "discarded-private-query", "paths": [None]}}]},
                     "expected_string", "$[0].arguments.paths[0]")]
        for value, reason, path in variants:
            before = copy.deepcopy(value)
            for stage in ("read", "followup"):
                with self.subTest(reason=reason, path=path, stage=stage):
                    rejected = parse(encoded(json.dumps(value)), stage)
                    self.assertEqual(rejected, {"action": "read_plan_rejected",
                        "code": "invalid_plan_argument_type", "path": "$[0].arguments",
                        "schema_reason": reason, "schema_path": path})
                    self.assertEqual(plan.public_rejection({**rejected, "raw": value}), rejected)
                    self.assertEqual(_saved_actions([{**rejected, "raw": value}]), [rejected])
                    self.assertNotIn("discarded-private", json.dumps(rejected))
                    self.assertEqual(value, before)

    def test_bad_typed_item_cannot_hide_unknown_control_or_invalid_sibling(self):
        bad = typed_plan(path=None)["calls"]
        other = [
            {"tool": "discarded-private-unknown", "arguments": {}},
            {"tool": "finish_reading", "arguments": {"reason": "enough_evidence"}},
            {"tool": "finish_reading", "arguments": {"reason": None}},
            {"tool": "read_file", "arguments": {"commit": fixture.READ[1]["commit"]}},
            {"tool": "read_file", "arguments": {**fixture.READ[1], "start_line": 0}},
            {"tool": "read_file", "arguments": {**fixture.READ[1], "path": " "}},
            {"tool": "read_file", "arguments": {**fixture.READ[1], "commit": " "}},
            {"tool": "read_file", "arguments": {**fixture.READ[1], "start_line": 3, "end_line": 2}},
            {"tool": "read_file", "arguments": {**fixture.READ[1], "extra": "discarded-private"}},
            {"tool": ["read_file"], "arguments": {}},
        ]
        for sibling in other:
            for calls in ([*bad, sibling], [sibling, *bad]):
                with self.subTest(sibling=sibling), self.assertRaises(transport.TransportError):
                    parse(encoded(json.dumps({"calls": calls})))
        # Detect a second, non-type error inside the same known operation too.
        for value in (typed_plan(path=None, commit=" "), typed_plan(path=None, start_line=0),
                      typed_plan(path=None, start_line=3, end_line=2)):
            with self.assertRaises(transport.TransportError):
                parse(encoded(json.dumps(value)))

    def test_resources_unknown_types_and_unclassified_containers_remain_hard_stops(self):
        for value in ({"calls": None}, {"calls": []}, {"calls": "discarded-private"},
                      {"calls": typed_plan(path=None)["calls"] * 5},
                      typed_plan(path=None, commit="x" * 32_001),
                      typed_plan(path=None, end_line=[0] * 65),
                      {"calls": typed_plan(path=None)["calls"], "other": None}):
            with self.subTest(value=str(value)[:60]), self.assertRaises(transport.TransportError):
                parse(encoded(json.dumps(value)))
        for value in (typed_plan(path=object()), typed_plan(path=b"bytes"), typed_plan(path=float("nan"))):
            with self.assertRaises(staged_protocol.ProtocolError):
                plan.normalize(value, "read")
        with self.assertRaises(transport.TransportError):
            parse(encoded('{"calls":[],"calls":null}'))

    def test_new_rejection_metadata_has_fixed_schema_only_paths(self):
        detail = parse(bad_response())
        for extra in ({"schema_reason": "unsupported_value_type"}, {"schema_reason": []},
                      {"schema_path": "$[4].arguments.path"}, {"schema_path": "$[0].arguments.private"},
                      {"schema_path": "$[0].arguments.paths[999]"}, {"schema_path": None}):
            self.assertEqual(plan.public_rejection({**detail, **extra}), {})

    def test_schema_failures_do_not_bypass_refusal_or_native_envelope_checks(self):
        for change in ("refusal", "unknown_tool", "argument_type", "content_type", "model", "multiple"):
            raw = json.loads(bad_response())
            message = raw["choices"][0]["message"]
            function = message["tool_calls"][0]["function"]
            if change == "refusal":
                message["refusal"] = "synthetic refusal"
            elif change == "unknown_tool":
                function["name"] = "unsupported_private_function"
            elif change == "argument_type":
                function["arguments"] = typed_plan(path=None)
            elif change == "content_type":
                message["content"] = []
            elif change == "model":
                raw["model"] = "different-model"
            else:
                message["tool_calls"].append(copy.deepcopy(message["tool_calls"][0]))
            with self.subTest(change=change), self.assertRaises(transport.TransportError):
                parse(json.dumps(raw).encode())

    def test_valid_sibling_is_not_executed_and_original_validator_is_unchanged(self):
        value = {"calls": [{"tool": "read_file", "arguments": fixture.READ[1]},
                           *typed_plan(path=None)["calls"]]}
        self.assertEqual(parse(encoded(json.dumps(value)))["schema_path"], "$[1].arguments.path")
        self.assertEqual(plan.normalize(typed_plan(), "read"),
                         staged_protocol.normalize_calls(typed_plan()["calls"], "read"))
        # The original native wire continues hard-stopping on the same defect.
        raw = json.loads(bad_response())
        call = raw["choices"][0]["message"]["tool_calls"][0]["function"]
        call.update(name="read_file", arguments=json.dumps({**fixture.READ[1], "path": None}))
        with self.assertRaises(transport.TransportError):
            transport.parse_chat_response(json.dumps(raw).encode(), response_mode="staged_tool", stage="read")


class ReadPlanSchemaRecoveryIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="t2-plan-schema-")
        self.addCleanup(self.temp.cleanup)
        self.ledger = RequestLedger(Path(self.temp.name) / "requests.jsonl", limit=96)
        self.addCleanup(self.ledger.close)

    def client(self, send, max_requests=12):
        client = DeepSeekClient("synthetic-not-a-key", self.ledger, run_id="synthetic",
            max_requests=max_requests, response_mode="staged_tool", thinking="enabled",
            annotation_format="assessed_tool", read_format="plan_tool", send=send)
        self.addCleanup(client.close)
        return client

    def test_full_controller_preserves_assessment_self_review_and_actual_read_budget(self):
        payloads, plans = [], []
        def send(body, *_):
            payload = json.loads(body)
            payloads.append(payload)
            if "tools" not in payload:
                return envelope(content=NOTE)
            if payload["tools"][0]["function"]["name"] == plan.TOOL_NAME:
                plans.append(payload)
                return bad_response() if len(plans) == 1 else response([
                    fixture.READ, fixture.CALLER] if len(plans) == 2 else [fixture.FINISH])
            return envelope(call=fixture.full_annotation(payload))
        client, repo, supplied = self.client(send), fixture.MemoryRepo(), job(False)
        result = produce(supplied, client, repo, max_calls=7, max_tool_calls=2)
        final = finalize_result(supplied, result, repo)
        self.assertIsNotNone(final["entry"], result["errors"])
        self.assertEqual(result["self_review_status"], "completed")
        # Exhausting the unchanged two-read allowance skips a needless finish
        # request; the correction still consumes one actual ledger reservation.
        self.assertEqual((client.calls, self.ledger.started, result["model_calls"]), (6, 6, 6))
        self.assertEqual(len(plans), 2)
        self.assertEqual((result["tool_calls"], repo.calls), (2, [fixture.READ, fixture.CALLER]))
        self.assertEqual(client.summary()["read_plan_rejection_count"], 1)
        self.assertEqual(client.summary()["automatic_retries"], 0)
        self.assertEqual(len([p for p in payloads if "tools" not in p]), 2)
        self.assertEqual(final["entry"]["verify"], 0)

    def test_one_correction_shares_read_followup_and_does_not_execute_bad_plan(self):
        payloads = []
        def send(body, *_):
            payloads.append(json.loads(body))
            return response([fixture.READ]) if len(payloads) == 2 else bad_response()
        client, repo = self.client(send), fixture.MemoryRepo()
        session = _ProductionSession(job(False), client, repo, 12, 24)
        session.prepare()
        self.assertEqual(session.complete("plan_and_read")["action"], "tools")
        self.assertEqual(repo.calls, [])
        self.assertEqual(payloads[1]["messages"][:-2], payloads[0]["messages"][:-1])
        self.assertIn("invalid_plan_argument_type", payloads[1]["messages"][-2]["content"])
        self.assertIsNone(session.complete("evidence_followup"))
        self.assertEqual((len(payloads), session.read_plan_encoding_reviews), (3, 1))
        self.assertEqual(session.result["actions"][-1]["summary"], "correction_limit")
        self.assertEqual(client.summary()["automatic_retries"], 0)

    def test_schema_and_syntax_share_the_same_single_allowance(self):
        calls = []
        client = self.client(lambda *_: calls.append(True) or (bad_response() if len(calls) == 1 else encoded()))
        repo = fixture.MemoryRepo()
        result = produce(job(False), client, repo, max_calls=8)
        self.assertEqual((len(calls), repo.calls, result["tool_calls"]), (2, [], 0))
        self.assertIn("failed", [a.get("summary") for a in result["actions"] if a["action"] == "read_plan_reencoding"])
        self.assertEqual(client.summary()["read_plan_rejection_count"], 2)
        self.assertEqual(client.summary()["automatic_retries"], 0)

    def test_permission_and_transport_failure_during_correction_stop_without_retries(self):
        for code in ("deepseek_access_denied", "deepseek_authentication_failed", "deepseek_network_unavailable"):
            sent = []
            def send(*_):
                sent.append(True)
                if len(sent) == 1:
                    return bad_response()
                raise transport.TransportError(code)
            with self.subTest(code=code):
                repo, client = fixture.MemoryRepo(), self.client(send)
                result = produce(job(False), client, repo, max_calls=8)
                self.assertEqual((len(sent), result["tool_calls"], repo.calls), (2, 0, []))
                self.assertEqual(client.halted, code)
                self.assertEqual(client.summary()["automatic_retries"], 0)

    def test_model_http_review_and_later_candidate_reserves_are_unchanged(self):
        for stage, max_calls, max_requests, reserved in (("plan_and_read", 5, 12, 0),
                ("plan_and_read", 8, 5, 0), ("plan_and_read", 8, 12, 3),
                ("evidence_followup", 3, 12, 0), ("evidence_followup", 8, 3, 0),
                ("evidence_followup", 8, 12, 5)):
            calls = []
            with self.subTest(stage=stage, calls=max_calls, http=max_requests, reserved=reserved):
                client = self.client(lambda *_: calls.append(True) or bad_response(), max_requests)
                session = _ProductionSession(job(False), client, fixture.MemoryRepo(), max_calls, 24)
                session.prepare()
                self.assertIsNone(session.complete(stage, reserved_calls=reserved))
                self.assertEqual((len(calls), session.read_plan_encoding_reviews), (1, 0))
                self.assertEqual(session.result["actions"][-1]["summary"], "budget_unavailable")

    def test_context_limit_and_rejected_argument_redaction_are_preserved(self):
        calls = []
        session = _ProductionSession(job(False), self.client(lambda *_: calls.append(True) or bad_response()),
                                     fixture.MemoryRepo(), 8, 24)
        session.prepare()
        system = len(annotation_rules.TASK_RULES + "\n" + annotation_rules.for_phase("read"))
        session.messages = [{"role": "system", "content": "replaced"},
            {"role": "user", "content": "x" * (100_000 - system - len(plan.instruction("read")) - 5)}]
        self.assertIsNone(session.complete("plan_and_read"))
        self.assertEqual(len(calls), 1)
        self.assertEqual(session.result["actions"][-1]["summary"], "context_unavailable")
        self.assertNotIn('"path": null', self.ledger.path.read_text())


if __name__ == "__main__":
    unittest.main()
