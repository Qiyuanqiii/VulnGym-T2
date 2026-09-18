"""Reject incomplete encodings wholesale; budget one new encoding, not a read."""
import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from vulngym_t2 import read_plan_protocol, staged_protocol as staged, transport
from vulngym_t2.llm import DeepSeekClient, RequestLedger
from vulngym_t2.output import _saved_actions, finalize_result
from vulngym_t2.pipeline import _ProductionSession, produce
from tests import test_t2_v2_staged_pipeline as fixture
from tests.test_t2_v2_assessed_tool import envelope, NOTE
from tests.test_t2_v2_pipeline import job
from tests.test_t2_v2_read_plan import response as plan_response


def encoded_response(arguments):
    raw = json.loads(envelope(call=fixture.annotation()))
    raw["choices"][0]["message"]["tool_calls"][0]["function"]["arguments"] = arguments
    return json.dumps(raw).encode()


def parse(raw):
    return transport.parse_chat_response(raw, response_mode="staged_tool", stage="annotation",
                                         location_key="source_id")


class IncompleteEncodingProtocolTests(unittest.TestCase):
    def test_missing_roots_reject_even_valid_siblings_without_inventing_fields(self):
        full = staged.source_id_snapshot(fixture.annotation()[1])
        for partial in ({}, {"commit": full["commit"]}, {k: v for k, v in full.items() if k != "trace"}):
            with self.subTest(keys=list(partial)):
                before = copy.deepcopy(partial)
                rejected = parse(encoded_response(json.dumps(partial)))
                self.assertEqual(rejected, {"action": "annotation_snapshot_rejected",
                    "code": "missing_root_fields", "path": "$[0].arguments",
                    "missing_fields": sorted(set(staged.ANNOTATION_FIELDS) - set(partial))})
                self.assertEqual(partial, before)
                self.assertNotIn("fields", rejected)
                self.assertEqual(staged.public_snapshot_rejection(rejected), rejected)
        # The previous native/evidence_ref wire retains its field-level policy.
        previous = staged.normalize_calls([{"tool": "submit_annotation", "arguments": {}}], "annotation")
        self.assertEqual(previous["action"], "draft")
        self.assertEqual(len(previous["annotation_errors"]), 8)

    def test_json_syntax_is_rejected_not_locally_repaired_or_returned(self):
        full = json.dumps(staged.source_id_snapshot(fixture.annotation()[1]))
        for bad in (full[:-1], '{"commit":', '{"commit":"synthetic-discarded',
                    '{"commit":{} "trace":[]}'):
            with self.subTest(syntax=bad[:20]):
                rejected = parse(encoded_response(bad))
                self.assertEqual(rejected, {"action": "annotation_snapshot_rejected",
                    "code": "invalid_annotation_json", "path": "$[0].arguments",
                    "answer_characters": len(bad)})
                self.assertEqual(_saved_actions([{**rejected, "raw": bad}]), [rejected])
                self.assertNotIn("synthetic-discarded", json.dumps(rejected))
                with self.assertRaises(transport._CompletionJSONBlocked):
                    transport._parse_completion_json(bad, unwrap_fence=False)

    def test_other_stages_modes_envelope_errors_and_refusals_still_stop(self):
        raw = encoded_response('{"commit":')
        for mode, stage, key in (("staged_tool", "annotation", "evidence_ref"),
                                 ("staged_tool", "read", "evidence_ref"),
                                 ("staged_tool", "followup", "evidence_ref"),
                                 ("strict_tool", None, "evidence_ref")):
            with self.subTest(mode=mode, stage=stage), self.assertRaises(transport.TransportError):
                transport.parse_chat_response(raw, response_mode=mode, stage=stage, location_key=key)
        for mutation in ("refusal", "finish", "unknown", "multiple", "model", "envelope"):
            value = json.loads(raw)
            choice = value["choices"][0]
            message = choice["message"]
            if mutation == "refusal":
                message["refusal"] = "synthetic refusal"
            elif mutation == "finish":
                choice["finish_reason"] = "length"
            elif mutation == "unknown":
                message["tool_calls"][0]["function"]["name"] = "synthetic_unknown"
            elif mutation == "multiple":
                message["tool_calls"].append(copy.deepcopy(message["tool_calls"][0]))
            elif mutation == "model":
                value["model"] = "different-model"
            else:
                value["choices"] = []
            with self.subTest(mutation=mutation), self.assertRaises(transport.TransportError):
                parse(json.dumps(value).encode())

    def test_resource_excess_nonfinite_and_unhandled_duplicate_values_still_stop(self):
        for bad in ('{"x":' + '[' * 17, '{"x":' + '"' + 'x' * 262_144,
                    '{"x":[' + '1,' * 10_000, '{"commit":NaN}',
                    '{"commit":{},"commit":{}}', '{"commit":{},"trace": ]}', '[]', '```json\n{}\n```'):
            with self.subTest(prefix=bad[:30]), self.assertRaises(transport.TransportError):
                parse(encoded_response(bad))
        for value in ({"calls": []}, {"fields": {}}, {"summary": "synthetic-discarded"}):
            with self.subTest(keys=list(value)):
                rejected = parse(encoded_response(json.dumps(value)))
                self.assertEqual(rejected["action"], "annotation_snapshot_rejected")
                self.assertEqual(rejected["missing_fields"], sorted(staged.ANNOTATION_FIELDS))
                self.assertNotIn("synthetic-discarded", json.dumps(rejected))
                self.assertNotIn("calls", rejected)
                self.assertNotIn("fields", rejected)

    def test_rejection_metadata_only_keeps_fixed_fields_and_bounded_counts(self):
        syntax = parse(encoded_response('{"commit":'))
        missing = parse(encoded_response('{}'))
        for changes in ({"answer_characters": True}, {"answer_characters": 0},
                        {"answer_characters": 262_145}, {"code": "unrecognized"}):
            self.assertEqual(staged.public_snapshot_rejection({**syntax, **changes}), {})
        for fields in ([], ["private"], ["commit", "commit"], [True]):
            self.assertEqual(staged.public_snapshot_rejection({**missing, "missing_fields": fields}), {})
        self.assertEqual(staged.public_snapshot_rejection({**syntax, "raw": "synthetic-discarded"}), syntax)


class IncompleteEncodingIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="t2-incomplete-encoding-")
        self.addCleanup(self.temp.cleanup)
        self.ledger = RequestLedger(Path(self.temp.name).resolve() / "requests.jsonl", limit=64)
        self.addCleanup(self.ledger.close)

    def client(self, send, max_requests=12):
        client = DeepSeekClient("synthetic-not-a-key", self.ledger, run_id="synthetic",
            max_requests=max_requests, response_mode="staged_tool", thinking="enabled",
            annotation_format="assessed_tool", read_format="plan_tool", send=send)
        self.addCleanup(client.close)
        return client

    def scripted(self, kind, *, repeat=False):
        payloads = []
        def send(body, *_):
            payload = json.loads(body)
            payloads.append(payload)
            if "tools" not in payload:
                return envelope(content=NOTE)
            if repeat or len(payloads) == 2:
                return encoded_response('{"commit":"synthetic-discarded' if kind == "syntax" else
                                        '{"fields":{"commit":"synthetic-discarded"},"calls":[{"tool":"read_file","arguments":{}}]}' if kind == "root" else
                                        '{"commit":{"reason":"synthetic-discarded"}}')
            return envelope(call=fixture.annotation())
        return payloads, send

    def test_one_new_encoding_uses_same_assessment_no_failed_values_and_no_state_mutation(self):
        for kind in ("syntax", "missing", "root"):
            with self.subTest(kind=kind):
                payloads, send = self.scripted(kind)
                client = self.client(send)
                session = _ProductionSession(job(False), client, fixture.MemoryRepo(), 8, 24)
                session.prepare()
                before = copy.deepcopy((session.result["fields"], session.result["field_reviews"], session.result["evidence"]))
                self.assertEqual(session.complete("self_review")["action"], "draft")
                self.assertEqual(len(payloads), 3)
                self.assertEqual(sum("tools" not in p for p in payloads), 1)
                self.assertEqual(payloads[2]["messages"][:-2], payloads[1]["messages"][:-1])
                self.assertNotIn("synthetic-discarded", json.dumps(payloads[2]))
                self.assertNotIn("synthetic-discarded", self.ledger.path.read_text())
                self.assertEqual((session.result["fields"], session.result["field_reviews"], session.result["evidence"]), before)
                self.assertEqual(client.summary()["automatic_retries"], 0)
                self.assertEqual(client.summary()["encoding_rejection_count"], 1)
                self.assertEqual(client.summary()["encoding_json_rejection_count"], int(kind == "syntax"))
                self.assertEqual(client.summary()["encoding_missing_root_rejection_count"], int(kind == "missing"))
                self.assertIsNone(client.halted)
                self.assertIn("annotation_snapshot_rejection", client.events[1]["diagnostics"])

    def test_repeated_rejection_stops_and_reserves_cannot_be_bypassed(self):
        for kind in ("syntax", "missing", "root"):
            for max_calls, max_requests, reserved in ((8, 12, 0), (2, 12, 0), (8, 2, 0), (5, 12, 3)):
                with self.subTest(kind=kind, calls=max_calls, requests=max_requests, reserved=reserved):
                    payloads, send = self.scripted(kind, repeat=True)
                    session = _ProductionSession(job(False), self.client(send, max_requests), fixture.MemoryRepo(), max_calls, 24)
                    session.prepare()
                    before = copy.deepcopy(session.result["fields"])
                    self.assertIsNone(session.complete("self_review", reserved_calls=reserved))
                    self.assertEqual(len(payloads), 3 if max_calls == 8 and max_requests == 12 else 2)
                    self.assertEqual(session.result["fields"], before)
                    self.assertIn(session.result["actions"][-1]["summary"], ("failed", "budget_unavailable"))

    def test_no_encoding_feedback_can_overrun_the_actual_context(self):
        for kind in ("syntax", "missing", "root"):
            payloads, send = self.scripted(kind)
            session = _ProductionSession(job(False), self.client(send), fixture.MemoryRepo(), 8, 24)
            session.prepare()
            wire = len(staged.instruction("annotation", location_key="source_id"))
            with patch.object(session, "encoding_context", return_value=[{"role": "system", "content": "x" * (100_000 - wire - 50)}]):
                self.assertIsNone(session.complete("self_review"))
            self.assertEqual(len(payloads), 2)
            self.assertEqual(session.result["actions"][-1]["summary"], "context_unavailable")

    def test_actual_production_recovers_draft_and_review_without_repeating_assessment_or_reads(self):
        for kind in ("syntax", "missing", "root"):
            payloads, encodings, plans = [], [], []
            def send(body, *_):
                payload = json.loads(body)
                payloads.append(payload)
                if "tools" not in payload:
                    return envelope(content=NOTE)
                if payload["tools"][0]["function"]["name"] == read_plan_protocol.TOOL_NAME:
                    plans.append(payload)
                    return plan_response([fixture.READ, fixture.CALLER] if len(plans) == 1 else [fixture.FINISH])
                call = fixture.full_annotation(payload)
                encodings.append(call)
                if len(encodings) in (1, 3):
                    raw = json.loads(envelope(call=call))
                    function = raw["choices"][0]["message"]["tool_calls"][0]["function"]
                    if kind == "syntax":
                        function["arguments"] = function["arguments"][:-1]
                    elif kind == "root":
                        function["arguments"] = json.dumps({"fields": json.loads(function["arguments"]),
                            "calls": [{"tool": "read_file", "arguments": {"path": "synthetic-discarded"}}]})
                    else:
                        decision = json.loads(function["arguments"])
                        function["arguments"] = json.dumps({"commit": decision["commit"]})
                    return json.dumps(raw).encode()
                return envelope(call=call)
            with self.subTest(kind=kind):
                client, repo, supplied = self.client(send), fixture.MemoryRepo(), job(False)
                # Keep the controller's existing focused-finish call as well as
                # both one-shot encodings inside an explicit nine-call budget.
                result = produce(supplied, client, repo, max_calls=9)
                final = finalize_result(supplied, result, repo)
                self.assertIsNotNone(final["entry"], json.dumps({"calls": len(payloads),
                    "errors": result["errors"], "annotation_errors": result["annotation_errors"],
                    "actions": [{k: a[k] for k in ("action", "stage", "summary", "code", "reason") if k in a}
                                for a in result["actions"] if a.get("action") not in ("tool", "evidence_assessment")]}, ensure_ascii=False))
                self.assertEqual(final["entry"]["verify"], 0)
                self.assertEqual(result["self_review_status"], "completed")
                self.assertEqual((len(payloads), len(encodings), len(plans)), (9, 4, 3))
                self.assertEqual(sum("tools" not in p for p in payloads), 2)
                self.assertEqual(repo.calls, [fixture.READ, fixture.CALLER])
                self.assertFalse(result["annotation_errors"])
                self.assertEqual(len([a for a in final["review"]["actions"] if a["action"] == "annotation_snapshot_rejected"]), 2)
                self.assertEqual(client.summary()["encoding_rejection_count"], 2)


if __name__ == "__main__":
    unittest.main()
