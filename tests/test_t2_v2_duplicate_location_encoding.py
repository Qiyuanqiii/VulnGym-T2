"""Synthetic malformed arguments: reject all values, then re-encode at most once."""
import copy
import json
from pathlib import Path
import tempfile
import unittest

from vulngym_t2 import annotation_rules, staged_protocol as staged, transport
from vulngym_t2.llm import DeepSeekClient, RequestLedger
from vulngym_t2.output import finalize_result, _saved_actions
from vulngym_t2.pipeline import _ProductionSession, produce
from tests import test_t2_v2_staged_pipeline as fixture
from tests.test_t2_v2_assessed_tool import envelope, NOTE
from tests.test_t2_v2_pipeline import job


def duplicate_arguments(snapshot, field="entry_point", key="start_line", second=9999):
    """Deliberately encode both occurrences; never model a last-key-wins repair."""
    snapshot = copy.deepcopy(snapshot)
    if field == "trace":
        snapshot[field]["value"] = [copy.deepcopy(snapshot["entry_point"]["value"])]
        location = snapshot[field]["value"][0]
    else:
        location = snapshot[field]["value"]
    location["desc"] = "synthetic-discarded-value"
    encoded = json.dumps(location)
    duplicate = encoded[:-1] + ", " + json.dumps(key) + ": " + json.dumps(second) + "}"
    return json.dumps(snapshot).replace(encoded, duplicate, 1)


def response(arguments):
    raw = json.loads(envelope(call=fixture.annotation()))
    raw["choices"][0]["message"]["tool_calls"][0]["function"]["arguments"] = arguments
    return json.dumps(raw).encode()


def duplicate_decision_refs(snapshot, field="entry_point", second=None):
    snapshot = copy.deepcopy(snapshot)
    decision = snapshot[field]
    decision["reason"] = "synthetic-discarded-reference-value"
    encoded = json.dumps(decision)
    repeated = decision["evidence_refs"] if second is None else second
    duplicate = encoded[:-1] + ', "evidence_refs": ' + json.dumps(repeated) + '}'
    return json.dumps(snapshot).replace(encoded, duplicate, 1)


class DuplicateLocationEncodingTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="t2-duplicate-encoding-")
        self.addCleanup(self.temp.cleanup)
        self.ledger = RequestLedger(Path(self.temp.name).resolve() / "requests.jsonl", limit=32)
        self.addCleanup(self.ledger.close)
        self.snapshot = staged.source_id_snapshot(fixture.annotation()[1])

    def parse(self, raw):
        return transport.parse_chat_response(raw, response_mode="staged_tool",
                                             stage="annotation", location_key="source_id")

    def client(self, send, max_requests=12):
        client = DeepSeekClient("synthetic-not-a-key", self.ledger, run_id="synthetic",
            max_requests=max_requests, response_mode="staged_tool", thinking="enabled",
            annotation_format="assessed_tool", send=send)
        self.addCleanup(client.close)
        return client

    def test_equal_and_different_duplicates_reject_entire_snapshot_without_any_values(self):
        for field in ("entry_point", "critical_operation", "trace"):
            for key, second in (("start_line", 0), ("start_line", 9999), ("end_line", 4),
                                ("source_id", "untrusted-id"), ("desc", "untrusted-text")):
                with self.subTest(field=field, key=key, second=second):
                    raw = response(duplicate_arguments(self.snapshot, field, key, second))
                    # Strict JSON parsing remains strict for all uses.
                    with self.assertRaises(transport._CompletionJSONBlocked):
                        transport._parse_completion_json(json.loads(raw)["choices"][0]["message"]
                            ["tool_calls"][0]["function"]["arguments"], unwrap_fence=False)
                    rejected = self.parse(raw)
                    self.assertEqual(rejected, {"action": "annotation_snapshot_rejected",
                        "code": "duplicate_location_key", "path": "$[0].arguments",
                        "duplicate_fields": [field], "known_duplicate_keys": [key], "duplicate_key_count": 1})
                    self.assertEqual(staged.public_snapshot_rejection(rejected), rejected)
                    self.assertEqual(_saved_actions([{**rejected, "stage": "self_review", "raw": "private"}]),
                                     [{**rejected, "stage": "self_review"}])
                    self.assertNotIn("synthetic-discarded", json.dumps(rejected))
                    self.assertNotIn("untrusted", json.dumps(rejected))
                    self.assertNotIn("fields", rejected)
                    self.assertNotIn("field_reviews", rejected)

    def test_other_duplicates_and_invalid_or_oversized_documents_remain_failures(self):
        good = duplicate_arguments(self.snapshot)
        cases = [
            good[:-1] + ', "commit": {}}',
            good.replace('"status": "missing"', '"status": "missing", "status": "supported"', 1),
            good.replace('"start_line": 9999', '"untrusted_key": 1, "untrusted_key": 2'),
            good[:-1] + ', "calls": []}',
            good[:-1] + ', "extra": 1}',
            good.replace('"start_line": 9999', '"start_line": NaN'),
            good.replace('"start_line": 9999', '"start_line": 1e9999'),
            good.replace('"start_line": 9999', '"start_line": ' + '[' * 20 + '0' + ']' * 20),
            good.replace('"start_line": 9999', '"start_line": ' + json.dumps("x" * 262_145)),
            good.replace('"start_line": 9999', '"start_line": ' + json.dumps("x" * 32_001)),
            good.replace('"start_line": 9999', '"start_line": ' + json.dumps([0] * 65)),
            good.replace('"start_line": 9999', '"start_line": 9999, "' + "x" * 65 + '": 0'),
            good.replace('"start_line": 9999', '"start_line": 9999, "' + "x" * 257 + '": 0'),
            good[:-1], good + "}", good[:-1] + ",}",
            '["not-an-object"]', "```json\n" + good + "\n```",
        ]
        missing = copy.deepcopy(self.snapshot)
        del missing["vuln_ids"]
        cases.append(duplicate_arguments(missing))
        for index, arguments in enumerate(cases):
            with self.subTest(index=index):
                self.assertIsNone(transport._duplicate_annotation_rejection(arguments))
                with self.assertRaises(transport.TransportError):
                    self.parse(response(arguments))

    def test_provider_envelope_refusal_wrong_stage_or_wire_never_enters_reencoding(self):
        raw = response(duplicate_arguments(self.snapshot))
        for mode, stage, key in (("staged_tool", "annotation", "evidence_ref"),
                                 ("staged_tool", "read", "evidence_ref"),
                                 ("staged_tool", "followup", "evidence_ref"),
                                 ("strict_tool", None, "evidence_ref")):
            with self.subTest(mode=mode, stage=stage, key=key):
                with self.assertRaises(transport.TransportError):
                    transport.parse_chat_response(raw, response_mode=mode, stage=stage, location_key=key)
        for mutation in ("refusal", "finish", "extra_function_key", "multiple_calls", "outer_duplicate"):
            malformed = json.loads(raw)
            choice = malformed["choices"][0]
            message = choice["message"]
            if mutation == "refusal":
                message["refusal"] = "synthetic refusal"
            elif mutation == "finish":
                choice["finish_reason"] = "content_filter"
            elif mutation == "extra_function_key":
                message["tool_calls"][0]["function"]["unexpected"] = True
            elif mutation == "multiple_calls":
                message["tool_calls"].append(copy.deepcopy(message["tool_calls"][0]))
            changed = json.dumps(malformed)
            if mutation == "outer_duplicate":
                changed = changed[:-1] + ', "model": "deepseek-flash"}'
            with self.subTest(mutation=mutation), self.assertRaises(transport.TransportError):
                self.parse(changed.encode())

    def test_rejection_metadata_never_exports_arbitrary_keys_values_or_counts(self):
        valid = self.parse(response(duplicate_arguments(self.snapshot)))
        for changes in ({"duplicate_fields": ["private"]}, {"known_duplicate_keys": ["private"]},
                        {"duplicate_key_count": True}, {"duplicate_key_count": 129},
                        {"duplicate_fields": []}, {"known_duplicate_keys": []}, {"code": "unknown"}):
            self.assertEqual(staged.public_snapshot_rejection({**valid, **changes}), {})
        self.assertEqual(staged.public_snapshot_rejection({**valid, "raw": "private"}), valid)

    def scripted(self, *, repeated=False, references=False):
        payloads = []
        def send(body, *_):
            payload = json.loads(body)
            payloads.append(payload)
            if "tools" not in payload:
                return envelope(content=NOTE)
            if repeated or len(payloads) == 2:
                encode = duplicate_decision_refs if references else duplicate_arguments
                return response(encode(self.snapshot))
            return envelope(call=fixture.annotation())
        return payloads, send

    def test_decision_references_reject_equal_or_conflicting_occurrences_in_all_fields(self):
        for field in staged.ANNOTATION_FIELDS:
            for second in (None, ["E9999"]):
                with self.subTest(field=field, second=second):
                    arguments = duplicate_decision_refs(self.snapshot, field, second)
                    with self.assertRaises(transport._CompletionJSONBlocked):
                        transport._parse_completion_json(arguments, unwrap_fence=False)
                    rejected = self.parse(response(arguments))
                    self.assertEqual(rejected, {"action": "annotation_snapshot_rejected",
                        "code": "duplicate_reference_key", "path": "$[0].arguments",
                        "duplicate_fields": [field], "known_duplicate_keys": ["evidence_refs"],
                        "duplicate_key_count": 1})
                    self.assertEqual(staged.public_snapshot_rejection(rejected), rejected)
                    self.assertNotIn("E9999", json.dumps(rejected))
                    self.assertNotIn("synthetic-discarded", json.dumps(rejected))
                    self.assertEqual(_saved_actions([{**rejected, "raw": "private"}]), [rejected])
                    for changes in ({"known_duplicate_keys": ["status"]},
                                    {"known_duplicate_keys": ["start_line"]},
                                    {"duplicate_fields": ["private"]},
                                    {"duplicate_key_count": True}):
                        self.assertEqual(staged.public_snapshot_rejection({**rejected, **changes}), {})

    def test_references_at_wrong_depth_other_duplicate_decisions_and_envelopes_still_stop(self):
        good = duplicate_decision_refs(self.snapshot)
        wrong_location = copy.deepcopy(self.snapshot)
        wrong_location["entry_point"]["value"]["evidence_refs"] = []
        for index, arguments in enumerate((
            duplicate_arguments(wrong_location, key="evidence_refs", second=[]),
            good[:-1] + ', "evidence_refs": [], "evidence_refs": []}',
            good.replace('"status": "missing"', '"status": "missing", "status": "supported"', 1),
            good.replace('"evidence_refs": []', '"evidence_refs": [{"x": 1, "x": 2}]', 1),
        )):
            with self.subTest(index=index), self.assertRaises(transport.TransportError):
                self.parse(response(arguments))
        for mutation in ("refusal", "wrong_stage", "multiple_calls"):
            raw = json.loads(response(good))
            message = raw["choices"][0]["message"]
            if mutation == "refusal":
                message["refusal"] = "synthetic refusal"
            elif mutation == "multiple_calls":
                message["tool_calls"].append(copy.deepcopy(message["tool_calls"][0]))
            with self.subTest(mutation=mutation), self.assertRaises(transport.TransportError):
                transport.parse_chat_response(json.dumps(raw).encode(), response_mode="staged_tool",
                    stage="read" if mutation == "wrong_stage" else "annotation",
                    location_key="evidence_ref" if mutation == "wrong_stage" else "source_id")

    def test_reference_reencoding_uses_one_original_assessment_and_no_rejected_values(self):
        payloads, send = self.scripted(references=True)
        session = _ProductionSession(job(False), self.client(send), fixture.MemoryRepo(), 8, 24)
        session.prepare()
        before = copy.deepcopy((session.result["fields"], session.result["field_reviews"], session.result["evidence"]))
        self.assertEqual(session.complete("self_review")["action"], "draft")
        self.assertEqual(len(payloads), 3)
        self.assertEqual(sum("tools" not in row for row in payloads), 1)
        self.assertEqual(payloads[2]["messages"][:-2], payloads[1]["messages"][:-1])
        self.assertNotIn("synthetic-discarded", json.dumps(payloads[2]))
        self.assertEqual((session.result["fields"], session.result["field_reviews"], session.result["evidence"]), before)
        self.assertEqual(session.result["actions"][-1]["summary"], "recovered")
        self.assertIn("one evidence_refs array", json.dumps(payloads[2]))

    def test_repeated_reference_reencoding_stops_without_loop_or_budget_growth(self):
        for max_calls in (2, 8):
            with self.subTest(max_calls=max_calls):
                payloads, send = self.scripted(references=True, repeated=True)
                client = self.client(send)
                session = _ProductionSession(job(False), client, fixture.MemoryRepo(), max_calls, 24)
                session.prepare()
                before = copy.deepcopy(session.result["fields"])
                self.assertIsNone(session.complete("self_review"))
                self.assertEqual(len(payloads), 2 if max_calls == 2 else 3)
                self.assertEqual(session.result["fields"], before)
                self.assertEqual(client.summary()["automatic_retries"], 0)

    def test_actual_client_and_session_reencode_from_same_assessment_with_no_duplicate_values(self):
        payloads, send = self.scripted()
        client = self.client(send)
        session = _ProductionSession(job(False), client, fixture.MemoryRepo(), 8, 24)
        session.prepare()
        before = copy.deepcopy((session.result["fields"], session.result["field_reviews"], session.result["evidence"]))
        reply = session.complete("self_review")
        self.assertEqual(reply["action"], "draft")
        self.assertEqual(len(payloads), 3)
        self.assertEqual(self.ledger.started, 3)
        self.assertEqual(sum("tools" not in row for row in payloads), 1)
        self.assertEqual(payloads[2]["messages"][:-2], payloads[1]["messages"][:-1])
        self.assertNotIn("synthetic-discarded", json.dumps(payloads[2]))
        self.assertNotIn("synthetic-discarded", self.ledger.path.read_text())
        self.assertEqual((session.result["fields"], session.result["field_reviews"], session.result["evidence"]), before)
        self.assertEqual(session.result["actions"][-1]["summary"], "recovered")
        self.assertEqual(client.summary()["automatic_retries"], 0)
        self.assertIsNone(client.halted)

    def test_repeated_duplicate_or_no_request_reserve_cannot_create_a_loop(self):
        for calls, max_requests, reserved in ((8, 12, 0), (2, 12, 0), (8, 2, 0), (5, 12, 3)):
            with self.subTest(calls=calls, max_requests=max_requests, reserved=reserved):
                payloads, send = self.scripted(repeated=True)
                session = _ProductionSession(job(False), self.client(send, max_requests), fixture.MemoryRepo(), calls, 24)
                session.prepare()
                before = copy.deepcopy(session.result["fields"])
                self.assertIsNone(session.complete("self_review", reserved_calls=reserved))
                self.assertEqual(len(payloads), 3 if calls == 8 and max_requests == 12 else 2)
                self.assertEqual(session.result["fields"], before)
                self.assertIn(session.result["actions"][-1]["summary"], ("failed", "budget_unavailable"))

    def check_final_production_reencoding(self, encode):
        payloads, encodings = [], []
        def send(body, *_):
            payload = json.loads(body)
            payloads.append(payload)
            if "tools" not in payload:
                return envelope(content=NOTE)
            if [row["function"]["name"] for row in payload["tools"]] == ["submit_annotation"]:
                annotation = fixture.full_annotation(payload)
                encodings.append(annotation)
                if len(encodings) == 2:
                    return response(encode(staged.source_id_snapshot(annotation[1])))
                return envelope(call=annotation)
            return envelope(call=fixture.READ if len(payloads) == 1 else fixture.FINISH)
        client, repo, supplied = self.client(send), fixture.MemoryRepo(), job(False)
        result = produce(supplied, client, repo, max_calls=8)
        final = finalize_result(supplied, result, repo)
        self.assertIsNotNone(final["entry"])
        self.assertEqual(final["entry"]["verify"], 0)
        self.assertEqual(result["self_review_status"], "completed")
        self.assertEqual(len(payloads), 8)
        self.assertEqual(sum("tools" not in row for row in payloads), 2)
        self.assertEqual(len(repo.calls), 1)
        self.assertEqual(len([row for row in final["review"]["actions"]
                              if row["action"] == "annotation_snapshot_reencoding"]), 1)
        self.assertNotIn("synthetic-discarded", json.dumps(final))

    def test_final_production_snapshot_recovers_without_extra_source_reads_or_assessment(self):
        self.check_final_production_reencoding(duplicate_arguments)

    def test_reference_reencoding_final_production_has_no_extra_assessment_or_source_reads(self):
        self.check_final_production_reencoding(duplicate_decision_refs)

    def test_scoped_semantics_and_unique_location_encoding_are_visible_in_real_payload(self):
        payloads, send = self.scripted()
        session = _ProductionSession(job(False), self.client(send), fixture.MemoryRepo(), 8, 24)
        session.prepare()
        session.complete("self_review")
        assessment = json.dumps(payloads[0]["messages"])
        encoding = json.dumps(payloads[1])
        self.assertIn("Separate registration/configuration from runtime steps", assessment)
        for rule in ("Write each property exactly once", "mapped persisted columns", "not runtime trace",
                     "Preserve read-branch conditions in commit.reason", "per observed branch",
                     "Equality/type/membership != truthiness", "Preserve exact operators"):
            self.assertIn(rule, encoding)
        self.assertIn("Copied keys != mapped persisted columns", annotation_rules.ENCODING_INSTRUCTION)


if __name__ == "__main__":
    unittest.main()
