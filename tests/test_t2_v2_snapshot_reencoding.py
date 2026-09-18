"""Reject invalid whole snapshots, then explicitly encode the same assessment once."""
import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from vulngym_t2 import staged_protocol as staged
from vulngym_t2.llm import DeepSeekClient, RequestLedger
from vulngym_t2.output import finalize_result, _saved_actions
from vulngym_t2.pipeline import _ProductionSession, produce
from tests import test_t2_v2_staged_pipeline as fixture
from tests.test_t2_v2_pipeline import job
from tests.test_t2_v2_assessed_tool import envelope, NOTE


class SnapshotReencodingTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="t2-snapshot-encoding-")
        self.addCleanup(self.temp.cleanup)
        self.ledger = RequestLedger(Path(self.temp.name).resolve() / "ledger.jsonl", limit=32)
        self.addCleanup(self.ledger.close)

    def client(self, send, max_requests=12):
        client = DeepSeekClient("synthetic-not-a-key", self.ledger, run_id="synthetic",
            max_requests=max_requests, response_mode="staged_tool", thinking="enabled",
            annotation_format="assessed_tool", send=send)
        self.addCleanup(client.close)
        return client

    def test_outer_extras_reject_every_value_without_leaking_unknown_keys_or_values(self):
        snapshot = staged.source_id_snapshot(fixture.annotation()[1])
        snapshot.update(summary="discarded-private-value", private_unknown="discarded-private-value")
        original = copy.deepcopy(snapshot)
        result = staged.normalize_calls([{"tool": "submit_annotation", "arguments": snapshot}],
                                        "annotation", location_key="source_id")
        self.assertEqual(result, {"action": "annotation_snapshot_rejected", "code": "unexpected_properties",
            "path": "$[0].arguments", "known_extra_keys": ["summary"], "unknown_extra_count": 1})
        self.assertEqual(snapshot, original)
        self.assertNotIn("fields", result)
        self.assertNotIn("private", json.dumps(result))
        self.assertEqual(_saved_actions([{**result, "stage": "self_review", "raw": "discarded-private-value"}]),
                         [{**result, "stage": "self_review"}])
        self.assertEqual(staged.public_snapshot_rejection({**result, "known_extra_keys": ["private_unknown"]}), {})

    def test_misplaced_wrappers_are_rejected_whole_other_modes_and_resource_excess_stop(self):
        base = staged.source_id_snapshot(fixture.annotation()[1])
        for snapshot in ({**base, "calls": []}, {"fields": base}, {"summary": "extra"}):
            with self.subTest(keys=list(snapshot)):
                rejected = staged.normalize_calls([{"tool": "submit_annotation", "arguments": snapshot}],
                                                  "annotation", location_key="source_id")
                self.assertEqual(rejected["action"], "annotation_snapshot_rejected")
                self.assertNotIn("fields", rejected)
                self.assertNotIn("calls", rejected)
        with self.assertRaises(staged.ProtocolError):
            staged.normalize_calls([{"tool": "submit_annotation", "arguments": {
                **base, "private_unknown": "x" * 100_001}}], "annotation", location_key="source_id")
        with self.assertRaises(staged.ProtocolError):
            staged.normalize_calls([{"tool": "submit_annotation", "arguments": {
                **fixture.annotation()[1], "summary": "extra"}}], "annotation")

    def test_native_annotation_single_trailing_separator_is_audited_without_a_retry(self):
        def send(body, *_):
            raw = json.loads(envelope(call=fixture.annotation()))
            function = raw["choices"][0]["message"]["tool_calls"][0]["function"]
            function["arguments"] = function["arguments"][:-1] + ",}"
            return json.dumps(raw).encode()
        client = self.client(send)
        reply = client.complete([{"role": "user", "content": "Synthetic assessment only."}], stage="annotation")
        self.assertEqual(reply["action"], "draft")
        self.assertEqual(reply["completion_json_normalizations"], [{"code": "trailing_separator_removed", "count": 1}])
        self.assertEqual(client.calls, 1)
        self.assertFalse(reply["fields"])
        self.assertIsNone(client.halted)

    def scripted(self, *, repeated=False, failure=None):
        payloads = []
        def send(body, *_):
            payload = json.loads(body)
            payloads.append(payload)
            if "tools" not in payload:
                return envelope(content=NOTE)
            if failure == "transport":
                raise OSError("synthetic disconnect")
            call = fixture.annotation()
            if failure == "resource":
                raw = json.loads(envelope(call=call))
                raw["choices"][0]["message"]["tool_calls"][0]["function"]["arguments"] = '{"broken":' + '[' * 40
                return json.dumps(raw).encode()
            if repeated or len(payloads) == 2:
                call[1]["summary"] = "discarded-private-value"
            return envelope(call=call)
        return payloads, send

    def test_reencoding_reuses_same_assessment_and_does_not_mutate_state_before_merge(self):
        payloads, send = self.scripted()
        client = self.client(send)
        session = _ProductionSession(job(False), client, fixture.MemoryRepo(), 8, 24)
        session.prepare()
        before = copy.deepcopy((session.result["fields"], session.result["field_reviews"], session.result["evidence"]))
        result = session.complete("self_review")
        self.assertEqual(result["action"], "draft")
        self.assertEqual(len(payloads), 3)
        self.assertEqual(self.ledger.started, 3)
        self.assertEqual(payloads[2]["messages"][:-2], payloads[1]["messages"][:-1])
        self.assertEqual(sum("tools" not in row for row in payloads), 1)
        self.assertNotIn("discarded-private-value", json.dumps(payloads[2]))
        self.assertNotIn("discarded-private-value", self.ledger.path.read_text())
        self.assertEqual((session.result["fields"], session.result["field_reviews"], session.result["evidence"]), before)
        self.assertEqual(session.result["actions"][-1]["summary"], "recovered")
        self.assertEqual(client.summary()["automatic_retries"], 0)
        self.assertIsNone(client.halted)

    def test_repeated_bad_encoding_stops_after_one_correction(self):
        payloads, send = self.scripted(repeated=True)
        session = _ProductionSession(job(False), self.client(send), fixture.MemoryRepo(), 8, 24)
        session.prepare()
        original = copy.deepcopy(session.result["fields"])
        self.assertIsNone(session.complete("self_review"))
        self.assertEqual(len(payloads), 3)
        self.assertEqual(session.result["fields"], original)
        self.assertEqual(session.result["actions"][-1]["summary"], "failed")
        self.assertTrue(session.result["errors"])

    def test_required_later_phases_keep_their_request_reserve(self):
        payloads, send = self.scripted()
        session = _ProductionSession(job(False), self.client(send), fixture.MemoryRepo(), 5, 24)
        session.prepare()
        self.assertIsNone(session.complete("self_review", reserved_calls=3))
        self.assertEqual(len(payloads), 2)
        self.assertEqual(session.result["actions"][-1]["summary"], "budget_unavailable")

    def test_correction_cannot_exceed_actual_context_budget(self):
        payloads, send = self.scripted()
        session = _ProductionSession(job(False), self.client(send), fixture.MemoryRepo(), 8, 24)
        session.prepare()
        wire = len(staged.instruction("annotation", location_key="source_id"))
        with patch.object(session, "encoding_context", return_value=[{"role": "system", "content": "x" * (100_000 - wire - 50)}]):
            self.assertIsNone(session.complete("self_review"))
        self.assertEqual(len(payloads), 2)
        self.assertEqual(session.result["actions"][-1]["summary"], "context_unavailable")

    def test_transport_or_resource_failure_never_enters_shape_correction(self):
        for failure in ("transport", "resource"):
            payloads, send = self.scripted(failure=failure)
            client = self.client(send)
            session = _ProductionSession(job(False), client, fixture.MemoryRepo(), 8, 24)
            session.prepare()
            self.assertIsNone(session.complete("self_review"))
            self.assertEqual(len(payloads), 2)
            self.assertTrue(client.halted)
            self.assertFalse(any(row["action"] == "annotation_snapshot_reencoding" for row in session.result["actions"]))

    def test_production_full_review_recovers_final_root_without_extra_reasoning_or_reads(self):
        payloads, encoded = [], []
        def send(body, *_):
            payload = json.loads(body)
            payloads.append(payload)
            if "tools" not in payload:
                return envelope(content=NOTE)
            if [row["function"]["name"] for row in payload["tools"]] == ["submit_annotation"]:
                call = fixture.full_annotation(payload)
                encoded.append(call)
                if len(encoded) == 2:
                    call[1]["summary"] = "discarded-private-value"
                return envelope(call=call)
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
        saved = final["review"]["actions"]
        self.assertEqual(len([row for row in saved if row["action"] == "annotation_snapshot_reencoding"]), 1)
        self.assertNotIn("discarded-private-value", json.dumps(saved))


if __name__ == "__main__":
    unittest.main()
