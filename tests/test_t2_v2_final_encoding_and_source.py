"""Final-phase source/encoding regressions use synthetic data and no network."""
import copy
import json
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch

from vulngym_t2 import staged_protocol as staged
from vulngym_t2.entry_navigation import focused_reference_request
from vulngym_t2.llm import DeepSeekClient, RequestLedger
from vulngym_t2.output import _saved_actions
from vulngym_t2.pipeline import _ProductionSession
from tests import test_t2_v2_staged_pipeline as fixture
from tests.test_t2_v2_assessed_tool import envelope, NOTE
from tests.test_t2_v2_snapshot_json import envelope as raw_envelope
from tests.test_t2_v2_entry_navigation import NavigationRepo, source_record
from tests.test_t2_v2_pipeline import VULNERABLE, job


def malformed_location():
    snapshot = staged.source_id_snapshot(fixture.annotation()[1])
    snapshot["entry_point"]["value"].update(status="supported", private_extra="discarded-secret-value")
    return snapshot


def search_receipt():
    return {"id": "E0050", "tool": "search_code", "success": True, "result": {
        "commit": VULNERABLE, "query": "gate", "complete": True, "truncated": False,
        "matches": [{"file": "src/widgets.ts", "line": 3, "code": "    gate(ctx);"}]}}


class FinalEncodingTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="t2-final-encoding-")
        self.addCleanup(self.temp.cleanup)
        self.ledger = RequestLedger(Path(self.temp.name).resolve() / "ledger.jsonl", limit=32)
        self.addCleanup(self.ledger.close)

    def session(self, *, repeated=False, max_calls=8, shape_error="location"):
        payloads = []

        def send(body, *_):
            payload = json.loads(body)
            payloads.append(payload)
            if "tools" not in payload:
                return envelope(content=NOTE)
            value = staged.source_id_snapshot(fixture.annotation()[1])
            if repeated or len(payloads) == 2:
                if shape_error == "location":
                    value = malformed_location()
                elif shape_error == "missing_root":
                    value = {"commit": value["commit"]}
            return raw_envelope(call=("submit_annotation", value))

        client = DeepSeekClient("synthetic-not-a-key", self.ledger, run_id="synthetic",
            response_mode="staged_tool", annotation_format="assessed_tool", thinking="enabled",
            max_requests=16, send=send)
        self.addCleanup(client.close)
        session = _ProductionSession(job(False), client, fixture.MemoryRepo(), max_calls, 24)
        session.prepare()
        return session, payloads

    def test_bounded_location_metadata_leaves_decoder_and_input_unchanged(self):
        snapshot = malformed_location()
        original = copy.deepcopy(snapshot)
        reply = staged.normalize_calls([{"tool": "submit_annotation", "arguments": snapshot}],
                                       "annotation", location_key="source_id")
        self.assertEqual(reply["action"], "draft")  # Decoder's partial-field contract is unchanged.
        self.assertTrue(reply["annotation_errors"])
        rejected = staged.location_snapshot_rejection(reply)
        self.assertEqual(rejected["code"], "invalid_location_shape")
        self.assertEqual(rejected["location_errors"][0]["known_extra_keys"], ["status"])
        self.assertEqual(rejected["location_errors"][0]["unknown_extra_count"], 1)
        self.assertNotIn("private_extra", json.dumps(rejected))
        self.assertNotIn("discarded-secret-value", json.dumps(rejected))
        self.assertNotIn("fields", rejected)
        self.assertEqual(snapshot, original)
        saved = _saved_actions([{**rejected, "stage": "self_review", "raw": "discarded-secret-value"}])
        self.assertEqual(saved, [{**rejected, "stage": "self_review"}])

    def test_shape_correction_does_not_apply_failed_siblings_or_repeat_assessment(self):
        session, payloads = self.session()
        original = copy.deepcopy((session.result["fields"], session.result["field_reviews"], session.result["evidence"]))
        reply = session.complete("self_review")
        self.assertEqual(reply["action"], "draft")
        self.assertEqual(len(payloads), 3)
        self.assertEqual(sum("tools" not in item for item in payloads), 1)
        self.assertNotIn("temperature", payloads[0])
        self.assertTrue(all(item["temperature"] == 0 for item in payloads[1:]))
        correction = json.dumps(payloads[2])
        self.assertIn("location_object_rule", correction)
        self.assertNotIn("discarded-secret-value", correction)
        self.assertNotIn("private_extra", correction)
        self.assertEqual(original, (session.result["fields"], session.result["field_reviews"], session.result["evidence"]))
        self.assertEqual(session.client.summary()["automatic_retries"], 0)
        self.assertEqual(session.result["actions"][-1]["summary"], "recovered")
        self.assertLessEqual(sum(len(row["content"]) for row in payloads[2]["messages"]), 100_000)

    def test_repeated_location_error_stops_after_one_encoding_correction(self):
        session, payloads = self.session(repeated=True)
        original = copy.deepcopy(session.result["fields"])
        self.assertIsNone(session.complete("self_review"))
        self.assertEqual(len(payloads), 3)
        self.assertEqual(session.result["actions"][-1]["summary"], "failed")
        self.assertEqual(session.result["fields"], original)

    def test_mismatched_or_nonlocation_errors_cannot_authorize_correction(self):
        reply = staged.normalize_calls([{"tool": "submit_annotation", "arguments": malformed_location()}],
                                       "annotation", location_key="source_id")
        for changed in (None, [], {**reply, "annotation_errors": []}, {**reply, "action": "tools"}):
            self.assertIsNone(staged.location_snapshot_rejection(changed))
        rejected = staged.location_snapshot_rejection(reply)
        for field in ("vuln_title", "commit"):
            invalid = copy.deepcopy(rejected)
            invalid["location_errors"][0].update(field=field, path="$[0].arguments." + field)
            self.assertEqual(staged.public_snapshot_rejection(invalid), {})
        for key, value in (("location_reference_key", "evidence_ref"), ("unknown_extra_count", True),
                           ("known_extra_keys", ["private_extra"]), ("path", "$[0].arguments.entry_point.value.status")):
            invalid = copy.deepcopy(rejected)
            invalid["location_errors"][0][key] = value
            self.assertEqual(staged.public_snapshot_rejection(invalid), {})

    def test_budget_still_stops_before_correction(self):
        session, payloads = self.session()
        self.assertIsNone(session.complete("self_review", reserved_calls=7))
        self.assertEqual(len(payloads), 2)
        self.assertEqual(session.result["actions"][-1]["summary"], "budget_unavailable")

    def test_optional_followup_leaves_one_slot_for_final_encoding(self):
        session, payloads = self.session(max_calls=12)
        session.drafted = session.accept_snapshot(staged.normalize_calls(
            [{"tool": "submit_annotation", "arguments": staged.source_id_snapshot(fixture.annotation()[1])}],
            "annotation", location_key="source_id"))
        session.initial_valid_updates = 1
        session.result["model_calls"] = 9  # Prior stages already consumed nine of twelve.
        session.result["actions"].append({"action": "annotation_snapshot_rejected", "stage": "draft"})
        with patch.object(session, "navigate_entry_context"):
            session.finish_draft()
        stages = [row["stage"] for row in session.result["actions"] if row["action"] == "model_call"]
        self.assertEqual(stages, ["self_review_assessment", "self_review", "encoding_shape_review"])
        self.assertEqual(session.result["model_calls"], 12)
        self.assertEqual(len(payloads), 3)
        self.assertEqual(session.result["self_review_status"], "completed")

    def test_first_error_in_final_snapshot_also_gets_original_correction_slot(self):
        session, payloads = self.session(max_calls=12, shape_error="missing_root")
        session.drafted = session.accept_snapshot(staged.normalize_calls(
            [{"tool": "submit_annotation", "arguments": staged.source_id_snapshot(fixture.annotation()[1])}],
            "annotation", location_key="source_id"))
        session.initial_valid_updates = 1
        session.result["model_calls"] = 9
        self.assertFalse(any(row["action"] == "annotation_snapshot_rejected" for row in session.result["actions"]))
        with patch.object(session, "navigate_entry_context") as navigate:
            session.finish_draft()
        navigate.assert_called_once()
        stages = [row["stage"] for row in session.result["actions"] if row["action"] == "model_call"]
        self.assertEqual(stages, ["self_review_assessment", "self_review", "encoding_shape_review"])
        self.assertEqual(session.result["model_calls"], 12)
        self.assertEqual(session.result["self_review_status"], "completed")
        self.assertEqual(session.result["evidence_followup_status"], "not_requested")
        self.assertEqual(len(payloads), 3)
        self.assertEqual(session.client.summary()["encoding_missing_root_rejection_count"], 1)

    def test_unused_final_reserve_is_not_spent(self):
        session, payloads = self.session(max_calls=12, shape_error=None)
        session.drafted = session.accept_snapshot(staged.normalize_calls(
            [{"tool": "submit_annotation", "arguments": staged.source_id_snapshot(fixture.annotation()[1])}],
            "annotation", location_key="source_id"))
        session.initial_valid_updates = 1
        session.result["model_calls"] = 9
        with patch.object(session, "navigate_entry_context"):
            session.finish_draft()
        self.assertEqual(session.result["model_calls"], 11)
        self.assertEqual(len(payloads), 2)
        self.assertEqual(session.result["self_review_status"], "completed")
        self.assertFalse(any(row["action"] == "annotation_snapshot_reencoding" for row in session.result["actions"]))

    def test_correction_cannot_exceed_actual_context_limit(self):
        session, payloads = self.session()
        wire = len(staged.instruction("annotation", location_key="source_id"))
        with patch.object(session, "encoding_context", return_value=[{
                "role": "system", "content": "x" * (100_000 - wire - 50)}]):
            self.assertIsNone(session.complete("self_review"))
        self.assertEqual(len(payloads), 2)
        self.assertEqual(session.result["actions"][-1]["summary"], "context_unavailable")

    def test_trace_shape_keeps_actual_index_but_never_unknown_values(self):
        snapshot = staged.source_id_snapshot(fixture.annotation()[1])
        loc = {"source_id": "E0001", "start_line": 1, "end_line": 1, "desc": "Synthetic observed row."}
        snapshot["trace"]["value"] = [copy.deepcopy(loc), {**loc, "private_extra": "discarded-secret-value"}]
        reply = staged.normalize_calls([{"tool": "submit_annotation", "arguments": snapshot}],
                                       "annotation", location_key="source_id")
        rejected = staged.location_snapshot_rejection(reply)
        self.assertEqual(rejected["location_errors"][0]["path"], "$[0].arguments.trace.value[1]")
        self.assertNotIn("discarded-secret-value", json.dumps(rejected))

    def test_known_vocabulary_diagnostics_do_not_accept_or_save_extra_values(self):
        snapshot = malformed_location()
        snapshot["entry_point"]["value"]["kind"] = "discarded-secret-value"
        reply = staged.normalize_calls([{"tool": "submit_annotation", "arguments": snapshot}],
                                       "annotation", location_key="source_id")
        rejected = staged.location_snapshot_rejection(reply)
        self.assertEqual(rejected["location_errors"][0]["known_extra_keys"], ["kind", "status"])
        self.assertNotIn("entry_point", reply["fields"])
        self.assertNotIn("discarded-secret-value", json.dumps(rejected))
        self.assertEqual(rejected["location_errors"][0]["unknown_extra_count"], 1)

    def test_exploration_leaves_initial_encoding_correction_and_review_budget(self):
        session, _ = self.session(max_calls=12)
        stages = []

        def complete(stage, **_):
            stages.append(stage)
            if stage == "plan_and_read":
                session.result["model_calls"] += 1
                return {"action": "read_request_rejected", "errors": []}
            self.assertEqual(stage, "draft")
            # Five required calls (assessment, encoding, sole correction and
            # the review pair) plus the one reserved follow-up decision window.
            self.assertEqual(session.max_calls - session.result["model_calls"], 6)
            session.result["model_calls"] += 3  # Assessment, encoding, sole correction.
            return staged.normalize_calls([{"tool": "submit_annotation", "arguments":
                staged.source_id_snapshot(fixture.annotation()[1])}], "annotation", location_key="source_id")

        with patch.object(session, "complete", side_effect=complete):
            session.read_and_draft()
        self.assertEqual(stages, ["plan_and_read"] * 6 + ["draft"])
        self.assertTrue(session.drafted)
        # The review pair plus the reserved decision window remain; the window
        # itself is spent only by a real follow-up decision, never force-spent.
        self.assertEqual(session.max_calls - session.result["model_calls"], 3)


class FinalSearchSourceTests(unittest.TestCase):
    def test_actual_hit_becomes_one_window_without_selecting_a_field(self):
        receipt = search_receipt()
        original = copy.deepcopy(receipt)
        self.assertEqual(focused_reference_request([receipt], []), {
            "commit": VULNERABLE, "path": "src/widgets.ts", "start_line": 1, "end_line": 35})
        self.assertEqual(receipt, original)
        self.assertIsNone(focused_reference_request([receipt], [source_record("E0051", "src/widgets.ts")]))
        receipt["result"]["matches"].insert(0, {"file": "src/widgets.ts", "line": 1, "code": "import { gate } from './helper';"})
        self.assertEqual(focused_reference_request([receipt], [])["end_line"], 35)

    def test_partial_failed_or_nonliteral_search_does_not_start_reads(self):
        for scope, key, value in (("result", "complete", False), ("result", "truncated", True),
                                 ("result", "commit", "not-a-sha"), ("result", "query", "gate|other"),
                                 ("result", "query", "get"), ("result", "error", "failed"),
                                 ("root", "success", False), ("root", "tool", "read_file")):
            receipt = search_receipt()
            (receipt if scope == "root" else receipt["result"])[key] = value
            self.assertIsNone(focused_reference_request([receipt], []))
        receipt = search_receipt()
        receipt["result"]["matches"][0]["file"] = "../outside.ts"
        self.assertIsNone(focused_reference_request([receipt], []))
        self.assertIsNone(focused_reference_request([search_receipt()] * 2, []))

    def test_production_hook_reads_once_and_preserves_model_decisions(self):
        session = _ProductionSession(job(False), SimpleNamespace(response_mode="staged_tool", halted=None),
                                     NavigationRepo(), 8, 24)
        session.prepare()
        original = copy.deepcopy((session.result["fields"], session.result["field_reviews"]))
        session.navigate_entry_context({}, focused_reads=[search_receipt()])
        self.assertEqual([tool for tool, _ in session.repo.calls], ["read_file"])
        self.assertEqual(session.result["tool_calls"], 1)
        self.assertEqual(session.result["model_calls"], 0)
        self.assertEqual(original, (session.result["fields"], session.result["field_reviews"]))
        session.navigate_entry_context({}, focused_reads=[search_receipt()])
        self.assertEqual(len(session.repo.calls), 1)

    def test_production_hook_obeys_provider_tool_and_context_stops(self):
        for boundary in ("provider", "tools", "context"):
            session = _ProductionSession(job(False), SimpleNamespace(response_mode="staged_tool", halted=None),
                                         NavigationRepo(), 8, 24)
            session.prepare()
            if boundary == "provider":
                session.client.halted = "stopped"
            elif boundary == "tools":
                session.result["tool_calls"] = 24
            else:
                session.messages = [{"role": "system", "content": "x" * 100_000}]
            with patch.object(session, "compact_candidate_context"):
                session.navigate_entry_context({}, focused_reads=[search_receipt()])
            self.assertEqual(session.repo.calls, [])


if __name__ == "__main__":
    unittest.main()
