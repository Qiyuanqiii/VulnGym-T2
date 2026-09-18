"""Two explicit, budgeted stages: fallible conclusions then strict annotation."""
import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from vulngym_t2 import annotation_rules, transport, staged_protocol
from vulngym_t2.llm import DeepSeekClient, MODEL, RequestLedger
from vulngym_t2.output import finalize_result, _saved_actions, _public
from vulngym_t2.pipeline import produce, _ProductionSession
from tests import test_t2_v2_staged_pipeline as fixture
from tests.test_t2_v2_pipeline import job, evidence_from, VULNERABLE, FIXED
from tests.test_t2_v2_snapshot_json import envelope as legacy_envelope


NOTE = "Synthetic assessment conclusion. Check saved source; this note is not evidence."


def envelope(*, content=None, call=None):
    if call is not None and call[0] == "submit_annotation":
        call = (call[0], staged_protocol.source_id_snapshot(call[1]))
    return legacy_envelope(content=content, call=call)


class AssessedToolTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="t2-assessed-")
        self.addCleanup(self.temp.cleanup)
        self.ledger = RequestLedger(Path(self.temp.name).resolve() / "ledger.jsonl", limit=32)
        self.addCleanup(self.ledger.close)

    def client(self, send, **overrides):
        options = dict(response_mode="staged_tool", thinking="enabled", annotation_format="assessed_tool",
                       max_requests=16, reasoning_effort="low", send=send)
        options.update(overrides)
        client = DeepSeekClient("synthetic-not-a-key", self.ledger, run_id="synthetic", **options)
        self.addCleanup(client.close)
        return client

    def source_send(self, payloads, *, note=NOTE):
        def send(body, *_):
            payload = json.loads(body)
            payloads.append(payload)
            if "tools" not in payload:
                return envelope(content=note)
            names = [tool["function"]["name"] for tool in payload["tools"]]
            if names == ["submit_annotation"]:
                return envelope(call=fixture.full_annotation(payload))
            return envelope(call=fixture.READ if len(payloads) == 1 else fixture.FINISH)
        return send

    def test_wire_has_explicit_assessment_then_native_format_not_json_repair(self):
        payloads = []
        def send(body, *_):
            payload = json.loads(body)
            payloads.append(payload)
            return envelope(content=NOTE) if "tools" not in payload else envelope(call=fixture.annotation())
        client = self.client(send)
        result = client.complete([{"role": "user", "content": "fixture"}], stage="assessment")
        self.assertEqual(result, {"action": "assessment", "text": NOTE})
        client.complete([{"role": "user", "content": "fixture"}], stage="annotation")
        self.assertEqual(payloads[0]["thinking"], {"type": "enabled"})
        for key in ("response_format", "tools", "tool_choice"):
            self.assertNotIn(key, payloads[0])
        self.assertEqual(payloads[1]["thinking"], {"type": "disabled"})
        self.assertEqual(payloads[1]["tool_choice"], "required")
        self.assertNotIn("reasoning_effort", payloads[1])
        self.assertEqual(self.ledger.started, 2)
        self.assertEqual(client.summary()["stage_settings"]["requests_per_snapshot"], 2)
        self.assertEqual(client.summary()["tool_choice"], "stage_specific")

    def test_complete_controller_counts_both_calls_and_reviews_again(self):
        payloads, repo, supplied = [], fixture.MemoryRepo(), job(False)
        client = self.client(self.source_send(payloads))
        result = produce(supplied, client, repo, max_calls=7)
        final = finalize_result(supplied, result, repo)
        self.assertIsNotNone(final["entry"])
        self.assertEqual(final["entry"]["verify"], 0)
        # Two read calls and both assessment/encoding pairs are retained.
        # Optional follow-up leaves one final correction slot; this valid
        # fixture never spends that unused reserve.
        self.assertEqual(result["model_calls"], 6)
        self.assertEqual(self.ledger.started, 6)
        self.assertEqual(result["evidence_followup_status"], "not_requested")
        self.assertEqual(result["self_review_status"], "completed")
        notes = [row for row in result["actions"] if row["action"] == "evidence_assessment"]
        self.assertEqual([row["stage"] for row in notes], ["draft", "self_review"])
        self.assertTrue(all(row["semantic_approval"] is False for row in notes))
        saved_notes = [row for row in final["review"]["actions"] if row["action"] == "evidence_assessment"]
        self.assertEqual([row["summary"] for row in saved_notes], [NOTE, NOTE])
        self.assertTrue(all(row["semantic_approval"] is False for row in saved_notes))
        self.assertNotIn(NOTE, json.dumps(result["evidence"]))
        self.assertNotIn("synthetic private reasoning", json.dumps(result))
        self.assertNotIn("synthetic private reasoning", self.ledger.path.read_text())
        for payload in payloads:
            self.assertLessEqual(sum(len(row["content"]) for row in payload["messages"]), 100_000)
            if "tools" not in payload:
                self.assertNotIn("assessment_to_check", json.dumps(payload))
                self.assertNotIn(annotation_rules.ENCODING_INSTRUCTION, payload["messages"][0]["content"])
            elif [x["function"]["name"] for x in payload["tools"]] == ["submit_annotation"]:
                self.assertIn("assessment_to_check", json.dumps(payload))
                self.assertIn(annotation_rules.ASSESSMENT_NOTE_BOUNDARY, json.dumps(payload))
                self.assertTrue(payload["messages"][0]["content"].endswith(annotation_rules.ENCODING_INSTRUCTION))
                self.assertIn(annotation_rules.for_phase("annotation"), payload["messages"][0]["content"])
                # The encoder keeps actual receipts; the assessment never
                # becomes a replacement source or an automatically applied field.
                self.assertTrue(any(row.get("tool") == "read_file" for row in evidence_from(payload["messages"])))
        self.assertEqual(client.summary()["automatic_retries"], 0)

    def test_encoding_role_fits_the_actual_review_reserve_and_longer_roles_reduce_headroom(self):
        client = self.client(self.source_send([]))
        session = _ProductionSession(job(False), client, fixture.MemoryRepo(), 8, 16)
        session.prepare()
        wire = len(staged_protocol.instruction("annotation", location_key="source_id"))
        required = (len(annotation_rules.for_phase("annotation")) + len(annotation_rules.ENCODING_INSTRUCTION)
                    + wire + session.assessment_context_reserve)
        self.assertGreaterEqual(session.review_instruction_budget(), required)
        old_limit = session.navigation_context_limit()
        # The old test assumed the encoder was shorter than every phase. Its
        # actual separately measured instruction now owns the reserve; never
        # grow the 100k context cap to accommodate a longer role.
        longer = annotation_rules.ENCODING_INSTRUCTION + "x" * 10_000
        with patch.object(annotation_rules, "ENCODING_INSTRUCTION", longer):
            self.assertGreaterEqual(session.review_instruction_budget(), required + 10_000)
            self.assertLess(session.navigation_context_limit(), old_limit)
            self.assertLessEqual(session.navigation_context_limit() + session.review_instruction_budget(), 100_000)
        self.assertIn("concrete source or contract conflict", annotation_rules.ENCODING_INSTRUCTION)
        self.assertIn("Never promote a field", annotation_rules.ENCODING_INSTRUCTION)

    def test_revision_comparison_reaches_full_assessment_without_automatic_selection(self):
        payloads = []
        client = self.client(self.source_send(payloads))
        session = _ProductionSession(job(False), client, fixture.MemoryRepo(), 8, 16)
        session.prepare()
        before = copy.deepcopy(session.result["fields"])
        session.complete("self_review")
        self.assertEqual(len(payloads), 2)
        guidance = annotation_rules.REVISION_REASSESSMENT_GUIDANCE
        self.assertIn(guidance, "\n".join(row["content"] for row in payloads[0]["messages"]))
        for boundary in ("proposed SHA is revisable", "each source-read candidate SHA",
                         "precise missing premise", "commit and all locations together",
                         "whether that mode is deployed are separate", "field recovery cannot change commit"):
            self.assertIn(boundary, guidance)
        for case_fact in ("GHSA-", "AUTO_LOGIN", "_read_flow", "198fab1", "73c1f203"):
            self.assertNotIn(case_fact, guidance)
        self.assertNotIn("commit", session.immutable)
        self.assertEqual(session.result["fields"], before)
        self.assertEqual(client.summary()["automatic_retries"], 0)
        self.assertLessEqual(sum(len(row["content"]) for row in payloads[0]["messages"]), 100_000)

    def test_value_flow_guidance_reaches_assessment_and_encoding_without_facts_or_new_calls(self):
        payloads = []
        client = self.client(self.source_send(payloads))
        session = _ProductionSession(job(False), client, fixture.MemoryRepo(), 8, 16)
        session.prepare()
        session.complete("self_review")
        guidance = annotation_rules.VALUE_FLOW_GUIDANCE
        self.assertEqual(len(payloads), 2)
        for payload in payloads:
            self.assertTrue(any(guidance in row["content"] for row in payload["messages"]))
            self.assertLessEqual(sum(len(row["content"]) for row in payload["messages"]), 100_000)
        self.assertIn("Hypothetical examples, NOT source facts", guidance)
        self.assertIn("keeps non-nullish x", guidance)
        self.assertIn("A reassignment does not by itself change the value", annotation_rules.TASK_RULES)
        self.assertIn("zero-iteration return can preserve input", guidance)
        self.assertIn("do not make that branch unknown", guidance)
        self.assertIn("Preserve if/unless polarity", guidance)
        self.assertIn("Equality/type/membership != truthiness", guidance)
        self.assertIn("Preserve exact operators", guidance)
        self.assertIn("Python `not x` tests falsiness, not just empty strings", guidance)
        self.assertIn("narrow types only with read proof", guidance)
        self.assertIn("never rewrite source or promote status", guidance)
        for case_fact in ("GHSA-", "chatId", "AUTO_LOGIN", "event_emitter", "req.body"):
            self.assertNotIn(case_fact, guidance)
        self.assertEqual(client.summary()["automatic_retries"], 0)

    def test_branch_identity_is_not_replaced_by_a_blanket_change_or_unknown_claim(self):
        for text in (annotation_rules.ASSESSMENT_INSTRUCTION, annotation_rules.ENCODING_INSTRUCTION,
                     annotation_rules.TRACE_DECISION_GUIDANCE):
            self.assertIn("zero-iteration return can preserve input", text)
            self.assertIn("Preserve if/unless polarity", text)
            self.assertNotIn("filtered/transformed result is not unchanged input", text)
            for case_fact in ("GHSA-", "process_filter_functions", "filter_functions", "E0016"):
                self.assertNotIn(case_fact, text)
        self.assertIn("only when the observed branch proves it", annotation_rules.TASK_RULES)

    def test_assessment_explicit_statuses_remain_untrusted_not_automatic_field_approval(self):
        instruction = annotation_rules.ASSESSMENT_INSTRUCTION
        for field in staged_protocol.ANNOTATION_FIELDS:
            self.assertIn(field, instruction)
        self.assertIn("starting 'field: status'", instruction)
        self.assertIn("not new evidence or approval", instruction)
        self.assertIn("A necessary receiver binding or connection left unknown makes that field uncertain", instruction)
        self.assertIn("values AND explicit statuses", annotation_rules.ENCODING_INSTRUCTION)
        self.assertIn("concrete source or contract conflict", annotation_rules.ENCODING_INSTRUCTION)
        payloads = []
        client = self.client(self.source_send(payloads, note="commit: supported; E9999 synthetic untrusted claim"))
        session = _ProductionSession(job(False), client, fixture.MemoryRepo(), 8, 16)
        session.prepare()
        before = copy.deepcopy(session.result["fields"])
        session.complete("self_review")
        # Completing the two stages alone never parses prose into approved data.
        self.assertEqual(session.result["fields"], before)
        self.assertEqual(len(payloads), 2)

    def test_encoder_uses_current_assessment_without_replaying_prior_review_commands(self):
        payloads = []
        client = self.client(self.source_send(payloads))
        state = _ProductionSession(job(False), client, fixture.MemoryRepo(), 8, 16)
        state.prepare()
        state.read_tool(*fixture.READ)
        state.result["field_reviews"]["commit"].update({
            "reason": "Historical caveat: no release mapping was read.",
            "revision_basis": "inspected_only", "status": "uncertain",
            "suggested_value": VULNERABLE})
        scope = {"scope": "Synthetic independent candidate", "evidence_refs": [state.input_id]}
        state.active_candidate_scope = scope
        checked = {"errors": [{"field": "commit", "code": "model_uncertain"}]}
        conflict = {"entry_point": {"reason": "Synthetic missing caller premise"}}
        state.messages.extend([
            {"role": "user", "content": "OLD_PHASE_COMMAND: redo the historical review"},
            {"role": "user", "content": json.dumps({"draft_validation": checked,
                "support_consistency_checks": conflict})},
            {"role": "user", "content": json.dumps({"revision_basis_review": {
                "revision_basis": "inspected_only", "stale_marker": "old basis is not current"}})},
        ])
        before = copy.deepcopy(state.result)
        state.complete("self_review")
        self.assertEqual(len(payloads), 2)
        self.assertIn("OLD_PHASE_COMMAND", json.dumps(payloads[0]))
        encoded = payloads[1]["messages"]
        body = json.loads(encoded[1]["content"])
        self.assertNotIn("OLD_PHASE_COMMAND", json.dumps(encoded))
        self.assertNotIn("stale_marker", json.dumps(encoded))
        self.assertEqual(body["candidate_scope"], scope)
        self.assertEqual(body["historical_checks"], [
            {"draft_validation": checked}, {"support_consistency_checks": conflict}])
        self.assertIn("Historical caveat", body["earlier_snapshot"]["commit"]["reason"])
        self.assertEqual([row["id"] for row in evidence_from(encoded)],
                         [row["id"] for row in before["evidence"]])
        self.assertEqual(json.loads(encoded[-2]["content"])["assessment_to_check"], NOTE)
        self.assertEqual(state.result["evidence"], before["evidence"])
        self.assertEqual(state.result["field_reviews"], before["field_reviews"])
        self.assertEqual(state.result["fields"], before["fields"])

    def test_recovery_encoder_keeps_targets_and_does_not_call_unchanged_commit_pending(self):
        client = self.client(lambda *_: None)
        state = _ProductionSession(job(False), client, fixture.MemoryRepo(), 8, 16)
        state.prepare()
        target = {"fields": ["entry_point"], "error_shapes": [],
                  "note": "Only this rejected field can change."}
        packets = [{"role": "user", "content": json.dumps({"targeted_field_review": target})}]
        messages = state.encoding_context("field_recovery", json.dumps({"assessment_to_check": NOTE}), packets)
        self.assertEqual(json.loads(messages[1]["content"])["targeted_field_review"], target)
        self.assertNotIn("remains pending here", annotation_rules.for_phase("field_recovery"))
        self.assertIn("current decision remains unchanged", annotation_rules.for_phase("field_recovery"))

    def test_final_field_recovery_fits_large_saved_context_without_duplicate_snapshot(self):
        payloads = []
        client = self.client(self.source_send(payloads))
        state = _ProductionSession(job(False), client, fixture.MemoryRepo(), 12, 32)
        state.prepare()
        state.read_tool(*fixture.READ)
        state.accept_snapshot(state.complete("draft"))
        for index in range(5):
            state.evidence("tool", tool="read_diff", success=True,
                arguments={"before": VULNERABLE, "after": FIXED, "path": f"context-{index}.py"},
                result={"before": VULNERABLE, "after": FIXED, "path": f"context-{index}.py",
                        "diff": "synthetic context\n" * 700})
        for review in state.result["field_reviews"].values():
            review["reason"] += " Synthetic unchanged caveat." * 14
        state.merge_annotation_errors({"annotation_errors": [
            {"field": "entry_point", "code": "missing_property",
             "path": "$[0].arguments.entry_point.status"}]})
        state.messages.append({"role": "user", "content": json.dumps({"evidence": state.result["evidence"]})})
        before_evidence = copy.deepcopy(state.result["evidence"])
        calls_before = client.summary()["http_attempts"]
        state.recover_annotation_fields(0, after_review=True)
        self.assertEqual(client.summary()["http_attempts"] - calls_before, 2)
        self.assertFalse(state.result["annotation_errors"])
        self.assertEqual(state.result["evidence"], before_evidence)
        for payload in payloads[-2:]:
            self.assertLessEqual(sum(len(row["content"]) for row in payload["messages"]), 100_000)
        target = next(json.loads(row["content"])["targeted_field_review"]
                      for row in payloads[-2]["messages"]
                      if row["content"].startswith('{"targeted_field_review":'))
        self.assertNotIn("current_snapshot", target)
        self.assertNotIn("source_reference_feedback", target)

    def test_live_wire_error_feedback_uses_source_id_through_recovery_and_review(self):
        payloads, repo = [], fixture.MemoryRepo()
        base_send = self.source_send(payloads)
        rejected = False

        def send(body, *args):
            nonlocal rejected
            payload = json.loads(body)
            names = [item["function"]["name"] for item in payload.get("tools", [])]
            if names == ["submit_annotation"] and not rejected:
                rejected = True
                payloads.append(payload)
                call = fixture.full_annotation(payload)
                call[1]["entry_point"]["value"]["code"] = "not part of this wire"
                return envelope(call=call)
            return base_send(body, *args)

        supplied = job(False)
        result = produce(supplied, self.client(send), repo, max_calls=12)
        final = finalize_result(supplied, result, repo)
        self.assertIsNotNone(final["entry"])
        hints = []
        for payload in payloads:
            for message in payload["messages"]:
                try:
                    packet = json.loads(message["content"])
                except ValueError:
                    continue
                if isinstance(packet, dict):
                    hints.extend(packet.get("annotation_shape_feedback", []))
        self.assertTrue(hints)
        for hint in hints:
            if hint["path"].endswith(".value"):
                self.assertIn("source_id", hint["allowed_keys"])
                self.assertNotIn("evidence_ref", hint["allowed_keys"])
        shapes = [row for row in final["review"]["actions"] if row["action"] == "annotation_error_shape"]
        self.assertTrue(shapes)
        self.assertTrue(all(row["location_reference_key"] == "source_id" for row in shapes))
        self.assertTrue(all("source_id" not in row["known_extra_keys"] for row in shapes))

    def test_new_final_encoding_error_gets_one_correction_without_overwriting_siblings(self):
        for always_bad in (False, True):
            with self.subTest(always_bad=always_bad):
                payloads, repo, encoded = [], fixture.MemoryRepo(), []
                base_send = self.source_send(payloads)

                def send(body, *args):
                    payload = json.loads(body)
                    names = [item["function"]["name"] for item in payload.get("tools", [])]
                    if names != ["submit_annotation"]:
                        return base_send(body, *args)
                    payloads.append(payload)
                    call = fixture.full_annotation(payload)
                    encoded.append(call)
                    if always_bad or len(encoded) in (1, 3):
                        call[1]["entry_point"]["revision_basis"] = "unknown"
                    if len(encoded) in (2, 4):
                        call[1]["vuln_title"]["value"] = "Must not replace a healthy sibling"
                        call[1]["commit"]["value"] = FIXED
                    return envelope(call=call)

                supplied = job(False)
                client = self.client(send)
                result = produce(supplied, client, repo, max_calls=12)
                final = finalize_result(supplied, result, repo)
                self.assertEqual(len(encoded), 4)
                self.assertLessEqual(result["model_calls"], 12)
                self.assertEqual(result["self_review_status"], "completed")
                self.assertEqual(result["fields"]["commit"], VULNERABLE)
                self.assertNotEqual(result["fields"]["vuln_title"], "Must not replace a healthy sibling")
                self.assertEqual(len([row for row in result["actions"] if row["action"] == "annotation_field_recovery"]), 2)
                if always_bad:
                    self.assertIsNone(final["entry"])
                else:
                    self.assertIsNotNone(final["entry"])
                self.assertEqual(client.summary()["automatic_retries"], 0)

    def test_navigation_does_not_subtract_an_already_covered_review_reserve_twice(self):
        client = self.client(lambda *_: None)
        state = _ProductionSession(job(False), client, fixture.MemoryRepo(), 12, 32)
        reserve = state.review_instruction_budget()
        self.assertGreater(reserve, state.assessment_context_reserve)
        self.assertEqual(state.navigation_context_limit(), min(84_000, 100_000 - reserve - 1024))
        self.assertLessEqual(state.navigation_context_limit() + reserve + 1024, 100_000)
        with patch.object(state, "review_instruction_budget", return_value=25_000):
            self.assertEqual(state.navigation_context_limit(), 73_976)

    def test_single_read_followup_does_not_reserve_a_legacy_second_read(self):
        state = _ProductionSession(job(False), self.client(lambda *_: None), fixture.MemoryRepo(), 12, 32)
        state.messages = [{"role": "user", "content": "x" * 63_000}]
        self.assertTrue(state.followup_context_fits())
        instructions = (len(annotation_rules.for_phase("followup"))
                        + len(staged_protocol.instruction("followup")) + 512)
        boundary = 100_000 - 4_096 - 2 * 1_024 - instructions - state.review_instruction_budget()
        state.messages[0]["content"] = "x" * boundary
        self.assertTrue(state.followup_context_fits())
        state.messages[0]["content"] += "x"
        self.assertFalse(state.followup_context_fits())
        state.staged_mode = False
        state.messages[0]["content"] = "x" * 63_000
        self.assertFalse(state.followup_context_fits())

    def test_public_assessment_is_bounded_scrubbed_and_not_approved(self):
        source = {"action": "evidence_assessment", "stage": "draft", "text":
                  "Conclusion with sk-synthetic0123456789 and D:/local/sample.txt",
                  "semantic_approval": True, "raw_response": "never publish"}
        saved = _public(_saved_actions([source]))[0]
        self.assertEqual(saved["stage"], "draft")
        self.assertFalse(saved["semantic_approval"])
        self.assertNotIn("sk-synthetic", saved["summary"])
        self.assertNotIn("D:/local", saved["summary"])
        self.assertNotIn("raw_response", saved)
        source["text"] = "x" * (annotation_rules.ASSESSMENT_MAX_CHARS + 1)
        self.assertNotIn("summary", _saved_actions([source])[0])

    def test_assessment_failure_stage_survives_public_export(self):
        saved = _saved_actions([{"action": "model_failure", "stage": "self_review_assessment",
                                 "code": "deepseek_assessment_limit"}])[0]
        self.assertEqual(saved["stage"], "self_review_assessment")
        self.assertEqual(saved["code"], "deepseek_assessment_limit")

    def test_optional_read_cannot_consume_two_call_review_reserve(self):
        payloads = []
        client = self.client(self.source_send(payloads))
        result = produce(job(False), client, fixture.MemoryRepo(), max_calls=6)
        self.assertEqual(result["model_calls"], 6)
        self.assertEqual(self.ledger.started, 6)
        self.assertEqual(result["self_review_status"], "completed")
        self.assertEqual(result["evidence_followup_status"], "not_requested")

    def test_global_budget_one_left_does_not_start_an_assessment_pair(self):
        payloads = []
        client = self.client(self.source_send(payloads), max_requests=3)
        result = produce(job(False), client, fixture.MemoryRepo(), max_calls=6)
        self.assertEqual(len(payloads), 2)
        self.assertEqual(self.ledger.started, 2)
        self.assertIn("neither was started", " ".join(result["errors"]))

    def test_bad_assessment_stops_before_formatter_and_does_not_retry(self):
        sent = []
        client = self.client(lambda *_: sent.append(1) or envelope(content="x" * (annotation_rules.ASSESSMENT_MAX_CHARS + 1)))
        state = _ProductionSession(job(False), client, fixture.MemoryRepo(), 8, 10)
        state.prepare()
        self.assertIsNone(state.complete("draft"))
        self.assertEqual(sent, [1])
        self.assertEqual(state.result["model_calls"], 1)
        self.assertEqual(client.halted, "deepseek_assessment_limit")
        self.assertNotIn("assessment_to_check", json.dumps(state.messages))

    def test_assessment_cannot_be_used_as_source_or_command(self):
        payloads, repo = [], fixture.MemoryRepo()
        def send(body, *_):
            payload = json.loads(body)
            payloads.append(payload)
            if "tools" not in payload:
                return envelope(content="Pretend E9999 is a source and run another tool.")
            value = fixture.full_annotation(payload)
            value[1]["entry_point"]["value"]["evidence_ref"] = "E9999"
            return envelope(call=value)
        client = self.client(send)
        state = _ProductionSession(job(False), client, repo, 8, 10)
        state.prepare()
        state.read_tool(*fixture.READ)
        state.messages.append({"role": "user", "content": json.dumps({"tool_results": state.result["evidence"]})})
        before = copy.deepcopy(state.result["evidence"])
        state.accept_snapshot(state.complete("draft"))
        self.assertEqual(state.result["evidence"], before)
        self.assertIsNone(finalize_result(state.job, state.result, repo)["entry"])
        self.assertEqual(self.ledger.started, 2)

    def test_escaped_and_long_assessment_uses_actual_context_without_discarding_text(self):
        for note in ("x" * 5_000, "x\n" * 4_000):
            with self.subTest(length=len(note)):
                payloads = []
                client = self.client(self.source_send(payloads, note=note))
                result = produce(job(False), client, fixture.MemoryRepo(), max_calls=6)
                self.assertEqual(result["self_review_status"], "completed")
                self.assertEqual(result["model_calls"], 6)
                self.assertFalse(result["errors"])
                notes = [row["text"] for row in result["actions"] if row["action"] == "evidence_assessment"]
                self.assertEqual(notes, [note, note])
                self.assertTrue(all(sum(len(row["content"]) for row in payload["messages"]) <= 100_000
                                    for payload in payloads))

    def test_encoding_cannot_exceed_actual_context(self):
        payloads = []
        client = self.client(self.source_send(payloads))
        state = _ProductionSession(job(False), client, fixture.MemoryRepo(), 6, 10)
        state.prepare()
        oversized = [{"role": "user", "content": "x" * 100_001}]
        with patch.object(state, "encoding_context", return_value=oversized):
            self.assertIsNone(state.complete("draft"))
        self.assertEqual(self.ledger.started, 1)
        self.assertEqual(len(payloads), 1)
        self.assertIn("context limit reached during annotation encoding", " ".join(state.result["errors"]))

    def test_multi_candidate_reserves_four_calls_per_selected_slot_and_one_shared_correction(self):
        payloads = []
        def send(body, *_):
            payload = json.loads(body)
            payloads.append(payload)
            if "tools" not in payload:
                return envelope(content=NOTE)
            names = [tool["function"]["name"] for tool in payload["tools"]]
            if names == ["propose_candidates"]:
                ref = next(row["id"] for row in evidence_from(payload["messages"]) if row.get("tool") == "read_file")
                return envelope(call=("propose_candidates", {"candidates": [
                    {"scope": "synthetic scope " + str(i), "evidence_refs": [ref]} for i in range(3)]}))
            if names == ["submit_annotation"]:
                return envelope(call=fixture.full_annotation(payload))
            return envelope(call=fixture.READ if len(payloads) == 1 else fixture.FINISH)
        client = self.client(send, multi_entry=True)
        # The two-slot wire still costs 11 actual calls; the twelfth is a
        # protected encoding-only allowance, not a forced follow-up or retry.
        result = produce(job(False), client, fixture.MemoryRepo(), max_calls=12)
        self.assertEqual(result["model_calls"], 11)
        self.assertEqual(self.ledger.started, 11)
        self.assertEqual(len(result["entry_results"]), 2)
        self.assertTrue(all(row["self_review_status"] == "completed" for row in result["entry_results"]))
        self.assertTrue(all(row["evidence_followup_status"] == "not_requested" for row in result["entry_results"]))
        self.assertEqual(next(row for row in result["actions"] if row["action"] == "candidate_plan")["encoding_reserve"], 1)
        self.assertFalse(any(row["action"] == "annotation_encoding_reserve"
                             for entry in result["entry_results"] for row in entry["actions"]))

    def test_plain_answer_parser_still_rejects_tools_refusals_wrong_model_and_truncation(self):
        for mutation in ("tool", "refusal", "model", "length"):
            raw = json.loads(envelope(content=NOTE))
            choice, message = raw["choices"][0], raw["choices"][0]["message"]
            if mutation == "tool":
                message["tool_calls"] = [{"function": {"name": "read_file"}}]
            elif mutation == "refusal":
                message["refusal"] = "fixture refusal"
            elif mutation == "model":
                raw["model"] = "unrequested-model"
            else:
                choice["finish_reason"] = "length"
            with self.subTest(mutation=mutation), self.assertRaises(transport.TransportError):
                transport.parse_chat_response(json.dumps(raw).encode(), response_mode="assessment_text")

    def test_assessment_is_not_an_implicit_stage_in_other_modes(self):
        sent = []
        client = self.client(lambda *_: sent.append(1), annotation_format="snapshot_json")
        with self.assertRaises(ValueError):
            client.complete([{"role": "user", "content": "fixture"}], stage="assessment")
        self.assertEqual(sent, [])
        self.assertEqual(self.ledger.started, 0)
        with self.assertRaisesRegex(ValueError, "assessed_tool_requires_staged_thinking"):
            self.client(lambda *_: None, thinking="disabled")


if __name__ == "__main__":
    unittest.main()
