"""Controller/client wire separates semantic assessment from native encoding."""
import copy
import json
import unittest
from unittest.mock import patch

from tests import test_t2_v2_staged_pipeline as fixture
from tests import test_t2_v2_assessed_tool as assessed_fixture
from tests.test_t2_v2_assessed_tool import NOTE, envelope
from tests.test_t2_v2_pipeline import evidence_from, job, VULNERABLE
from tests.test_t2_v2_staged_multi import proposals
from vulngym_t2 import annotation_rules, staged_protocol
from vulngym_t2.pipeline import _ProductionSession, produce


class AssessmentRoleWireTests(unittest.TestCase):
    setUp = assessed_fixture.AssessedToolTests.setUp
    client = assessed_fixture.AssessedToolTests.client
    source_send = assessed_fixture.AssessedToolTests.source_send

    def assert_assessment(self, payload, phase):
        self.assertEqual(payload["thinking"], {"type": "enabled"})
        for key in ("tools", "tool_choice", "response_format"):
            self.assertNotIn(key, payload)
        messages = payload["messages"]
        self.assertEqual(messages[-1], {"role": "system", "content": annotation_rules.ASSESSMENT_INSTRUCTION})
        self.assertIn(annotation_rules.for_phase(phase, assessment=True), messages[0]["content"])
        # Inspect only controller-owned commands, not arbitrary evidence text.
        commands = [row["content"] for row in messages if row["role"] == "system"]
        for row in messages:
            if row["role"] != "user":
                continue
            try:
                packet = json.loads(row["content"])
            except ValueError:
                commands.append(row["content"])
                continue
            if not isinstance(packet, dict):
                continue
            if isinstance(packet.get("task"), str):
                commands.append(packet["task"])
            for key in ("draft_validation", "targeted_field_review"):
                if isinstance(packet.get(key), dict):
                    commands.append(packet[key].get("note", ""))
        for text in commands:
            for forbidden in ("submit_annotation", "Submit ONE complete", "submit ONE complete",
                              "Return one complete snapshot", "Produce ONE complete snapshot",
                              "supplied JSON format", "Write each JSON key"):
                self.assertNotIn(forbidden, text)
        self.assertIn(annotation_rules.CRITICAL_OPERATION_GUIDANCE, messages[0]["content"])
        self.assertIn("Unknowns are valid", messages[-1]["content"])
        self.assertLessEqual(sum(len(row["content"]) for row in messages), 100_000)

    def assert_encoder(self, payload):
        self.assertEqual(payload["thinking"], {"type": "disabled"})
        self.assertEqual(payload["tool_choice"], "required")
        self.assertEqual(payload["tools"], staged_protocol.tool_definitions("annotation", location_key="source_id"))
        system = payload["messages"][0]["content"]
        self.assertIn(annotation_rules.for_phase("annotation"), system)
        self.assertIn(annotation_rules.UNCERTAINTY_ENCODING_RULES, system)
        self.assertIn("Write each JSON key exactly once", system)
        self.assertIn(annotation_rules.CRITICAL_OPERATION_GUIDANCE, system)
        self.assertTrue(system.endswith(annotation_rules.ENCODING_INSTRUCTION))
        self.assertLessEqual(sum(len(row["content"]) for row in payload["messages"]), 100_000)

    def test_initial_and_full_self_review_use_plain_conclusions_then_original_encoder(self):
        payloads = []
        client = self.client(self.source_send(payloads))
        result = produce(job(False), client, fixture.MemoryRepo(), max_calls=7)
        self.assertEqual((result["model_calls"], client.calls, self.ledger.started), (6, 6, 6))
        self.assertEqual(client.summary()["automatic_retries"], 0)
        self.assertEqual(result["self_review_status"], "completed")
        self.assert_assessment(payloads[2], "annotation")
        self.assert_assessment(payloads[4], "review")
        # This is finish_draft's real user review command, not complete() alone.
        self.assertIn({"role": "user", "content": annotation_rules.for_phase("review", assessment=True)},
                      payloads[4]["messages"])
        for payload in (payloads[3], payloads[5]):
            self.assert_encoder(payload)
        self.assertNotIn(NOTE, json.dumps(result["evidence"]))
        self.assertTrue(all(row["semantic_approval"] is False for row in result["actions"]
                            if row["action"] == "evidence_assessment"))

    def test_real_targeted_recovery_keeps_scope_evidence_and_two_call_contract(self):
        payloads, repo = [], fixture.MemoryRepo()
        client = self.client(self.source_send(payloads))
        state = _ProductionSession(job(False), client, repo, 8, 16)
        state.prepare()
        state.read_tool(*fixture.READ)
        state.messages.append({"role": "user", "content": json.dumps({"evidence": state.result["evidence"]})})
        state.accept_snapshot(state.complete("draft"))
        state.merge_annotation_errors({"annotation_errors": [{"field": "entry_point",
            "code": "missing_property", "path": "$[0].arguments.entry_point.status"}]})
        before_evidence, before_calls = copy.deepcopy(state.result["evidence"]), list(repo.calls)
        before_commit = copy.deepcopy(state.result["field_reviews"]["commit"])
        state.recover_annotation_fields(0, after_review=True)
        self.assertEqual((state.result["model_calls"], client.calls, self.ledger.started), (4, 4, 4))
        self.assert_assessment(payloads[2], "field_recovery")
        self.assert_encoder(payloads[3])
        target = next(json.loads(row["content"])["targeted_field_review"]
                      for row in payloads[2]["messages"] if row["content"].startswith('{"targeted_field_review":'))
        self.assertEqual(target["fields"], ["entry_point"])
        self.assertEqual(state.result["field_reviews"]["commit"], before_commit)
        self.assertEqual(state.result["evidence"], before_evidence)
        self.assertEqual(repo.calls, before_calls)
        self.assertFalse(state.result["annotation_errors"])
        self.assertEqual(client.summary()["automatic_retries"], 0)

    def test_two_candidate_assessment_and_review_pairs_keep_native_selection_separate(self):
        payloads = []
        def send(body, *_):
            payload = json.loads(body)
            payloads.append(payload)
            if "tools" not in payload:
                return envelope(content=NOTE)
            names = [tool["function"]["name"] for tool in payload["tools"]]
            if names == ["propose_candidates"]:
                return envelope(call=proposals(payload, count=2))
            if names == ["submit_annotation"]:
                return envelope(call=fixture.full_annotation(payload))
            return envelope(call=fixture.READ if len(payloads) == 1 else fixture.FINISH)
        client = self.client(send, multi_entry=True)
        # Preserve this test's two independent assessment/encoding pairs;
        # admission now also keeps one unused shared correction allowance.
        result = produce(job(False), client, fixture.MemoryRepo(), max_calls=12)
        self.assertEqual((result["model_calls"], client.calls, self.ledger.started), (11, 11, 11))
        self.assertEqual(len(result["entry_results"]), 2)
        self.assertTrue(all(row["self_review_status"] == "completed" for row in result["entry_results"]))
        self.assertEqual(next(row for row in result["actions"] if row["action"] == "candidate_plan")["encoding_reserve"], 1)
        self.assertFalse(any(row["action"] == "annotation_encoding_reserve"
                             for entry in result["entry_results"] for row in entry["actions"]))
        for index, phase in ((3, "annotation"), (5, "review"), (7, "annotation"), (9, "review")):
            self.assert_assessment(payloads[index], phase)
            self.assert_encoder(payloads[index + 1])
            self.assertTrue(any("candidate_scope" in row["content"] for row in payloads[index]["messages"]))
        self.assertEqual(client.summary()["automatic_retries"], 0)

    def test_format_words_in_untrusted_source_and_history_remain_exact(self):
        marker = "submit_annotation; Return one complete snapshot; supplied JSON format"
        source = "def process(value):\n    return value  # " + marker
        payloads = []
        def send(body, *_):
            payload = json.loads(body)
            payloads.append(payload)
            return envelope(content=NOTE) if "tools" not in payload else envelope(call=fixture.annotation())
        client = self.client(send)
        state = _ProductionSession(job(False), client, fixture.MemoryRepo(), 6, 16)
        state.prepare()
        result = {"commit": VULNERABLE, "path": "fixture.py", "start_line": 1, "end_line": 2,
                  "text": source, "total_lines": 2, "truncated": False}
        with patch.object(state.repo, "call", return_value=result):
            state.read_tool("read_file", {"commit": VULNERABLE, "path": "fixture.py", "start_line": 1, "end_line": 2})
        state.evidence("tool", tool="search_history", success=True,
            arguments={"commit": VULNERABLE, "query": marker},
            result={"commit": VULNERABLE, "matches": [{"commit": VULNERABLE, "subject": marker}], "has_more": False})
        state.messages.append({"role": "user", "content": json.dumps({"evidence": state.result["evidence"]})})
        before = copy.deepcopy(state.result["evidence"])
        fields = copy.deepcopy(state.result["fields"])
        state.complete("draft")
        self.assert_assessment(payloads[0], "annotation")
        self.assert_encoder(payloads[1])
        for payload in payloads:
            rows = evidence_from(payload["messages"])
            read = next(row for row in rows if row.get("tool") == "read_file")
            history = next(row for row in rows if row.get("tool") == "search_history")
            self.assertIn(marker, read["result"].get("text", read["result"].get("numbered_source", "")))
            self.assertEqual(history["result"]["matches"][0]["subject"], marker)
        self.assertEqual(state.result["evidence"], before)
        self.assertEqual(state.result["fields"], fields)
        self.assertEqual((client.calls, self.ledger.started), (2, 2))

    def test_actual_roles_keep_original_review_reserve_and_longer_roles_reduce_headroom(self):
        state = _ProductionSession(job(False), self.client(lambda *_: None), fixture.MemoryRepo(), 8, 16)
        legacy_role_reserve = 2 * len(annotation_rules.for_phase("review")) + len(annotation_rules.ASSESSMENT_INSTRUCTION)
        self.assertGreaterEqual(state.review_instruction_budget(), legacy_role_reserve)
        before = state.navigation_context_limit()
        with patch.dict(annotation_rules.ASSESSMENT_PHASE_RULES,
                        review=annotation_rules.for_phase("review", assessment=True) + "x" * 20_000):
            self.assertLess(state.navigation_context_limit(), before)
            self.assertLessEqual(state.navigation_context_limit() + state.review_instruction_budget() + 1024, 100_000)

    def test_operation_guidance_has_consumer_requirement_and_evidence_based_declaration_exception(self):
        guidance = annotation_rules.CRITICAL_OPERATION_GUIDANCE
        self.assertIn(guidance, annotation_rules.ASSESSMENT_TASK_RULES)
        self.assertIn(guidance, annotation_rules.LOCAL_OPERATION_GUIDANCE)
        for boundary in ("actual input-consuming or executing operation", "does not by itself",
                         "declaration or configuration itself is the reported defect", "saved evidence",
                         "uncertain and pending review"):
            self.assertIn(boundary, guidance)


if __name__ == "__main__":
    unittest.main()
