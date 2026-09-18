"""Synthetic field-consistency regressions; no target reads or model service.

Finite admissions may block a claim; not matching one never proves semantics.
"""
from copy import deepcopy
import unittest

from vulngym_t2 import annotation_rules, staged_protocol
from vulngym_t2.output import finalize_result
from vulngym_t2.pipeline import produce
from vulngym_t2.support_consistency import RULE_VERSION, basis_changed, check_support, public_checks
from tests import test_t2_v2_output as output_fixture
from tests import test_t2_v2_pipeline as pipeline_fixture
from tests import test_t2_v2_retest_failures as wire_fixture
from tests import test_t2_v2_staged_pipeline as staged_fixture


RECEIVER_GAP = "The method consumes the supplied value. Caveat: adapter is not read as a Parser instance."
TRACE_GAP = "The necessary connection is not established."
CLEAN_REASON = "The saved fixture locations support this synthetic assessment, not independent semantic approval."
FLOW = [{"file": "synthetic.py", "line": 1, "code": "consume(value)", "desc": "fixture"}]


def assessment(reason, *, status="supported"):
    return {"status": status, "reason": reason, "evidence_refs": ["E0003"]}


class EssentialPremiseTests(unittest.TestCase):
    def test_receiver_admission_is_held_only_in_its_own_current_field(self):
        for field in ("entry_point", "critical_operation", "trace"):
            for reason in (RECEIVER_GAP, "The receiver type binding is not established.",
                           "The returned-object assignment itself has not been confirmed."):
                with self.subTest(field=field, reason=reason):
                    decision = assessment(reason)
                    before = deepcopy(decision)
                    checked = check_support(field, decision, value=FLOW)
                    self.assertEqual(checked["issues"], [{"code": "supported_reason_conflict",
                        "prerequisite": "receiver_binding", "rule": "receiver_binding_disclaimed"}])
                    self.assertEqual(checked["version"], RULE_VERSION)
                    self.assertEqual(public_checks({field: checked}), {field: checked})
                    self.assertEqual(decision, before)
        for field in ("commit", "vuln_title", "project"):
            self.assertEqual(check_support(field, assessment(RECEIVER_GAP), value=FLOW)["issues"], [])

    def test_explicit_required_relation_is_not_supported_by_a_caveat(self):
        for field in ("entry_point", "critical_operation", "trace"):
            for reason in (TRACE_GAP, "The essential receiver binding is not verified.",
                           "必要的类型绑定尚未证实。"):
                with self.subTest(field=field, reason=reason):
                    checked = check_support(field, assessment(reason), value=FLOW)
                    self.assertEqual(len(checked["issues"]), 1)
                    self.assertIn(checked["issues"][0]["rule"],
                                  ("required_relation_disclaimed", "receiver_binding_disclaimed"))

    def test_optional_trace_means_omittable_not_permission_for_unsupported_steps(self):
        for reason in ("The trace connection is not established.",
                       "Generator consumption is not read.",
                       "Optional trace: " + TRACE_GAP):
            with self.subTest(reason=reason):
                self.assertTrue(check_support("trace", assessment(reason), value=FLOW)["issues"])
                for empty in ([], None, {}, "invalid"):
                    self.assertEqual(check_support("trace", assessment(reason), value=empty)["issues"], [])
        for field in ("entry_point", "critical_operation"):
            self.assertEqual(check_support(field, assessment("Optional trace: " + TRACE_GAP))["issues"], [])

    def test_runtime_checks_unread_callees_conditions_and_release_mapping_are_not_blanket_gates(self):
        reasons = (
            "The receiver is not runtime type-checked; its static binding is read.",
            "The returned object's deployment type is not observed at runtime.",
            "The callee was not read; the selected local missing guard is directly visible.",
            "Deployment configuration is not established; only the shown local condition is claimed.",
            "Release mapping is not established; the observed local mechanism is separately evidenced.",
            "The parser is directly read; an explicit escaping call is absent.",
            "The receiver binding is established, but the deployment type is not established.",
            "An unrelated receiver binding is not established.",
            "The unclaimed trace connection is not established.",
            "The downstream helper is not independently read.",
            "The static definition supports the operation; no sequence is claimed for the definition.",
        )
        for field in ("entry_point", "critical_operation", "trace"):
            for reason in reasons:
                with self.subTest(field=field, reason=reason):
                    checked = check_support(field, assessment(reason), value=FLOW)
                    self.assertEqual(checked["issues"], [])
                    self.assertNotIn("supported", checked)
                    self.assertNotIn("approved", checked)

    def test_quoted_historical_resolved_hypothetical_and_non_supported_are_not_current_admissions(self):
        for reason in ('The note says "adapter is not read as a Parser instance".',
                       "Previously adapter was not read as a Parser instance, but now confirmed.",
                       "If the receiver binding is not established, retain uncertainty.",
                       "The receiver binding was not established but is now read in the saved evidence."):
            for field in ("entry_point", "critical_operation", "trace"):
                with self.subTest(reason=reason, field=field):
                    self.assertEqual(check_support(field, assessment(reason), value=FLOW)["issues"], [])
        for status in ("uncertain", "missing", "conflicting"):
            self.assertEqual(check_support("entry_point", assessment(RECEIVER_GAP, status=status))["issues"], [])

    def test_v4_history_survives_without_accepting_new_rules_in_old_or_wrong_fields(self):
        historical = check_support("entry_point", assessment("The downstream link is not read."))
        historical["version"] = "declared-support-v4"
        self.assertEqual(public_checks({"entry_point": historical}), {"entry_point": historical})
        receiver = check_support("entry_point", assessment(RECEIVER_GAP))
        trace = check_support("trace", assessment("The trace connection is not established."), value=FLOW)
        self.assertEqual(public_checks({"commit": receiver, "entry_point": trace}), {})
        old = deepcopy(receiver)
        old["version"] = "declared-support-v4"
        self.assertEqual(public_checks({"entry_point": old}), {})
        self.assertEqual(public_checks({"trace": historical}), {})

    def test_trace_rewording_is_not_new_basis_but_explicit_omission_is(self):
        before = assessment(TRACE_GAP)
        after = assessment(CLEAN_REASON)
        changed = deepcopy(FLOW)
        changed[0]["desc"] = "Reworded only."
        self.assertFalse(basis_changed("trace", FLOW, before, changed, after, []))
        self.assertTrue(basis_changed("trace", FLOW, before, [], after, []))

    def test_rules_require_actual_transform_behavior_and_keep_static_definitions_out_of_runtime_order(self):
        self.assertIn("parser/transform's actual behavior", annotation_rules.CRITICAL_OPERATION_GUIDANCE)
        self.assertIn("no explicit escaping call is not proof of no escaping", annotation_rules.CRITICAL_OPERATION_GUIDANCE)
        self.assertIn("necessary receiver binding or connection left unknown", annotation_rules.ASSESSMENT_INSTRUCTION)
        self.assertIn("Static declarations are supporting evidence, not ordered runtime steps", annotation_rules.TRACE_DECISION_GUIDANCE)
        self.assertLessEqual(len(annotation_rules.TASK_RULES), 12_804)
        self.assertLessEqual(len(annotation_rules.ASSESSMENT_INSTRUCTION), 2_999)
        self.assertLessEqual(len(annotation_rules.TRACE_DECISION_GUIDANCE), 800)


class EssentialPremiseOutputTests(unittest.TestCase):
    def test_receiver_caveat_rejects_claim_without_losing_evidence_or_promoting_other_fields(self):
        for field in ("entry_point", "critical_operation"):
            job, result = output_fixture.fixture()
            result["field_reviews"][field]["reason"] = RECEIVER_GAP
            before = deepcopy(result)
            final = finalize_result(job, result, output_fixture.StubRepoReader())
            with self.subTest(field=field):
                self.assertIsNone(final["entry"])
                review = final["review"]
                self.assertIsNone(review["draft_fields"][field])
                self.assertEqual(review["suggested_values"][field], before["fields"][field])
                self.assertEqual(review["field_reviews"][field]["status"], "uncertain")
                self.assertEqual(review["field_reviews"][field]["reason"], RECEIVER_GAP)
                for other in ({"entry_point", "critical_operation", "commit"} - {field}):
                    self.assertEqual(review["draft_fields"][other], before["fields"][other])
                self.assertEqual((review["model_calls"], review["tool_calls"]), (3, 1))
                self.assertEqual(review["draft_fields"]["verify"], 0)
                self.assertEqual(result, before)

    def test_disputed_nonempty_trace_is_omitted_with_its_suggestion_preserved(self):
        job, result = output_fixture.fixture()
        steps = [deepcopy(result["fields"]["entry_point"]), deepcopy(result["fields"]["critical_operation"])]
        result["fields"]["trace"] = steps
        result["field_reviews"]["trace"] = assessment(TRACE_GAP)
        before = deepcopy(result)
        final = finalize_result(job, result, output_fixture.StubRepoReader())
        self.assertIsNotNone(final["entry"])
        self.assertEqual(final["entry"]["trace"], [])
        self.assertEqual(len(final["entry"]), 15)
        self.assertEqual(final["entry"]["verify"], 0)
        review = final["review"]
        self.assertEqual(review["suggested_values"]["trace"], steps)
        self.assertEqual(review["field_reviews"]["trace"]["status"], "uncertain")
        self.assertEqual(set(review["support_consistency_checks"]), {"trace"})
        for field in ("entry_point", "critical_operation"):
            self.assertEqual(final["entry"][field], before["fields"][field])
            self.assertEqual(review["field_reviews"][field]["status"], "supported")
        self.assertEqual(result, before)

    def test_empty_trace_does_not_resurrect_pending_or_suggested_steps(self):
        job, result = output_fixture.fixture()
        result["field_reviews"]["trace"] = assessment(TRACE_GAP)
        result["field_reviews"]["trace"]["pending_support_conflict"] = check_support(
            "trace", assessment(TRACE_GAP), value=FLOW)
        result["field_reviews"]["trace"]["suggested_value"] = deepcopy(FLOW)
        final = finalize_result(job, result, output_fixture.StubRepoReader())
        self.assertIsNotNone(final["entry"])
        self.assertEqual(final["entry"]["trace"], [])
        self.assertNotIn("trace", final["review"]["support_consistency_checks"])


class PremiseClient(wire_fixture.UnknownClient):
    """Three scripted stages: one fixture read, initial draft, self-review."""
    def __init__(self, field, correction):
        super().__init__()
        self.field, self.correction, self.stages = field, correction, []

    def complete(self, messages, *, stage):
        self.messages.append(deepcopy(messages))
        self.stages.append(stage)
        call = len(self.messages)
        if call == 1:
            name, arguments = staged_fixture.READ
            return staged_protocol.normalize_calls([{"tool": name, "arguments": arguments}], stage)
        if call not in (2, 3):
            raise AssertionError("No extra call, retry or follow-up is authorized by this fixture")
        name, arguments = wire_fixture.full_annotation({"messages": messages})
        field = arguments[self.field]
        if self.field == "trace":
            field.update(status="supported", value=[deepcopy(arguments["critical_operation"]["value"])],
                         evidence_refs=list(arguments["critical_operation"]["evidence_refs"]))
        field["reason"] = (TRACE_GAP if self.field == "trace" else RECEIVER_GAP) if call == 2 else CLEAN_REASON
        if call == 3 and self.correction == "description" and self.field == "trace":
            field["value"][0]["desc"] = "Only the description changed."
        if call == 3 and self.correction == "omit":
            field["value"] = []
        return staged_protocol.normalize_calls([{"tool": name, "arguments": arguments}], stage)


class EssentialPremiseWireTests(unittest.TestCase):
    def test_self_review_cannot_clear_required_premise_by_rewording_at_fixed_call_count(self):
        for field, correction in (("entry_point", "reason"), ("critical_operation", "reason"),
                                  ("trace", "reason"), ("trace", "description"), ("trace", "omit")):
            client, repo, job = PremiseClient(field, correction), wire_fixture.MemoryRepo(), pipeline_fixture.job(False)
            result = produce(job, client, repo, max_calls=3, max_tool_calls=1)
            final = finalize_result(job, result, repo)
            with self.subTest(field=field, correction=correction):
                self.assertEqual(client.stages, ["read", "annotation", "annotation"])
                self.assertEqual((result["model_calls"], result["tool_calls"]), (3, 1))
                self.assertEqual(result["self_review_status"], "completed")
                feedback = next(row for row in result["actions"] if row["action"] == "draft_validation")
                self.assertIn(field, feedback["support_consistency_checks"])
                if correction == "omit":
                    self.assertNotIn("pending_support_conflict", result["field_reviews"][field])
                    self.assertNotIn(field, final["review"]["support_consistency_checks"])
                else:
                    self.assertIn("pending_support_conflict", result["field_reviews"][field])
                    self.assertEqual(final["review"]["field_reviews"][field]["status"], "uncertain")
                if field == "trace":
                    self.assertIsNotNone(final["entry"])
                    self.assertEqual(final["entry"]["trace"], [])
                    self.assertEqual(final["entry"]["verify"], 0)
                else:
                    self.assertIsNone(final["entry"])


if __name__ == "__main__":
    unittest.main()
