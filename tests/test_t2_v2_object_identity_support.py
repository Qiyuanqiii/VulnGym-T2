"""Own-field identity/dispatch regressions: synthetic tools, no model service."""
from copy import deepcopy
import unittest

from vulngym_t2 import annotation_rules, staged_protocol
from vulngym_t2.output import finalize_result
from vulngym_t2.pipeline import produce
from vulngym_t2.support_consistency import RULE_VERSION, check_support, public_checks
from tests import test_t2_v2_output as output_fixture
from tests import test_t2_v2_pipeline as pipeline_fixture
from tests import test_t2_v2_retest_failures as wire_fixture
from tests import test_t2_v2_staged_pipeline as staged_fixture


IDENTITY = "The loaded object's identity as Parser is inferred from the saved path/docstring, not separately read."
CONNECTION = "The saved source shows parse -> split -> consume."
GAP = CONNECTION + " " + IDENTITY
LOCAL = "The saved source shows the public API receiving the supplied text."
FLOW = [{"file": "synthetic.py", "line": 1, "code": "consume(value)", "desc": "fixture"}]
RULE = "object_identity_dispatch_disclaimed"


def assessment(reason, status="supported"):
    return {"status": status, "reason": reason, "evidence_refs": ["E0003"]}


class ObjectIdentitySupportTests(unittest.TestCase):
    def test_own_claim_and_unread_identity_are_both_required(self):
        for reason in (GAP,
                       "Saved code shows Decoder.parse() → Decoder.consume(). " + IDENTITY,
                       "The dispatch to the selected implementation is shown. "
                       "The returned object's class identity is only inferred from a name, not directly read.",
                       "The entry-to-operation connection is established. "
                       "The identity of the returned object is inferred from documentation, not independently read."):
            for field in ("entry_point", "critical_operation", "trace"):
                with self.subTest(field=field, reason=reason):
                    decision = assessment(reason)
                    before = deepcopy(decision)
                    checked = check_support(field, decision, value=FLOW)
                    self.assertEqual(checked["issues"], [{"code": "supported_reason_conflict",
                        "prerequisite": "receiver_identity_for_dispatch", "rule": RULE}])
                    self.assertEqual(checked["version"], RULE_VERSION)
                    self.assertEqual(public_checks({field: checked}), {field: checked})
                    self.assertEqual(decision, before)
        for reason in (CONNECTION, IDENTITY, LOCAL + " " + IDENTITY,
                       "The method inventory is parse -> consume. " + IDENTITY,
                       "The dispatch is not shown but the local API is shown. " + IDENTITY):
            with self.subTest(reason=reason):
                self.assertEqual(check_support("entry_point", assessment(reason))["issues"], [])

    def test_saved_v83_reason_exposes_specific_conjunction_not_every_local_api(self):
        # Verbatim saved public assessment, not a new read of any target source.
        reason = (
            "E0014 L96-107 shows the public function reading external text and calling tokenize; "
            "E0010 L1273-1277 shows tokenize -> sentences_from_text -> span_tokenize -> _slices_from_text. "
            "The loaded object's identity as PunktSentenceTokenizer is inferred from the punkt pickle path/docstring, "
            "not separately read; advisory 'unpredictable user input' provenance is reported, not independently proven.")
        self.assertEqual(check_support("entry_point", assessment(reason))["issues"][0]["rule"], RULE)
        narrowed = LOCAL + " " + IDENTITY + " I do not claim the downstream connection."
        self.assertEqual(check_support("entry_point", assessment(narrowed))["issues"], [])

    def test_narrow_local_claim_quotation_history_and_static_binding_do_not_trigger(self):
        reasons = (
            GAP + " I do not claim the cross-method connection.",
            GAP + " No downstream connection is claimed.",
            CONNECTION + ' The note says "' + IDENTITY + '".',
            CONNECTION + " The previous report says '" + IDENTITY + "'.",
            CONNECTION + " Previously " + IDENTITY,
            CONNECTION + " If " + IDENTITY,
            CONNECTION + " " + IDENTITY[:-1] + ", but is now read in a static assignment.",
            CONNECTION + " The loaded object's static binding is read in the constructor assignment; no runtime type test was run.",
            CONNECTION + " The loaded object's class identity is read from the saved return annotation, not observed at runtime.",
            CONNECTION + " An unrelated " + IDENTITY,
        )
        for field in ("entry_point", "critical_operation", "trace"):
            for reason in reasons:
                with self.subTest(field=field, reason=reason):
                    self.assertEqual(check_support(field, assessment(reason), value=FLOW)["issues"], [])

    def test_other_fields_statuses_and_omitted_trace_cannot_supply_a_missing_premise(self):
        for field in ("commit", "vuln_title", "project"):
            self.assertEqual(check_support(field, assessment(GAP), value=FLOW)["issues"], [])
        for status in ("uncertain", "missing", "conflicting"):
            self.assertEqual(check_support("entry_point", assessment(GAP, status))["issues"], [])
        for empty in ([], None, {}, "invalid"):
            self.assertEqual(check_support("trace", assessment(GAP), value=empty)["issues"], [])
        # Separately supplied reasons never combine into one claim. Nor does a
        # model-invented nested assessment field change the check's evidence.
        decision = assessment(IDENTITY)
        decision["other_field"] = assessment(CONNECTION)
        self.assertEqual(check_support("entry_point", decision)["issues"], [])
        self.assertEqual(check_support("critical_operation", assessment(CONNECTION))["issues"], [])
        optional = CONNECTION + " Optional trace: " + IDENTITY
        for field in ("entry_point", "critical_operation"):
            self.assertEqual(check_support(field, assessment(optional))["issues"], [])
        self.assertEqual(check_support("trace", assessment(optional), value=FLOW)["issues"][0]["rule"], RULE)

    def test_v4_v5_metadata_stays_readable_but_cannot_claim_v6_rules(self):
        for version, field, reason, value in (
                ("declared-support-v4", "entry_point", "The downstream link is not read.", None),
                ("declared-support-v5", "entry_point", "The downstream link is not read.", None),
                ("declared-support-v5", "entry_point", "The receiver type binding is not established.", None),
                ("declared-support-v5", "trace", "The trace connection is not established.", FLOW)):
            with self.subTest(version=version, field=field):
                packet = check_support(field, assessment(reason), value=value)
                packet["version"] = version
                self.assertEqual(public_checks({field: packet}), {field: packet})
        packet = check_support("entry_point", assessment(GAP))
        self.assertEqual(public_checks({"commit": packet}), {})
        for version in ("declared-support-v4", "declared-support-v5"):
            old = deepcopy(packet)
            old["version"] = version
            self.assertEqual(public_checks({"entry_point": old}), {})

    def test_output_holds_only_pairing_claim_and_preserves_api_location(self):
        job, result = output_fixture.fixture()
        result["field_reviews"]["entry_point"]["reason"] = GAP
        before = deepcopy(result)
        final = finalize_result(job, result, output_fixture.StubRepoReader())
        self.assertIsNone(final["entry"])
        review = final["review"]
        self.assertIsNone(review["draft_fields"]["entry_point"])
        self.assertEqual(review["suggested_values"]["entry_point"], before["fields"]["entry_point"])
        self.assertEqual(review["field_reviews"]["entry_point"]["status"], "uncertain")
        self.assertEqual(set(review["support_consistency_checks"]), {"entry_point"})
        for field in ("critical_operation", "commit"):
            self.assertEqual(review["draft_fields"][field], before["fields"][field])
        self.assertEqual(review["draft_fields"]["verify"], 0)
        self.assertEqual(result, before)

    def test_nonempty_trace_is_local_and_optional_without_demoting_ep_or_co(self):
        job, result = output_fixture.fixture()
        result["fields"]["trace"] = [deepcopy(result["fields"]["critical_operation"])]
        result["field_reviews"]["trace"] = assessment(GAP)
        final = finalize_result(job, result, output_fixture.StubRepoReader())
        self.assertIsNotNone(final["entry"])
        self.assertEqual(final["entry"]["trace"], [])
        self.assertEqual((len(final["entry"]), final["entry"]["verify"]), (15, 0))
        self.assertEqual(set(final["review"]["support_consistency_checks"]), {"trace"})
        for field in ("entry_point", "critical_operation"):
            self.assertEqual(final["entry"][field], result["fields"][field])

    def test_followup_prioritizes_needed_binding_without_requiring_runtime_work(self):
        text = annotation_rules.for_phase("followup")
        for phrase in ("one focused read or finish_reading", "remaining decision budget",
                       "missing receiver binding", "actual lazy/generator consumption",
                       "needed for a claimed connection", "no runtime test is required"):
            self.assertIn(phrase, text)


class IdentityClient(wire_fixture.UnknownClient):
    """Same three fake calls: fixture read, overclaimed draft, self-review."""
    def __init__(self):
        super().__init__()
        self.stages = []

    def complete(self, messages, *, stage):
        self.messages.append(deepcopy(messages))
        self.stages.append(stage)
        call = len(self.messages)
        if call == 1:
            name, arguments = staged_fixture.READ
        elif call in (2, 3):
            name, arguments = wire_fixture.full_annotation({"messages": messages})
            arguments["entry_point"]["reason"] = GAP if call == 2 else LOCAL
        else:
            raise AssertionError("No extra model or read call is allowed")
        return staged_protocol.normalize_calls([{"tool": name, "arguments": arguments}], stage)


class ObjectIdentityWireTests(unittest.TestCase):
    def test_rewording_cannot_clear_original_gap_or_increase_calls(self):
        client, repo, job = IdentityClient(), wire_fixture.MemoryRepo(), pipeline_fixture.job(False)
        result = produce(job, client, repo, max_calls=3, max_tool_calls=1)
        final = finalize_result(job, result, repo)
        self.assertEqual(client.stages, ["read", "annotation", "annotation"])
        self.assertEqual((result["model_calls"], result["tool_calls"]), (3, 1))
        self.assertEqual(result["self_review_status"], "completed")
        feedback = next(row for row in result["actions"] if row["action"] == "draft_validation")
        self.assertEqual(feedback["support_consistency_checks"]["entry_point"]["issues"][0]["rule"], RULE)
        self.assertIn("pending_support_conflict", result["field_reviews"]["entry_point"])
        self.assertIsNone(final["entry"])
        self.assertEqual(final["review"]["field_reviews"]["entry_point"]["status"], "uncertain")


if __name__ == "__main__":
    unittest.main()
