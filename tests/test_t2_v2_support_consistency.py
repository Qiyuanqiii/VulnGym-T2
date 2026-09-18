"""Finite declared-support checks on synthetic prose, not semantic validation."""
from copy import deepcopy
import unittest

from vulngym_t2.output import finalize_job, finalize_result
from vulngym_t2.support_consistency import check_support, public_checks, RULE_VERSION
from tests.test_t2_v2_output import StubRepoReader, fixture


OPENCLAW_EP_REASON = (
    "The selected location is the factory. The handler’s run/enclosing dispatch "
    "from this factory is not directly read, so that bridge is inferred from naming."
)
RULES = {
    "external_entry_role": {"entry_role_disclaimed", "factory_dispatch_inferred", "entry_dispatch_diff_only", "framework_dispatch_inferred", "entry_flow_disclaimed"},
    "operation_behavior": {"operation_behavior_disclaimed"},
    "affected_behavior": {"revision_behavior_disclaimed"},
    "affected_range_mapping": {"range_mapping_disclaimed"},
}


def assessment(reason, *, status="supported", basis=None):
    result = {"status": status, "reason": reason, "evidence_refs": ["E0003"]}
    if basis is not None:
        result["revision_basis"] = basis
    return result


class SupportConsistencyTests(unittest.TestCase):
    def test_current_entry_to_operation_gap_is_not_hidden_by_an_independent_route(self):
        reason = "This is a static input boundary. The downstream link into middleware was not read."
        checked = self.assert_issue("entry_point", reason, "external_entry_role")
        self.assertEqual(checked["issues"][0]["rule"], "entry_flow_disclaimed")
        self.assertEqual(public_checks({"entry_point": checked})["entry_point"], checked)
        for field in ("critical_operation", "commit", "trace"):
            self.assert_no_issue(field, reason, basis="behavior_at_revision")
        for prefix in ("If ", "Previously ", "Optional trace: "):
            self.assert_no_issue("entry_point", prefix + "the downstream link into middleware was not read.")
        self.assert_no_issue("entry_point", "The downstream link into middleware is read in E0008.")
        old = deepcopy(checked)
        old["version"] = "declared-support-v3"
        self.assertEqual(public_checks({"entry_point": old}), {})

    def test_framework_dispatch_admission_from_v8_real_review_requires_review(self):
        reason = ("The registration/dispatch that makes Carbon invoke this run is inferred "
                  "from the framework subclass, not separately read.")
        checked = self.assert_issue("entry_point", reason, "external_entry_role")
        self.assertEqual(checked["issues"][0]["rule"], "framework_dispatch_inferred")
        self.assertEqual(public_checks({"entry_point": checked})["entry_point"], checked)
        for prefix in ("If ", "Previously ", "Optional downstream trace: "):
            self.assert_no_issue("entry_point", prefix + reason)
        for other in ("The framework callback body and registration are directly read.",
                      "The dispatch is not inferred from the framework subclass; the registration is read.",
                      "Framework dispatch is read, but deployment permissions are not separately read."):
            self.assert_no_issue("entry_point", other)

    def assert_issue(self, field, reason, prerequisite, *, basis=None):
        source = assessment(reason, basis=basis)
        before = deepcopy(source)
        checked = check_support(field, source)
        self.assertEqual(source, before)
        self.assertEqual(checked["version"], RULE_VERSION)
        self.assertIs(type(checked["truncated"]), bool)
        self.assertFalse(checked["truncated"])
        self.assertGreaterEqual(len(checked["issues"]), 1, checked)
        for issue in checked["issues"]:
            self.assertEqual(set(issue), {"code", "prerequisite", "rule"})
            self.assertEqual(issue["code"], "supported_reason_conflict")
            self.assertEqual(issue["prerequisite"], prerequisite)
            self.assertIn(issue["rule"], RULES[prerequisite])
        self.assertEqual(checked, check_support(field, source))
        return checked

    def assert_no_issue(self, field, reason, *, status="supported", basis=None):
        checked = check_support(field, assessment(reason, status=status, basis=basis))
        self.assertEqual(checked, {"version": RULE_VERSION, "issues": [], "truncated": False})

    def test_actual_factory_handler_reason_requires_entry_role_review(self):
        self.assert_issue("entry_point", OPENCLAW_EP_REASON, "external_entry_role")

    def test_explicit_diff_only_external_dispatch_with_no_read_is_not_supported(self):
        reason = ("Its role as the callback reached from the external component event dispatch "
                  "is only shown via the diff callers (E0006), not a read receipt for the dispatch itself.")
        checked = self.assert_issue("entry_point", reason, "external_entry_role")
        self.assertEqual(checked["issues"][0]["rule"], "entry_dispatch_diff_only")
        self.assertEqual(public_checks({"entry_point": checked})["entry_point"], checked)
        for field in ("commit", "critical_operation", "trace"):
            self.assert_no_issue(field, reason, basis="behavior_at_revision")
        for prefix in ("If ", "Previously ", "Optional trace: "):
            self.assert_no_issue("entry_point", prefix + reason)
        for text in (
            "The external component callback is read directly; the diff describes its historical change.",
            "Its role in external dispatch is only shown via the diff; a direct read receipt is also available.",
            "The external callback declaration is read; no read receipt for the optional downstream trace exists.",
        ):
            self.assert_no_issue("entry_point", text)

    def test_legacy_support_metadata_preserves_version_without_forging_new_rule(self):
        old = check_support("entry_point", assessment("The entry point role is not established."))
        old["version"] = "declared-support-v1"
        self.assertEqual(public_checks({"entry_point": old})["entry_point"], old)
        old["issues"][0]["rule"] = "entry_dispatch_diff_only"
        self.assertEqual(public_checks({"entry_point": old}), {})

    def test_unread_factory_dispatch_and_naming_bridge_requires_entry_role_review(self):
        self.assert_issue(
            "entry_point",
            "The factory returns a handler. The enclosing dispatch from this factory "
            "is not directly read, so that bridge is inferred from naming.",
            "external_entry_role",
        )

    def test_explicit_unestablished_entry_role_requires_review(self):
        self.assert_issue("entry_point", "The entry point role is not established.", "external_entry_role")

    def test_already_uncertain_or_missing_decisions_are_not_rejected_again(self):
        for status in ("uncertain", "missing", "conflicting"):
            with self.subTest(status=status):
                self.assert_no_issue("entry_point", OPENCLAW_EP_REASON, status=status)

    def test_unrelated_unknowns_do_not_demote_observed_entry(self):
        for reason in (
            "The external handler directly reads the request body. The full route prefix is unknown.",
            "The handler declaration and request read are visible. Deployment permissions are not established.",
            "The entry point role is established, but the deployment configuration is not established.",
            "The external entry is directly read. Optional downstream trace is unknown and omitted.",
            "The enclosing handler is directly read; the downstream helper is not directly read.",
        ):
            with self.subTest(reason=reason):
                self.assert_no_issue("entry_point", reason)

    def test_hypothetical_quoted_resolved_and_negated_inference_are_not_current_admissions(self):
        for reason in (
            "If the entry point role is not established, it should remain uncertain.",
            'The advisory says "the entry point role is not established"; this is a quoted assertion.',
            "Previously the entry point role was not established, but the current read shows the external handler.",
            "The bridge is not inferred from naming; the handler's enclosing dispatch is directly read.",
            "The enclosing dispatch from this factory is not directly read; that bridge is not inferred "
            "from naming and is not asserted.",
            "The current source establishes the entry point role, not an inferred relationship.",
        ):
            with self.subTest(reason=reason):
                self.assert_no_issue("entry_point", reason)

    def test_only_supported_current_field_reason_is_examined(self):
        for field in ("trace", "vuln_title", "vuln_category_l1", "vuln_category_l2", "vuln_ids", "project"):
            with self.subTest(field=field):
                self.assert_no_issue(field, OPENCLAW_EP_REASON)
        source = assessment("The handler declaration and input read are visible.")
        source["suggested_value"] = OPENCLAW_EP_REASON
        source["omitted_assessment"] = assessment(OPENCLAW_EP_REASON)
        self.assertEqual(check_support("entry_point", source)["issues"], [])

    def test_selected_revision_behavior_explicitly_unestablished_requires_review(self):
        self.assert_issue(
            "commit", "The affected behavior at the selected revision is not established.",
            "affected_behavior", basis="behavior_at_revision",
        )

    def test_revision_range_gap_only_conflicts_with_range_and_source_basis(self):
        reason = (
            "The defective behavior is directly observed at the selected revision. "
            "The mapping of this revision to the affected range is not established."
        )
        self.assert_no_issue("commit", reason, basis="behavior_at_revision")
        self.assert_issue("commit", reason, "affected_range_mapping", basis="affected_range_and_source")

    def test_operation_defect_admission_is_specific_not_any_unread_callee(self):
        self.assert_issue(
            "critical_operation", "The claimed defective behavior of this operation is not established.",
            "operation_behavior",
        )
        for reason in (
            "The selected guard omits the required check in the displayed code. The callee was not read.",
            "The missing local guard is directly visible; end-to-end delivery is unknown and not claimed.",
            "If the claimed defective behavior of this operation is not established, keep it uncertain.",
        ):
            with self.subTest(reason=reason):
                self.assert_no_issue("critical_operation", reason)

    def test_empty_or_nontext_reason_is_not_a_semantic_approval(self):
        for reason in ("", None, [], {"reason": OPENCLAW_EP_REASON}):
            with self.subTest(reason=reason):
                checked = check_support("entry_point", assessment(reason))
                self.assertEqual(checked["issues"], [])
                self.assertNotIn("supported", checked)
                self.assertNotIn("approved", checked)
                self.assertNotIn("consistent", checked)

    def test_bounded_reason_reports_truncation_without_mutating_or_inventing_a_match(self):
        for source in (
            assessment("x" * 2_001),
            {**assessment("The external handler is directly read."), "reason_truncated": True},
        ):
            original = deepcopy(source)
            with self.subTest(source_length=len(source["reason"])):
                checked = check_support("entry_point", source)
                self.assertTrue(checked["truncated"])
                self.assertEqual(checked["issues"], [])
                self.assertEqual(source, original)


class SupportConsistencyOutputTests(unittest.TestCase):
    def test_rejected_entry_role_preserves_candidate_and_unrelated_fields(self):
        job, result = fixture()
        result["annotation_mode"] = "snapshot"
        result["self_review_status"] = "completed"
        result["field_reviews"]["entry_point"]["reason"] = OPENCLAW_EP_REASON
        original = deepcopy(result)
        finalized = finalize_result(job, result, StubRepoReader())
        review = finalized["review"]
        field_review = review["field_reviews"]["entry_point"]
        self.assertIsNone(finalized["entry"])
        self.assertEqual(review["status"], "draft")
        self.assertEqual(field_review["status"], "uncertain")
        self.assertEqual(field_review["reason"], OPENCLAW_EP_REASON)
        self.assertEqual(field_review["evidence_refs"], original["field_reviews"]["entry_point"]["evidence_refs"])
        self.assertEqual(field_review["pre_check_status"], "supported")
        self.assertEqual(field_review["support_consistency"]["version"], RULE_VERSION)
        self.assertEqual(field_review["support_consistency"], review["support_consistency_checks"]["entry_point"])
        self.assertIsNone(review["draft_fields"]["entry_point"])
        self.assertEqual(review["suggested_values"]["entry_point"], original["fields"]["entry_point"])
        self.assertIn("supported_reason_conflict", field_review["validation_errors"])
        self.assertTrue(any(row["field"] == "entry_point" and row["code"] == "supported_reason_conflict"
                            for row in review["errors"]))
        for field in ("commit", "critical_operation", "vuln_title", "vuln_category_l1", "project"):
            self.assertEqual(review["draft_fields"][field], original["fields"][field])
            self.assertEqual(review["field_reviews"][field]["status"], "supported")
        for category in ("annotation_errors", "model_errors", "pipeline_errors", "tool_errors"):
            self.assertEqual(review[category], [], category)
        self.assertEqual(review["self_review_status"], "completed")
        self.assertEqual(review["draft_fields"]["verify"], 0)
        self.assertEqual((review["model_calls"], review["tool_calls"]), (3, 1))
        self.assertEqual(result, original)

    def test_optional_trace_admission_does_not_demote_independent_entry_or_operation(self):
        job, result = fixture()
        result["field_reviews"]["trace"] = assessment(
            "The entry point role is not established for the suggested downstream step.", status="uncertain")
        result["field_reviews"]["trace"]["suggested_value"] = [deepcopy(result["fields"]["critical_operation"])]
        finalized = finalize_result(job, result, StubRepoReader())
        self.assertIsNotNone(finalized["entry"])
        self.assertEqual(finalized["entry"]["trace"], [])
        for field in ("entry_point", "critical_operation"):
            self.assertEqual(finalized["entry"][field], result["fields"][field])
            self.assertEqual(finalized["review"]["field_reviews"][field]["status"], "supported")
        self.assertFalse(any(row["code"] == "supported_reason_conflict" for row in finalized["review"]["errors"]))

    def test_multiple_candidates_isolate_admitted_entry_gap_without_extra_usage(self):
        job, result = fixture()
        result["annotation_mode"] = "snapshot"
        candidates = []
        for slot in (1, 2):
            candidates.append({"slot": slot, "fields": deepcopy(result["fields"]),
                               "field_reviews": deepcopy(result["field_reviews"]),
                               "annotation_errors": [], "errors": [], "actions": [],
                               "self_review_status": "completed", "evidence_followup_status": "not_requested",
                               "initial_draft_status": "accepted"})
        candidates[0]["field_reviews"]["entry_point"]["reason"] = OPENCLAW_EP_REASON
        result["entry_results"] = candidates
        original = deepcopy(result)
        finalized = finalize_job(job, result, StubRepoReader(), entry_ids={1: job["entry_id"], 2: "entry-00002"})
        self.assertEqual(finalized["status"], "partial")
        first, second = finalized["items"]
        self.assertIsNone(first["entry"])
        self.assertEqual(first["review"]["field_reviews"]["entry_point"]["status"], "uncertain")
        self.assertIsNotNone(second["entry"])
        self.assertEqual(second["entry"]["entry_id"], "entry-00002")
        self.assertEqual(second["entry"]["entry_point"], original["fields"]["entry_point"])
        self.assertEqual(second["review"]["field_reviews"]["entry_point"]["status"], "supported")
        self.assertFalse(any(row["code"] == "supported_reason_conflict" for row in second["review"]["errors"]))
        self.assertEqual(sum(item["review"]["model_calls"] for item in finalized["items"]), 3)
        self.assertEqual(sum(item["review"]["tool_calls"] for item in finalized["items"]), 1)
        self.assertEqual(second["entry"]["verify"], 0)
        self.assertEqual(result, original)


if __name__ == "__main__":
    unittest.main()
